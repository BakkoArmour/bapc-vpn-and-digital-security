import type {EC2Client} from "@aws-sdk/client-ec2";
import {RunInstancesCommand, TerminateInstancesCommand, DescribeInstancesCommand} from "@aws-sdk/client-ec2";

export interface RelayProvisionRequest {region:string; instanceType:string;}
export interface RelayInstance {instanceId:string; region:string; publicIp:string; endpoint:string;}
export interface RelayProvisionerConfig {
  amiId:string; relayPort:number;
  subnetId?:string; securityGroupIds?:string[]; keyName?:string;
  // Overridable so tests don't have to wait out a real 60s timeout.
  pollAttempts?:number; pollIntervalMs?:number;
}

const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));

// Boots a relay from a pre-baked "golden AMI" that already has the relay
// software installed as a systemd unit (bapc-relay.service) — see
// docs/RELAY-FLEET-AMI.md for how to bake one. This UserData only writes
// config and (re)starts that unit; it deliberately does NOT try to git-clone
// and build this repo on every boot (slow, needs outbound network/git access
// on a box whose only job is proxying traffic, and a much larger surface for
// something to go wrong on a fleet you're trying to scale quickly).
const buildUserData=(relayPort:number):string=>`#!/bin/bash
set -e
mkdir -p /etc/bapc
cat > /etc/bapc/relay.env <<EOF
RELAY_PORT=${relayPort}
RELAY_BIND_HOST=0.0.0.0
EOF
systemctl restart bapc-relay || { echo "bapc-relay.service not found — this AMI must have the relay pre-installed, see docs/RELAY-FLEET-AMI.md" >&2; exit 1; }
`;

// Real AWS EC2 provisioning — not a stub — for the relay fleet described in
// the `relays` table (db/002_operational_tables.sql) and selected by
// RelayRoutingService. Gated purely on RelayFleetConfig existing (see
// loadRelayFleetConfig in this file's caller); see
// [[user-build-everything-coming-soon]].
export class AwsEc2RelayProvisioner {
  constructor(private client:EC2Client,private config:RelayProvisionerConfig){}

  async launch(req:RelayProvisionRequest):Promise<RelayInstance>{
    const result=await this.client.send(new RunInstancesCommand({
      ImageId:this.config.amiId,InstanceType:req.instanceType as any,
      MinCount:1,MaxCount:1,
      UserData:Buffer.from(buildUserData(this.config.relayPort)).toString("base64"),
      TagSpecifications:[{ResourceType:"instance",Tags:[
        {Key:"Name",Value:"bapc-relay"},{Key:"bapc:managed",Value:"true"},{Key:"bapc:role",Value:"relay"}
      ]}],
      ...(this.config.subnetId?{SubnetId:this.config.subnetId}:{}),
      ...(this.config.securityGroupIds?{SecurityGroupIds:this.config.securityGroupIds}:{}),
      ...(this.config.keyName?{KeyName:this.config.keyName}:{})
    }));
    const instanceId=result.Instances?.[0]?.InstanceId;
    if(!instanceId)throw new Error("AWS EC2 did not return an instance id for the new relay");

    const publicIp=await this.pollForPublicIp(instanceId);
    return {instanceId,region:req.region,publicIp,endpoint:`${publicIp}:${this.config.relayPort}`};
  }

  private async pollForPublicIp(instanceId:string):Promise<string>{
    const attempts=this.config.pollAttempts??30,intervalMs=this.config.pollIntervalMs??2000;
    for(let i=0;i<attempts;i++){
      const result=await this.client.send(new DescribeInstancesCommand({InstanceIds:[instanceId]}));
      const ip=result.Reservations?.[0]?.Instances?.[0]?.PublicIpAddress;
      if(ip)return ip;
      await sleep(intervalMs);
    }
    throw new Error(`relay instance ${instanceId} did not receive a public IP within ${(attempts*intervalMs)/1000}s — check its subnet has auto-assign public IP enabled`);
  }

  async terminate(instanceId:string):Promise<void>{
    await this.client.send(new TerminateInstancesCommand({InstanceIds:[instanceId]}));
  }
}
