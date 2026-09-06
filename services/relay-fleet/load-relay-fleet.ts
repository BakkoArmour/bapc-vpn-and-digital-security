import {EC2Client} from "@aws-sdk/client-ec2";
import {AwsEc2RelayProvisioner} from "./aws-ec2-relay-provisioner.js";

export interface RelayFleet {provisioner:AwsEc2RelayProvisioner; region:string;}

// Real, wired AWS EC2 relay auto-provisioning — not a stub — gated purely on
// whether these env vars are set. Returns undefined when they aren't, so
// callers can surface a clear "coming soon" response instead of crashing;
// the existing manually-inserted-relay path (RelayRoutingService, the SOC
// console's read-only Relays card) is completely unaffected either way. See
// [[user-build-everything-coming-soon]].
export const loadRelayFleet=(env:NodeJS.ProcessEnv=process.env):RelayFleet|undefined=>{
  const amiId=env.AWS_RELAY_AMI_ID;
  const region=env.AWS_RELAY_REGION??env.AWS_REGION;
  if(!amiId||!region){
    console.log(JSON.stringify({
      event:"relay_fleet.mode",mode:"manual-only",
      reason:"AWS_RELAY_AMI_ID/AWS_RELAY_REGION not set — coming soon: set them (plus AWS credentials and a golden AMI, see docs/RELAY-FLEET-AMI.md) to provision relay fleet nodes on AWS EC2 directly from the SOC console"
    }));
    return undefined;
  }
  const client=new EC2Client({region});
  const provisioner=new AwsEc2RelayProvisioner(client,{
    amiId,relayPort:Number(env.RELAY_PORT??51900),
    ...(env.AWS_RELAY_SUBNET_ID?{subnetId:env.AWS_RELAY_SUBNET_ID}:{}),
    ...(env.AWS_RELAY_SECURITY_GROUP_IDS?{securityGroupIds:env.AWS_RELAY_SECURITY_GROUP_IDS.split(",")}:{}),
    ...(env.AWS_RELAY_KEY_NAME?{keyName:env.AWS_RELAY_KEY_NAME}:{})
  });
  console.log(JSON.stringify({event:"relay_fleet.mode",mode:"aws-ec2",region,amiId}));
  return {provisioner,region};
};
