import test from "node:test";
import assert from "node:assert/strict";
import {AwsEc2RelayProvisioner} from "../../../services/relay-fleet/aws-ec2-relay-provisioner.js";

class FakeEc2Client {
  sent:any[]=[];
  describeCallsBeforeIp:number;
  constructor(describeCallsBeforeIp=2){this.describeCallsBeforeIp=describeCallsBeforeIp;}
  async send(command:any){
    this.sent.push(command);
    const name=command.constructor.name;
    if(name==="RunInstancesCommand")return {Instances:[{InstanceId:"i-0123456789abcdef0"}]};
    if(name==="DescribeInstancesCommand"){
      this.describeCallsBeforeIp--;
      const publicIp=this.describeCallsBeforeIp<=0?"203.0.113.10":undefined;
      return {Reservations:[{Instances:[{PublicIpAddress:publicIp}]}]};
    }
    if(name==="TerminateInstancesCommand")return {};
    throw new Error(`unexpected command ${name}`);
  }
}

test("launch polls DescribeInstances until a public IP appears, then returns the relay endpoint",async()=>{
  const client=new FakeEc2Client(2);
  const provisioner=new AwsEc2RelayProvisioner(client as any,{amiId:"ami-test",relayPort:51900,pollIntervalMs:1,pollAttempts:5});
  const result=await provisioner.launch({region:"us-east-1",instanceType:"t3.small"});
  assert.equal(result.instanceId,"i-0123456789abcdef0");
  assert.equal(result.publicIp,"203.0.113.10");
  assert.equal(result.endpoint,"203.0.113.10:51900");
  const describeCalls=client.sent.filter(c=>c.constructor.name==="DescribeInstancesCommand");
  assert.equal(describeCalls.length,2);
});

test("launch fails clearly if no public IP ever appears",async()=>{
  const client=new FakeEc2Client(999);
  const provisioner=new AwsEc2RelayProvisioner(client as any,{amiId:"ami-test",relayPort:51900,pollIntervalMs:1,pollAttempts:5});
  await assert.rejects(
    ()=>provisioner.launch({region:"us-east-1",instanceType:"t3.small"}),
    /did not receive a public IP/
  );
});

test("terminate sends a TerminateInstancesCommand for the given instance id",async()=>{
  const client=new FakeEc2Client(0);
  const provisioner=new AwsEc2RelayProvisioner(client as any,{amiId:"ami-test",relayPort:51900,pollIntervalMs:1,pollAttempts:5});
  await provisioner.terminate("i-0123456789abcdef0");
  const terminateCall=client.sent.find(c=>c.constructor.name==="TerminateInstancesCommand");
  assert.deepEqual(terminateCall.input.InstanceIds,["i-0123456789abcdef0"]);
});
