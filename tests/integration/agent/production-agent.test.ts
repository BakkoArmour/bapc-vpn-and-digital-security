import test from "node:test";
import assert from "node:assert/strict";
import {ProductionAgent, type AgentController} from "../../../agents/shared/production-agent.js";
import type {PlatformAdapter} from "../../../native/shared/platform-adapter.js";

// ProductionAgent.execute's command switch had no dedicated test — every
// command type it dispatches (including the new APPLY_PEERS, added alongside
// PgMeshCommandSink) was only ever exercised indirectly, if at all. This
// pins down that each command type reaches the right PlatformAdapter method
// and that the controller is acknowledged accordingly.
class FakePlatform implements PlatformAdapter {
  readonly platform="linux" as const;
  calls:Array<{method:string;args:unknown[]}>=[];
  async applyWireGuard(...args:unknown[]){this.calls.push({method:"applyWireGuard",args});}
  async applyPeers(...args:unknown[]){this.calls.push({method:"applyPeers",args});}
  async rotatePrivateKey(...args:unknown[]){this.calls.push({method:"rotatePrivateKey",args});}
  async applyFirewall(...args:unknown[]){this.calls.push({method:"applyFirewall",args});}
  async rollbackFirewall(...args:unknown[]){this.calls.push({method:"rollbackFirewall",args});}
  async setKillSwitch(...args:unknown[]){this.calls.push({method:"setKillSwitch",args});}
  async setDns(...args:unknown[]){this.calls.push({method:"setDns",args});}
  async isolate(...args:unknown[]){this.calls.push({method:"isolate",args});}
  async restore(...args:unknown[]){this.calls.push({method:"restore",args});}
  async collectPosture(){
    return {osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false};
  }
}

class FakeController implements AgentController {
  acked:Array<{id:string;result:unknown}>=[];
  private commandsToReturn:Array<{id:string;type:string;payload:any}>;
  private served=false;
  constructor(commands:Array<{id:string;type:string;payload:any}>){this.commandsToReturn=commands;}
  async heartbeat(){
    if(this.served)return {commands:[]};
    this.served=true;
    return {commands:this.commandsToReturn};
  }
  async acknowledge(id:string,result:unknown){this.acked.push({id,result});}
}

const runOneHeartbeat=async(platform:FakePlatform,controller:FakeController)=>{
  const agent=new ProductionAgent("node-1","0.4.0",platform,controller,5);
  const run=agent.run();
  await new Promise(r=>setTimeout(r,20));
  agent.stop();
  await run;
};

test("ProductionAgent.execute dispatches APPLY_PEERS to PlatformAdapter.applyPeers and echoes a topologyHash",async()=>{
  const peers=[{publicKey:"pk1",allowedIps:["10.144.0.2/32"],keepaliveSeconds:25}];
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-1",type:"APPLY_PEERS",payload:{peers}}]);
  await runOneHeartbeat(platform,controller);
  assert.deepEqual(platform.calls,[{method:"applyPeers",args:[peers]}]);
  const result=controller.acked[0]!.result as any;
  assert.equal(result.ok,true);
  assert.match(result.topologyHash,/^[0-9a-f]{64}$/);
});

// NodeReconciliationService needs the applied value echoed back, not just
// ok:true, to know whether a node's kill-switch/DNS state still matches its
// desired state.
test("ProductionAgent.execute echoes the applied value back for SET_KILL_SWITCH and SET_DNS",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([
    {id:"cmd-ks",type:"SET_KILL_SWITCH",payload:{enabled:true}},
    {id:"cmd-dns",type:"SET_DNS",payload:{servers:["1.1.1.1","9.9.9.9"]}}
  ]);
  await runOneHeartbeat(platform,controller);
  assert.equal((controller.acked[0]!.result as any).enabled,true);
  assert.deepEqual((controller.acked[1]!.result as any).servers,["1.1.1.1","9.9.9.9"]);
});

// Regression: controller_commands.payload is jsonb, which does not preserve
// object key insertion order — a command built with keys in one order can
// come back out (and be delivered to the agent) with keys in a different
// order. The echoed hash must be identical either way, or
// NodeReconciliationService would see permanent, spurious topology drift on
// every single check even when nothing ever actually changed.
test("ProductionAgent.execute's APPLY_PEERS topologyHash is unaffected by the peer object's key order",async()=>{
  const peer={publicKey:"pk1",allowedIps:["10.144.0.2/32"],keepaliveSeconds:25,endpoint:"relay:51900"};
  const reorderedPeer={endpoint:"relay:51900",keepaliveSeconds:25,publicKey:"pk1",allowedIps:["10.144.0.2/32"]};
  const runWith=async(peers:unknown)=>{
    const platform=new FakePlatform();
    const controller=new FakeController([{id:"cmd-1",type:"APPLY_PEERS",payload:{peers}}]);
    await runOneHeartbeat(platform,controller);
    return (controller.acked[0]!.result as any).topologyHash;
  };
  assert.equal(await runWith([peer]),await runWith([reorderedPeer]));
});

test("ProductionAgent.execute echoes commitId and a firewallHash for APPLY_FIREWALL",async()=>{
  const platform=new FakePlatform();
  const rules=[{id:"p1",action:"ALLOW",protocols:["TCP"],ports:[443],sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"]}];
  const controller=new FakeController([{id:"cmd-fw",type:"APPLY_FIREWALL",payload:{commitId:"commit-1",defaultAction:"DENY",rules}}]);
  await runOneHeartbeat(platform,controller);
  const result=controller.acked[0]!.result as any;
  assert.equal(result.commitId,"commit-1");
  assert.match(result.firewallHash,/^[0-9a-f]{64}$/);
});

test("ProductionAgent.execute dispatches QUARANTINE to PlatformAdapter.isolate with the given reason",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-2",type:"QUARANTINE",payload:{reason:"threat detected"}}]);
  await runOneHeartbeat(platform,controller);
  assert.deepEqual(platform.calls,[{method:"isolate",args:["threat detected"]}]);
  assert.equal((controller.acked[0]!.result as any).ok,true);
});

test("ProductionAgent.execute dispatches RESTORE to PlatformAdapter.restore",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-3",type:"RESTORE",payload:{}}]);
  await runOneHeartbeat(platform,controller);
  assert.deepEqual(platform.calls,[{method:"restore",args:[]}]);
});

test("ProductionAgent.execute acknowledges an unsupported command type with a failure, not a throw",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-4",type:"NOT_A_REAL_COMMAND",payload:{}}]);
  await runOneHeartbeat(platform,controller);
  assert.equal(platform.calls.length,0);
  assert.equal((controller.acked[0]!.result as any).ok,false);
  assert.match((controller.acked[0]!.result as any).error,/unsupported controller command/);
});

// ROTATE_IDENTITY_REQUIRED (ThreatEngine's emergency-tier response) must
// never rotate server-side — the server never holds this node's private
// key. The node generates its own replacement key, signs the rotation
// itself with its enrolled identity key, and only then rotates its local
// interface. These pin down that whole chain, and that a rejected rotation
// never touches the local interface at all.
class FakeRotationClient {
  calls:Array<{nodeId:string;newPublicKey:string;signature:Buffer}>=[];
  constructor(private response:{acknowledged:boolean;effectiveEpoch:number}){}
  async rotatePeerKey(nodeId:string,newPublicKey:string,signature:Buffer){
    this.calls.push({nodeId,newPublicKey,signature});
    return this.response;
  }
}
class FakeIdentitySigner {
  calls:Array<{nodeId:string;newPublicKey:string}>=[];
  sign(nodeId:string,newPublicKey:string){this.calls.push({nodeId,newPublicKey});return Buffer.from("fake-signature");}
}

test("ProductionAgent.execute rotates locally only after the server acknowledges a signed rotation",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-5",type:"ROTATE_IDENTITY_REQUIRED",payload:{}}]);
  const rotationClient=new FakeRotationClient({acknowledged:true,effectiveEpoch:3});
  const identitySigner=new FakeIdentitySigner();
  const agent=new ProductionAgent("node-1","0.4.0",platform,controller,5,undefined,rotationClient as any,identitySigner as any);
  const run=agent.run();
  await new Promise(r=>setTimeout(r,20));
  agent.stop();
  await run;

  assert.equal(rotationClient.calls.length,1);
  assert.equal(rotationClient.calls[0]!.nodeId,"node-1");
  assert.equal(identitySigner.calls.length,1);
  assert.equal(identitySigner.calls[0]!.newPublicKey,rotationClient.calls[0]!.newPublicKey);
  assert.equal(platform.calls.length,1);
  assert.equal(platform.calls[0]!.method,"rotatePrivateKey");
  const acked=controller.acked[0]!.result as any;
  assert.equal(acked.ok,true);
  assert.equal(acked.newPublicKey,rotationClient.calls[0]!.newPublicKey);
  assert.equal(acked.effectiveEpoch,3);
});

test("ProductionAgent.execute never touches the local interface if the server rejects the rotation",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-6",type:"ROTATE_IDENTITY_REQUIRED",payload:{}}]);
  const rotationClient=new FakeRotationClient({acknowledged:false,effectiveEpoch:0});
  const identitySigner=new FakeIdentitySigner();
  const agent=new ProductionAgent("node-1","0.4.0",platform,controller,5,undefined,rotationClient as any,identitySigner as any);
  const run=agent.run();
  await new Promise(r=>setTimeout(r,20));
  agent.stop();
  await run;

  assert.equal(platform.calls.length,0);
  assert.equal((controller.acked[0]!.result as any).ok,false);
});

test("ProductionAgent.execute fails cleanly when ROTATE_IDENTITY_REQUIRED arrives with no rotation client/signer configured",async()=>{
  const platform=new FakePlatform();
  const controller=new FakeController([{id:"cmd-7",type:"ROTATE_IDENTITY_REQUIRED",payload:{}}]);
  await runOneHeartbeat(platform,controller);
  assert.equal(platform.calls.length,0);
  assert.match((controller.acked[0]!.result as any).error,/no MeshRotationClient\/IdentitySigner is configured/);
});
