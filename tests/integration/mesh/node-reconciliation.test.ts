import test from "node:test";
import assert from "node:assert/strict";
import {NodeReconciliationService} from "../../../src/application/node-reconciliation.js";
import type {MeshNode, NetworkPolicy} from "../../../src/domain/types.js";
import type {NodeDesiredState} from "../../../services/mesh-controller/pg-desired-state-store.js";

// RECONCILE and its siblings (SET_DNS, SET_KILL_SWITCH, APPLY_PEERS,
// APPLY_FIREWALL) had real, fully-tested node-side consumers with nothing on
// the control plane that ever compared desired state against what a node
// last reported and corrected the difference. These pin down each of
// NodeReconciliationService's five drift dimensions independently: no drift
// when the last acknowledgement already matches, and the right corrective
// command enqueued (or MeshController.reconcile invoked) when it doesn't.

const testNode=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:`pk-${id}`,internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});
const desiredState=(overrides:Partial<NodeDesiredState>={}):NodeDesiredState=>({
  nodeId:"n1",revision:2,routes:[{destination:"10.0.0.0/8",interfaceName:"wg0",metric:100}],
  dnsServers:["1.1.1.1"],killSwitchEnabled:true,integrityFiles:{"/etc/wg0.conf":"abc"},
  updatedAt:new Date(),...overrides
});
const policy:NetworkPolicy={
  id:"p1",name:"allow-app",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
  protocols:["TCP"],destinationPorts:[443],action:"ALLOW",requiredRoles:[],requiresJit:false,
  priority:10,version:1,active:true
};

class FakeNodeRepository {
  constructor(private nodes:MeshNode[]){}
  async get(id:string){return this.nodes.find(n=>n.id===id);}
  async list(){return this.nodes;}
  async findByPublicKey(){return undefined;}
  async save(){}
}
class FakePolicyRepository {
  constructor(private policies:NetworkPolicy[]){}
  async listActive(){return this.policies;}
  async get(){return undefined;}
  async save(){}
}
class FakeDesiredStateStore {
  constructor(private states:Record<string,NodeDesiredState|undefined>){}
  async get(nodeId:string){return this.states[nodeId]??null;}
  async all(){return Object.values(this.states).filter((s):s is NodeDesiredState=>Boolean(s));}
  async upsert(){throw new Error("not used in these tests");}
}
class FakeCommandQueue {
  enqueued:Array<{nodeId:string;type:string;payload:any}>=[];
  constructor(private acks:Record<string,{status:string;details:any}|undefined>={}){}
  async enqueue(nodeId:string,type:string,payload:unknown){this.enqueued.push({nodeId,type,payload});}
  async latestAcknowledgement(_nodeId:string,commandType:string){
    const ack=this.acks[commandType];
    return ack?{commandId:"cmd",status:ack.status,acknowledgedAt:new Date(),details:ack.details}:null;
  }
}
class FakeMeshController {
  reconciled=0;
  constructor(private hash:string){}
  async planFor(){return {peers:[],topologyHash:this.hash};}
  async reconcile(){this.reconciled++;return {nodeId:"n1",peerCount:0,topologyHash:this.hash};}
}
class FakeDb {
  async query(){return {rows:[{commit_id:"commit-latest"}]};}
}

const buildService=(opts:{
  nodes?:MeshNode[];policies?:NetworkPolicy[];states?:Record<string,NodeDesiredState|undefined>;
  acks?:Record<string,{status:string;details:any}>;topologyHash?:string;
}={})=>{
  const queue=new FakeCommandQueue(opts.acks??{});
  const meshController=new FakeMeshController(opts.topologyHash??"hash-current");
  const service=new NodeReconciliationService(
    new FakeNodeRepository(opts.nodes??[testNode("n1")]) as any,
    new FakePolicyRepository(opts.policies??[policy]) as any,
    new FakeDesiredStateStore(opts.states??{n1:desiredState()}) as any,
    queue as any,meshController as any,new FakeDb() as any
  );
  return {service,queue,meshController};
};

test("checkNode returns no findings when the node has no desired state configured",async()=>{
  const {service}=buildService({states:{}});
  const result=await service.checkNode("n1");
  assert.deepEqual(result.checked,[]);
});

test("checkNode throws for an unknown node",async()=>{
  const {service}=buildService({nodes:[]});
  await assert.rejects(()=>service.checkNode("n1"),/unknown node/);
});

test("ROUTES_AND_INTEGRITY: no drift when the last RECONCILE ack already reached the desired revision",async()=>{
  const {service,queue}=buildService({acks:{RECONCILE:{status:"SUCCEEDED",details:{status:"APPLIED",revision:2}}}});
  const result=await service.checkNode("n1");
  const finding=result.checked.find(c=>c.dimension==="ROUTES_AND_INTEGRITY")!;
  assert.equal(finding.drifted,false);
  assert.equal(queue.enqueued.find(e=>e.type==="RECONCILE"),undefined);
});

test("ROUTES_AND_INTEGRITY: drifted and re-issues RECONCILE when the node has never acknowledged one",async()=>{
  const {service,queue}=buildService({acks:{}});
  const result=await service.checkNode("n1");
  const finding=result.checked.find(c=>c.dimension==="ROUTES_AND_INTEGRITY")!;
  assert.equal(finding.drifted,true);
  const cmd=queue.enqueued.find(e=>e.type==="RECONCILE")!;
  assert.equal(cmd.payload.revision,2);
  assert.deepEqual(cmd.payload.routes,desiredState().routes);
  assert.deepEqual(cmd.payload.integrityFiles,desiredState().integrityFiles);
  assert.equal(cmd.payload.firewallPlan.defaultAction,"DENY");
  assert.equal(cmd.payload.firewallPlan.rules[0].id,"p1");
});

// A node reporting an older revision than desired — even a SUCCEEDED one —
// is exactly what a stale/expired earlier command looks like, and must still
// be treated as drift so the node gets caught up.
test("ROUTES_AND_INTEGRITY: drifted when the last acknowledged revision is behind the desired revision",async()=>{
  const {service}=buildService({acks:{RECONCILE:{status:"SUCCEEDED",details:{status:"APPLIED",revision:1}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="ROUTES_AND_INTEGRITY")!.drifted,true);
});

// AgentReconciler.reconcile reports STALE (not APPLIED) when the payload it
// received was itself behind what the node already has — that's not a
// confirmation the current desired revision is in place.
test("ROUTES_AND_INTEGRITY: a STALE acknowledgement still counts as drift, not as in-sync",async()=>{
  const {service}=buildService({acks:{RECONCILE:{status:"SUCCEEDED",details:{status:"STALE",revision:5}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="ROUTES_AND_INTEGRITY")!.drifted,true);
});

test("DNS: no drift when the last SET_DNS ack echoed exactly the desired server list",async()=>{
  const {service,queue}=buildService({acks:{SET_DNS:{status:"SUCCEEDED",details:{servers:["1.1.1.1"]}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="DNS")!.drifted,false);
  assert.equal(queue.enqueued.find(e=>e.type==="SET_DNS"),undefined);
});

test("DNS: drifted and re-issues SET_DNS when the echoed list differs from desired",async()=>{
  const {service,queue}=buildService({acks:{SET_DNS:{status:"SUCCEEDED",details:{servers:["8.8.8.8"]}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="DNS")!.drifted,true);
  assert.deepEqual(queue.enqueued.find(e=>e.type==="SET_DNS")!.payload,{servers:["1.1.1.1"]});
});

test("KILL_SWITCH: no drift when the last ack echoed the desired enabled value",async()=>{
  const {service}=buildService({acks:{SET_KILL_SWITCH:{status:"SUCCEEDED",details:{enabled:true}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="KILL_SWITCH")!.drifted,false);
});

test("KILL_SWITCH: drifted and re-issues SET_KILL_SWITCH when the echoed value differs",async()=>{
  const {service,queue}=buildService({acks:{SET_KILL_SWITCH:{status:"SUCCEEDED",details:{enabled:false}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="KILL_SWITCH")!.drifted,true);
  assert.deepEqual(queue.enqueued.find(e=>e.type==="SET_KILL_SWITCH")!.payload,{enabled:true});
});

test("PEER_TOPOLOGY: no drift and no resend when the last APPLY_PEERS ack's hash matches the current plan",async()=>{
  const {service,meshController}=buildService({topologyHash:"same-hash",acks:{APPLY_PEERS:{status:"SUCCEEDED",details:{topologyHash:"same-hash"}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="PEER_TOPOLOGY")!.drifted,false);
  assert.equal(meshController.reconciled,0);
});

test("PEER_TOPOLOGY: drifted and calls meshController.reconcile when the echoed hash doesn't match",async()=>{
  const {service,meshController}=buildService({topologyHash:"new-hash",acks:{APPLY_PEERS:{status:"SUCCEEDED",details:{topologyHash:"old-hash"}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="PEER_TOPOLOGY")!.drifted,true);
  assert.equal(meshController.reconciled,1);
});

test("POLICY_VERSION: no drift when the last APPLY_FIREWALL ack's firewallHash matches the active policy set's compiled rules",async()=>{
  // Compute the same hash the service does, over the same compiled rules,
  // so this test doesn't need to know the hash algorithm's internals.
  const {createHash}=await import("node:crypto");
  const {firewallRulesFor}=await import("../../../src/infrastructure/pg-policy-enforcer.js");
  const {canonicalJson}=await import("../../../src/infrastructure/canonical-json.js");
  const rules=firewallRulesFor([policy]);
  const hash=createHash("sha256").update(canonicalJson(rules)).digest("hex");
  const {service,queue}=buildService({acks:{APPLY_FIREWALL:{status:"SUCCEEDED",details:{firewallHash:hash}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="POLICY_VERSION")!.drifted,false);
  assert.equal(queue.enqueued.find(e=>e.type==="APPLY_FIREWALL"),undefined);
});

test("POLICY_VERSION: drifted and re-issues APPLY_FIREWALL with the latest committed commitId when the hash doesn't match",async()=>{
  const {service,queue}=buildService({acks:{APPLY_FIREWALL:{status:"SUCCEEDED",details:{firewallHash:"stale-hash"}}}});
  const result=await service.checkNode("n1");
  assert.equal(result.checked.find(c=>c.dimension==="POLICY_VERSION")!.drifted,true);
  const cmd=queue.enqueued.find(e=>e.type==="APPLY_FIREWALL")!;
  assert.equal(cmd.payload.commitId,"commit-latest");
  assert.equal(cmd.payload.rules[0].id,"p1");
});

test("checkAll runs checkNode for every node with configured desired state",async()=>{
  const states={
    n1:desiredState({nodeId:"n1"}),
    n2:desiredState({nodeId:"n2",dnsServers:["9.9.9.9"]})
  };
  const {service}=buildService({
    nodes:[testNode("n1"),testNode("n2")],states,
    acks:{RECONCILE:{status:"SUCCEEDED",details:{status:"APPLIED",revision:2}}}
  });
  const results=await service.checkAll();
  assert.deepEqual(results.map(r=>r.nodeId).sort(),["n1","n2"]);
});
