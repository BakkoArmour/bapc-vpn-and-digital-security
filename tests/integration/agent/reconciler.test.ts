import test from "node:test";
import assert from "node:assert/strict";
import {AgentReconciler, type AgentPlatform, type AgentDesiredState, type Route} from "../../../src/agent/reconciler.js";
import {ProductionAgent, type AgentController} from "../../../agents/shared/production-agent.js";
import type {PlatformAdapter} from "../../../native/shared/platform-adapter.js";

const fakePlatform=(overrides:Partial<AgentPlatform> = {}):AgentPlatform&{calls:string[]}=>{
  const calls:string[]=[];
  return {
    calls,
    readRoutes:overrides.readRoutes??(async()=>{calls.push("readRoutes");return [];}),
    replaceRoutes:overrides.replaceRoutes??(async(r:Route[])=>{calls.push(`replaceRoutes:${r.length}`);}),
    readFileHash:overrides.readFileHash??(async(p:string)=>{calls.push(`readFileHash:${p}`);return "expected-hash";}),
    applyFirewallPlan:overrides.applyFirewallPlan??(async()=>{calls.push("applyFirewallPlan");}),
    clearTransientCredentials:overrides.clearTransientCredentials??(async()=>{calls.push("clearTransientCredentials");})
  };
};

const desiredState=(overrides:Partial<AgentDesiredState> = {}):AgentDesiredState => ({
  revision:1,routes:[],firewallPlan:{ok:true},integrityFiles:{},...overrides
});

test("reconcile applies the firewall plan and advances the revision on first run",async()=>{
  const platform=fakePlatform();
  const reconciler=new AgentReconciler(platform);
  const result=await reconciler.reconcile(desiredState({revision:1}));
  assert.deepEqual(result,{status:"APPLIED",revision:1});
  assert.ok(platform.calls.includes("applyFirewallPlan"));
});

test("reconcile rejects a state older than the last applied revision",async()=>{
  const platform=fakePlatform();
  const reconciler=new AgentReconciler(platform);
  await reconciler.reconcile(desiredState({revision:5}));
  const result=await reconciler.reconcile(desiredState({revision:3}));
  assert.deepEqual(result,{status:"STALE",revision:5});
});

test("reconcile replaces routes only when the current routes differ from desired",async()=>{
  const currentRoutes:Route[]=[{destination:"0.0.0.0/0",gateway:"10.0.0.1",interfaceName:"eth0",metric:100}];
  const platform=fakePlatform({readRoutes:async()=>currentRoutes});
  const reconciler=new AgentReconciler(platform);

  // Desired state matches current routes exactly -> no replaceRoutes call.
  await reconciler.reconcile(desiredState({revision:1,routes:currentRoutes}));
  assert.ok(!platform.calls.some(c=>c.startsWith("replaceRoutes")));

  // Desired state differs -> replaceRoutes is called with the desired set.
  const desiredRoutes:Route[]=[{destination:"0.0.0.0/0",gateway:"10.0.0.2",interfaceName:"eth0",metric:100}];
  await reconciler.reconcile(desiredState({revision:2,routes:desiredRoutes}));
  assert.ok(platform.calls.includes("replaceRoutes:1"));
});

test("reconcile detects a content change even when the route count stays the same (regression: stable() used to strip all route fields for same-length arrays)",async()=>{
  const currentRoutes:Route[]=[
    {destination:"0.0.0.0/0",gateway:"10.0.0.1",interfaceName:"eth0",metric:100},
    {destination:"10.144.0.0/24",interfaceName:"bapc0",metric:0}
  ];
  const desiredRoutes:Route[]=[
    {destination:"0.0.0.0/0",gateway:"10.0.0.1",interfaceName:"eth0",metric:100},
    {destination:"10.144.0.0/24",interfaceName:"bapc0",metric:50} // same length, one field differs
  ];
  const platform=fakePlatform({readRoutes:async()=>currentRoutes});
  const reconciler=new AgentReconciler(platform);
  await reconciler.reconcile(desiredState({revision:1,routes:desiredRoutes}));
  assert.ok(platform.calls.includes("replaceRoutes:2"));
});

test("reconcile treats a reordered-but-identical route set as unchanged",async()=>{
  const currentRoutes:Route[]=[
    {destination:"0.0.0.0/0",gateway:"10.0.0.1",interfaceName:"eth0",metric:100},
    {destination:"10.144.0.0/24",interfaceName:"bapc0",metric:0}
  ];
  const reorderedSameRoutes:Route[]=[currentRoutes[1]!,currentRoutes[0]!];
  const platform=fakePlatform({readRoutes:async()=>currentRoutes});
  const reconciler=new AgentReconciler(platform);
  await reconciler.reconcile(desiredState({revision:1,routes:reorderedSameRoutes}));
  assert.ok(!platform.calls.some(c=>c.startsWith("replaceRoutes")));
});

test("reconcile clears transient credentials and throws on an integrity mismatch, without touching routes or firewall",async()=>{
  const platform=fakePlatform({readFileHash:async()=>"actual-hash-does-not-match"});
  const reconciler=new AgentReconciler(platform);
  await assert.rejects(
    ()=>reconciler.reconcile(desiredState({integrityFiles:{"/etc/bapc-security/agent.env":"expected-hash"}})),
    /integrity failure/
  );
  assert.ok(platform.calls.includes("clearTransientCredentials"));
  assert.ok(!platform.calls.includes("applyFirewallPlan"));
});

test("ProductionAgent dispatches a RECONCILE command to the configured AgentReconciler",async()=>{
  const platform:PlatformAdapter={
    platform:"linux",
    async applyWireGuard(){},async applyFirewall(){},async rollbackFirewall(){},
    async setKillSwitch(){},async setDns(){},async isolate(){},async restore(){},
    async collectPosture(){return {osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false};}
  };
  const acknowledged:Array<{id:string;result:unknown}>=[];
  const reconciler=new AgentReconciler(fakePlatform());
  const controller:AgentController={
    async heartbeat(){return {commands:[{id:"cmd-1",type:"RECONCILE",payload:desiredState()}]};},
    async acknowledge(id,result){acknowledged.push({id,result});}
  };
  const agent=new ProductionAgent("node-1","1.0.0",platform,controller,10,reconciler);
  await (agent as any).execute({id:"cmd-1",type:"RECONCILE",payload:desiredState()});
  assert.equal(acknowledged.length,1);
  assert.equal((acknowledged[0]!.result as any).ok,true);
  assert.equal((acknowledged[0]!.result as any).status,"APPLIED");
});

test("ProductionAgent fails a RECONCILE command cleanly when no reconciler is configured",async()=>{
  const platform:PlatformAdapter={
    platform:"linux",
    async applyWireGuard(){},async applyFirewall(){},async rollbackFirewall(){},
    async setKillSwitch(){},async setDns(){},async isolate(){},async restore(){},
    async collectPosture(){return {osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false};}
  };
  const acknowledged:Array<{id:string;result:unknown}>=[];
  const controller:AgentController={
    async heartbeat(){return {commands:[]};},
    async acknowledge(id,result){acknowledged.push({id,result});}
  };
  const agent=new ProductionAgent("node-1","1.0.0",platform,controller,10); // no reconciler
  await (agent as any).execute({id:"cmd-1",type:"RECONCILE",payload:desiredState()});
  assert.equal((acknowledged[0]!.result as any).ok,false);
  assert.match((acknowledged[0]!.result as any).error,/no AgentReconciler is configured/);
});
