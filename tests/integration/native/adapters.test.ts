import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync, mkdtempSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createHash} from "node:crypto";
import type {CommandRunner} from "../../../native/shared/command-runner.js";
import {LinuxPlatformAdapter} from "../../../native/linux/adapter.js";
import {WindowsPlatformAdapter} from "../../../native/windows/adapter.js";
import {ApplePlatformAdapter} from "../../../native/apple/adapter.js";
import type {PlatformAdapter} from "../../../native/shared/platform-adapter.js";

const VALID_KEY="A".repeat(42)+"c="; // matches the 44-char base64 WireGuard key shape

// A fake CommandRunner: no real process is ever spawned in these tests, so
// they never touch this machine's actual network/firewall/WireGuard state.
const fakeRunner=(handlers:Record<string,(args:string[])=>{stdout:string;stderr:string}>):{
  run:CommandRunner; calls:Array<{cmd:string;args:string[]}>;
}=>{
  const calls:Array<{cmd:string;args:string[]}>=[];
  const run:CommandRunner=async(cmd,args)=>{
    calls.push({cmd,args});
    const handler=handlers[cmd];
    if(!handler)throw new Error(`unexpected command: ${cmd}`);
    return handler(args);
  };
  return {run,calls};
};

test("LinuxPlatformAdapter.applyWireGuard rejects a malformed peer key",async()=>{
  const {run}=fakeRunner({which:()=>({stdout:"/usr/bin/wg",stderr:""})});
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await assert.rejects(()=>adapter.applyWireGuard({
    privateKeyReference:"key-material",addresses:["10.0.0.1/32"],
    peers:[{publicKey:"not-a-real-key",allowedIps:["10.0.0.2/32"],keepaliveSeconds:25}]
  }),/invalid peer public key/);
});

test("LinuxPlatformAdapter.applyWireGuard configures the interface via wg/ip",async()=>{
  const {run,calls}=fakeRunner({
    which:()=>({stdout:"/usr/bin/x",stderr:""}),
    ip:(args)=>{
      if(args[0]==="link"&&args[1]==="show")throw new Error("no such device");
      return {stdout:"",stderr:""};
    },
    wg:()=>({stdout:"",stderr:""})
  });
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await adapter.applyWireGuard({
    privateKeyReference:"dev-only-key-material",addresses:["10.144.0.5/32"],listenPort:51820,
    peers:[{publicKey:VALID_KEY,allowedIps:["10.144.0.6/32"],keepaliveSeconds:25,endpoint:"relay.example:51820"}]
  });
  const wgCall=calls.find(c=>c.cmd==="wg");
  assert.ok(wgCall);
  assert.ok(wgCall!.args.includes("peer"));
  assert.ok(wgCall!.args.includes(VALID_KEY));
  assert.ok(calls.some(c=>c.cmd==="ip"&&c.args.includes("add")));
});

test("LinuxPlatformAdapter.applyPeers updates peers via `wg set` without ever touching private-key",async()=>{
  const {run,calls}=fakeRunner({
    which:()=>({stdout:"/usr/bin/wg",stderr:""}),
    wg:()=>({stdout:"",stderr:""})
  });
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await adapter.applyPeers([{publicKey:VALID_KEY,allowedIps:["10.144.0.6/32"],keepaliveSeconds:25,endpoint:"relay.example:51820"}]);
  const wgCall=calls.find(c=>c.cmd==="wg");
  assert.ok(wgCall);
  assert.ok(wgCall!.args.includes("peer"));
  assert.ok(wgCall!.args.includes(VALID_KEY));
  assert.ok(wgCall!.args.includes("endpoint"));
  assert.ok(!wgCall!.args.includes("private-key"));
  assert.equal(calls.some(c=>c.cmd==="ip"),false);
});

test("LinuxPlatformAdapter.applyPeers rejects a malformed peer key",async()=>{
  const {run}=fakeRunner({which:()=>({stdout:"/usr/bin/wg",stderr:""})});
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await assert.rejects(()=>adapter.applyPeers([{publicKey:"not-a-real-key",allowedIps:["10.0.0.2/32"],keepaliveSeconds:25}]),/invalid peer public key/);
});

test("LinuxPlatformAdapter.applyFirewall writes an nft ruleset and applies it",async()=>{
  const {run,calls}=fakeRunner({
    which:()=>({stdout:"/usr/sbin/nft",stderr:""}),
    nft:()=>({stdout:"",stderr:""})
  });
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await adapter.applyFirewall({
    commitId:"c1",defaultAction:"DENY",
    rules:[{id:"r1",action:"ALLOW",protocols:["TCP"],ports:[443],sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"]}]
  });
  const applyCall=calls.find(c=>c.cmd==="nft"&&c.args[0]==="-f");
  assert.ok(applyCall);
  const rulesText=readFileSync(applyCall!.args[1]!,"utf8");
  assert.match(rulesText,/table inet bapc_security/);
  assert.match(rulesText,/"r1"/);
});

test("LinuxPlatformAdapter.collectPosture reflects missing firewall table",async()=>{
  const {run}=fakeRunner({
    nft:(args)=>{ if(args[0]==="list")throw new Error("no such table"); return {stdout:"",stderr:""}; }
  });
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  const posture=await adapter.collectPosture();
  assert.equal(posture.firewallEnabled,false);
});

test("LinuxPlatformAdapter.readRoutes parses real `ip route show` output",async()=>{
  const {run}=fakeRunner({
    which:()=>({stdout:"/usr/sbin/ip",stderr:""}),
    ip:()=>({stdout:
      "default via 192.168.1.1 dev eth0 proto dhcp metric 100 \n"+
      "10.144.0.0/24 dev bapc0 proto kernel scope link src 10.144.0.5 metric 0 \n",
      stderr:""})
  });
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  const routes=await adapter.readRoutes();
  assert.deepEqual(routes,[
    {destination:"0.0.0.0/0",gateway:"192.168.1.1",interfaceName:"eth0",metric:100},
    {destination:"10.144.0.0/24",interfaceName:"bapc0",metric:0}
  ]);
});

test("LinuxPlatformAdapter.replaceRoutes issues one `ip route replace` per route",async()=>{
  const {run,calls}=fakeRunner({which:()=>({stdout:"/usr/sbin/ip",stderr:""}),ip:()=>({stdout:"",stderr:""})});
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await adapter.replaceRoutes([
    {destination:"0.0.0.0/0",gateway:"192.168.1.1",interfaceName:"eth0",metric:100},
    {destination:"10.144.0.0/24",interfaceName:"bapc0",metric:0}
  ]);
  const replaceCalls=calls.filter(c=>c.cmd==="ip"&&c.args[1]==="replace");
  assert.equal(replaceCalls.length,2);
  assert.ok(replaceCalls[0]!.args.includes("via"));
  assert.ok(!replaceCalls[1]!.args.includes("via")); // no gateway on this route
});

test("LinuxPlatformAdapter.readFileHash computes a real SHA-256 over the file",async()=>{
  const dir=mkdtempSync(join(tmpdir(),"bapc-hash-"));
  const filePath=join(dir,"agent.env");
  writeFileSync(filePath,"NODE_ENV=production\n");
  const adapter=new LinuxPlatformAdapter("bapc0",fakeRunner({}).run);
  const hash=await adapter.readFileHash(filePath);
  assert.equal(hash,createHash("sha256").update("NODE_ENV=production\n").digest("hex"));
});

test("LinuxPlatformAdapter.clearTransientCredentials brings the interface down",async()=>{
  const {run,calls}=fakeRunner({which:()=>({stdout:"/usr/bin/ip",stderr:""}),ip:()=>({stdout:"",stderr:""})});
  const adapter=new LinuxPlatformAdapter("bapc0",run);
  await adapter.clearTransientCredentials();
  assert.ok(calls.some(c=>c.cmd==="ip"&&c.args.join(" ")==="link set bapc0 down"));
});

test("WindowsPlatformAdapter.readRoutes parses apply.ps1's GetRoutes JSON",async()=>{
  const {run}=fakeRunner({
    "powershell.exe":()=>({
      stdout:JSON.stringify({routes:[
        {destination:"0.0.0.0/0",gateway:"192.168.1.1",interfaceName:"Ethernet",metric:25},
        {destination:"10.144.0.0/24",gateway:null,interfaceName:"BAPC",metric:0}
      ]}),
      stderr:""
    })
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  const routes=await adapter.readRoutes();
  assert.deepEqual(routes,[
    {destination:"0.0.0.0/0",interfaceName:"Ethernet",metric:25,gateway:"192.168.1.1"},
    {destination:"10.144.0.0/24",interfaceName:"BAPC",metric:0}
  ]);
});

test("WindowsPlatformAdapter.replaceRoutes sends the desired routes as a JSON payload",async()=>{
  const {run,calls}=fakeRunner({
    "powershell.exe":(args)=>{
      const payloadPath=args[args.indexOf("-PayloadPath")+1]!;
      const payload=JSON.parse(readFileSync(payloadPath,"utf8"));
      assert.equal(payload.routes.length,1);
      return {stdout:JSON.stringify({replaced:1}),stderr:""};
    }
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  await adapter.replaceRoutes([{destination:"0.0.0.0/0",gateway:"192.168.1.1",interfaceName:"Ethernet",metric:25}]);
  assert.ok(calls.some(c=>c.args.includes("ReplaceRoutes")));
});

test("WindowsPlatformAdapter.readFileHash computes a real SHA-256 over the file",async()=>{
  const dir=mkdtempSync(join(tmpdir(),"bapc-hash-"));
  const filePath=join(dir,"agent.env");
  writeFileSync(filePath,"NODE_ENV=production\n");
  const adapter=new WindowsPlatformAdapter("BAPC",fakeRunner({}).run);
  const hash=await adapter.readFileHash(filePath);
  assert.equal(hash,createHash("sha256").update("NODE_ENV=production\n").digest("hex"));
});

test("WindowsPlatformAdapter.clearTransientCredentials uninstalls the tunnel service",async()=>{
  const {run,calls}=fakeRunner({
    "powershell.exe":()=>({stdout:JSON.stringify({cleared:true}),stderr:""})
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  await adapter.clearTransientCredentials();
  assert.ok(calls.some(c=>c.args.includes("ClearCredentials")));
});

test("WindowsPlatformAdapter.applyWireGuard writes a conf and installs the tunnel service",async()=>{
  const {run,calls}=fakeRunner({
    "wireguard.exe":()=>({stdout:"",stderr:""})
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  await adapter.applyWireGuard({
    privateKeyReference:"dev-only-key-material",addresses:["10.144.0.9/32"],listenPort:51820,
    peers:[{publicKey:VALID_KEY,allowedIps:["10.144.0.10/32"],keepaliveSeconds:25}]
  });
  const install=calls.find(c=>c.args.includes("/installtunnelservice"));
  assert.ok(install);
  const confPath=install!.args[1]!;
  const conf=readFileSync(confPath,"utf8");
  assert.match(conf,/\[Interface\]/);
  assert.match(conf,new RegExp(VALID_KEY.replace(/\+/g,"\\+")));
});

test("WindowsPlatformAdapter.applyPeers updates peers via wg.exe, never reinstalling the tunnel service",async()=>{
  const {run,calls}=fakeRunner({
    "wg.exe":()=>({stdout:"",stderr:""})
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  await adapter.applyPeers([{publicKey:VALID_KEY,allowedIps:["10.144.0.10/32"],keepaliveSeconds:25}]);
  const wgCall=calls.find(c=>c.cmd==="wg.exe");
  assert.ok(wgCall);
  assert.ok(wgCall!.args.includes("peer"));
  assert.ok(wgCall!.args.includes(VALID_KEY));
  assert.equal(calls.some(c=>c.cmd==="wireguard.exe"),false);
});

test("WindowsPlatformAdapter.applyFirewall passes rules to apply.ps1 as a JSON payload file",async()=>{
  const {run,calls}=fakeRunner({
    "powershell.exe":(args)=>{
      const payloadPath=args[args.indexOf("-PayloadPath")+1]!;
      const payload=JSON.parse(readFileSync(payloadPath,"utf8"));
      assert.equal(payload.commitId,"c1");
      return {stdout:JSON.stringify({applied:"BAPC-c1"}),stderr:""};
    }
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  await adapter.applyFirewall({
    commitId:"c1",defaultAction:"DENY",
    rules:[{id:"r1",action:"ALLOW",protocols:["TCP"],ports:[443],sourceZones:[],destinationZones:[]}]
  });
  assert.ok(calls.some(c=>c.cmd==="powershell.exe"&&c.args.includes("ApplyFirewall")));
});

test("WindowsPlatformAdapter.collectPosture parses apply.ps1's JSON output",async()=>{
  const {run}=fakeRunner({
    "powershell.exe":()=>({
      stdout:JSON.stringify({osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false}),
      stderr:""
    })
  });
  const adapter=new WindowsPlatformAdapter("BAPC",run);
  const posture=await adapter.collectPosture();
  assert.equal(posture.diskEncrypted,true);
});

test("ApplePlatformAdapter throws NotImplemented rather than silently succeeding",async()=>{
  const adapter:PlatformAdapter=new ApplePlatformAdapter("ios");
  await assert.rejects(()=>adapter.applyWireGuard({privateKeyReference:"x",addresses:[],peers:[]}),/NetworkExtension/);
  await assert.rejects(()=>adapter.applyPeers([]),/NetworkExtension/);
  await assert.rejects(()=>adapter.collectPosture(),/NetworkExtension/);
});
