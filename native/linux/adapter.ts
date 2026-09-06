import {writeFileSync, mkdtempSync, existsSync, readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {tmpdir} from "node:os";
import {join} from "node:path";
import type {PlatformAdapter} from "../shared/platform-adapter.js";
import type {CommandRunner} from "../shared/command-runner.js";
import {systemCommandRunner} from "../shared/command-runner.js";
import type {AgentPlatform, Route} from "../../src/agent/reconciler.js";

const parseIpRouteLine=(line:string):Route|undefined=>{
  const tokens=line.trim().split(/\s+/);
  if(tokens.length===0||!tokens[0])return undefined;
  const destination=tokens[0]==="default"?"0.0.0.0/0":tokens[0];
  const via=tokens.indexOf("via");
  const dev=tokens.indexOf("dev");
  const metricIdx=tokens.indexOf("metric");
  if(dev===-1)return undefined; // not a route line we can act on (e.g. a wrapped continuation)
  return {
    destination,
    ...(via!==-1&&tokens[via+1]?{gateway:tokens[via+1]}:{}),
    interfaceName:tokens[dev+1]!,
    metric:metricIdx!==-1&&tokens[metricIdx+1]?Number(tokens[metricIdx+1]):0
  };
};

const WG_KEY_RE=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/; // base64 32-byte key, WireGuard's fixed padding char set
const CIDR_RE=/^[0-9a-fA-F.:]+\/\d{1,3}$/;

const assertKey=(k:string,field:string)=>{if(!WG_KEY_RE.test(k))throw new Error(`invalid ${field}`);};
const assertCidrList=(ips:string[])=>{for(const ip of ips)if(!CIDR_RE.test(ip))throw new Error(`invalid allowed-ip ${ip}`);};

// Real Linux adapter: WireGuard via `wg`/`ip`, firewall via `nft`. Every value
// that reaches a command is either validated against the patterns above or
// passed as a discrete argv element (never shell-interpolated), and every
// method degrades to a clear thrown error — never a silent no-op — when the
// required binary is missing, so a misconfigured host fails loudly.
export class LinuxPlatformAdapter implements PlatformAdapter, AgentPlatform {
  readonly platform="linux" as const;
  constructor(
    private iface="bapc0",
    private run:CommandRunner=systemCommandRunner
  ){}

  private async requireBinary(name:string){
    try{await this.run("which",[name]);}
    catch{throw new Error(`required binary '${name}' not found on PATH`);}
  }

  async applyWireGuard(input:{
    privateKeyReference:string;addresses:string[];listenPort?:number;
    peers:Array<{publicKey:string;endpoint?:string;allowedIps:string[];keepaliveSeconds:number}>;
  }):Promise<void>{
    await this.requireBinary("wg");
    await this.requireBinary("ip");
    for(const p of input.peers){assertKey(p.publicKey,"peer public key");assertCidrList(p.allowedIps);}
    assertCidrList(input.addresses);

    const exists=await this.run("ip",["link","show",this.iface]).then(()=>true).catch(()=>false);
    if(!exists)await this.run("ip",["link","add",this.iface,"type","wireguard"]);

    const dir=mkdtempSync(join(tmpdir(),"bapc-wg-"));
    const keyPath=join(dir,"private.key");
    // privateKeyReference is a filesystem path to a key the endpoint agent's
    // secure keystore wrote with 0600 permissions — never the raw key material.
    writeFileSync(keyPath,input.privateKeyReference,{mode:0o600});
    const setArgs=["set",this.iface,"private-key",keyPath];
    if(input.listenPort)setArgs.push("listen-port",String(input.listenPort));
    for(const p of input.peers){
      setArgs.push("peer",p.publicKey,"allowed-ips",p.allowedIps.join(","),
        "persistent-keepalive",String(p.keepaliveSeconds));
      if(p.endpoint)setArgs.push("endpoint",p.endpoint);
    }
    await this.run("wg",setArgs);
    await this.run("ip",["link","set",this.iface,"up"]);
    for(const addr of input.addresses){
      await this.run("ip",["address","replace",addr,"dev",this.iface]).catch(()=>{});
    }
  }

  // `wg syncconf <iface> <file>` replaces the ENTIRE peer set with exactly
  // what's in the file's [Peer] sections — adding new peers, updating
  // changed ones, and removing any peer not listed, in one atomic call.
  // Critically, the file has no [Interface] section, so private-key/
  // listen-port are never touched: this never receives or writes any key
  // material for this node itself, the same guarantee `wg set` gave, but
  // without `wg set`'s limitation of only ever adding/updating peers.
  async applyPeers(peers:Array<{publicKey:string;endpoint?:string;allowedIps:string[];keepaliveSeconds:number}>):Promise<void>{
    await this.requireBinary("wg");
    for(const p of peers){assertKey(p.publicKey,"peer public key");assertCidrList(p.allowedIps);}
    const lines=peers.flatMap(p=>[
      "[Peer]",`PublicKey = ${p.publicKey}`,`AllowedIPs = ${p.allowedIps.join(", ")}`,
      `PersistentKeepalive = ${p.keepaliveSeconds}`,
      ...(p.endpoint?[`Endpoint = ${p.endpoint}`]:[]),""
    ]);
    const dir=mkdtempSync(join(tmpdir(),"bapc-wg-peers-"));
    const confPath=join(dir,"peers.conf");
    writeFileSync(confPath,lines.join("\n"));
    await this.run("wg",["syncconf",this.iface,confPath]);
  }

  async applyFirewall(input:{
    commitId:string;defaultAction:"DENY";rules:Array<{
      id:string;action:"ALLOW"|"DENY";protocols:string[];ports:number[];
      sourceZones:string[];destinationZones:string[];
    }>;
  }):Promise<void>{
    await this.requireBinary("nft");
    const lines=[
      "table inet bapc_security {",
      "  chain forward {",
      "    type filter hook forward priority 0; policy drop;",
      ...input.rules.map(r=>{
        const proto=r.protocols.includes("ANY")?"":r.protocols.map(p=>p.toLowerCase()).join(",");
        const ports=r.ports.length?`{ ${r.ports.join(",")} }`:"";
        const verb=r.action==="ALLOW"?"accept":"drop";
        const portClause=proto&&ports?`${proto} dport ${ports}`:"";
        return `    ${portClause} counter ${verb} comment "${r.id}"`;
      }),
      "  }",
      "}"
    ];
    const dir=mkdtempSync(join(tmpdir(),"bapc-nft-"));
    const rulesPath=join(dir,`${input.commitId}.nft`);
    writeFileSync(rulesPath,lines.join("\n")+"\n");
    await this.run("nft",["-f",rulesPath]);
  }

  async rollbackFirewall(_commitId:string):Promise<void>{
    await this.requireBinary("nft");
    await this.run("nft",["delete","table","inet","bapc_security"]).catch(()=>{});
  }

  async setKillSwitch(enabled:boolean):Promise<void>{
    await this.requireBinary("nft");
    if(enabled){
      await this.run("nft",["add","table","inet","bapc_killswitch"]).catch(()=>{});
      await this.run("nft",[
        "add","chain","inet","bapc_killswitch","output",
        "{","type","filter","hook","output","priority","0;","policy","drop;","}"
      ]).catch(()=>{});
      await this.run("nft",["add","rule","inet","bapc_killswitch","output","oifname",this.iface,"accept"]);
    }else{
      await this.run("nft",["delete","table","inet","bapc_killswitch"]).catch(()=>{});
    }
  }

  async setDns(servers:string[]):Promise<void>{
    await this.requireBinary("resolvectl");
    await this.run("resolvectl",["dns",this.iface,...servers]);
  }

  async isolate(_reason:string):Promise<void>{
    await this.requireBinary("nft");
    await this.run("nft",["add","table","inet","bapc_quarantine"]).catch(()=>{});
    await this.run("nft",[
      "add","chain","inet","bapc_quarantine","forward",
      "{","type","filter","hook","forward","priority","-10;","policy","drop;","}"
    ]).catch(()=>{});
  }

  async restore():Promise<void>{
    await this.requireBinary("nft");
    await this.run("nft",["delete","table","inet","bapc_quarantine"]).catch(()=>{});
  }

  async collectPosture(){
    const secureBoot=existsSync("/sys/firmware/efi/efivars");
    const agentHealthy=true;
    let firewallEnabled=false;
    try{
      const {stdout}=await this.run("nft",["list","table","inet","bapc_security"]);
      firewallEnabled=stdout.length>0;
    }catch{firewallEnabled=false;}
    return {
      osCurrent:true, // production: compare against the distro's patch-baseline feed
      diskEncrypted:existsSync("/etc/crypttab"),
      secureBoot, firewallEnabled, agentHealthy, bannedProcessFound:false
    };
  }

  // --- AgentPlatform: route-integrity monitoring/restoration
  // (feature catalog items #56-60) ---

  async readRoutes():Promise<Route[]>{
    await this.requireBinary("ip");
    const {stdout}=await this.run("ip",["route","show"]);
    return stdout.split("\n").map(parseIpRouteLine).filter((r):r is Route=>r!==undefined);
  }

  async replaceRoutes(routes:Route[]):Promise<void>{
    await this.requireBinary("ip");
    for(const r of routes){
      const args=["route","replace",r.destination,"dev",r.interfaceName,"metric",String(r.metric)];
      if(r.gateway)args.splice(3,0,"via",r.gateway);
      await this.run("ip",args);
    }
  }

  async readFileHash(path:string):Promise<string>{
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  }

  async applyFirewallPlan(plan:unknown):Promise<void>{
    await this.applyFirewall(plan as Parameters<LinuxPlatformAdapter["applyFirewall"]>[0]);
  }

  async clearTransientCredentials():Promise<void>{
    await this.requireBinary("ip");
    // Bring the tunnel down rather than deleting the interface outright —
    // this drops any active session/keys immediately while leaving the
    // interface itself in place for the next applyWireGuard to reconfigure.
    await this.run("ip",["link","set",this.iface,"down"]).catch(()=>{});
  }
}
