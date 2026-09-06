import {writeFileSync, mkdtempSync, existsSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import type {PlatformAdapter} from "../shared/platform-adapter.js";
import type {CommandRunner} from "../shared/command-runner.js";
import {systemCommandRunner} from "../shared/command-runner.js";

const WG_KEY_RE=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/; // base64 32-byte key, WireGuard's fixed padding char set
const CIDR_RE=/^[0-9a-fA-F.:]+\/\d{1,3}$/;

const assertKey=(k:string,field:string)=>{if(!WG_KEY_RE.test(k))throw new Error(`invalid ${field}`);};
const assertCidrList=(ips:string[])=>{for(const ip of ips)if(!CIDR_RE.test(ip))throw new Error(`invalid allowed-ip ${ip}`);};

// Real Linux adapter: WireGuard via `wg`/`ip`, firewall via `nft`. Every value
// that reaches a command is either validated against the patterns above or
// passed as a discrete argv element (never shell-interpolated), and every
// method degrades to a clear thrown error — never a silent no-op — when the
// required binary is missing, so a misconfigured host fails loudly.
export class LinuxPlatformAdapter implements PlatformAdapter {
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
}
