import {writeFileSync, mkdtempSync, readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {tmpdir} from "node:os";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";
import type {PlatformAdapter} from "../shared/platform-adapter.js";
import type {CommandRunner} from "../shared/command-runner.js";
import {systemCommandRunner} from "../shared/command-runner.js";
import type {AgentPlatform, Route} from "../../src/agent/reconciler.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH=join(__dirname,"apply.ps1");
const WG_KEY_RE=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

// Real Windows adapter. Firewall/DNS/posture actions are delegated to
// apply.ps1 with the request payload passed as a JSON FILE (see that script's
// header) so caller-controlled values never touch a command line or get
// interpolated into PowerShell source. WireGuard tunnel management shells
// out to the official wireguard.exe CLI. Requires an elevated session and
// WireGuard for Windows installed; every method throws (rather than
// silently no-op'ing) when a prerequisite is missing.
export class WindowsPlatformAdapter implements PlatformAdapter, AgentPlatform {
  readonly platform="windows" as const;
  constructor(
    private interfaceAlias="BAPC",
    private run:CommandRunner=systemCommandRunner
  ){}

  private async invokePs1<T=unknown>(action:string,payload?:unknown):Promise<T>{
    const args=["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",SCRIPT_PATH,"-Action",action];
    if(payload!==undefined){
      const dir=mkdtempSync(join(tmpdir(),"bapc-ps-"));
      const payloadPath=join(dir,"payload.json");
      writeFileSync(payloadPath,JSON.stringify(payload));
      args.push("-PayloadPath",payloadPath);
    }
    const {stdout}=await this.run("powershell.exe",args);
    return JSON.parse(stdout.trim()||"{}") as T;
  }

  async applyWireGuard(input:{
    privateKeyReference:string;addresses:string[];listenPort?:number;
    peers:Array<{publicKey:string;endpoint?:string;allowedIps:string[];keepaliveSeconds:number}>;
  }):Promise<void>{
    for(const p of input.peers)if(!WG_KEY_RE.test(p.publicKey))throw new Error("invalid peer public key");
    const dir=mkdtempSync(join(tmpdir(),"bapc-wg-"));
    const confPath=join(dir,`${this.interfaceAlias}.conf`);
    const lines=[
      "[Interface]",
      `PrivateKey = ${input.privateKeyReference}`,
      `Address = ${input.addresses.join(", ")}`,
      ...(input.listenPort?[`ListenPort = ${input.listenPort}`]:[]),
      ...input.peers.flatMap(p=>[
        "",
        "[Peer]",
        `PublicKey = ${p.publicKey}`,
        `AllowedIPs = ${p.allowedIps.join(", ")}`,
        `PersistentKeepalive = ${p.keepaliveSeconds}`,
        ...(p.endpoint?[`Endpoint = ${p.endpoint}`]:[])
      ])
    ];
    writeFileSync(confPath,lines.join("\n")+"\n");
    await this.run("wireguard.exe",["/uninstalltunnelservice",this.interfaceAlias]).catch(()=>{});
    await this.run("wireguard.exe",["/installtunnelservice",confPath]);
  }

  // WireGuard for Windows installs `wg.exe` alongside `wireguard.exe` — the
  // same cross-platform `wg` CLI Linux uses. `wg.exe set <alias> peer ...`
  // updates/adds each named peer in the running tunnel without touching
  // `PrivateKey`, unlike applyWireGuard's full uninstall/reinstall of the
  // tunnel service. Does not remove peers absent from `peers` — see the
  // Linux adapter's applyPeers comment for why that's a separate concern.
  async applyPeers(peers:Array<{publicKey:string;endpoint?:string;allowedIps:string[];keepaliveSeconds:number}>):Promise<void>{
    for(const p of peers)if(!WG_KEY_RE.test(p.publicKey))throw new Error("invalid peer public key");
    if(peers.length===0)return;
    const setArgs=["set",this.interfaceAlias];
    for(const p of peers){
      setArgs.push("peer",p.publicKey,"allowed-ips",p.allowedIps.join(","),
        "persistent-keepalive",String(p.keepaliveSeconds));
      if(p.endpoint)setArgs.push("endpoint",p.endpoint);
    }
    await this.run("wg.exe",setArgs);
  }

  async applyFirewall(input:{
    commitId:string;defaultAction:"DENY";
    rules:Array<{id:string;action:"ALLOW"|"DENY";protocols:string[];ports:number[];sourceZones:string[];destinationZones:string[];}>;
  }):Promise<void>{
    await this.invokePs1("ApplyFirewall",input);
  }

  async rollbackFirewall(commitId:string):Promise<void>{
    await this.invokePs1("RollbackFirewall",{commitId});
  }

  async setKillSwitch(enabled:boolean):Promise<void>{
    await this.invokePs1("SetKillSwitch",{enabled,interfaceAlias:this.interfaceAlias});
  }

  async setDns(servers:string[]):Promise<void>{
    await this.invokePs1("SetDns",{servers,interfaceAlias:this.interfaceAlias});
  }

  async isolate(_reason:string):Promise<void>{
    await this.invokePs1("Isolate");
  }

  async restore():Promise<void>{
    await this.invokePs1("Restore");
  }

  async collectPosture(){
    return this.invokePs1<{
      osCurrent:boolean;diskEncrypted:boolean;secureBoot:boolean;
      firewallEnabled:boolean;agentHealthy:boolean;bannedProcessFound:boolean;
    }>("CollectPosture");
  }

  // --- AgentPlatform: route-integrity monitoring/restoration
  // (feature catalog items #56-60) ---

  async readRoutes():Promise<Route[]>{
    const result=await this.invokePs1<{routes:Array<{destination:string;gateway:string|null;interfaceName:string;metric:number}>}>("GetRoutes");
    const routes=Array.isArray(result.routes)?result.routes:[result.routes].filter(Boolean);
    return routes.map(r=>({
      destination:r.destination,interfaceName:r.interfaceName,metric:r.metric,
      ...(r.gateway?{gateway:r.gateway}:{})
    }));
  }

  async replaceRoutes(routes:Route[]):Promise<void>{
    await this.invokePs1("ReplaceRoutes",{routes});
  }

  async readFileHash(path:string):Promise<string>{
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  }

  async applyFirewallPlan(plan:unknown):Promise<void>{
    await this.applyFirewall(plan as Parameters<WindowsPlatformAdapter["applyFirewall"]>[0]);
  }

  async clearTransientCredentials():Promise<void>{
    await this.invokePs1("ClearCredentials",{interfaceAlias:this.interfaceAlias});
  }
}
