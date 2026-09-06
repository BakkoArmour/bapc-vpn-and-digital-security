import { createHash } from "node:crypto";
export interface Route {destination:string;gateway?:string;interfaceName:string;metric:number;}
export interface AgentPlatform {readRoutes():Promise<Route[]>;replaceRoutes(routes:Route[]):Promise<void>;readFileHash(path:string):Promise<string>;applyFirewallPlan(plan:unknown):Promise<void>;clearTransientCredentials():Promise<void>;}
export interface AgentDesiredState {revision:number;routes:Route[];firewallPlan:unknown;integrityFiles:Record<string,string>;}
// A correct canonical/order-independent JSON serialization for comparing
// route sets. The original `JSON.stringify(v, Object.keys(v).sort())` here
// was broken for arrays: `Object.keys()` of an array yields numeric index
// strings ("0","1",...), and JSON.stringify's array-form replacer filters
// EVERY object in the graph (not just the top level) down to keys present
// in that allowlist — so every Route object's actual fields (none of which
// are named "0" or "1") were silently stripped, making any two route lists
// of the same LENGTH compare as identical regardless of content. That
// defeated "restores unauthorized route changes" (feature catalog #57)
// whenever an attacker's route change didn't also change the route count.
const stable=(v:unknown):string=>{
  if(v===null||typeof v!=="object")return JSON.stringify(v);
  if(Array.isArray(v))return `[${v.map(stable).join(",")}]`;
  return `{${Object.entries(v as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([k,val])=>`${JSON.stringify(k)}:${stable(val)}`).join(",")}}`;
};
// A route table can legitimately come back in a different order across two
// reads of the same underlying routes (kernel/OS implementation detail),
// so sort before comparing — otherwise reordering alone would look like an
// unauthorized change and trigger a needless replaceRoutes call.
const routeKey=(r:Route)=>`${r.destination}|${r.interfaceName}|${r.gateway??""}|${r.metric}`;
const sortRoutes=(routes:Route[])=>[...routes].sort((a,b)=>routeKey(a).localeCompare(routeKey(b)));

export class AgentReconciler {
  private revision=0;
  constructor(private platform:AgentPlatform){}
  async reconcile(state:AgentDesiredState){
    if(state.revision<this.revision)return {status:"STALE" as const,revision:this.revision};
    for(const [path,expected] of Object.entries(state.integrityFiles)){
      const actual=await this.platform.readFileHash(path);
      if(actual!==expected){
        await this.platform.clearTransientCredentials();
        throw new Error(`integrity failure: ${path}`);
      }
    }
    const current=await this.platform.readRoutes();
    const currentHash=createHash("sha256").update(stable(sortRoutes(current))).digest("hex");
    const desiredHash=createHash("sha256").update(stable(sortRoutes(state.routes))).digest("hex");
    if(currentHash!==desiredHash)await this.platform.replaceRoutes(state.routes);
    await this.platform.applyFirewallPlan(state.firewallPlan);
    this.revision=state.revision;
    return {status:"APPLIED" as const,revision:this.revision};
  }
}
