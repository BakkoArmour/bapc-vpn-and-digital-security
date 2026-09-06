import { createHash } from "node:crypto";
import { ValidationError } from "../domain/errors.js";
import type { NetworkPolicy } from "../domain/types.js";
import type { AppleEnforcementPlan, LinuxEnforcementPlan, PolicyIrDocument, PolicyIrRule, WindowsEnforcementPlan } from "../domain/policy-ir.js";
const zones=new Set(["ZONE_PROD_DATA","ZONE_PROD_APP","ZONE_STAGING","ZONE_DEV","ZONE_ADMIN_MGMT","ZONE_FORENSIC_ISOLATION"]);
export class PolicyCompiler {
 compile(policies:NetworkPolicy[],now=new Date()):PolicyIrDocument {const rules=policies.filter(x=>x.active).sort((a,b)=>b.priority-a.priority).map<PolicyIrRule>(p=>{if(!p.sourceZones.every(x=>zones.has(x))||!p.destinationZones.every(x=>zones.has(x)))throw new ValidationError(`invalid zone in ${p.name}`);if(p.destinationPorts.some(x=>x<1||x>65535))throw new ValidationError(`invalid port in ${p.name}`);return{id:p.id,source:p.sourceZones,destination:p.destinationZones,protocols:p.protocols,ports:p.destinationPorts,action:p.action,log:true};});const body=JSON.stringify(rules);return{version:1,generatedAt:now,checksum:createHash("sha256").update(body).digest("hex"),rules};}
 linux(ir:PolicyIrDocument):LinuxEnforcementPlan {return{ebpfMapEntries:ir.rules.map(r=>({key:`${r.source.join(",")}|${r.destination.join(",")}|${r.protocols.join(",")}|${r.ports.join(",")}`,value:r.action})),nftablesFallback:ir.rules.map(r=>`${r.action.toLowerCase()} ${r.protocols.join(",")} dport { ${r.ports.join(",")} } comment ${r.id}`)}}
 windows(ir:PolicyIrDocument):WindowsEnforcementPlan {return{wfpFilters:ir.rules.map(r=>({name:`BAPC-${r.id}`,layer:"ALE_AUTH_CONNECT_V4_V6",action:r.action==="ALLOW"?"PERMIT":"BLOCK",conditions:{zones:`${r.source.join(",")}->${r.destination.join(",")}`,protocols:r.protocols.join(","),ports:r.ports.join(",")}}))}}
 apple(ir:PolicyIrDocument):AppleEnforcementPlan {return{networkExtensionRules:ir.rules.map(r=>({matchDomains:[],matchNetworks:r.destination,action:r.action==="ALLOW"?"allow":"drop"}))}}
}
