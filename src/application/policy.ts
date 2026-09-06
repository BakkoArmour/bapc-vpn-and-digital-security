import type { AccessDecision, Device, IdentityContext, JitGrant, MeshNode, NetworkPolicy, ResourceContext } from "../domain/types.js";
import type { Clock, DecisionSigner, IdGenerator } from "../ports/infrastructure.js";
import type { JitRepository, PolicyRepository } from "../ports/repositories.js";
const postureOk=(d:Device)=>!d.revoked&&!d.compromised&&d.posture.osCurrent&&d.posture.diskEncrypted&&d.posture.secureBoot&&d.posture.firewallEnabled&&d.posture.agentHealthy&&!d.posture.bannedProcessFound;
export class PolicyDecisionService {
 constructor(private policies:PolicyRepository,private jit:JitRepository,private ids:IdGenerator,private clock:Clock,private signer:DecisionSigner){}
 async decide(identity:IdentityContext,device:Device,node:MeshNode,resource:ResourceContext){
  const now=this.clock.now(); let action:AccessDecision["action"]="DENY",reason="default deny",policyId:string|undefined;
  if(!identity.mfa) reason="MFA required"; else if(!postureOk(device)||!node.active) reason="device is not trusted"; else {
   const policies=(await this.policies.listActive()).sort((a,b)=>b.priority-a.priority);
   for(const p of policies){if(!this.matches(p,node,resource,identity.roles))continue; policyId=p.id; action=p.action; reason=`policy ${p.name}`;
    if(p.requiresJit&&!await this.hasJit(identity.userId,resource,now)){action="DENY";reason="active JIT grant required";} break;}
  }
  const decision:AccessDecision={allowed:action==="ALLOW",action,reason,decisionId:this.ids.next(),expiresAt:new Date(now.getTime()+30_000),...(policyId?{policyId}:{})};
  return {decision,signature:await this.signer.sign(decision)};
 }
 private matches(p:NetworkPolicy,n:MeshNode,r:ResourceContext,roles:string[]){return p.sourceZones.includes(n.zone)&&p.destinationZones.includes(r.zone)&&(p.protocols.includes("ANY")||p.protocols.includes(r.protocol))&&(!r.port||p.destinationPorts.length===0||p.destinationPorts.includes(r.port))&&p.requiredRoles.every(x=>roles.includes(x));}
 private async hasJit(userId:string,r:ResourceContext,now:Date){return (await this.jit.listActive(now)).some((g:JitGrant)=>g.userId===userId&&g.targetZone===r.zone&&g.targetResource===r.resource&&!g.terminated&&g.expiresAt>now);}
}
