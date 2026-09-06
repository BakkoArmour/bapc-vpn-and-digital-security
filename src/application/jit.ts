import { AuthorizationError, NotFoundError, ValidationError } from "../domain/errors.js";
import type { SecurityZone } from "../domain/types.js";
import type { Clock, EventBus, IdGenerator } from "../ports/infrastructure.js";
import type { JitRepository } from "../ports/repositories.js";
export class JitService {
 constructor(private repo:JitRepository,private ids:IdGenerator,private clock:Clock,private bus:EventBus){}
 async request(userId:string,targetResource:string,targetZone:SecurityZone,durationMinutes:15|30|60,justification:string){
  if(justification.trim().length<12) throw new ValidationError("a meaningful justification is required"); const now=this.clock.now();
  const grant={id:this.ids.next(),userId,targetResource,targetZone,justification,grantedAt:now,expiresAt:new Date(now.getTime()+durationMinutes*60_000),terminated:false}; await this.repo.save(grant); await this.bus.publish("security.jit.requested",grant); return grant;
 }
 async approve(grantId:string,approverId:string,approverRoles:string[]){if(!approverRoles.includes("security-approver"))throw new AuthorizationError("security approver role required");const g=await this.repo.get(grantId);if(!g)throw new NotFoundError("JIT grant");const updated={...g,approvedBy:approverId};await this.repo.save(updated);await this.bus.publish("security.jit.approved",updated);return updated;}
 async terminate(grantId:string,reason:string){const g=await this.repo.get(grantId);if(!g)throw new NotFoundError("JIT grant");const updated={...g,terminated:true,terminationReason:reason};await this.repo.save(updated);await this.bus.publish("security.jit.terminated",updated);return updated;}
}
