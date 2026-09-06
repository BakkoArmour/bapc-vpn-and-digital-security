import { ValidationError } from "../domain/errors.js";
import type { NetworkPolicy } from "../domain/types.js";
import type { Clock, ConnectivityProbe, EventBus, IdGenerator, PolicyEnforcer } from "../ports/infrastructure.js";
export class SafeApplyService {
 constructor(private enforce:PolicyEnforcer,private probe:ConnectivityProbe,private bus:EventBus,private ids:IdGenerator,private clock:Clock){}
 async apply(policies:NetworkPolicy[],timeoutMs=60_000){if(timeoutMs<5_000||timeoutMs>300_000)throw new ValidationError("rollback window must be between 5 and 300 seconds");const commitId=this.ids.next();await this.enforce.stage(commitId,policies);await this.bus.publish("security.policy.staged",{commitId,at:this.clock.now(),timeoutMs});
  let timer:ReturnType<typeof setTimeout>|undefined; try {const timedOut=new Promise<boolean>(resolve=>{timer=setTimeout(()=>resolve(false),timeoutMs)});const ok=await Promise.race([this.probe.verifyControlPlane(),timedOut]);if(!ok){await this.enforce.rollback(commitId);await this.bus.publish("security.policy.rolled_back",{commitId});return {commitId,status:"ROLLED_BACK" as const};}await this.enforce.commit(commitId);await this.bus.publish("security.policy.committed",{commitId});return {commitId,status:"COMMITTED" as const};}catch(error){await this.enforce.rollback(commitId);throw error;}finally{if(timer)clearTimeout(timer);}}
}
