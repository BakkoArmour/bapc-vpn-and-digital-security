import type {SocActions} from "./backend.js";
import type {ThreatResponseService} from "../../src/application/threat-response.js";
import type {NodeRepository, JitRepository} from "../../src/ports/repositories.js";
import type {PolicyEnforcer, EventBus, IdGenerator, Clock} from "../../src/ports/infrastructure.js";

export class PgSocActions implements SocActions {
  constructor(
    private threatResponse:ThreatResponseService,
    private nodes:NodeRepository,
    private jit:JitRepository,
    private enforce:PolicyEnforcer,
    private bus:EventBus,
    private ids:IdGenerator,
    private clock:Clock
  ){}

  async quarantine(nodeId:string,reason:string,actor:string){
    await this.threatResponse.handle({
      id:this.ids.next(),nodeId,at:this.clock.now(),
      severity:"CRITICAL",engine:"soc-console",type:"MANUAL_QUARANTINE",
      description:reason,metadata:{score:90,actor}
    });
  }

  async restore(nodeId:string,_actor:string,clearanceToken:string){
    await this.threatResponse.restore(nodeId,clearanceToken,this.clock.now());
  }

  // The "ecosystem master kill switch": isolates every active node and
  // terminates every active JIT grant. This is the owner-only, fully
  // logged/recoverable emergency control the feature catalog describes
  // (item 121) — recoverable because it only isolates (PolicyEnforcer state
  // + JIT termination), it does not revoke credentials or certificates, so
  // SecuritySocBackend.restore-style per-node recovery still applies
  // afterward.
  async emergencyLockdown(reason:string,actor:string,confirmation:string){
    const now=this.clock.now();
    const activeNodes=(await this.nodes.list()).filter(n=>n.active);
    for(const node of activeNodes)await this.enforce.isolateNode(node.id);
    const activeGrants=await this.jit.listActive(now);
    for(const grant of activeGrants){
      await this.jit.save({...grant,terminated:true,terminationReason:`emergency lockdown: ${reason}`});
    }
    await this.bus.publish("security.emergency_lockdown",{
      reason,actor,confirmation,at:now.toISOString(),
      nodesIsolated:activeNodes.length,grantsTerminated:activeGrants.length
    });
  }
}
