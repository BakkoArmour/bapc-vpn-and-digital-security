import type {ConnectivityProbe} from "../ports/infrastructure.js";

export interface HealthCheckable {health():Promise<boolean>;}

// Replaces HealthyProbe (which always returns true) in production.
// SafeApplyService uses this to decide whether a staged policy broke
// something badly enough to auto-rollback within the timeout window. Nodes
// only pull commands on their own heartbeat interval (this is a pull, not a
// push, control plane — see agents/shared/production-agent.ts), so per-node
// reachability can't be verified synchronously here; this checks the one
// thing that actually is synchronously verifiable and that every node
// delivery path depends on — the control plane's own database.
export class PgControlPlaneProbe implements ConnectivityProbe {
  constructor(private db:HealthCheckable){}
  async verifyControlPlane():Promise<boolean>{
    try{return await this.db.health();}
    catch{return false;}
  }
}
