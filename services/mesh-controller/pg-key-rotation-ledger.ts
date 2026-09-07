import type {KeyRotationLedger} from "../../src/api/grpc/server.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

// Real, persisted audit trail — replaces InMemoryKeyRotationLedger, which
// even in the real running mesh-grpc process kept its epoch counter only in
// memory (reset to 0 on every restart, no record of who rotated to what or
// when). Signature verification against the node's enrollment identity
// happens in the caller (src/api/grpc/server.ts's rotatePeerKey handler,
// which has the DeviceRepository lookup this port doesn't) — this class is
// purely the append-only ledger.
export class PgKeyRotationLedger implements KeyRotationLedger {
  constructor(private db:PgQueryable){}

  async rotate(nodeId:string,newPublicKey:string,_signature:Uint8Array):Promise<{acknowledged:boolean;effectiveEpoch:number}>{
    // A unique (node_id, epoch) constraint plus retry-on-conflict is simpler
    // and just as correct as row-locking an aggregate MAX() for what is, in
    // practice, a rare, human/ops-triggered operation rather than a
    // high-throughput one.
    for(let attempt=0;attempt<5;attempt++){
      const current=await this.db.query(
        `SELECT COALESCE(MAX(epoch),0) AS max_epoch FROM bapc_security_core.key_rotations WHERE node_id=$1`,
        [nodeId]
      );
      const nextEpoch=Number(current.rows[0].max_epoch)+1;
      try{
        await this.db.query(
          `INSERT INTO bapc_security_core.key_rotations(node_id,epoch,new_public_key) VALUES($1,$2,$3)`,
          [nodeId,nextEpoch,newPublicKey]
        );
        return {acknowledged:true,effectiveEpoch:nextEpoch};
      }catch(error){
        // Unique-violation (23505): another concurrent rotation for this
        // node won this epoch first — recompute and retry.
        if((error as {code?:string}).code!=="23505")throw error;
      }
    }
    throw new Error(`could not allocate a key-rotation epoch for node ${nodeId} after 5 attempts (concurrent rotations?)`);
  }

  // KEY_ROTATION_DAYS (config.ts's keyRotationDays) was loaded and even
  // validated at startup with nothing anywhere that ever compared a node's
  // rotation history against it — see KeyRotationSchedulerService
  // (src/application/key-rotation-scheduler.ts), the real periodic consumer
  // this was missing. Only covers nodes that have rotated their identity key
  // at least once: mesh_nodes carries no enrollment timestamp, so a node
  // that has never rotated since initial enrollment has nothing in this
  // table to compare against yet — a real, narrower limitation of this
  // schema, not something worth fabricating a substitute timestamp for.
  // $2 needs an explicit ::timestamptz cast: left untyped, Postgres can't
  // unambiguously resolve "$2 - make_interval(...)" (both timestamptz-minus-
  // interval and interval-minus-interval are valid overloads) and silently
  // picks the wrong one, then fails comparing the result against
  // last_rotated with "operator does not exist: timestamp with time zone <
  // interval" — caught against a real Postgres instance, not by the unit
  // tests, which mock the query and never actually parse this SQL.
  async nodesOverdueForRotation(maxAgeDays:number,now:Date):Promise<string[]>{
    const r=await this.db.query(
      `SELECT node_id FROM (
         SELECT node_id, MAX(rotated_at) AS last_rotated
         FROM bapc_security_core.key_rotations GROUP BY node_id
       ) latest WHERE last_rotated < $2::timestamptz - make_interval(days=>$1)`,
      [maxAgeDays,now]
    );
    return r.rows.map((row:any)=>row.node_id);
  }
}
