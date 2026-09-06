import type {RecoveryStore} from "./controller.js";

export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rows:any[]}>;
}

// Best-effort ordering, not a transaction: PgQueryable here is intentionally
// the minimal single-statement interface used elsewhere in this repo. A
// caller that needs strict atomicity should run both statements through
// Postgres.transaction() and pass the transactional client in as this
// PgQueryable for the duration of the call.
export class PgRecoveryStore implements RecoveryStore {
  constructor(private db:PgQueryable){}

  async save(snapshot:{id:string;scope:string;checksum:string;document:unknown;createdBy:string;lkg:boolean}){
    if(snapshot.lkg){
      await this.db.query(
        `UPDATE bapc_security_core.recovery_snapshots
         SET is_last_known_good=false WHERE scope=$1 AND is_last_known_good=true`,
        [snapshot.scope]
      );
    }
    await this.db.query(
      `INSERT INTO bapc_security_core.recovery_snapshots
         (snapshot_id,scope,checksum,document,created_by,is_last_known_good)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [snapshot.id,snapshot.scope,snapshot.checksum,snapshot.document,snapshot.createdBy,snapshot.lkg]
    );
  }

  async lastKnownGood(scope:string){
    const r=await this.db.query(
      `SELECT snapshot_id,document,checksum FROM bapc_security_core.recovery_snapshots
       WHERE scope=$1 AND is_last_known_good=true LIMIT 1`,
      [scope]
    );
    if(!r.rows.length)return undefined;
    const row=r.rows[0];
    return {id:row.snapshot_id,document:row.document,checksum:row.checksum};
  }

  // The SOC console's recovery/OOB status panel (Item 3) needs to show
  // every scope's current recovery posture, not just one the operator
  // already knows to ask about — checkpoint() only ever refused/succeeded
  // for a single caller-supplied scope with nothing to look back at
  // afterward.
  async listLastKnownGood(){
    const r=await this.db.query(
      `SELECT scope,snapshot_id,checksum,created_by,created_at
       FROM bapc_security_core.recovery_snapshots WHERE is_last_known_good=true
       ORDER BY created_at DESC`
    );
    return r.rows.map(row=>({
      scope:row.scope,id:row.snapshot_id,checksum:row.checksum,
      createdBy:row.created_by,createdAt:new Date(row.created_at)
    }));
  }
}
