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
}
