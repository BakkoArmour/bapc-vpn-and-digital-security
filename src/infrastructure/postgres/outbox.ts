import {createHash,randomUUID} from "node:crypto";
import {Postgres} from "./client.js";
import type {EventBus} from "../../ports/infrastructure.js";

export class TransactionalOutbox implements EventBus {
  constructor(private db:Postgres){}
  async publish(topic:string,event:unknown){
    const body=JSON.stringify(event);
    const key=createHash("sha256").update(topic).update(body).digest("hex");
    await this.db.query(`INSERT INTO bapc_security_core.event_outbox
      (outbox_id,topic,event_key,payload) VALUES($1,$2,$3,$4)
      ON CONFLICT DO NOTHING`,[randomUUID(),topic,key,event]);
  }
}
export class OutboxDispatcher {
  constructor(private db:Postgres,private send:(topic:string,event:unknown)=>Promise<void>){}
  // `FOR UPDATE SKIP LOCKED` only provides real concurrency safety (multiple
  // dispatcher replicas never double-deliver the same row) if the SELECT and
  // its row locks live inside the SAME transaction as the later UPDATEs —
  // run as a standalone statement, the lock is released the instant the
  // SELECT completes, before this process has even started sending. Wrapping
  // the whole flush in one transaction is what this repository's earlier
  // (never-called) version of this method did NOT do; fixed here.
  async flush(limit=100){
    return this.db.transaction(async client=>{
      const rows=await client.query(`SELECT outbox_id,topic,payload FROM bapc_security_core.event_outbox
        WHERE published_at IS NULL ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1`,[limit]);
      for(const row of rows.rows as any[]){
        try{
          await this.send(row.topic,row.payload);
          await client.query(`UPDATE bapc_security_core.event_outbox
            SET published_at=now(),attempt_count=attempt_count+1,last_error=NULL WHERE outbox_id=$1`,[row.outbox_id]);
        }catch(error){
          await client.query(`UPDATE bapc_security_core.event_outbox
            SET attempt_count=attempt_count+1,last_error=$2 WHERE outbox_id=$1`,
            [row.outbox_id,error instanceof Error?error.message:String(error)]);
        }
      }
      return rows.rowCount??0;
    });
  }
}
