import {Postgres} from "./client.js";

export class RetentionService {
  constructor(private db:Postgres){}
  async ensureUpcomingPartitions(monthsAhead=1){
    const created:string[]=[];
    for(let i=0;i<=monthsAhead;i++){
      const target=new Date(Date.UTC(new Date().getUTCFullYear(),new Date().getUTCMonth()+i,1));
      const r=await this.db.query<{ensure_month_partition:string}>(
        "SELECT bapc_security_core.ensure_month_partition($1) ",[target]
      );
      created.push(r.rows[0]!.ensure_month_partition);
    }
    return created;
  }
  async dropExpiredPartitions(retentionMonths:number){
    const r=await this.db.query<{drop_expired_event_partitions:string}>(
      "SELECT bapc_security_core.drop_expired_event_partitions($1)",[retentionMonths]
    );
    return r.rows.map(x=>x.drop_expired_event_partitions);
  }
  async purgeExpiredRows(){
    const r=await this.db.query<{idempotency_deleted:string;nonces_deleted:string;outbox_deleted:string}>(
      "SELECT * FROM bapc_security_core.purge_expired_control_plane_rows()"
    );
    const row=r.rows[0]!;
    return {
      idempotencyDeleted:Number(row.idempotency_deleted),
      noncesDeleted:Number(row.nonces_deleted),
      outboxDeleted:Number(row.outbox_deleted)
    };
  }
}
