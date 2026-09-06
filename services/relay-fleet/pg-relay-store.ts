export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

export interface RelayRow {relayId:string; region:string; endpoint:string; isAvailable:boolean; instanceId:string|null;}

// Real CRUD against the `relays` table (db/002_operational_tables.sql),
// which previously had no write path at all outside manual SQL — the SOC
// console/API could only ever read relays someone inserted by hand.
export class PgRelayStore {
  constructor(private db:PgQueryable){}

  async insert(relayId:string,region:string,endpoint:string,instanceId:string):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.relays(relay_id,region,endpoint,is_available,last_heartbeat,instance_id)
       VALUES($1,$2,$3,true,now(),$4)`,
      [relayId,region,endpoint,instanceId]
    );
  }

  async get(relayId:string):Promise<RelayRow|null>{
    const result=await this.db.query(
      `SELECT relay_id,region,endpoint,is_available,instance_id FROM bapc_security_core.relays WHERE relay_id=$1`,
      [relayId]
    );
    const row=result.rows[0];
    if(!row)return null;
    return {relayId:row.relay_id,region:row.region,endpoint:row.endpoint,isAvailable:row.is_available,instanceId:row.instance_id};
  }

  async remove(relayId:string):Promise<void>{
    await this.db.query(`DELETE FROM bapc_security_core.relays WHERE relay_id=$1`,[relayId]);
  }
}
