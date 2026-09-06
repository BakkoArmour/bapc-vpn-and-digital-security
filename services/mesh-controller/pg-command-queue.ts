export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rows:any[]}>;
}
export interface QueuedCommand {id:string;type:string;payload:any;}

// Backs controller_commands (db/004_security_hardening.sql): the durable
// queue an endpoint agent's heartbeat drains and acknowledges.
export class PgCommandQueue {
  constructor(private db:PgQueryable){}

  async enqueue(nodeId:string,type:string,payload:unknown,priority=100,ttlMinutes=60){
    await this.db.query(
      `INSERT INTO bapc_security_core.controller_commands
         (node_id,command_type,payload,priority,expires_at)
       VALUES($1,$2,$3,$4,now()+make_interval(mins=>$5))`,
      [nodeId,type,payload,priority,ttlMinutes]
    );
  }

  async pending(nodeId:string,limit=20):Promise<QueuedCommand[]>{
    const r=await this.db.query(
      `SELECT command_id,command_type,payload FROM bapc_security_core.controller_commands
       WHERE node_id=$1 AND acknowledged_at IS NULL AND not_before<=now() AND expires_at>now()
       ORDER BY priority DESC, issued_at LIMIT $2`,
      [nodeId,limit]
    );
    return r.rows.map(row=>({id:row.command_id,type:row.command_type,payload:row.payload}));
  }

  async acknowledge(commandId:string,result:unknown){
    await this.db.query(
      `UPDATE bapc_security_core.controller_commands
       SET acknowledged_at=now(), result=$2 WHERE command_id=$1`,
      [commandId,result]
    );
  }
}
