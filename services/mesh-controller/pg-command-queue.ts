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

  // command_acknowledgements (db/002_operational_tables.sql) existed with no
  // write path at all — controller_commands already tracks
  // acknowledged_at/result in place, but a row there is only ever updated,
  // never archived: if controller_commands is ever pruned (expires_at
  // implies that's the intent — there's no purge job yet, but the column
  // only makes sense if one eventually exists), every acknowledgement
  // history would disappear with it. This keeps a permanent record
  // regardless of what happens to the row it came from.
  async acknowledge(commandId:string,result:unknown){
    const r=await this.db.query(
      `UPDATE bapc_security_core.controller_commands
       SET acknowledged_at=now(), result=$2 WHERE command_id=$1
       RETURNING node_id, command_type, issued_at`,
      [commandId,result]
    );
    const row=r.rows[0];
    if(!row)return;
    const ok=(result as {ok?:unknown})?.ok;
    const status=typeof ok==="boolean"?(ok?"SUCCEEDED":"FAILED"):"ACKNOWLEDGED";
    await this.db.query(
      `INSERT INTO bapc_security_core.command_acknowledgements
         (command_id,node_id,command_type,issued_at,acknowledged_at,status,details)
       VALUES($1,$2,$3,$4,now(),$5,$6)`,
      [commandId,row.node_id,row.command_type,row.issued_at,status,result??{}]
    );
  }
}
