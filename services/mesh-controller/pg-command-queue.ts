export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rows:any[]}>;
}
export interface QueuedCommand {id:string;type:string;payload:any;}
export interface CommandAcknowledgement {
  commandId:string;status:string;acknowledgedAt:Date;details:any;
}

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

  // A node that keeps reporting the same problem (a chronically-failing
  // heartbeat, a key still overdue on the next daily rotation sweep) has
  // nothing stopping the caller from calling enqueue() again on every check
  // — without this, ThreatEngine's EMERGENCY tier and
  // KeyRotationSchedulerService would each pile up a fresh
  // ROTATE_IDENTITY_REQUIRED row per check, forever, for a node that simply
  // hasn't acknowledged the first one yet.
  async hasPending(nodeId:string,type:string):Promise<boolean>{
    const r=await this.db.query(
      `SELECT 1 FROM bapc_security_core.controller_commands
       WHERE node_id=$1 AND command_type=$2 AND acknowledged_at IS NULL AND expires_at>now() LIMIT 1`,
      [nodeId,type]
    );
    return r.rows.length>0;
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

  // NodeReconciliationService's proxy for "what did this node last report
  // for this dimension" — the heartbeat wire format has no general
  // current-state field, but every command a node acts on already writes
  // its result here (see acknowledge above), so a node's most recent
  // successful acknowledgement for a command type is the most honest signal
  // this architecture has for whether that command's effect is still in
  // place, without inventing a new reporting channel.
  async latestAcknowledgement(nodeId:string,commandType:string):Promise<CommandAcknowledgement|null>{
    const r=await this.db.query(
      `SELECT command_id,status,acknowledged_at,details FROM bapc_security_core.command_acknowledgements
       WHERE node_id=$1 AND command_type=$2 AND status='SUCCEEDED'
       ORDER BY acknowledged_at DESC LIMIT 1`,
      [nodeId,commandType]
    );
    const row=r.rows[0];
    return row?{commandId:row.command_id,status:row.status,acknowledgedAt:new Date(row.acknowledged_at),details:row.details}:null;
  }
}
