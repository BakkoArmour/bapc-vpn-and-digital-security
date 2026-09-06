export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

export interface Route {destination:string;gateway?:string;interfaceName:string;metric:number;}

export interface NodeDesiredState {
  nodeId:string;revision:number;routes:Route[];dnsServers:string[];
  killSwitchEnabled:boolean;integrityFiles:Record<string,string>;updatedAt:Date;
}

// Backs node_desired_state (db/016_node_desired_state.sql) — the control
// plane's record of what a node's routes/DNS/kill-switch/integrity files
// SHOULD be, compared by NodeReconciliationService (src/application/
// node-reconciliation.ts) against what the node last reported applying.
export class PgDesiredStateStore {
  constructor(private db:PgQueryable){}

  async get(nodeId:string):Promise<NodeDesiredState|null>{
    const r=await this.db.query(
      `SELECT node_id,revision,routes,dns_servers,kill_switch_enabled,integrity_files,updated_at
       FROM bapc_security_core.node_desired_state WHERE node_id=$1`,
      [nodeId]
    );
    return r.rows[0]?this.toState(r.rows[0]):null;
  }

  async all():Promise<NodeDesiredState[]>{
    const r=await this.db.query(
      `SELECT node_id,revision,routes,dns_servers,kill_switch_enabled,integrity_files,updated_at
       FROM bapc_security_core.node_desired_state`
    );
    return r.rows.map(row=>this.toState(row));
  }

  // Every field is replaced on each call (not merged) — a caller that wants
  // to change only DNS still needs to pass the node's current routes/
  // kill-switch/integrity values, the same way PUT semantics work elsewhere
  // in this API (see PUT /api/v1/policies/:id). revision always increments,
  // even if the new values are identical to the old ones: a re-PUT is
  // treated as a legitimate reason to re-verify the node actually has them,
  // not a no-op.
  async upsert(nodeId:string,input:{
    routes:Route[];dnsServers:string[];killSwitchEnabled:boolean;integrityFiles:Record<string,string>;
  },updatedBy?:string):Promise<NodeDesiredState>{
    const r=await this.db.query(
      `INSERT INTO bapc_security_core.node_desired_state
         (node_id,revision,routes,dns_servers,kill_switch_enabled,integrity_files,updated_at,updated_by)
       VALUES($1,1,$2,$3,$4,$5,now(),$6)
       ON CONFLICT(node_id) DO UPDATE SET
         revision=node_desired_state.revision+1,
         routes=$2,dns_servers=$3,kill_switch_enabled=$4,integrity_files=$5,
         updated_at=now(),updated_by=$6
       RETURNING node_id,revision,routes,dns_servers,kill_switch_enabled,integrity_files,updated_at`,
      [nodeId,JSON.stringify(input.routes),JSON.stringify(input.dnsServers),input.killSwitchEnabled,JSON.stringify(input.integrityFiles),updatedBy??null]
    );
    return this.toState(r.rows[0]);
  }

  private toState(row:any):NodeDesiredState{
    return {
      nodeId:row.node_id,revision:row.revision,
      routes:typeof row.routes==="string"?JSON.parse(row.routes):row.routes,
      dnsServers:typeof row.dns_servers==="string"?JSON.parse(row.dns_servers):row.dns_servers,
      killSwitchEnabled:row.kill_switch_enabled,
      integrityFiles:typeof row.integrity_files==="string"?JSON.parse(row.integrity_files):row.integrity_files,
      updatedAt:new Date(row.updated_at)
    };
  }
}
