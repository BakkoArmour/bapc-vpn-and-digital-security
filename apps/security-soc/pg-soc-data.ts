import type {SocData} from "./backend.js";

export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rows:any[]}>;
}

// SocData needs relays/certificates/incidents, none of which are exposed by
// the DeviceRepository/NodeRepository/PolicyRepository/JitRepository/
// EventRepository ports (those model the domain aggregates; relays,
// certificates and incidents are separate tables from db/002). This queries
// them directly rather than stretching the domain ports to cover a
// read-only dashboard concern.
export class PgSocData implements SocData {
  constructor(private db:PgQueryable){}
  async nodes(){
    const r=await this.db.query(`SELECT node_id,device_id,zone_assignment,node_type,is_active,last_handshake
      FROM bapc_security_core.mesh_nodes ORDER BY node_id`);
    return r.rows;
  }
  async incidents(){
    const r=await this.db.query(`SELECT incident_id,title,severity,status,primary_node_id,opened_at,closed_at
      FROM bapc_security_core.incidents ORDER BY opened_at DESC LIMIT 100`);
    return r.rows;
  }
  async policies(){
    const r=await this.db.query(`SELECT policy_id,name,version,priority,is_active
      FROM bapc_security_core.network_policies WHERE is_active=true ORDER BY priority DESC`);
    return r.rows;
  }
  async jit(){
    const r=await this.db.query(`SELECT grant_id,user_id,target_resource,target_zone,granted_at,expires_at
      FROM bapc_security_core.jit_grants WHERE is_terminated=false AND expires_at>now() ORDER BY expires_at`);
    return r.rows;
  }
  async relays(){
    const r=await this.db.query(`SELECT relay_id,node_id,region,endpoint,load_percent,latency_ms,is_available,last_heartbeat
      FROM bapc_security_core.relays ORDER BY region`);
    return r.rows;
  }
  async certificates(){
    const r=await this.db.query(`SELECT cert_id,node_id,serial_number,subject_dn,issued_at,expires_at,is_revoked
      FROM bapc_security_core.certificates WHERE is_revoked=false ORDER BY expires_at LIMIT 200`);
    return r.rows;
  }
  // revocation_reason is authenticated-audience-only: certificates() above
  // and the public CRL endpoint both deliberately withhold it — see
  // SocData.revokedCertificates' own comment.
  async revokedCertificates(){
    const r=await this.db.query(`SELECT cert_id,node_id,serial_number,subject_dn,revoked_at,revocation_reason
      FROM bapc_security_core.certificates WHERE is_revoked=true ORDER BY revoked_at DESC LIMIT 200`);
    return r.rows;
  }
  async events(limit:number){
    const r=await this.db.query(`SELECT event_id,node_id,event_timestamp,severity,engine_source,event_type,description
      FROM bapc_security_core.security_events ORDER BY event_timestamp DESC LIMIT $1`,[Math.max(1,Math.min(limit,500))]);
    return r.rows;
  }
}
