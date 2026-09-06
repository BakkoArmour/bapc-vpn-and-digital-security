import type {EgressGateway} from "./selector.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}
export interface EgressGatewayRow {gatewayId:string;region:string;fixedIp:string;isHealthy:boolean;state:string;}

// Real persistence for egress_gateways (db/014_egress_gateways.sql) —
// EgressSelector existed fully built and tested with nothing to select
// from at all: unlike relays, there was no registry, so there were never
// any real candidates and no caller. Modeled directly on PgRelayStore.
export class PgEgressStore {
  constructor(private db:PgQueryable){}

  // Idempotent upsert — a restarting gateway process just re-registers
  // under the same id rather than erroring or accumulating duplicate rows.
  async insert(gatewayId:string,region:string,fixedIp:string):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.egress_gateways(gateway_id,region,fixed_ip,is_healthy,state,last_heartbeat)
       VALUES($1,$2,$3,true,'ACTIVE',now())
       ON CONFLICT(gateway_id) DO UPDATE SET region=EXCLUDED.region,fixed_ip=EXCLUDED.fixed_ip,
       is_healthy=true,last_heartbeat=now()`,
      [gatewayId,region,fixedIp]
    );
  }

  async get(gatewayId:string):Promise<EgressGatewayRow|null>{
    const r=await this.db.query(
      `SELECT gateway_id,region,fixed_ip,is_healthy,state FROM bapc_security_core.egress_gateways WHERE gateway_id=$1`,
      [gatewayId]
    );
    const row=r.rows[0];
    if(!row)return null;
    return {gatewayId:row.gateway_id,region:row.region,fixedIp:row.fixed_ip,isHealthy:row.is_healthy,state:row.state};
  }

  async remove(gatewayId:string):Promise<void>{
    await this.db.query(`DELETE FROM bapc_security_core.egress_gateways WHERE gateway_id=$1`,[gatewayId]);
  }

  async heartbeat(gatewayId:string,health:{loadPercent:number;healthy:boolean}):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.egress_gateways
       SET load_percent=$2, is_healthy=$3, last_heartbeat=now()
       WHERE gateway_id=$1`,
      [gatewayId,health.loadPercent,health.healthy]
    );
  }

  // Real candidate data for EgressSelector.select(). "Recently
  // heartbeated" mirrors PgRelayStore.candidates()'s freshness window,
  // scaled to EgressSelector's own 30s staleness check (select() itself
  // also re-checks lastCheck age, so this is a coarse pre-filter, not the
  // only staleness gate).
  async candidates():Promise<EgressGateway[]>{
    const r=await this.db.query(
      `SELECT gateway_id,region,fixed_ip,is_healthy,load_percent,last_heartbeat
       FROM bapc_security_core.egress_gateways
       WHERE state='ACTIVE' AND last_heartbeat IS NOT NULL AND last_heartbeat>now()-interval '30 seconds'`
    );
    return r.rows.map((row:any)=>({
      id:row.gateway_id,region:row.region,fixedIp:row.fixed_ip,
      healthy:row.is_healthy,loadPercent:Number(row.load_percent),
      lastCheck:new Date(row.last_heartbeat)
    }));
  }
}
