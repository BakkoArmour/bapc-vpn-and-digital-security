import type {EgressGateway} from "./selector.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}
export interface EgressGatewayRow {gatewayId:string;region:string;fixedIp:string;isHealthy:boolean;state:string;}
export interface EgressHeartbeat {loadPercent:number;healthy:boolean;latencyMs:number;activeSessions:number;}

// capacityPercent is computed at read time from active_sessions/
// max_sessions rather than stored separately, so it always reflects the
// current pair rather than a snapshot that could go stale.
const toGateway=(row:any):EgressGateway=>{
  const activeSessions=Number(row.active_sessions);
  const maxSessions=Number(row.max_sessions);
  return {
    id:row.gateway_id,region:row.region,fixedIp:row.fixed_ip,
    healthy:row.is_healthy,loadPercent:Number(row.load_percent),
    lastCheck:row.last_heartbeat?new Date(row.last_heartbeat):new Date(0),
    latencyMs:Number(row.latency_ms),activeSessions,
    capacityPercent:maxSessions>0?Math.min(100,(activeSessions/maxSessions)*100):0
  };
};

// Real persistence for egress_gateways (db/014_egress_gateways.sql,
// extended by db/015_relay_egress_metrics.sql) — EgressSelector existed
// fully built and tested with nothing to select from at all: unlike
// relays, there was no registry, so there were never any real candidates
// and no caller. Modeled directly on PgRelayStore.
export class PgEgressStore {
  constructor(private db:PgQueryable){}

  // Idempotent upsert — a restarting gateway process just re-registers
  // under the same id rather than erroring or accumulating duplicate rows.
  // maxSessions is optional: a self-registering gateway reports its own
  // configured ceiling (EGRESS_MAX_SESSIONS — see src/runtime/egress-
  // server.ts) rather than this always defaulting to the schema's generic
  // 500.
  async insert(gatewayId:string,region:string,fixedIp:string,maxSessions?:number):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.egress_gateways(gateway_id,region,fixed_ip,is_healthy,state,last_heartbeat,max_sessions)
       VALUES($1,$2,$3,true,'ACTIVE',now(),COALESCE($4,500))
       ON CONFLICT(gateway_id) DO UPDATE SET region=EXCLUDED.region,fixed_ip=EXCLUDED.fixed_ip,
       is_healthy=true,last_heartbeat=now(),max_sessions=EXCLUDED.max_sessions`,
      [gatewayId,region,fixedIp,maxSessions??null]
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

  async heartbeat(gatewayId:string,health:EgressHeartbeat):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.egress_gateways
       SET load_percent=$2, is_healthy=$3, latency_ms=$4, active_sessions=$5, last_heartbeat=now()
       WHERE gateway_id=$1`,
      [gatewayId,health.loadPercent,health.healthy,health.latencyMs,health.activeSessions]
    );
  }

  private static readonly SELECT_HEALTH=`SELECT gateway_id,region,fixed_ip,is_healthy,load_percent,last_heartbeat,latency_ms,active_sessions,max_sessions
       FROM bapc_security_core.egress_gateways`;

  // Unlike candidates(), this returns every gateway including
  // stale/unhealthy ones — for diagnosing an outage, not for routing.
  async list():Promise<EgressGateway[]>{
    const r=await this.db.query(`${PgEgressStore.SELECT_HEALTH} ORDER BY region,gateway_id`);
    return r.rows.map(toGateway);
  }

  // Real candidate data for EgressSelector.select(). "Recently
  // heartbeated" mirrors PgRelayStore.candidates()'s freshness window,
  // scaled to EgressSelector's own 30s staleness check (select() itself
  // also re-checks lastCheck age, so this is a coarse pre-filter, not the
  // only staleness gate).
  async candidates():Promise<EgressGateway[]>{
    const r=await this.db.query(
      `${PgEgressStore.SELECT_HEALTH}
       WHERE state='ACTIVE' AND last_heartbeat IS NOT NULL AND last_heartbeat>now()-interval '30 seconds'`
    );
    return r.rows.map(toGateway);
  }
}
