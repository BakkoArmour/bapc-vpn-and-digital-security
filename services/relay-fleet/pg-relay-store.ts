import type {RelayHealth} from "../../src/application/relay-routing.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

export interface RelayRow {relayId:string; region:string; endpoint:string; isAvailable:boolean; instanceId:string|null;}
export interface RelayHeartbeat {loadPercent:number;latencyMs:number;activeSessions:number;throughputBytesPerSec:number;}

// capacity_mbps (db/004_security_hardening.sql) is an operator-configured
// ceiling from the now-deleted RelayRegistry's convention: *20 to get an
// approximate max session count. Computed here at read time rather than
// stored as a separate percent column, so it always reflects the current
// activeSessions/capacity_mbps pair rather than a snapshot that could go
// stale.
const toHealth=(row:any):RelayHealth=>{
  const activeSessions=Number(row.active_sessions);
  const maxSessions=Number(row.capacity_mbps)*20;
  return {
    id:row.relay_id,region:row.region,endpoint:row.endpoint,
    latencyMs:Number(row.latency_ms),loadPercent:Number(row.load_percent),
    available:row.is_available,
    lastHeartbeat:row.last_heartbeat?new Date(row.last_heartbeat):new Date(0),
    activeSessions,
    capacityPercent:maxSessions>0?Math.min(100,(activeSessions/maxSessions)*100):0,
    throughputBytesPerSec:Number(row.throughput_bytes_per_sec)
  };
};

// Real CRUD against the `relays` table (db/002_operational_tables.sql,
// db/004_security_hardening.sql, extended by db/015_relay_egress_metrics.sql),
// which previously had no write path at all outside manual SQL — the SOC
// console/API could only ever read relays someone inserted by hand.
export class PgRelayStore {
  constructor(private db:PgQueryable){}

  // instanceId is optional: AWS-provisioned relays (POST /api/v1/relays/
  // provision) have one, but a self-registering fixed relay process
  // (POST /api/v1/relays/register — src/runtime/relay-server.ts) doesn't.
  // ON CONFLICT makes registration idempotent across restarts of the same
  // relay id, rather than erroring on the second one.
  // capacityMbps is optional: a self-registering relay reports its own
  // configured ceiling (RELAY_MAX_SESSIONS/20 — see src/runtime/relay-
  // server.ts) rather than this always defaulting to the schema's generic
  // 1000; AWS-provisioned relays (POST /api/v1/relays/provision) leave it
  // at that default until they self-heartbeat too.
  async insert(relayId:string,region:string,endpoint:string,instanceId?:string,capacityMbps?:number):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.relays(relay_id,region,endpoint,is_available,last_heartbeat,instance_id,capacity_mbps)
       VALUES($1,$2,$3,true,now(),$4,COALESCE($5,1000))
       ON CONFLICT(relay_id) DO UPDATE SET region=EXCLUDED.region,endpoint=EXCLUDED.endpoint,
       is_available=true,last_heartbeat=now(),capacity_mbps=EXCLUDED.capacity_mbps`,
      [relayId,region,endpoint,instanceId??null,capacityMbps??null]
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

  private static readonly SELECT_HEALTH=`SELECT relay_id,region,endpoint,load_percent,latency_ms,is_available,last_heartbeat,
              active_sessions,capacity_mbps,throughput_bytes_per_sec
       FROM bapc_security_core.relays`;

  // Unlike candidates() (only fresh/healthy ones, for real routing
  // decisions), this returns every relay including stale/unavailable ones
  // — an operator diagnosing a relay outage (see
  // docs/INCIDENT-RESPONSE-RUNBOOK.md) needs to see what dropped out, not
  // just what's currently usable.
  async list():Promise<RelayHealth[]>{
    const r=await this.db.query(`${PgRelayStore.SELECT_HEALTH} ORDER BY region,relay_id`);
    return r.rows.map(toHealth);
  }

  // relays.load_percent/latency_ms/last_heartbeat/active_sessions/
  // throughput_bytes_per_sec had no write path at all before this — a
  // relay's recorded health was whatever it was set to at insert() time
  // (load 0, latency 0, sessions 0), forever. A real relay process calls
  // this periodically (POST /api/v1/relays/:id/heartbeat) with real
  // measurements — see src/runtime/relay-server.ts.
  async heartbeat(relayId:string,health:RelayHeartbeat):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.relays
       SET load_percent=$2, latency_ms=$3, active_sessions=$4, throughput_bytes_per_sec=$5,
           is_available=true, last_heartbeat=now()
       WHERE relay_id=$1`,
      [relayId,health.loadPercent,health.latencyMs,health.activeSessions,health.throughputBytesPerSec]
    );
  }

  // Real candidate data for RelayRoutingService.select() — previously
  // nothing ever queried relays' health at all; MeshController.reconcile's
  // relayEndpoint parameter had no real caller supplying one, so mesh
  // topology was always DIRECT regardless of whether a healthy relay
  // existed. "Recently heartbeated" mirrors the same 45s freshness window
  // RelayRoutingService.select() itself re-checks.
  async candidates():Promise<RelayHealth[]>{
    const r=await this.db.query(
      `${PgRelayStore.SELECT_HEALTH}
       WHERE is_available=true AND last_heartbeat IS NOT NULL AND last_heartbeat>now()-interval '45 seconds'`
    );
    return r.rows.map(toHealth);
  }
}
