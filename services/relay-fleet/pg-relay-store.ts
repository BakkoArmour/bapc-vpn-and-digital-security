import type {RelayHealth} from "../../src/application/relay-routing.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

export interface RelayRow {relayId:string; region:string; endpoint:string; isAvailable:boolean; instanceId:string|null;}

// Real CRUD against the `relays` table (db/002_operational_tables.sql),
// which previously had no write path at all outside manual SQL — the SOC
// console/API could only ever read relays someone inserted by hand.
export class PgRelayStore {
  constructor(private db:PgQueryable){}

  // instanceId is optional: AWS-provisioned relays (POST /api/v1/relays/
  // provision) have one, but a self-registering fixed relay process
  // (POST /api/v1/relays/register — src/runtime/relay-server.ts) doesn't.
  // ON CONFLICT makes registration idempotent across restarts of the same
  // relay id, rather than erroring on the second one.
  async insert(relayId:string,region:string,endpoint:string,instanceId?:string):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.relays(relay_id,region,endpoint,is_available,last_heartbeat,instance_id)
       VALUES($1,$2,$3,true,now(),$4)
       ON CONFLICT(relay_id) DO UPDATE SET region=EXCLUDED.region,endpoint=EXCLUDED.endpoint,
       is_available=true,last_heartbeat=now()`,
      [relayId,region,endpoint,instanceId??null]
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

  // Unlike candidates() (only fresh/healthy ones, for real routing
  // decisions), this returns every relay including stale/unavailable ones
  // — an operator diagnosing a relay outage (see
  // docs/INCIDENT-RESPONSE-RUNBOOK.md) needs to see what dropped out, not
  // just what's currently usable.
  async list():Promise<RelayHealth[]>{
    const r=await this.db.query(
      `SELECT relay_id,region,endpoint,load_percent,latency_ms,is_available,last_heartbeat
       FROM bapc_security_core.relays ORDER BY region,relay_id`
    );
    return r.rows.map((row:any)=>({
      id:row.relay_id,region:row.region,endpoint:row.endpoint,
      latencyMs:Number(row.latency_ms),loadPercent:Number(row.load_percent),
      available:row.is_available,
      lastHeartbeat:row.last_heartbeat?new Date(row.last_heartbeat):new Date(0)
    }));
  }

  // relays.load_percent/latency_ms/last_heartbeat (db/002_operational_tables.sql)
  // existed with no write path at all — a relay's health was whatever it
  // was set to at insert() time (load 0, latency 0) forever after, since
  // nothing ever updated it. A real relay process calls this periodically
  // (POST /api/v1/relays/:id/heartbeat).
  async heartbeat(relayId:string,health:{loadPercent:number;latencyMs:number}):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.relays
       SET load_percent=$2, latency_ms=$3, is_available=true, last_heartbeat=now()
       WHERE relay_id=$1`,
      [relayId,health.loadPercent,health.latencyMs]
    );
  }

  // Real candidate data for RelayRoutingService.select() — previously
  // nothing ever queried relays' health at all; MeshController.reconcile's
  // relayEndpoint parameter had no real caller supplying one, so mesh
  // topology was always DIRECT regardless of whether a healthy relay
  // existed. "Recently heartbeated" mirrors RelayRegistry's own 45s
  // freshness window.
  async candidates():Promise<RelayHealth[]>{
    const r=await this.db.query(
      `SELECT relay_id,region,endpoint,load_percent,latency_ms,is_available,last_heartbeat
       FROM bapc_security_core.relays
       WHERE is_available=true AND last_heartbeat IS NOT NULL AND last_heartbeat>now()-interval '45 seconds'`
    );
    return r.rows.map((row:any)=>({
      id:row.relay_id,region:row.region,endpoint:row.endpoint,
      latencyMs:Number(row.latency_ms),loadPercent:Number(row.load_percent),
      available:row.is_available,lastHeartbeat:new Date(row.last_heartbeat)
    }));
  }
}
