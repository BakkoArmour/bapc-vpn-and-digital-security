import type {ThreatSignal} from "./engine.js";
import type {ThreatSignalStore} from "./threat-signal-store.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

const UNATTRIBUTED="__unattributed__";

// Backs threat_signal_window (db/017_threat_signal_window.sql) — the
// durable replacement for ThreatCorrelator's in-memory sliding-window Map.
export class PgThreatSignalStore implements ThreatSignalStore {
  constructor(private db:PgQueryable){}

  async record(nodeKey:string,signal:ThreatSignal):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.threat_signal_window
         (node_key,kind,confidence,weight,occurred_at,metadata)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [nodeKey,signal.kind,signal.confidence,signal.weight,signal.at,JSON.stringify(signal.metadata)]
    );
  }

  // Prunes (deletes) anything older than sinceMs before reading, so the
  // table never accumulates signals this node's correlation window has
  // already aged out of.
  async window(nodeKey:string,sinceMs:number):Promise<ThreatSignal[]>{
    await this.db.query(
      `DELETE FROM bapc_security_core.threat_signal_window WHERE node_key=$1 AND occurred_at<$2`,
      [nodeKey,new Date(sinceMs)]
    );
    const r=await this.db.query(
      `SELECT kind,confidence,weight,occurred_at,metadata
       FROM bapc_security_core.threat_signal_window WHERE node_key=$1 ORDER BY occurred_at`,
      [nodeKey]
    );
    return r.rows.map(row=>this.toSignal(nodeKey,row));
  }

  async clear(nodeKey:string):Promise<number>{
    const r=await this.db.query(
      `DELETE FROM bapc_security_core.threat_signal_window WHERE node_key=$1 RETURNING signal_id`,
      [nodeKey]
    );
    return r.rows.length;
  }

  // The SOC console's Threat Signals panel (Item 3) needs to know which
  // nodes currently have an active, un-escalated correlation window without
  // polling every enrolled node individually — this lists exactly that,
  // most-recently-active first.
  async activeWindows(sinceMs:number):Promise<Array<{nodeKey:string;signalCount:number;latestAt:Date}>>{
    const r=await this.db.query(
      `SELECT node_key,count(*)::int AS signal_count,max(occurred_at) AS latest_at
       FROM bapc_security_core.threat_signal_window WHERE occurred_at>=$1
       GROUP BY node_key ORDER BY latest_at DESC`,
      [new Date(sinceMs)]
    );
    return r.rows.map(row=>({nodeKey:row.node_key,signalCount:row.signal_count,latestAt:new Date(row.latest_at)}));
  }

  private toSignal(nodeKey:string,row:any):ThreatSignal{
    return {
      ...(nodeKey!==UNATTRIBUTED?{nodeId:nodeKey}:{}),
      kind:row.kind,confidence:Number(row.confidence),weight:Number(row.weight),
      at:new Date(row.occurred_at),
      metadata:typeof row.metadata==="string"?JSON.parse(row.metadata):row.metadata
    };
  }
}
