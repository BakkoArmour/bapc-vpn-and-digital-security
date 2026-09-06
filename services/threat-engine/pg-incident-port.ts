import type {IncidentPort} from "./engine.js";
import type {EventRepository} from "../../src/ports/repositories.js";
import type {IdGenerator, Clock} from "../../src/ports/infrastructure.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

// Real implementation of ThreatEngine's incident port. `incidents`
// (db/002_operational_tables.sql) existed with no write path at all —
// ThreatEngine.evaluate's open() had nowhere real to persist to. event()
// writes through the same EventRepository/security_events table every
// other event-sourced action in this app already uses, so correlated
// threat evaluations show up in GET /api/v1/events like anything else.
export class PgIncidentPort implements IncidentPort {
  constructor(private db:PgQueryable,private events:EventRepository,private ids:IdGenerator,private clock:Clock){}

  async open(input:{id:string;nodeId?:string;severity:string;score:number;signals:unknown[]}):Promise<void>{
    await this.db.query(
      `INSERT INTO bapc_security_core.incidents
         (incident_id,title,severity,status,primary_node_id,metadata)
       VALUES($1,$2,$3,'OPEN',$4,$5)`,
      [
        input.id,`Correlated threat evaluation (score ${input.score})`,input.severity,
        input.nodeId??null,{score:input.score,signalCount:input.signals.length,signals:input.signals}
      ]
    );
  }

  async close(nodeId:string,closedBy:string):Promise<number>{
    const r=await this.db.query(
      `UPDATE bapc_security_core.incidents SET status='RESOLVED',closed_at=$2
       WHERE primary_node_id=$1 AND status='OPEN' RETURNING incident_id`,
      [nodeId,this.clock.now()]
    );
    if(r.rows.length)await this.event({
      severity:"INFO",type:"INCIDENT_RESOLVED",
      description:`${r.rows.length} incident(s) resolved for node ${nodeId}`,
      metadata:{nodeId,closedBy,incidentIds:r.rows.map((row:any)=>row.incident_id)}
    });
    return r.rows.length;
  }

  async event(input:{severity:string;type:string;description:string;metadata:Record<string,unknown>}):Promise<void>{
    await this.events.append({
      id:this.ids.next(),at:this.clock.now(),severity:input.severity as any,
      engine:"threat-correlator",type:input.type,description:input.description,metadata:input.metadata
    });
  }
}
