import type {PoolClient} from "pg";
import type {
  AuditRecord,Device,JitGrant,MeshNode,NetworkPolicy,SecurityEvent
} from "../../domain/types.js";
import type {
  AuditRepository,DeviceRepository,EventRepository,JitRepository,
  NodeRepository,PolicyRepository,UnitOfWork
} from "../../ports/repositories.js";
import {Postgres} from "./client.js";

const json=<T>(v:unknown)=>v as T;
const date=(v:unknown)=>v instanceof Date?v:new Date(String(v));

export class PgRepositories implements DeviceRepository,NodeRepository,
  PolicyRepository,JitRepository,EventRepository,AuditRepository,UnitOfWork {
  private tx:PoolClient|undefined;
  constructor(private db:Postgres,tx?:PoolClient){this.tx=tx;}
  private q(text:string,values:unknown[]=[]){
    return this.tx?this.tx.query(text,values):this.db.query(text,values);
  }
  async transaction<T>(work:()=>Promise<T>):Promise<T>{
    return this.db.transaction(async client=>{
      const original=this.tx; this.tx=client;
      try{return await work();}finally{this.tx=original;}
    });
  }

  async findByHardwareId(hardwareId:string):Promise<Device|undefined>{
    const r=await this.q(`SELECT * FROM bapc_security_core.devices WHERE hardware_uuid=$1`,[hardwareId]);
    return r.rowCount?this.device(r.rows[0]):undefined;
  }
  async findByPublicKey(publicKey:string):Promise<MeshNode|undefined>{
    const r=await this.q(`SELECT * FROM bapc_security_core.mesh_nodes WHERE public_key=$1`,[publicKey]);
    return r.rowCount?this.node(r.rows[0]):undefined;
  }
  async get(id:string):Promise<any>{
    for(const [table,key,map] of [
      ["devices","device_id",(x:any)=>this.device(x)],
      ["mesh_nodes","node_id",(x:any)=>this.node(x)],
      ["network_policies","policy_id",(x:any)=>this.policy(x)],
      ["jit_grants","grant_id",(x:any)=>this.grant(x)]
    ] as const){
      const r=await this.q(`SELECT * FROM bapc_security_core.${table} WHERE ${key}=$1`,[id]);
      if(r.rowCount) return map(r.rows[0]);
    }
    return undefined;
  }
  async save(value:any):Promise<void>{
    if("hardwareId" in value) return this.saveDevice(value);
    if("wireGuardPublicKey" in value) return this.saveNode(value);
    if("sourceZones" in value) return this.savePolicy(value);
    return this.saveGrant(value);
  }
  async list():Promise<any[]>{
    const r=await this.q(`SELECT * FROM bapc_security_core.mesh_nodes WHERE is_active=true ORDER BY node_id`);
    return r.rows.map(x=>this.node(x));
  }
  async listActive(now?:Date):Promise<any[]>{
    if(now){
      const r=await this.q(`SELECT * FROM bapc_security_core.jit_grants
        WHERE is_terminated=false AND expires_at>$1 ORDER BY expires_at`,[now]);
      return r.rows.map(x=>this.grant(x));
    }
    const r=await this.q(`SELECT * FROM bapc_security_core.network_policies
      WHERE is_active=true ORDER BY priority DESC,policy_id`);
    return r.rows.map(x=>this.policy(x));
  }
  async append(value:any):Promise<void>{
    if("hash" in value){
      await this.q(`INSERT INTO bapc_security_core.audit_chain
        (event_timestamp,actor,action,subject,payload,previous_hash,event_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [value.at,value.actor,value.action,value.subject,value.payload,value.previousHash,value.hash]);
      return;
    }
    const e=value as SecurityEvent;
    await this.q(`INSERT INTO bapc_security_core.security_events
      (event_id,node_id,event_timestamp,severity,engine_source,event_type,description,metadata)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [e.id,e.nodeId??null,e.at,e.severity,e.engine,e.type,e.description,e.metadata]);
  }
  async recent(limit:number):Promise<SecurityEvent[]>{
    const r=await this.q(`SELECT * FROM bapc_security_core.security_events
      ORDER BY event_timestamp DESC LIMIT $1`,[Math.max(1,Math.min(limit,500))]);
    return r.rows.map((x:any)=>({
      id:x.event_id,nodeId:x.node_id??undefined,at:date(x.event_timestamp),
      severity:x.severity,engine:x.engine_source,type:x.event_type,
      description:x.description,metadata:json<Record<string,unknown>>(x.metadata)
    }));
  }
  async last():Promise<AuditRecord|undefined>{
    const r=await this.q(`SELECT * FROM bapc_security_core.audit_chain
      ORDER BY sequence DESC LIMIT 1`);
    if(!r.rowCount)return undefined;
    const x:any=r.rows[0];
    return {sequence:Number(x.sequence),at:date(x.event_timestamp),actor:x.actor,
      action:x.action,subject:x.subject,payload:x.payload,
      previousHash:x.previous_hash,hash:x.event_hash};
  }

  private async saveDevice(d:Device){
    // attestation_public_key was silently dropped here — the CSR-verified
    // identity key captured at enrollment (see enrollment.ts) never actually
    // reached Postgres, so nothing that persisted could ever check a node's
    // identity against it (e.g. verifying a key-rotation request really came
    // from the node that originally enrolled — see PgKeyRotationLedger).
    await this.q(`INSERT INTO bapc_security_core.devices
      (device_id,hostname,hardware_uuid,platform,os_version,attestation_public_key,is_compromised,is_revoked,posture,created_at,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT(device_id) DO UPDATE SET hostname=EXCLUDED.hostname,
      os_version=EXCLUDED.os_version,is_compromised=EXCLUDED.is_compromised,
      is_revoked=EXCLUDED.is_revoked,posture=EXCLUDED.posture,updated_at=EXCLUDED.updated_at`,
      [d.id,d.hostname,d.hardwareId,d.platform,d.osVersion,d.publicAttestationKey??null,d.compromised,d.revoked,d.posture,d.createdAt,d.updatedAt]);
  }
  private async saveNode(n:MeshNode){
    await this.q(`INSERT INTO bapc_security_core.mesh_nodes
      (node_id,device_id,public_key,internal_ipv4,internal_ipv6,listen_port,node_type,zone_assignment,is_active,last_handshake)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT(node_id) DO UPDATE SET public_key=EXCLUDED.public_key,
      zone_assignment=EXCLUDED.zone_assignment,is_active=EXCLUDED.is_active,last_handshake=EXCLUDED.last_handshake`,
      [n.id,n.deviceId,n.wireGuardPublicKey,n.internalIpv4,n.internalIpv6,n.listenPort,n.nodeType,n.zone,n.active,n.lastHandshake??null]);
  }
  private async savePolicy(p:NetworkPolicy){
    await this.q(`INSERT INTO bapc_security_core.network_policies
      (policy_id,name,document,version,priority,is_active)
      VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(policy_id) DO UPDATE SET name=EXCLUDED.name,document=EXCLUDED.document,
      version=EXCLUDED.version,priority=EXCLUDED.priority,is_active=EXCLUDED.is_active`,
      [p.id,p.name,p,p.version,p.priority,p.active]);
  }
  private async saveGrant(g:JitGrant){
    await this.q(`INSERT INTO bapc_security_core.jit_grants
      (grant_id,user_id,target_resource,target_zone,justification,approved_by,granted_at,expires_at,is_terminated,termination_reason)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT(grant_id) DO UPDATE SET approved_by=EXCLUDED.approved_by,
      is_terminated=EXCLUDED.is_terminated,termination_reason=EXCLUDED.termination_reason`,
      [g.id,g.userId,g.targetResource,g.targetZone,g.justification,g.approvedBy??null,
       g.grantedAt,g.expiresAt,g.terminated,g.terminationReason??null]);
  }

  private device(x:any):Device{return {
    id:x.device_id,hostname:x.hostname,hardwareId:x.hardware_uuid,platform:x.platform,
    osVersion:x.os_version,compromised:x.is_compromised,revoked:x.is_revoked,
    posture:json(x.posture),createdAt:date(x.created_at),updatedAt:date(x.updated_at),
    ...(x.attestation_public_key?{publicAttestationKey:x.attestation_public_key}:{})
  } as Device;}
  private node(x:any):MeshNode{return {
    id:x.node_id,deviceId:x.device_id,wireGuardPublicKey:x.public_key,
    internalIpv4:String(x.internal_ipv4),internalIpv6:String(x.internal_ipv6),
    listenPort:x.listen_port,nodeType:x.node_type,zone:x.zone_assignment,
    active:x.is_active,lastHandshake:x.last_handshake?date(x.last_handshake):undefined
  } as MeshNode;}
  private policy(x:any):NetworkPolicy{
    const d=json<any>(x.document);
    return {...d,id:x.policy_id,name:x.name,version:x.version,priority:x.priority,active:x.is_active};
  }
  private grant(x:any):JitGrant{return {
    id:x.grant_id,userId:x.user_id,targetResource:x.target_resource,targetZone:x.target_zone,
    justification:x.justification,approvedBy:x.approved_by??undefined,grantedAt:date(x.granted_at),
    expiresAt:date(x.expires_at),terminated:x.is_terminated,
    terminationReason:x.termination_reason??undefined
  } as JitGrant;}
}
