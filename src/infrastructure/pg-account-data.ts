import {createHash} from "node:crypto";
import type {AccountDataStore, AccountExport, AdminAccountDetail, AdminAccountRow, AdminStore} from "../application/account-data.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}
export interface PgTransactional extends PgQueryable {transaction<T>(work:(client:PgQueryable)=>Promise<T>):Promise<T>;}

const T="bapc_security_core";
const pseudonym=(accountId:string)=>`erased:${createHash("sha256").update(`bapc-vpn/erased/${accountId}`).digest("hex").slice(0,24)}`;
const date=(v:unknown)=>v?new Date(v as string):null;

// db/022_portal_audit.sql plus the portal's own tables (db/020, db/021).
export class PgAccountData implements AccountDataStore {
  constructor(private db:PgTransactional){}

  async audit(accountId:string,actor:"customer"|"system"|"staff",action:string,detail:Record<string,unknown>={},ip:string|null=null){
    await this.db.query(
      `INSERT INTO ${T}.portal_audit(account_id,actor,action,detail,ip) VALUES($1,$2,$3,$4,$5)`,
      [accountId,actor,action,JSON.stringify(detail),ip]
    );
  }

  async hasSignedInBefore(accountId:string){
    const r=await this.db.query(`SELECT 1 FROM ${T}.portal_audit WHERE account_id=$1 AND action='auth.signed_in' LIMIT 1`,[accountId]);
    return r.rows.length>0;
  }

  async exportAccount(accountId:string):Promise<AccountExport>{
    const devices=await this.db.query(
      `SELECT cd.name,cd.kind,cd.created_at,cd.suspended,cd.removed_at,n.internal_ipv4,n.last_handshake
       FROM ${T}.customer_devices cd LEFT JOIN ${T}.mesh_nodes n ON n.node_id=cd.node_id
       WHERE cd.account_id=$1 ORDER BY cd.created_at`,[accountId]);
    const invites=await this.db.query(
      `SELECT label,device_name,created_at,expires_at,used_at FROM ${T}.enrollment_invites WHERE account_id=$1 ORDER BY created_at`,[accountId]);
    const activity=await this.db.query(
      `SELECT at,actor,action,detail,ip FROM ${T}.portal_audit WHERE account_id=$1 ORDER BY at DESC LIMIT 5000`,[accountId]);
    return {
      devices:devices.rows.map(x=>({name:x.name,kind:x.kind,address:x.internal_ipv4?String(x.internal_ipv4):"",createdAt:new Date(x.created_at),
        suspended:x.suspended,removedAt:date(x.removed_at),lastHandshake:date(x.last_handshake)})),
      invites:invites.rows.map(x=>({label:x.label,deviceName:x.device_name,createdAt:new Date(x.created_at),expiresAt:new Date(x.expires_at),redeemedAt:date(x.used_at)})),
      activity:activity.rows.map(x=>({at:new Date(x.at),actor:x.actor,action:x.action,detail:x.detail??{},ip:x.ip}))
    };
  }

  async eraseAccount(accountId:string){
    const p=pseudonym(accountId);
    return this.db.transaction(async c=>{
      const invites=await c.query(`DELETE FROM ${T}.enrollment_invites WHERE account_id=$1 AND used_at IS NULL RETURNING invite_id`,[accountId]);
      await c.query(`UPDATE ${T}.enrollment_invites SET account_id=NULL,account_email=NULL,device_name=NULL,created_by='customer:erased' WHERE account_id=$1`,[accountId]);
      const sessions=await c.query(`DELETE FROM ${T}.portal_sessions WHERE account_id=$1 RETURNING token_hash`,[accountId]);
      // Device rows stay (removed, so the gateway keeps refusing those keys) but no longer say whose they were.
      const devices=await c.query(
        `UPDATE ${T}.customer_devices SET account_id=$2,email='',name='Removed device',removed_at=COALESCE(removed_at,now()),suspended=true
         WHERE account_id=$1 RETURNING node_id`,[accountId,p]);
      const audit=await c.query(`UPDATE ${T}.portal_audit SET account_id=$2,detail='{}'::jsonb,ip=NULL WHERE account_id=$1 RETURNING id`,[accountId,p]);
      return {devices:devices.rows.length,invites:invites.rows.length,sessions:sessions.rows.length,auditRows:audit.rows.length};
    });
  }
}

// Staff view of portal accounts (db/021-023). An account is anyone who has signed in or has a device; erased
// accounts are left out. Search matches the email (case-insensitive) or the exact bapc.app account id.
export class PgAdminStore implements AdminStore {
  constructor(private db:PgQueryable){}

  async listAccounts(q:{search?:string;page:number;pageSize:number}){
    const search=(q.search??"").trim().toLowerCase().slice(0,200);
    const accounts=`
      WITH a AS (
        SELECT account_id FROM ${T}.customer_devices WHERE account_id NOT LIKE 'erased:%'
        UNION SELECT account_id FROM ${T}.portal_audit WHERE action='auth.signed_in' AND account_id NOT LIKE 'erased:%'
        UNION SELECT account_id FROM ${T}.portal_sessions),
      e AS (SELECT DISTINCT ON (account_id) account_id, email FROM (
        SELECT account_id, email, created_at AS t FROM ${T}.customer_devices WHERE email<>''
        UNION ALL SELECT account_id, email, expires_at AS t FROM ${T}.portal_sessions) x ORDER BY account_id, t DESC),
      rows AS (
        SELECT a.account_id, COALESCE(e.email,'') AS email,
          (SELECT count(*) FROM ${T}.customer_devices d WHERE d.account_id=a.account_id AND d.removed_at IS NULL AND NOT d.suspended)::int AS active,
          (SELECT count(*) FROM ${T}.customer_devices d WHERE d.account_id=a.account_id AND d.removed_at IS NULL AND d.suspended)::int AS paused,
          (SELECT max(at) FROM ${T}.portal_audit p WHERE p.account_id=a.account_id AND p.action='auth.signed_in') AS last_sign_in,
          LEAST((SELECT min(at) FROM ${T}.portal_audit p WHERE p.account_id=a.account_id),(SELECT min(created_at) FROM ${T}.customer_devices d WHERE d.account_id=a.account_id)) AS first_seen
        FROM a LEFT JOIN e ON e.account_id=a.account_id
        WHERE $1='' OR lower(COALESCE(e.email,'')) LIKE '%'||$1||'%' OR a.account_id=$1)`;
    const total=await this.db.query(`${accounts} SELECT count(*)::int AS n FROM rows`,[search]);
    const r=await this.db.query(`${accounts} SELECT * FROM rows ORDER BY COALESCE(last_sign_in,first_seen) DESC NULLS LAST, account_id LIMIT $2 OFFSET $3`,
      [search,q.pageSize,Math.max(0,q.page-1)*q.pageSize]);
    const rows:AdminAccountRow[]=r.rows.map(x=>({accountId:x.account_id,email:x.email,activeDevices:x.active,pausedDevices:x.paused,
      lastSignIn:x.last_sign_in?new Date(x.last_sign_in):null,firstSeen:x.first_seen?new Date(x.first_seen):null}));
    return {rows,total:total.rows[0]?.n??0};
  }

  async accountDetail(accountId:string):Promise<AdminAccountDetail|null>{
    if(accountId.startsWith("erased:"))return null;
    const devices=await this.db.query(
      `SELECT cd.node_id,cd.name,cd.kind,cd.created_at,cd.suspended,cd.removed_at,cd.email,n.internal_ipv4,n.last_handshake
       FROM ${T}.customer_devices cd LEFT JOIN ${T}.mesh_nodes n ON n.node_id=cd.node_id WHERE cd.account_id=$1 ORDER BY cd.created_at DESC LIMIT 200`,[accountId]);
    const activity=await this.db.query(`SELECT at,actor,action,detail,ip FROM ${T}.portal_audit WHERE account_id=$1 ORDER BY at DESC LIMIT 100`,[accountId]);
    const session=await this.db.query(`SELECT email FROM ${T}.portal_sessions WHERE account_id=$1 ORDER BY expires_at DESC LIMIT 1`,[accountId]);
    if(!devices.rows.length&&!activity.rows.length&&!session.rows.length)return null;
    return {
      accountId,email:devices.rows.find(x=>x.email)?.email??session.rows[0]?.email??null,
      devices:devices.rows.map(x=>({nodeId:x.node_id,name:x.name,kind:x.kind,address:x.internal_ipv4?String(x.internal_ipv4):"",createdAt:new Date(x.created_at),
        suspended:x.suspended,removedAt:x.removed_at?new Date(x.removed_at):null,lastHandshake:x.last_handshake?new Date(x.last_handshake):null})),
      activity:activity.rows.map(x=>({at:new Date(x.at),actor:x.actor,action:x.action,detail:x.detail??{},ip:x.ip}))
    };
  }
}
