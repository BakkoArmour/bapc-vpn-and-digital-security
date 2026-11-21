import {createHash} from "node:crypto";
import type {AccountDataStore, AccountExport} from "../application/account-data.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}
export interface PgTransactional extends PgQueryable {transaction<T>(work:(client:PgQueryable)=>Promise<T>):Promise<T>;}

const T="bapc_security_core";
const pseudonym=(accountId:string)=>`erased:${createHash("sha256").update(`bapc-vpn/erased/${accountId}`).digest("hex").slice(0,24)}`;
const date=(v:unknown)=>v?new Date(v as string):null;

// db/022_portal_audit.sql plus the portal's own tables (db/020, db/021).
export class PgAccountData implements AccountDataStore {
  constructor(private db:PgTransactional){}

  async audit(accountId:string,actor:"customer"|"system",action:string,detail:Record<string,unknown>={},ip:string|null=null){
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
