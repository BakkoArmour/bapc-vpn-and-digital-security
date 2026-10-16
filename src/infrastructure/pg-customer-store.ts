import type {CustomerDeviceRecorder, InviteAccount} from "../application/device-join.js";
import type {CustomerDevice, CustomerSession, CustomerStore} from "../application/customer-devices.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

const T="bapc_security_core";

// Persistence for the customer portal (db/021_customer_portal.sql).
export class PgCustomerStore implements CustomerStore, CustomerDeviceRecorder {
  constructor(private db:PgQueryable){}

  // --- Sign in with BAPC ---
  async saveSignIn(state:string,verifier:string,nextPath:string,expiresAt:Date):Promise<void>{
    await this.db.query(`DELETE FROM ${T}.portal_sign_in_requests WHERE expires_at<now()`);
    await this.db.query(
      `INSERT INTO ${T}.portal_sign_in_requests(state,verifier,next_path,expires_at) VALUES($1,$2,$3,$4)`,
      [state,verifier,nextPath,expiresAt]
    );
  }

  // One use only: the row is deleted as it's read.
  async takeSignIn(state:string):Promise<{verifier:string;nextPath:string}|null>{
    const r=await this.db.query(
      `DELETE FROM ${T}.portal_sign_in_requests WHERE state=$1 AND expires_at>now() RETURNING verifier,next_path`,
      [state]
    );
    return r.rows[0]?{verifier:r.rows[0].verifier,nextPath:r.rows[0].next_path}:null;
  }

  async createSession(tokenHash:string,s:Omit<CustomerSession,"tokenHash">,expiresAt:Date):Promise<void>{
    await this.db.query(`DELETE FROM ${T}.portal_sessions WHERE expires_at<now()`);
    await this.db.query(
      `INSERT INTO ${T}.portal_sessions(token_hash,account_id,email,name,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
      [tokenHash,s.accountId,s.email,s.name,s.csrfToken,expiresAt]
    );
  }

  async session(tokenHash:string):Promise<CustomerSession|null>{
    const r=await this.db.query(
      `SELECT token_hash,account_id,email,name,csrf_token FROM ${T}.portal_sessions WHERE token_hash=$1 AND expires_at>now()`,
      [tokenHash]
    );
    const x=r.rows[0];
    return x?{tokenHash:x.token_hash,accountId:x.account_id,email:x.email,name:x.name,csrfToken:x.csrf_token}:null;
  }

  async deleteSession(tokenHash:string):Promise<void>{
    await this.db.query(`DELETE FROM ${T}.portal_sessions WHERE token_hash=$1`,[tokenHash]);
  }

  // --- devices ---
  async record(nodeId:string,account:InviteAccount,kind:string):Promise<void>{
    await this.db.query(
      `INSERT INTO ${T}.customer_devices(node_id,account_id,email,name,kind) VALUES($1,$2,$3,$4,$5)
       ON CONFLICT(node_id) DO NOTHING`,
      [nodeId,account.accountId,account.email,account.deviceName,kind]
    );
  }

  async devices(accountId:string):Promise<CustomerDevice[]>{
    const r=await this.db.query(
      `SELECT cd.node_id,cd.name,cd.kind,cd.created_at,cd.suspended,n.internal_ipv4,n.last_handshake
       FROM ${T}.customer_devices cd JOIN ${T}.mesh_nodes n ON n.node_id=cd.node_id
       WHERE cd.account_id=$1 AND cd.removed_at IS NULL ORDER BY cd.created_at`,
      [accountId]
    );
    return r.rows.map(x=>({
      nodeId:x.node_id,name:x.name,kind:x.kind,createdAt:new Date(x.created_at),
      suspended:x.suspended,address:String(x.internal_ipv4)
    }));
  }

  async markRemoved(accountId:string,nodeId:string):Promise<boolean>{
    const r=await this.db.query(
      `UPDATE ${T}.customer_devices SET removed_at=now() WHERE account_id=$1 AND node_id=$2 AND removed_at IS NULL RETURNING node_id`,
      [accountId,nodeId]
    );
    return r.rows.length>0;
  }

  async setSuspended(accountId:string,suspended:boolean):Promise<number>{
    const r=await this.db.query(
      `UPDATE ${T}.customer_devices SET suspended=$2 WHERE account_id=$1 AND removed_at IS NULL AND suspended<>$2 RETURNING node_id`,
      [accountId,suspended]
    );
    return r.rows.length;
  }

  async accountsWithDevices():Promise<string[]>{
    const r=await this.db.query(`SELECT DISTINCT account_id FROM ${T}.customer_devices WHERE removed_at IS NULL`);
    return r.rows.map(x=>x.account_id);
  }

  async suspendedNodeIds():Promise<Set<string>>{
    const r=await this.db.query(`SELECT node_id FROM ${T}.customer_devices WHERE suspended OR removed_at IS NOT NULL`);
    return new Set(r.rows.map(x=>x.node_id));
  }
}
