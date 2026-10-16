import type {EnrollmentInviteStore} from "../application/device-join.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

// Real persistence for enrollment_invites (db/020_enrollment_invites.sql).
// claim() is a single conditional UPDATE so two concurrent joins presenting
// the same code can never both succeed — whichever commits first wins and
// the other sees zero rows.
export class PgEnrollmentInviteStore implements EnrollmentInviteStore {
  constructor(private db:PgQueryable){}

  async create(invite:{codeHash:string;expiresAt:Date;createdBy:string;label:string}):Promise<{inviteId:string}>{
    const r=await this.db.query(
      `INSERT INTO bapc_security_core.enrollment_invites(code_hash,label,created_by,expires_at)
       VALUES($1,$2,$3,$4) RETURNING invite_id`,
      [invite.codeHash,invite.label,invite.createdBy,invite.expiresAt]
    );
    return {inviteId:r.rows[0].invite_id};
  }

  async claim(codeHash:string,now:Date):Promise<string|null>{
    const r=await this.db.query(
      `UPDATE bapc_security_core.enrollment_invites SET used_at=$2
       WHERE code_hash=$1 AND used_at IS NULL AND expires_at>$2 RETURNING invite_id`,
      [codeHash,now]
    );
    return r.rows[0]?.invite_id??null;
  }

  // Only un-claims an invite that never got as far as producing a node — a
  // join that failed partway (bad attestation, duplicate hardware) gives the
  // owner's code back instead of burning it.
  async release(inviteId:string):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.enrollment_invites SET used_at=NULL
       WHERE invite_id=$1 AND used_by_node IS NULL`,
      [inviteId]
    );
  }

  async bindNode(inviteId:string,nodeId:string):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.enrollment_invites SET used_by_node=$2 WHERE invite_id=$1`,
      [inviteId,nodeId]
    );
  }
}
