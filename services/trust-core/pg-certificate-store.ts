import type {CertificateRecordStore} from "./issuer.js";

export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rows:any[]}>;
}
export class PgCertificateStore implements CertificateRecordStore {
  constructor(private db:PgQueryable){}
  async save(record:{
    id:string;nodeId:string;issuerId:string;serial:string;subject:string;
    issuedAt:Date;expiresAt:Date;revoked:boolean;keyReference:string;
  }){
    await this.db.query(
      `INSERT INTO bapc_security_core.certificates
         (cert_id,node_id,issuer_id,serial_number,subject_dn,issued_at,expires_at,is_revoked)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [record.id,record.nodeId,record.issuerId,record.serial,record.subject,
       record.issuedAt,record.expiresAt,record.revoked]
    );
  }
  async revoke(serial:string,reason:string,at:Date){
    await this.db.query(
      `UPDATE bapc_security_core.certificates
       SET is_revoked=true, revocation_reason=$2, revoked_at=$3
       WHERE serial_number=$1`,
      [serial,reason,at]
    );
  }
  // Threat response needs to revoke a compromised node's certificate by
  // node id, but revoke() only takes a serial — nothing looked one up by
  // node before. Most-recently-issued, non-revoked certificate for the
  // node; a node only ever has one active certificate at a time in
  // practice (re-enrollment issues a fresh one rather than adding a
  // second), but ORDER BY + LIMIT 1 makes that explicit rather than
  // assumed.
  async activeCertificateFor(nodeId:string):Promise<{serial:string}|undefined>{
    const r=await this.db.query(
      `SELECT serial_number FROM bapc_security_core.certificates
       WHERE node_id=$1 AND is_revoked=false ORDER BY issued_at DESC LIMIT 1`,
      [nodeId]
    );
    return r.rows[0]?{serial:r.rows[0].serial_number}:undefined;
  }
  async expiringWithin(days:number){
    const r=await this.db.query(
      `SELECT cert_id,node_id,serial_number,subject_dn,expires_at
       FROM bapc_security_core.certificates
       WHERE is_revoked=false AND expires_at < now() + make_interval(days=>$1)
       ORDER BY expires_at`,
      [days]
    );
    return r.rows;
  }
  async listRevoked(){
    const r=await this.db.query(
      `SELECT serial_number, revoked_at FROM bapc_security_core.certificates
       WHERE is_revoked=true AND revoked_at IS NOT NULL ORDER BY revoked_at`
    );
    return r.rows.map(row=>({serialHex:row.serial_number as string,revokedAt:row.revoked_at as Date}));
  }
}
