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
  async revoke(serial:string,reason:string,_at:Date){
    await this.db.query(
      `UPDATE bapc_security_core.certificates
       SET is_revoked=true, revocation_reason=$2
       WHERE serial_number=$1`,
      [serial,reason]
    );
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
}
