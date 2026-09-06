export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

// Backs the cross-process dev-CA sharing described in
// db/009_dev_trust_anchor.sql. loadOrCreate is race-safe: if two processes
// (e.g. control-api and mesh-grpc) both boot for the first time at once and
// both decide no anchor exists yet, only one of their generated keys wins
// (INSERT ... ON CONFLICT DO NOTHING) and the loser re-reads the winner's row
// instead of running with a CA nothing else in the deployment recognizes.
export class PgDevTrustAnchorStore {
  constructor(private db:PgQueryable){}

  async loadOrCreate(
    keyReference:string,subjectCn:string,
    generate:()=>Promise<{certificatePem:string;privateKeyPem:string}>
  ):Promise<{certificatePem:string;privateKeyPem:string}>{
    const existing=await this.db.query(
      `SELECT certificate_pem, private_key_pem FROM bapc_security_core.dev_trust_anchor WHERE key_reference=$1`,
      [keyReference]
    );
    if(existing.rows.length>0){
      return {certificatePem:existing.rows[0].certificate_pem,privateKeyPem:existing.rows[0].private_key_pem};
    }
    const generated=await generate();
    await this.db.query(
      `INSERT INTO bapc_security_core.dev_trust_anchor(key_reference,subject_cn,certificate_pem,private_key_pem)
       VALUES($1,$2,$3,$4) ON CONFLICT (key_reference) DO NOTHING`,
      [keyReference,subjectCn,generated.certificatePem,generated.privateKeyPem]
    );
    const winner=await this.db.query(
      `SELECT certificate_pem, private_key_pem FROM bapc_security_core.dev_trust_anchor WHERE key_reference=$1`,
      [keyReference]
    );
    return {certificatePem:winner.rows[0].certificate_pem,privateKeyPem:winner.rows[0].private_key_pem};
  }
}
