import {KMSClient} from "@aws-sdk/client-kms";
import {DevKeyProvider} from "./dev-key-provider.js";
import {AwsKmsKeyProvider} from "./aws-kms-key-provider.js";
import {selfSignWithExistingKey, createSelfSignedDevCa} from "./dev-self-signed.js";
import {PgDevTrustAnchorStore, type PgQueryable} from "./pg-dev-trust-anchor-store.js";
import type {ProtectedKeyProvider} from "./issuer.js";

export interface TrustAnchor {
  keys:ProtectedKeyProvider;
  keyReference:string;
  issuerId:string;
  certificatePem:string;
  algorithm:"RS256";
  mode:"aws-kms"|"development-shared-ca";
}

// certificates.issuer_id is a real foreign key into certificate_issuers (see
// db/002_operational_tables.sql) — not just an informational label. Keeps
// that row in sync with whichever anchor is actually active: ON CONFLICT
// (name) DO UPDATE means switching from the dev-shared CA to a real AWS KMS
// key (by finally setting AWS_KMS_INTERMEDIATE_KEY_ID) updates this row to
// the new anchor on next boot instead of certificates silently continuing to
// reference a stale issuer.
const ISSUER_NAME="bapc-trust-anchor";
// is_active (db/002_operational_tables.sql) existed with no read path at
// all — nothing ever checked it, so an operator had no way to hard-stop
// issuance from this anchor short of pulling its key material. The WHERE
// clause makes ON CONFLICT's UPDATE a no-op (and RETURNING empty) against a
// row that's been explicitly deactivated, instead of silently reusing it.
export const upsertIssuerRow=async(db:PgQueryable,certificatePem:string,keyReference:string):Promise<string>=>{
  const result=await db.query(
    `INSERT INTO bapc_security_core.certificate_issuers(name,certificate_pem,key_reference)
     VALUES($1,$2,$3)
     ON CONFLICT (name) DO UPDATE SET certificate_pem=EXCLUDED.certificate_pem,key_reference=EXCLUDED.key_reference
     WHERE certificate_issuers.is_active
     RETURNING issuer_id`,
    [ISSUER_NAME,certificatePem,keyReference]
  );
  if(!result.rows[0])throw new Error(`certificate issuer '${ISSUER_NAME}' has been deactivated — cannot issue or sign with it`);
  return result.rows[0].issuer_id;
};

// The single place that decides whether node-certificate issuance and CRL
// signing run against a real AWS KMS key or an ephemeral dev CA — see
// [[user-build-everything-coming-soon]]: the KMS path is real, wired,
// production-shaped code, gated only on whether an AWS account/key actually
// exists yet, not a stub. Both production-server.ts (CRL + threat-response
// certificate issuance) and grpc-server.ts (enrollment) call this so they
// always share one issuer identity.
export const loadTrustAnchor=async(db:PgQueryable,env:NodeJS.ProcessEnv=process.env):Promise<TrustAnchor>=>{
  const kmsKeyId=env.AWS_KMS_INTERMEDIATE_KEY_ID;
  if(kmsKeyId){
    const client=new KMSClient(env.AWS_REGION?{region:env.AWS_REGION}:{});
    const keys=new AwsKmsKeyProvider(client,new Map([["intermediate",kmsKeyId]]));
    const certificatePem=await selfSignWithExistingKey(keys,env.TRUST_ANCHOR_SUBJECT??"BAPC Intermediate CA 1","intermediate");
    const issuerId=await upsertIssuerRow(db,certificatePem,"intermediate");
    console.log(JSON.stringify({event:"trust_core.mode",mode:"aws-kms",kmsKeyId,region:env.AWS_REGION}));
    return {keys,keyReference:"intermediate",issuerId,certificatePem,algorithm:"RS256",mode:"aws-kms"};
  }

  console.log(JSON.stringify({
    event:"trust_core.mode",mode:"development-shared-ca",
    reason:"AWS_KMS_INTERMEDIATE_KEY_ID not set — coming soon: set it (plus AWS_REGION and IAM credentials) to sign with a real AWS KMS-backed key instead of an ephemeral development CA"
  }));
  const store=new PgDevTrustAnchorStore(db);
  const keyReference="trust-anchor";
  // Keep this ASCII and comma-free: node-forge's DN encoding doesn't
  // round-trip non-ASCII characters cleanly, and this repo's `subject`
  // strings are naively split on "," (see parseDn in x509-forge.ts) — a
  // comma inside the CN value itself gets misread as a second DN attribute.
  // Both were confirmed by reproduction, not guessed.
  const subjectCn="BAPC Development CA - not for production";
  // createSelfSignedDevCa (this exact "throwaway dev CA" case, per its own
  // doc comment) was defined but never actually called anywhere — this
  // duplicated its body inline instead of using it.
  const anchor=await store.loadOrCreate(keyReference,subjectCn,async()=>{
    const {keys,certificatePem}=await createSelfSignedDevCa(subjectCn,keyReference);
    return {certificatePem,privateKeyPem:keys.exportPrivateKeyPemForDevOnly(keyReference)};
  });
  const keys=new DevKeyProvider();
  keys.importPrivateKeyPem(keyReference,anchor.privateKeyPem);
  const issuerId=await upsertIssuerRow(db,anchor.certificatePem,keyReference);
  return {keys,keyReference,issuerId,certificatePem:anchor.certificatePem,algorithm:"RS256",mode:"development-shared-ca"};
};
