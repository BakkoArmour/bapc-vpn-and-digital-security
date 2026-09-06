import forge from "node-forge";
import {DevKeyProvider} from "./dev-key-provider.js";
import {ForgeX509Builder} from "./x509-forge.js";
import type {ProtectedKeyProvider} from "./issuer.js";

// Self-signs a CA certificate for a key that already exists behind the given
// ProtectedKeyProvider (an AWS KMS key, or a dev key reconstructed from a
// persisted PEM) — shared by createSelfSignedDevCa below (which generates a
// brand-new dev key first) and by trust-anchor.ts's AWS KMS / persisted-dev
// paths, so all three produce a structurally-identical self-signed CA cert.
export const selfSignWithExistingKey=async(
  keys:ProtectedKeyProvider,subjectCn:string,keyReference:string,
  validityDays=365
):Promise<string>=>{
  const publicKeyPem=await keys.publicKey(keyReference);
  const x509=new ForgeX509Builder();
  const placeholder=forge.pki.createCertificate();
  placeholder.publicKey=forge.pki.publicKeyFromPem(publicKeyPem);
  placeholder.setSubject([{name:"commonName",value:subjectCn}]);
  placeholder.validity.notBefore=new Date();
  placeholder.validity.notAfter=new Date(Date.now()+validityDays*86_400_000);
  placeholder.signatureOid=placeholder.siginfo.algorithmOid=forge.pki.oids["sha256WithRSAEncryption"]!;
  placeholder.signature="";
  const placeholderPem=forge.pki.certificateToPem(placeholder);

  return x509.create({
    serial:"01",subject:`CN=${subjectCn}`,publicKeyPem,issuerCertificatePem:placeholderPem,
    notBefore:new Date(),notAfter:new Date(Date.now()+validityDays*86_400_000),
    extensions:{basicConstraints:"CA:TRUE",keyUsage:"keyCertSign,cRLSign"},
    sign:tbs=>keys.sign(keyReference,"RS256",tbs)
  });
};

// Convenience for spinning up a throwaway self-signed dev CA (key + cert) —
// used wherever this repo needs "an issuer" to demonstrate a real signing
// pipeline (X.509 issuance, CRL generation) without a production HSM/KMS
// wired up yet. NEVER use in production: see runbooks/root-ca-ceremony.md.
export const createSelfSignedDevCa=async(subjectCn:string,keyReference:string)=>{
  const keys=new DevKeyProvider();
  keys.generate(keyReference,3072);
  const certificatePem=await selfSignWithExistingKey(keys,subjectCn,keyReference);
  return {keys,certificatePem,keyReference};
};
