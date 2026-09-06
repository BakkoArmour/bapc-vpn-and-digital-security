import {mkdirSync, writeFileSync} from "node:fs";
import {join} from "node:path";
import {createHash} from "node:crypto";
import forge from "node-forge";
import {DevKeyProvider} from "./dev-key-provider.js";
import {ForgeX509Builder} from "./x509-forge.js";

const YEARS=(n:number)=>new Date(Date.now()+n*365*86_400_000);

/**
 * Reference/dev root+intermediate CA ceremony. Produces real, chain-verifiable
 * X.509 certificates using in-memory RSA keys — useful for local development,
 * CI and staging. It is explicitly NOT the production ceremony: a production
 * root key must be generated on an air-gapped HSM, never exist as a PEM file
 * on any general-purpose disk, and be brought up under dual control by named
 * key custodians. See runbooks/root-ca-ceremony.md for that procedure; this
 * script's structure (root -> intermediate, TBS-then-external-sign) is what
 * the production ceremony tooling should mirror once wired to real HSM calls.
 */
export const runDevCeremony=async(outDir:string)=>{
  mkdirSync(outDir,{recursive:true});
  const keys=new DevKeyProvider();
  const x509=new ForgeX509Builder();

  const rootPublicKeyPem=keys.generate("root",4096);
  const rootSerial="01";
  const rootSelfPem=await (async()=>{
    // A self-signed root: its own "issuer certificate" is itself, so we first
    // build a placeholder self-referencing cert to hand ForgeX509Builder the
    // subject it should copy into the issuer field.
    const placeholder=forge.pki.createCertificate();
    placeholder.publicKey=forge.pki.publicKeyFromPem(rootPublicKeyPem);
    placeholder.setSubject([{name:"commonName",value:"BAPC Root CA"}]);
    placeholder.validity.notBefore=new Date();
    placeholder.validity.notAfter=YEARS(15);
    // This placeholder is only a vehicle to carry the subject DN into
    // ForgeX509Builder's issuerCertificatePem parameter below — it is never
    // used as a real certificate — but forge's PEM serializer still requires
    // a signature/algorithm to be present, so stub one in.
    placeholder.signatureOid=placeholder.siginfo.algorithmOid=forge.pki.oids["sha256WithRSAEncryption"]!;
    placeholder.signature="";
    return forge.pki.certificateToPem(placeholder);
  })();
  const rootCertPem=await x509.create({
    serial:rootSerial,subject:"CN=BAPC Root CA",publicKeyPem:rootPublicKeyPem,
    issuerCertificatePem:rootSelfPem,notBefore:new Date(),notAfter:YEARS(15),
    extensions:{basicConstraints:"CA:TRUE",keyUsage:"keyCertSign,cRLSign"},
    sign:tbs=>keys.sign("root","RS256",tbs)
  });

  const intermediatePublicKeyPem=keys.generate("intermediate",3072);
  const intermediateCertPem=await x509.create({
    serial:"02",subject:"CN=BAPC Intermediate CA 1",publicKeyPem:intermediatePublicKeyPem,
    issuerCertificatePem:rootCertPem,notBefore:new Date(),notAfter:YEARS(5),
    extensions:{basicConstraints:"CA:TRUE",keyUsage:"keyCertSign,cRLSign"},
    sign:tbs=>keys.sign("root","RS256",tbs)
  });

  writeFileSync(join(outDir,"root-ca.crt.pem"),rootCertPem);
  writeFileSync(join(outDir,"intermediate-ca.crt.pem"),intermediateCertPem);
  // DEV ONLY — a production ceremony never writes root/intermediate private
  // keys to a filesystem at all; they exist only inside the HSM.
  writeFileSync(join(outDir,"DEV-ONLY-root.key.pem"),keys.exportPrivateKeyPemForDevOnly("root"));
  writeFileSync(join(outDir,"DEV-ONLY-intermediate.key.pem"),keys.exportPrivateKeyPemForDevOnly("intermediate"));

  const fingerprint=(pem:string)=>{
    const der=forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(pem))).getBytes();
    return createHash("sha256").update(Buffer.from(der,"binary")).digest("hex");
  };
  const manifest={
    generatedAt:new Date().toISOString(),
    warning:"DEVELOPMENT CEREMONY ARTIFACTS — do not use in production.",
    root:{subject:"CN=BAPC Root CA",serial:rootSerial,sha256:fingerprint(rootCertPem)},
    intermediate:{subject:"CN=BAPC Intermediate CA 1",serial:"02",sha256:fingerprint(intermediateCertPem)}
  };
  writeFileSync(join(outDir,"manifest.json"),JSON.stringify(manifest,null,2));
  return manifest;
};

if(process.argv[1]?.endsWith("ceremony.js")){
  const outDir=process.argv[2]??"deploy/dev-ca";
  const manifest=await runDevCeremony(outDir);
  console.log(JSON.stringify(manifest,null,2));
}
