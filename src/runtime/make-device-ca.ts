// Makes the BAPC VPN device CA for one stage: an RSA-3072 key and a self-signed CA certificate valid for 10 years,
// written as two files for BAPC Secrets (TRUST_CA_KEY_PEM, TRUST_CA_CERT_PEM; mode 600, never overwritten):
//
//   node dist/src/runtime/make-device-ca.js --stage production|staging --out <empty folder>
//
// Store both in the stage's BAPC Secrets environment (bapc-vpn-prod / bapc-vpn-staging), then delete the files.
// The control API, customer portal and mesh gRPC read them at start; production refuses to run without them.
import {generateKeyPairSync} from "node:crypto";
import {writeFileSync} from "node:fs";
import {join} from "node:path";
import {VaultKeyProvider} from "../../services/trust-core/vault-key-provider.js";
import {selfSignWithExistingKey} from "../../services/trust-core/dev-self-signed.js";
import {checkDeviceCa} from "../../services/trust-core/trust-anchor.js";

export const DEVICE_CA_SUBJECTS={production:"BAPC VPN Device CA 2026",staging:"BAPC VPN Staging Device CA 2026"} as const;

export const makeDeviceCa=async(stage:keyof typeof DEVICE_CA_SUBJECTS)=>{
  const subject=DEVICE_CA_SUBJECTS[stage];
  if(!subject)throw new Error("stage must be production or staging");
  const keyPem=generateKeyPairSync("rsa",{modulusLength:3072}).privateKey.export({type:"pkcs8",format:"pem"}).toString();
  const keys=new VaultKeyProvider({"device-ca":keyPem});
  const certificatePem=await selfSignWithExistingKey(keys,subject,"device-ca",3650);
  const cert=checkDeviceCa(certificatePem,await keys.publicKey("device-ca"));
  return {keyPem,certificatePem,subject:cert.subject,validTo:cert.validTo,fingerprint256:cert.fingerprint256};
};

if(process.argv[1]?.endsWith("make-device-ca.js")){
  const arg=(name:string)=>{const i=process.argv.indexOf(`--${name}`);return i>0?process.argv[i+1]:undefined;};
  const stage=arg("stage") as keyof typeof DEVICE_CA_SUBJECTS|undefined, out=arg("out");
  if(!stage||!out||!(stage in DEVICE_CA_SUBJECTS)){console.error("usage: make-device-ca.js --stage production|staging --out <folder>");process.exit(2);}
  const ca=await makeDeviceCa(stage);
  writeFileSync(join(out,"TRUST_CA_KEY_PEM"),ca.keyPem,{mode:0o600,flag:"wx"});
  writeFileSync(join(out,"TRUST_CA_CERT_PEM"),ca.certificatePem,{mode:0o600,flag:"wx"});
  console.log(JSON.stringify({stage,subject:ca.subject,validTo:ca.validTo,fingerprint256:ca.fingerprint256}));
}
