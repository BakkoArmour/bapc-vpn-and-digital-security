import test from "node:test";
import assert from "node:assert/strict";
import {X509Certificate,generateKeyPairSync,verify} from "node:crypto";
import {loadTrustAnchor,checkDeviceCa} from "../../../services/trust-core/trust-anchor.js";
import {VaultKeyProvider} from "../../../services/trust-core/vault-key-provider.js";
import {makeDeviceCa} from "../../../src/runtime/make-device-ca.js";

// Production signs device certificates with its own CA from BAPC Secrets and refuses the development CA
// (22 Nov 2026: production had been running on "BAPC Development CA - not for production").
const fakeDb=()=>{
  const calls:{text:string;values:unknown[]}[]=[];
  return {calls,query:async(text:string,values:unknown[]=[])=>{calls.push({text,values});return {rows:[{issuer_id:"iss_1"}]} as any;}};
};

test("make-device-ca: an RSA-3072 CA certificate for 10 years, for its own key",async()=>{
  const ca=await makeDeviceCa("production");
  const cert=new X509Certificate(ca.certificatePem);
  assert.equal(cert.ca,true);
  assert.equal(cert.subject,"CN=BAPC VPN Device CA 2026");
  assert.ok(new Date(cert.validTo).getTime()-Date.now()>9.9*365*86_400_000);
  assert.ok(cert.verify(cert.publicKey),"self-signed with its own key");
  assert.equal((await makeDeviceCa("staging")).subject,"CN=BAPC VPN Staging Device CA 2026");
});

test("trust anchor: uses the device CA from BAPC Secrets and signs with it",async()=>{
  const ca=await makeDeviceCa("staging");
  const db=fakeDb();
  const anchor=await loadTrustAnchor(db,{NODE_ENV:"production",TRUST_CA_KEY_PEM:ca.keyPem,TRUST_CA_CERT_PEM:ca.certificatePem});
  assert.equal(anchor.mode,"bapc-secrets");
  assert.equal(anchor.certificatePem,ca.certificatePem);
  assert.equal(anchor.issuerId,"iss_1");
  assert.deepEqual(db.calls[0]!.values,["bapc-trust-anchor",ca.certificatePem,"bapc-secrets:device-ca"]);
  const signature=await anchor.keys.sign(anchor.keyReference,"RS256",Buffer.from("tbs"));
  assert.ok(verify("sha256",Buffer.from("tbs"),new X509Certificate(ca.certificatePem).publicKey,signature));
  // Nothing about the key goes to the database.
  assert.ok(!JSON.stringify(db.calls).includes("PRIVATE KEY"));
});

test("trust anchor: refuses a half-set, mismatched or non-CA device CA, and the development CA in production",async()=>{
  const a=await makeDeviceCa("production"), b=await makeDeviceCa("production");
  await assert.rejects(loadTrustAnchor(fakeDb(),{NODE_ENV:"production",TRUST_CA_KEY_PEM:a.keyPem}),/must both be set/);
  await assert.rejects(loadTrustAnchor(fakeDb(),{NODE_ENV:"production",TRUST_CA_KEY_PEM:a.keyPem,TRUST_CA_CERT_PEM:b.certificatePem}),/does not belong/);
  await assert.rejects(loadTrustAnchor(fakeDb(),{NODE_ENV:"production"}),/does not run on the development CA/);
  const publicKeyPem=await new VaultKeyProvider({k:a.keyPem}).publicKey("k");
  assert.throws(()=>checkDeviceCa(a.certificatePem,publicKeyPem,new Date(Date.now()+11*365*86_400_000)),/not valid now/);
  const small=generateKeyPairSync("rsa",{modulusLength:2048}).privateKey.export({type:"pkcs8",format:"pem"}).toString();
  assert.throws(()=>new VaultKeyProvider({k:small}),/at least 3072/);
});
