import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync, createSign} from "node:crypto";
import {
  DevelopmentAttestationProvider, WindowsTpmAttestationProvider,
  LinuxTpm2AttestationProvider, AppleSecureEnclaveAttestationProvider
} from "../../../src/infrastructure/attestation/providers.js";
import {attestationSignedPayload} from "../../../src/infrastructure/attestation/envelope.js";

// These build a REAL attestation key pair and a REAL signature over the
// exact payload the provider verifies — the whole point is proving the
// cryptographic verification path genuinely works (and genuinely rejects
// tampering), not just that a mock returns true. What's still missing
// without live hardware — the Endorsement Key certificate chain up to a
// TPM manufacturer root, and comparing pcrDigest against a real measured-
// boot baseline — is documented on RealHardwareAttestationProvider itself.

const rsaKeyPair=()=>generateKeyPairSync("rsa",{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});
const ecKeyPair=()=>generateKeyPairSync("ec",{namedCurve:"prime256v1",publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});

const signedEnvelope=(
  provider:"windows-tpm"|"linux-tpm2",keys:{publicKey:string;privateKey:string},
  overrides:{hardwareId?:string;identityPublicKeyPem?:string;pcrDigest?:string;nonce?:string}={}
)=>{
  const envelope={
    provider,nonce:overrides.nonce??"fresh-nonce-value",
    pcrDigest:overrides.pcrDigest??"b".repeat(64),
    akPublicKeyPem:keys.publicKey
  };
  const payload=attestationSignedPayload(overrides.hardwareId??"hw-1",envelope,overrides.identityPublicKeyPem);
  const signature=createSign("SHA256").update(payload).sign(keys.privateKey,"base64");
  return {...envelope,signature};
};
const bytes=(obj:unknown)=>new TextEncoder().encode(JSON.stringify(obj));

test("DevelopmentAttestationProvider allows everything (mock, never used in production — see attestation-verifier.ts)",async()=>{
  const provider=new DevelopmentAttestationProvider();
  assert.equal(await provider.verify("anything",new Uint8Array(0)),true);
});

test("AppleSecureEnclaveAttestationProvider throws rather than silently allowing enrollment",async()=>{
  const provider=new AppleSecureEnclaveAttestationProvider();
  await assert.rejects(()=>provider.verify("hw-1",new Uint8Array(0)),/Apple Secure Enclave/);
});

test("WindowsTpmAttestationProvider accepts a genuinely valid RSA-signed envelope",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("windows-tpm",keys,{hardwareId:"hw-1"});
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",bytes(envelope)),true);
});

test("WindowsTpmAttestationProvider rejects when the identity public key doesn't match what was signed",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("windows-tpm",keys,{hardwareId:"hw-1",identityPublicKeyPem:"identity-A"});
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",bytes(envelope),"identity-B"),false);
  assert.equal(await provider.verify("hw-1",bytes(envelope),"identity-A"),true);
});

test("WindowsTpmAttestationProvider rejects a tampered pcrDigest even with a structurally valid signature field",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("windows-tpm",keys,{hardwareId:"hw-1"});
  const tampered={...envelope,pcrDigest:"c".repeat(64)};
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",bytes(tampered)),false);
});

test("WindowsTpmAttestationProvider rejects a quote whose hardwareId doesn't match the one being enrolled",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("windows-tpm",keys,{hardwareId:"hw-1"});
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-DIFFERENT",bytes(envelope)),false);
});

test("WindowsTpmAttestationProvider rejects an envelope that declares a different provider",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("linux-tpm2",{publicKey:rsaKeyPair().publicKey,privateKey:keys.privateKey},{hardwareId:"hw-1"});
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",bytes(envelope)),false);
});

// Windows TPM AIKs are RSA; an EC key masquerading as one must be rejected
// before signature verification is even attempted, regardless of what the
// envelope's provider field says.
test("WindowsTpmAttestationProvider rejects an EC key (wrong key family for this provider)",async()=>{
  const keys=ecKeyPair();
  const envelope=signedEnvelope("windows-tpm",keys,{hardwareId:"hw-1"});
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",bytes(envelope)),false);
});

test("LinuxTpm2AttestationProvider accepts a genuinely valid EC-signed envelope",async()=>{
  const keys=ecKeyPair();
  const envelope=signedEnvelope("linux-tpm2",keys,{hardwareId:"hw-2"});
  const provider=new LinuxTpm2AttestationProvider();
  assert.equal(await provider.verify("hw-2",bytes(envelope)),true);
});

test("LinuxTpm2AttestationProvider rejects an RSA key (wrong key family for this provider)",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("linux-tpm2",keys,{hardwareId:"hw-2"});
  const provider=new LinuxTpm2AttestationProvider();
  assert.equal(await provider.verify("hw-2",bytes(envelope)),false);
});

test("a real provider fails closed (returns false, never throws) on a malformed quote",async()=>{
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",new TextEncoder().encode("garbage")),false);
});

test("a real provider fails closed on a signature that is well-formed base64 but simply wrong",async()=>{
  const keys=rsaKeyPair();
  const envelope=signedEnvelope("windows-tpm",keys,{hardwareId:"hw-1"});
  const otherKeys=rsaKeyPair();
  const wrongSignature=createSign("SHA256").update("something else entirely").sign(otherKeys.privateKey,"base64");
  const provider=new WindowsTpmAttestationProvider();
  assert.equal(await provider.verify("hw-1",bytes({...envelope,signature:wrongSignature})),false);
});
