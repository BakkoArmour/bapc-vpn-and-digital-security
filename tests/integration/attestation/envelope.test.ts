import test from "node:test";
import assert from "node:assert/strict";
import {parseAttestationEnvelope, attestationSignedPayload, AttestationEnvelopeError} from "../../../src/infrastructure/attestation/envelope.js";

const validEnvelope=()=>({
  provider:"windows-tpm",nonce:"a-fresh-nonce-1",pcrDigest:"a".repeat(64),
  akPublicKeyPem:"-----BEGIN PUBLIC KEY-----\nMIIBIjANBg==\n-----END PUBLIC KEY-----",
  signature:"c29tZS1zaWduYXR1cmU="
});
const bytes=(obj:unknown)=>new TextEncoder().encode(JSON.stringify(obj));

test("parseAttestationEnvelope accepts a well-formed envelope",()=>{
  const envelope=parseAttestationEnvelope(bytes(validEnvelope()));
  assert.equal(envelope.provider,"windows-tpm");
  assert.equal(envelope.pcrDigest,"a".repeat(64));
});

test("parseAttestationEnvelope rejects non-JSON bytes rather than throwing an unrelated parse error",()=>{
  assert.throws(()=>parseAttestationEnvelope(new TextEncoder().encode("not json at all")),AttestationEnvelopeError);
});

test("parseAttestationEnvelope rejects an empty quote (the real gap this control plane still has — see enroll-node.ts)",()=>{
  assert.throws(()=>parseAttestationEnvelope(new Uint8Array(0)),AttestationEnvelopeError);
});

test("parseAttestationEnvelope rejects an unrecognized provider",()=>{
  assert.throws(()=>parseAttestationEnvelope(bytes({...validEnvelope(),provider:"quantum-tpm"})),AttestationEnvelopeError);
});

test("parseAttestationEnvelope rejects a pcrDigest that isn't a 64-character hex string",()=>{
  assert.throws(()=>parseAttestationEnvelope(bytes({...validEnvelope(),pcrDigest:"not-hex"})),AttestationEnvelopeError);
});

test("parseAttestationEnvelope rejects a missing akPublicKeyPem",()=>{
  const {akPublicKeyPem,...rest}=validEnvelope();
  assert.throws(()=>parseAttestationEnvelope(bytes(rest)),AttestationEnvelopeError);
});

test("attestationSignedPayload changes when the identity public key changes, binding the two together",()=>{
  const envelope=validEnvelope();
  const withoutIdentity=attestationSignedPayload("hw-1",envelope);
  const withIdentityA=attestationSignedPayload("hw-1",envelope,"identity-key-a");
  const withIdentityB=attestationSignedPayload("hw-1",envelope,"identity-key-b");
  assert.notEqual(withoutIdentity,withIdentityA);
  assert.notEqual(withIdentityA,withIdentityB);
});

test("attestationSignedPayload is deterministic for the same inputs",()=>{
  const envelope=validEnvelope();
  assert.equal(attestationSignedPayload("hw-1",envelope,"k"),attestationSignedPayload("hw-1",envelope,"k"));
});
