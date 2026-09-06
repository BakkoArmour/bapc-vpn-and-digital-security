import test from "node:test";
import assert from "node:assert/strict";
import {buildAttestationVerifier} from "../../../src/infrastructure/attestation/attestation-verifier.js";
import {
  DevelopmentAttestationProvider, WindowsTpmAttestationProvider,
  LinuxTpm2AttestationProvider, AppleSecureEnclaveAttestationProvider
} from "../../../src/infrastructure/attestation/providers.js";

// loadConfig (src/config.ts) already refuses a "development" config in
// production — this is the defense-in-depth repeat inside the factory
// itself, plus proof each provider name actually resolves to the right
// class.

test("buildAttestationVerifier returns DevelopmentAttestationProvider outside production",()=>{
  assert.ok(buildAttestationVerifier("development","development") instanceof DevelopmentAttestationProvider);
  assert.ok(buildAttestationVerifier("development","test") instanceof DevelopmentAttestationProvider);
});

test("buildAttestationVerifier refuses to build a development provider in production",()=>{
  assert.throws(()=>buildAttestationVerifier("development","production"),/cannot be used when NODE_ENV=production/);
});

test("buildAttestationVerifier resolves each real provider name to its real class, in any environment",()=>{
  assert.ok(buildAttestationVerifier("windows-tpm","production") instanceof WindowsTpmAttestationProvider);
  assert.ok(buildAttestationVerifier("linux-tpm2","production") instanceof LinuxTpm2AttestationProvider);
  assert.ok(buildAttestationVerifier("apple-secure-enclave","production") instanceof AppleSecureEnclaveAttestationProvider);
  assert.ok(buildAttestationVerifier("windows-tpm","development") instanceof WindowsTpmAttestationProvider);
});
