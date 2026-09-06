import {canonicalJson} from "../canonical-json.js";

export type AttestationProviderName="windows-tpm"|"linux-tpm2"|"apple-secure-enclave";

// The wire format a node's hardware_attestation_quote bytes (mesh.proto)
// must decode to for any REAL (non-development) provider. Not a raw TPM2
// TPMS_ATTEST/TPMT_SIGNATURE structure — marshaling and verifying that
// exact binary format (plus its Endorsement Key certificate chain up to a
// TPM manufacturer root, which this environment has no real device
// certificates to validate against) is genuinely hardware/vendor-dependent
// work; see docs on WindowsTpmAttestationProvider/LinuxTpm2AttestationProvider
// for exactly what's real here versus what a live device still needs. This
// envelope is what the control plane can fully and honestly verify without
// live hardware: a real cryptographic signature, by a real attestation key,
// over a real measured-state digest and a caller-supplied nonce.
export interface AttestationEnvelope {
  provider:AttestationProviderName;
  // Caller-supplied entropy bound into the signature — without a
  // server-issued challenge round trip (mesh.proto's RegisterNode is a
  // single call, not challenge/response), this doesn't prevent replay of a
  // captured quote on its own; it exists so the signed payload is never
  // just a static, endlessly-reusable blob. Real replay protection would
  // need a challenge RPC added to the enrollment contract — a real gap,
  // listed as such rather than silently worked around.
  nonce:string;
  // Hex SHA-256 digest of whatever measured-boot/PCR state the platform's
  // real quote actually attests to. This control plane has no known-good
  // baseline to compare it against (that baseline is specific to each real
  // device's firmware/bootloader/OS build) — it is verified for
  // well-formedness and included in the signed payload, but not compared
  // against an expected value. See the providers' own comments.
  pcrDigest:string;
  akPublicKeyPem:string;
  // Base64 signature over signedPayload(hardwareId, {nonce, pcrDigest}).
  signature:string;
}

const HEX64=/^[0-9a-f]{64}$/i;

export class AttestationEnvelopeError extends Error {}

export const parseAttestationEnvelope=(quote:Uint8Array):AttestationEnvelope=>{
  let parsed:unknown;
  try{parsed=JSON.parse(Buffer.from(quote).toString("utf8"));}
  catch{throw new AttestationEnvelopeError("attestation quote is not a valid attestation envelope (not JSON)");}
  if(typeof parsed!=="object"||parsed===null)
    throw new AttestationEnvelopeError("attestation envelope must be a JSON object");
  const e=parsed as Record<string,unknown>;
  if(typeof e.provider!=="string"||!["windows-tpm","linux-tpm2","apple-secure-enclave"].includes(e.provider))
    throw new AttestationEnvelopeError("attestation envelope has an unrecognized provider");
  if(typeof e.nonce!=="string"||e.nonce.length<8)
    throw new AttestationEnvelopeError("attestation envelope nonce must be a string of at least 8 characters");
  if(typeof e.pcrDigest!=="string"||!HEX64.test(e.pcrDigest))
    throw new AttestationEnvelopeError("attestation envelope pcrDigest must be a 64-character hex SHA-256 digest");
  if(typeof e.akPublicKeyPem!=="string"||!e.akPublicKeyPem.includes("BEGIN PUBLIC KEY"))
    throw new AttestationEnvelopeError("attestation envelope akPublicKeyPem must be a PEM-encoded public key");
  if(typeof e.signature!=="string"||e.signature.length===0)
    throw new AttestationEnvelopeError("attestation envelope signature is required");
  return e as unknown as AttestationEnvelope;
};

// The exact bytes every real provider verifies a signature over — shared so
// a provider's verify() and whatever produces a genuine quote in a test
// fixture (or, eventually, a real device) can never drift out of sync with
// each other, the same reasoning as controller.ts's applyPeersPayload.
//
// identityPublicKeyPem (EnrollmentService's attestationPublicKey — the
// CSR-verified X.509 identity key, a different key entirely from the
// attestation key that signs this envelope) is folded in when present so a
// captured, otherwise-valid quote can't be paired with a different
// enrollment's identity key: the attestation key is cryptographically
// vouching for THIS specific identity key, not just "some enrollment,
// at some point".
export const attestationSignedPayload=(
  hardwareId:string,envelope:Pick<AttestationEnvelope,"nonce"|"pcrDigest">,identityPublicKeyPem?:string
):string=>
  canonicalJson({hardwareId,nonce:envelope.nonce,pcrDigest:envelope.pcrDigest,identityPublicKeyPem:identityPublicKeyPem??null});
