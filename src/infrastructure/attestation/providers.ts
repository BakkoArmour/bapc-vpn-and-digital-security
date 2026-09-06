import {createVerify, createPublicKey} from "node:crypto";
import type {AttestationVerifier} from "../../ports/infrastructure.js";
import {parseAttestationEnvelope, attestationSignedPayload, AttestationEnvelopeError, type AttestationProviderName} from "./envelope.js";

// Explicit, unmissable dev/mock provider — replaces AllowAttestation, which
// verified nothing and returned true unconditionally with no gate at all
// preventing it from also being the thing production used. This class still
// verifies nothing (by design — it's the mock), but AttestationVerifierFactory
// (attestation-verifier.ts) refuses to construct one when environment is
// "production", so the allow-all path can no longer reach production silently.
export class DevelopmentAttestationProvider implements AttestationVerifier {
  async verify(_hardwareId?:string,_quote?:Uint8Array,_identityPublicKeyPem?:string):Promise<boolean>{return true;}
}

// Shared by the two real providers below: parses the envelope, confirms it
// declares itself as the expected provider (a Linux node's evidence must
// never be accepted as Windows TPM evidence or vice versa), confirms the
// attestation key is the algorithm family that provider's real hardware
// actually produces, and verifies a real cryptographic signature over
// attestationSignedPayload. What this does NOT do — and cannot honestly do
// without real devices to test against — is validate the attestation key's
// Endorsement Key certificate chain up to a TPM manufacturer root, or
// compare pcrDigest against a known-good measured-boot baseline specific to
// each real machine's firmware/bootloader/OS build. Both are genuine
// external-hardware/vendor-material requirements, not implementation
// shortcuts; see this repo's four-list report for where they're tracked.
abstract class RealHardwareAttestationProvider implements AttestationVerifier {
  protected abstract readonly provider:AttestationProviderName;
  protected abstract readonly expectedKeyType:"rsa"|"ec";

  async verify(hardwareId:string,quote:Uint8Array,identityPublicKeyPem?:string):Promise<boolean>{
    let envelope;
    try{envelope=parseAttestationEnvelope(quote);}
    catch(error){
      if(error instanceof AttestationEnvelopeError)return false;
      throw error;
    }
    if(envelope.provider!==this.provider)return false;

    let keyType:string;
    try{keyType=createPublicKey(envelope.akPublicKeyPem).asymmetricKeyType??"";}
    catch{return false;}
    if(keyType!==this.expectedKeyType)return false;

    try{
      const payload=attestationSignedPayload(hardwareId,envelope,identityPublicKeyPem);
      return createVerify("SHA256").update(payload).verify(envelope.akPublicKeyPem,envelope.signature,"base64");
    }catch{
      // A malformed signature/key combination throws inside node:crypto
      // rather than returning false — attestation failure, not a crash.
      return false;
    }
  }
}

// Windows TPM 2.0 attestation keys (AIKs created via NCryptCreatePersistedKey/
// the TBS APIs) are conventionally RSA-2048 — enforced here as a real check,
// not a formality: it stops a key of the wrong family from ever reaching
// signature verification at all, regardless of what the envelope claims its
// provider is.
export class WindowsTpmAttestationProvider extends RealHardwareAttestationProvider {
  protected readonly provider="windows-tpm" as const;
  protected readonly expectedKeyType="rsa" as const;
}

// Linux tpm2-tools' tpm2_createak defaults to an ECC P-256 attestation key
// (RSA is also possible but ECC is the common default this provider targets).
export class LinuxTpm2AttestationProvider extends RealHardwareAttestationProvider {
  protected readonly provider="linux-tpm2" as const;
  protected readonly expectedKeyType="ec" as const;
}

const NOT_IMPLEMENTED=
  "Apple Secure Enclave attestation (DeviceCheck/App Attest) requires a "+
  "native Swift component running under an Apple Developer Program "+
  "entitlement to produce and this control plane to verify against Apple's "+
  "own attestation service — this cannot be implemented or tested without "+
  "that, and there is no Apple client in this repository yet (see "+
  "native/apple/adapter.ts's own NOT_IMPLEMENTED for the matching gap on "+
  "the network-control side). This class exists so a future Apple client "+
  "has a real AttestationVerifier contract to implement against, the same "+
  "role ApplePlatformAdapter plays for PlatformAdapter.";

// Throws on every call by design — see NOT_IMPLEMENTED above. Never stub
// this to return true: an unimplemented verifier that silently allowed
// enrollment would be worse than one that refuses outright.
export class AppleSecureEnclaveAttestationProvider implements AttestationVerifier {
  async verify(_hardwareId?:string,_quote?:Uint8Array,_identityPublicKeyPem?:string):Promise<boolean>{throw new Error(NOT_IMPLEMENTED);}
}
