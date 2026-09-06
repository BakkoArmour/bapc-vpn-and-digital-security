import type {AttestationVerifier} from "../../ports/infrastructure.js";
import type {AttestationProviderName} from "../../config.js";
import {DevelopmentAttestationProvider, WindowsTpmAttestationProvider, LinuxTpm2AttestationProvider, AppleSecureEnclaveAttestationProvider} from "./providers.js";

// The single place that turns config.attestationProvider into a real
// AttestationVerifier — see providers.ts for what each one actually does.
// loadConfig (src/config.ts) already refuses to produce a "development"
// config when NODE_ENV=production; the check is repeated here too (defense
// in depth, not because it's expected to ever trigger through loadConfig)
// so this factory is never itself the thing standing between a
// misconfiguration and an allow-all verifier reaching production.
export const buildAttestationVerifier=(provider:AttestationProviderName,environment:"development"|"test"|"production"):AttestationVerifier=>{
  if(provider==="development"){
    if(environment==="production"){
      throw new Error("ATTESTATION_PROVIDER=development cannot be used when NODE_ENV=production");
    }
    return new DevelopmentAttestationProvider();
  }
  if(provider==="windows-tpm")return new WindowsTpmAttestationProvider();
  if(provider==="linux-tpm2")return new LinuxTpm2AttestationProvider();
  return new AppleSecureEnclaveAttestationProvider();
};
