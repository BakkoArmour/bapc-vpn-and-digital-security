SET search_path TO bapc_security_core;

-- Holds the ONE ephemeral development CA key+cert shared across every
-- process in this deployment (control-api, mesh-grpc, ...) when no AWS KMS
-- key is configured (see services/trust-core/trust-anchor.ts). Without this,
-- each process would mint its own self-signed dev CA independently, and
-- certificates issued by mesh-grpc's enrollment path would not chain-verify
-- against the CRL control-api signs, or against each other.
--
-- DEV-ONLY: a real deployment sets AWS_KMS_INTERMEDIATE_KEY_ID and never
-- populates this table — the private key column only ever holds a
-- throwaway, in-memory-generated RSA key, the same trust boundary as
-- DevKeyProvider itself (see runbooks/root-ca-ceremony.md for the real
-- production ceremony).
CREATE TABLE dev_trust_anchor (
  key_reference    text PRIMARY KEY,
  subject_cn       text NOT NULL,
  certificate_pem  text NOT NULL,
  private_key_pem  text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);
