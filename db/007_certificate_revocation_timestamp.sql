SET search_path TO bapc_security_core;

ALTER TABLE certificates
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

CREATE INDEX IF NOT EXISTS certificates_revoked_idx
  ON certificates(revoked_at)
  WHERE is_revoked=true;
