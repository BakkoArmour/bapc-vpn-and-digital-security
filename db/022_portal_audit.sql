SET search_path TO bapc_security_core;

-- Who did what, when, in the customer portal (sign-in, devices, data export,
-- account deletion, payment pauses). Append-only from the app's side. Kept
-- apart from audit_chain (the control plane's hash-chained operator log): two
-- processes appending to one chain at once could fork it.
-- On account deletion the account's rows are pseudonymised (account_id
-- replaced by a hash, detail and ip cleared); the fact that actions happened
-- stays for security review.
CREATE TABLE portal_audit(
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  account_id text NOT NULL,
  actor text NOT NULL CHECK (actor IN ('customer','system')),
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip text
);
CREATE INDEX portal_audit_account_idx ON portal_audit(account_id, at DESC);
