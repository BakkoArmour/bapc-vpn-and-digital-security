SET search_path TO bapc_security_core;

-- Paying customers (the customer portal, src/runtime/customer-portal.ts).
-- An "account" is the person's bapc.app user id; payment state lives in BAPC
-- Billing and is checked live, never copied here except as the suspended
-- flag below.

-- Sign in with BAPC (bapc.app OAuth + PKCE): one row per started sign-in,
-- deleted on first use.
CREATE TABLE portal_sign_in_requests(
  state text PRIMARY KEY,
  verifier text NOT NULL,
  next_path text NOT NULL DEFAULT '/account',
  expires_at timestamptz NOT NULL
);

-- Signed-in browser sessions. Only the SHA-256 of the cookie token is kept.
CREATE TABLE portal_sessions(
  token_hash text PRIMARY KEY,
  account_id text NOT NULL,
  email text NOT NULL,
  name text,
  csrf_token text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX portal_sessions_expiry_idx ON portal_sessions(expires_at);

-- Which customer owns which VPN device. A device with no row here (e.g. the
-- owner's own, joined with an owner-minted invite) is never suspended for
-- billing reasons. suspended=true removes it from the gateway until the
-- account pays again; removed_at is the customer deleting it for good (the
-- underlying device is also revoked).
CREATE TABLE customer_devices(
  node_id uuid PRIMARY KEY REFERENCES mesh_nodes(node_id) ON DELETE CASCADE,
  account_id text NOT NULL,
  email text NOT NULL,
  name text NOT NULL,
  kind text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  suspended boolean NOT NULL DEFAULT false,
  removed_at timestamptz
);
CREATE INDEX customer_devices_account_idx ON customer_devices(account_id) WHERE removed_at IS NULL;

-- An invite minted from the portal belongs to the customer who minted it, so
-- the Windows PC that redeems it lands in their device list.
ALTER TABLE enrollment_invites
  ADD COLUMN account_id text,
  ADD COLUMN account_email text,
  ADD COLUMN device_name text;
