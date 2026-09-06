SET search_path TO bapc_security_core;

CREATE TABLE IF NOT EXISTS event_outbox(
  outbox_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  topic text NOT NULL,
  event_key text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  last_error text
);

CREATE INDEX IF NOT EXISTS outbox_unpublished_idx
  ON event_outbox(created_at)
  WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS api_idempotency(
  idempotency_key text PRIMARY KEY,
  actor text NOT NULL,
  request_hash char(64) NOT NULL,
  response_status integer NOT NULL,
  response_body jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS api_idempotency_expiry_idx
  ON api_idempotency(expires_at);

CREATE TABLE IF NOT EXISTS replay_nonces(
  nonce text PRIMARY KEY,
  actor text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS replay_nonce_expiry_idx ON replay_nonces(expires_at);
