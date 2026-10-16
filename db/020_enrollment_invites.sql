SET search_path TO bapc_security_core;

-- One-time device invites for the public HTTPS join route (POST
-- /api/v1/devices/join, see src/application/device-join.ts). The plaintext
-- code is shown to the owner exactly once when minted and never stored —
-- only its SHA-256, so a database read alone can't be turned into a working
-- invite. A row is single-use: claim() sets used_at atomically, and
-- used_by_node records which enrollment consumed it.
CREATE TABLE enrollment_invites(
  invite_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text UNIQUE NOT NULL,
  label text NOT NULL DEFAULT '',
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  used_by_node uuid REFERENCES mesh_nodes(node_id) ON DELETE SET NULL
);
CREATE INDEX enrollment_invites_open_idx ON enrollment_invites(expires_at) WHERE used_at IS NULL;
