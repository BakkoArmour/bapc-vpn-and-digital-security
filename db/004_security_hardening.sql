SET search_path TO bapc_security_core;

CREATE TABLE IF NOT EXISTS recovery_snapshots(
  snapshot_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope text NOT NULL,
  checksum char(64) NOT NULL,
  document jsonb NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  is_last_known_good boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS one_lkg_per_scope
  ON recovery_snapshots(scope)
  WHERE is_last_known_good=true;

CREATE TABLE IF NOT EXISTS controller_commands(
  command_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id uuid NOT NULL REFERENCES mesh_nodes(node_id) ON DELETE CASCADE,
  command_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  priority integer NOT NULL DEFAULT 100,
  issued_at timestamptz NOT NULL DEFAULT now(),
  not_before timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  acknowledged_at timestamptz,
  result jsonb
);

CREATE INDEX IF NOT EXISTS controller_pending_idx
  ON controller_commands(node_id,priority DESC,issued_at)
  WHERE acknowledged_at IS NULL;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS last_posture_at timestamptz,
  ADD COLUMN IF NOT EXISTS agent_version text,
  ADD COLUMN IF NOT EXISTS quarantine_reason text;

ALTER TABLE relays
  ADD COLUMN IF NOT EXISTS capacity_mbps integer NOT NULL DEFAULT 1000,
  ADD COLUMN IF NOT EXISTS active_sessions integer NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION touch_device_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at=now(); RETURN NEW; END $$;

DROP TRIGGER IF EXISTS devices_touch_updated_at ON devices;
CREATE TRIGGER devices_touch_updated_at BEFORE UPDATE ON devices
FOR EACH ROW EXECUTE FUNCTION touch_device_updated_at();
