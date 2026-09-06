SET search_path TO bapc_security_core;

-- ThreatCorrelator (services/threat-engine/correlator.ts) existed fully built
-- and tested, sliding-window-correlating repeated weak signals into an
-- escalating evaluation — but the window itself lived in a plain in-memory
-- Map, so a control-plane restart silently erased every un-escalated
-- signal a node had accumulated so far. An attacker (or a flaky process)
-- that timed activity around a routine deploy/restart would reset the
-- correlation window for free. This is the durable equivalent — one row per
-- signal, pruned to the correlation window on read.
CREATE TABLE threat_signal_window(
  signal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- A node's own id, or the literal string '__unattributed__' for signals
  -- with no node (ThreatCorrelator.ingest's existing convention) — kept as
  -- text rather than a nullable uuid FK so that convention doesn't need a
  -- schema-level special case.
  node_key text NOT NULL,
  kind text NOT NULL,
  confidence numeric(4,3) NOT NULL,
  weight numeric(10,2) NOT NULL,
  occurred_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX threat_signal_window_node_idx ON threat_signal_window(node_key,occurred_at);
