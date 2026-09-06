SET search_path TO bapc_security_core;

-- RECONCILE (agents/shared/production-agent.ts, src/agent/reconciler.ts) had
-- a fully built consumer with no producer anywhere: nothing on the control
-- plane ever tracked what a node's routes/DNS/kill-switch/integrity files
-- SHOULD be, so nothing ever compared that against what a node last reported
-- applying and nothing ever issued a corrective RECONCILE command. This is
-- that missing desired-state record — one row per node, the control plane's
-- source of truth for "what this node should look like right now".
CREATE TABLE node_desired_state(
  node_id uuid PRIMARY KEY REFERENCES mesh_nodes(node_id) ON DELETE CASCADE,
  revision integer NOT NULL DEFAULT 1,
  routes jsonb NOT NULL DEFAULT '[]',
  dns_servers jsonb NOT NULL DEFAULT '[]',
  kill_switch_enabled boolean NOT NULL DEFAULT false,
  integrity_files jsonb NOT NULL DEFAULT '{}',
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
