SET search_path TO bapc_security_core;

-- SafeApplyService's "did this actually work" check was ONLY the control
-- plane's own database health (PgControlPlaneProbe) — a staged policy could
-- be reported COMMITTED even if every single targeted node failed to apply
-- it or never even received it, as long as Postgres itself stayed up. This
-- is the per-node record that closes that gap: one row per node targeted by
-- a policy rollout, tracking whether it actually succeeded, failed, timed
-- out, or was rolled back.
CREATE TABLE policy_rollout_nodes(
  commit_id uuid NOT NULL REFERENCES policy_commits(commit_id) ON DELETE CASCADE,
  node_id uuid NOT NULL REFERENCES mesh_nodes(node_id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','SUCCEEDED','FAILED','TIMED_OUT','ROLLED_BACK')),
  acknowledged_at timestamptz,
  details jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY(commit_id,node_id)
);
