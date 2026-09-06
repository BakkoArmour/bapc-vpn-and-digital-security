SET search_path TO bapc_security_core;

-- Audit trail for WireGuard key rotation (gRPC RotatePeerKey). Previously
-- rotation used InMemoryKeyRotationLedger even in the real running
-- mesh-grpc process: it accepted any non-empty signature (no cryptographic
-- verification against the node's actual identity) and its epoch counter
-- lived only in process memory, resetting to 0 on every restart with no
-- record of which node rotated to which key or when. PgKeyRotationLedger
-- replaces it with a real, persisted, monotonic-per-node epoch.
CREATE TABLE key_rotations (
  node_id        uuid NOT NULL REFERENCES mesh_nodes(node_id) ON DELETE CASCADE,
  epoch          integer NOT NULL,
  new_public_key varchar(64) NOT NULL,
  rotated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, epoch)
);
