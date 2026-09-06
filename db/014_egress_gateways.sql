SET search_path TO bapc_security_core;

-- EgressSelector (src/application/egress-routing... actually
-- services/egress/selector.ts) existed fully built and tested with no
-- registry to select from at all — unlike relays (the `relays` table),
-- egress gateways had no persistence anywhere, so the selector had zero
-- real candidates and no caller. Modeled on `relays`: gateway id, endpoint
-- (fixed_ip — matches EgressSelector's EgressGateway.fixedIp field),
-- region, health, load, a lifecycle state, and last heartbeat.
CREATE TABLE egress_gateways(
  gateway_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  region text NOT NULL,
  fixed_ip text NOT NULL,
  is_healthy boolean NOT NULL DEFAULT true,
  load_percent numeric(5,2) NOT NULL DEFAULT 0,
  state text NOT NULL DEFAULT 'ACTIVE',
  last_heartbeat timestamptz
);
