SET search_path TO bapc_security_core;

-- relays.active_sessions/capacity_mbps already exist
-- (db/004_security_hardening.sql, added for the now-deleted RelayRegistry)
-- but were never actually updated by any code — relay-server.ts hardcoded
-- loadPercent:0/latencyMs:0 and touched neither column. Only throughput is
-- genuinely new here; capacity utilization is computed at read time from
-- the existing active_sessions/capacity_mbps pair (see PgRelayStore),
-- matching the *20 sessions-per-Mbps convention RelayRegistry used to.
ALTER TABLE relays ADD COLUMN throughput_bytes_per_sec bigint NOT NULL DEFAULT 0;

-- egress_gateways (db/014_egress_gateways.sql, new this session) had no
-- latency, session-count, or capacity concept at all. max_sessions is a
-- real configured ceiling (reported by the gateway itself at registration
-- — see EGRESS_MAX_SESSIONS in src/runtime/egress-server.ts) rather than a
-- fixed guess, so capacity utilization reflects what that gateway process
-- actually believes its own limit is.
ALTER TABLE egress_gateways ADD COLUMN latency_ms integer NOT NULL DEFAULT 0;
ALTER TABLE egress_gateways ADD COLUMN active_sessions integer NOT NULL DEFAULT 0;
ALTER TABLE egress_gateways ADD COLUMN max_sessions integer NOT NULL DEFAULT 500;
