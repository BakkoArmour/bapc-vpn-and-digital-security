SET search_path TO bapc_security_core;

-- audit_chain.previous_hash was char(64) — a FIXED-length type that
-- right-pads any shorter value with spaces on storage. Every real hash
-- value is always exactly 64 hex characters (unaffected), but the genesis
-- sentinel AuditService uses for a chain's first entry ("GENESIS", 7
-- characters — see src/application/audit.ts) came back from a SELECT as
-- "GENESIS" plus 57 trailing spaces: silently different from the literal
-- "GENESIS" both record() and verify() compare against in memory. Every
-- chain's first entry therefore failed verify() even with zero tampering,
-- the moment anything actually read the chain back from Postgres —
-- previously nothing did (AuditService had no caller anywhere until it was
-- wired into production-server.ts). varchar(64) never pads, so this both
-- fixes future writes and repairs any row already corrupted by the old
-- column type.
ALTER TABLE audit_chain ALTER COLUMN previous_hash TYPE varchar(64);
UPDATE audit_chain SET previous_hash=rtrim(previous_hash) WHERE previous_hash<>rtrim(previous_hash);
