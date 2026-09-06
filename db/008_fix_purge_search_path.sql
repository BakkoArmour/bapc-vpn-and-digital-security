SET search_path TO bapc_security_core;

-- Fixes a real bug in 006_retention.sql's purge_expired_control_plane_rows():
-- its three DELETEs used unqualified table names, relying on the migration
-- session's `SET search_path` — which is a SESSION setting, not part of the
-- function definition. Any *later* caller (a pooled connection from the app,
-- exactly how RetentionService actually invokes this) has its own default
-- search_path and the function failed with "relation ... does not exist".
-- Caught only by running this against a real Postgres — the unit tests
-- against a fake PgQueryable could only ever check the SQL text sent, not
-- whether Postgres could actually resolve the names in it.
--
-- Fixed by schema-qualifying every table reference, matching the pattern
-- ensure_month_partition/drop_expired_event_partitions already used
-- correctly. (CREATE FUNCTION ... SET search_path = ... at the function
-- level would also fix it, but explicit qualification matches this
-- repository's existing style and needs no cross-referencing to see what
-- schema a call resolves against.)
CREATE OR REPLACE FUNCTION purge_expired_control_plane_rows()
RETURNS TABLE(idempotency_deleted bigint, nonces_deleted bigint, outbox_deleted bigint)
LANGUAGE plpgsql AS $$
DECLARE
  i bigint; n bigint; o bigint;
BEGIN
  DELETE FROM bapc_security_core.api_idempotency WHERE expires_at < now();
  GET DIAGNOSTICS i = ROW_COUNT;
  DELETE FROM bapc_security_core.replay_nonces WHERE expires_at < now();
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM bapc_security_core.event_outbox WHERE published_at IS NOT NULL AND published_at < now() - interval '7 days';
  GET DIAGNOSTICS o = ROW_COUNT;
  RETURN QUERY SELECT i, n, o;
END $$;
