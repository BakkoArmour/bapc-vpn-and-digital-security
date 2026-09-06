SET search_path TO bapc_security_core;

-- Drops security_events partitions entirely older than retention_months.
-- Returns the names of partitions actually dropped.
CREATE OR REPLACE FUNCTION drop_expired_event_partitions(retention_months integer)
RETURNS SETOF text LANGUAGE plpgsql AS $$
DECLARE
  cutoff date := (date_trunc('month', now()) - make_interval(months => retention_months))::date;
  rec record;
BEGIN
  FOR rec IN
    SELECT c.relname AS partition_name,
      to_date(substring(c.relname FROM 'security_events_(\d{4}_\d{2})$'),'YYYY_MM') AS partition_month
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='bapc_security_core' AND c.relname LIKE 'security_events_%'
  LOOP
    IF rec.partition_month < cutoff THEN
      EXECUTE format('DROP TABLE IF EXISTS bapc_security_core.%I', rec.partition_name);
      RETURN NEXT rec.partition_name;
    END IF;
  END LOOP;
END $$;

-- Purges expired idempotency keys, replay nonces and published outbox rows.
CREATE OR REPLACE FUNCTION purge_expired_control_plane_rows()
RETURNS TABLE(idempotency_deleted bigint, nonces_deleted bigint, outbox_deleted bigint)
LANGUAGE plpgsql AS $$
DECLARE
  i bigint; n bigint; o bigint;
BEGIN
  DELETE FROM api_idempotency WHERE expires_at < now();
  GET DIAGNOSTICS i = ROW_COUNT;
  DELETE FROM replay_nonces WHERE expires_at < now();
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM event_outbox WHERE published_at IS NOT NULL AND published_at < now() - interval '7 days';
  GET DIAGNOSTICS o = ROW_COUNT;
  RETURN QUERY SELECT i, n, o;
END $$;
