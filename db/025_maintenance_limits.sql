SET search_path TO bapc_security_core;

-- Limits on the two maintenance functions that run with the owner's rights (024). A caller can no longer drop the
-- current month's events (retention below 3 months) or create partitions far in the past or future (catalogue
-- bloat). The maintenance worker asks for the current and next month and keeps 13 months, well inside these limits.
CREATE OR REPLACE FUNCTION ensure_month_partition(for_date date)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = bapc_security_core, pg_temp AS $$
DECLARE
  start_of_month date := date_trunc('month', for_date)::date;
  start_of_next  date := (date_trunc('month', for_date) + interval '1 month')::date;
  partition_name text := format('security_events_%s', to_char(start_of_month,'YYYY_MM'));
BEGIN
  IF for_date IS NULL
     OR start_of_month < (date_trunc('month', now()) - interval '1 month')::date
     OR start_of_month > (date_trunc('month', now()) + interval '2 months')::date THEN
    RAISE EXCEPTION 'ensure_month_partition: % is outside last month to two months ahead', for_date;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='bapc_security_core' AND c.relname=partition_name
  ) THEN
    EXECUTE format(
      'CREATE TABLE bapc_security_core.%I PARTITION OF bapc_security_core.security_events
         FOR VALUES FROM (%L) TO (%L)',
      partition_name, start_of_month, start_of_next
    );
  END IF;
  RETURN partition_name;
END $$;

CREATE OR REPLACE FUNCTION drop_expired_event_partitions(retention_months integer)
RETURNS SETOF text LANGUAGE plpgsql SECURITY DEFINER SET search_path = bapc_security_core, pg_temp AS $$
DECLARE
  cutoff date;
  rec record;
BEGIN
  IF retention_months IS NULL OR retention_months < 3 OR retention_months > 120 THEN
    RAISE EXCEPTION 'drop_expired_event_partitions: retention of % months is outside 3 to 120', retention_months;
  END IF;
  cutoff := (date_trunc('month', now()) - make_interval(months => retention_months))::date;
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

REVOKE ALL ON FUNCTION ensure_month_partition(date) FROM PUBLIC;
REVOKE ALL ON FUNCTION drop_expired_event_partitions(integer) FROM PUBLIC;
