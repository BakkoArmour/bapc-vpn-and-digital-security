SET search_path TO bapc_security_core;

-- security_events is PARTITION BY RANGE(event_timestamp) with no partitions yet.
-- ensure_month_partition(date) creates the monthly partition covering that date
-- if it does not already exist, so writes never hit the parent's missing-partition error.
CREATE OR REPLACE FUNCTION ensure_month_partition(for_date date)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  start_of_month date := date_trunc('month', for_date)::date;
  start_of_next  date := (date_trunc('month', for_date) + interval '1 month')::date;
  partition_name text := format('security_events_%s', to_char(start_of_month,'YYYY_MM'));
BEGIN
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

-- Convenience: make sure the current and next calendar month both exist.
SELECT ensure_month_partition(CURRENT_DATE);
SELECT ensure_month_partition((CURRENT_DATE + interval '1 month')::date);
