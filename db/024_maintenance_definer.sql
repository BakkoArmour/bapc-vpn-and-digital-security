SET search_path TO bapc_security_core;

-- Least privilege for the running services. On BAPC Cheisgos the services sign in as a runtime role that may read
-- and write rows but not create or drop tables; only the migrations run as the schema owner. The maintenance
-- worker still has to create next month's event partition and drop expired ones, so these three functions run
-- with their owner's rights (SECURITY DEFINER) and a fixed search_path (so a caller cannot redirect what they
-- touch), and only roles that were granted EXECUTE may call them (the migrate step grants the runtime role).
-- Where the services sign in as the owner itself (the Docker deployment), nothing changes.
ALTER FUNCTION ensure_month_partition(date) SECURITY DEFINER SET search_path = bapc_security_core, pg_temp;
ALTER FUNCTION drop_expired_event_partitions(integer) SECURITY DEFINER SET search_path = bapc_security_core, pg_temp;
ALTER FUNCTION purge_expired_control_plane_rows() SECURITY DEFINER SET search_path = bapc_security_core, pg_temp;

REVOKE ALL ON FUNCTION ensure_month_partition(date) FROM PUBLIC;
REVOKE ALL ON FUNCTION drop_expired_event_partitions(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION purge_expired_control_plane_rows() FROM PUBLIC;
