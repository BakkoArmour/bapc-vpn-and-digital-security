SET search_path TO bapc_security_core;

-- RelayRoutingService.select already distinguished LOCAL_RELAY from
-- REGIONAL_RELAY (relays already carry a region column, db/002) — the
-- collapse was upstream of it: MeshController.selectRelayEndpoint had no
-- geography for the requesting NODE to compare a relay's region against, so
-- it always passed every healthy relay in as "regional" and never had a
-- real candidate for the LOCAL_RELAY tier. This is that missing half,
-- deliberately separate from zone_assignment (a security classification,
-- not a geography — see MeshController's own comment on that distinction).
-- 'unassigned' (not NULL) means exactly what it says: no operator has set
-- this node's region yet, so routing correctly treats every relay as
-- regional-at-best rather than guessing at a false "local" match.
ALTER TABLE mesh_nodes ADD COLUMN region text NOT NULL DEFAULT 'unassigned';
