SET search_path TO bapc_security_core;

-- Closes a gap docs/INCIDENT-RESPONSE-RUNBOOK.md called out explicitly:
-- ZONE_FORENSIC_ISOLATION (src/domain/types.ts) is a defined zone with no
-- concrete access policy backing it, so PolicyDecisionService's default-deny
-- meant nobody — not even an approved investigator — could actually reach a
-- quarantined node's forensic data through POST /api/v1/access/decide.
--
-- This default policy allows a security-approver identity, connecting from
-- an admin-management-zone node, to reach ZONE_FORENSIC_ISOLATION resources
-- on any protocol/port — but only with an active, matching JIT grant
-- (requires_jit), so access is still time-boxed and justified per incident
-- rather than a standing exception. Tighten destination_ports/protocols in
-- your own policy library if your diagnostics tooling uses a fixed port.
INSERT INTO network_policies (policy_id, name, document, version, priority, is_active)
VALUES (
  gen_random_uuid(),
  'default-forensic-isolation-diagnostics-access',
  jsonb_build_object(
    'name', 'default-forensic-isolation-diagnostics-access',
    'sourceZones', jsonb_build_array('ZONE_ADMIN_MGMT'),
    'destinationZones', jsonb_build_array('ZONE_FORENSIC_ISOLATION'),
    'protocols', jsonb_build_array('ANY'),
    'destinationPorts', jsonb_build_array(),
    'action', 'ALLOW',
    'requiredRoles', jsonb_build_array('security-approver'),
    'requiresJit', true,
    'priority', 100,
    'version', 1,
    'active', true
  ),
  1,
  100,
  true
)
ON CONFLICT (name) DO NOTHING;
