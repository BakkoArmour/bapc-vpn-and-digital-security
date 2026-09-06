export type UUID = string;
export type Platform = "linux" | "windows" | "macos" | "ios" | "ipados" | "container";
export type SecurityZone = "ZONE_PROD_DATA" | "ZONE_PROD_APP" | "ZONE_STAGING" | "ZONE_DEV" | "ZONE_ADMIN_MGMT" | "ZONE_FORENSIC_ISOLATION";
export type Severity = "INFO" | "WARN" | "CRITICAL" | "EMERGENCY";
export type NodeType = "CLIENT" | "SERVER" | "RELAY" | "EGRESS";
export type PolicyAction = "ALLOW" | "DENY" | "ISOLATE";
export type ThreatLevel = 0 | 1 | 2 | 3;
 
export interface DevicePosture { osCurrent: boolean; diskEncrypted: boolean; secureBoot: boolean; firewallEnabled: boolean; agentHealthy: boolean; bannedProcessFound: boolean; assessedAt: Date; }
// lastPostureAt/agentVersion (db/004) are set from HeartbeatService.accept's
// real heartbeat payload; quarantineReason is set from the SecurityEvent
// description that triggered ThreatResponseService.handle's quarantine and
// cleared on restore() — all three columns existed with no read/write path
// at all before this.
export interface Device { id: UUID; hostname: string; hardwareId: string; platform: Platform; osVersion: string; publicAttestationKey?: string; compromised: boolean; revoked: boolean; posture: DevicePosture; createdAt: Date; updatedAt: Date; lastPostureAt?: Date; agentVersion?: string; quarantineReason?: string; }
// Sentinel for a node with no operator-assigned geography yet (db/019's
// column default) — deliberately not a real region code, so routing never
// mistakes "unset" for a genuine LOCAL_RELAY match.
export const UNASSIGNED_REGION = "unassigned";
// `region` is a geographic placement (e.g. "us-east-1"), entirely separate
// from `zone` (a security classification like ZONE_PROD_APP) — see
// MeshController's own comment on why those must never be conflated.
// Optional (like lastHandshake) rather than defaulted to UNASSIGNED_REGION
// here: real rows always carry one (db/019's column default), but plenty of
// callers build a MeshNode without caring about geography at all.
export interface MeshNode { id: UUID; deviceId: UUID; wireGuardPublicKey: string; internalIpv4: string; internalIpv6: string; listenPort: number; nodeType: NodeType; zone: SecurityZone; region?: string; active: boolean; lastHandshake?: Date; }
export interface IdentityContext { userId: UUID; roles: string[]; attributes: Record<string,string>; mfa: boolean; sourceIp: string; }
export interface ResourceContext { resource: string; zone: SecurityZone; protocol: "TCP"|"UDP"|"ICMP"|"ANY"; port?: number; }
export interface NetworkPolicy { id: UUID; name: string; sourceZones: SecurityZone[]; destinationZones: SecurityZone[]; protocols: Array<ResourceContext["protocol"]>; destinationPorts: number[]; action: PolicyAction; requiredRoles: string[]; requiresJit: boolean; priority: number; version: number; active: boolean; }
export interface AccessDecision { allowed: boolean; action: PolicyAction; reason: string; policyId?: UUID; decisionId: UUID; expiresAt: Date; }
export interface JitGrant { id: UUID; userId: UUID; targetResource: string; targetZone: SecurityZone; justification: string; approvedBy?: UUID; grantedAt: Date; expiresAt: Date; terminated: boolean; terminationReason?: string; }
export interface SecurityEvent { id: UUID; nodeId?: UUID; at: Date; severity: Severity; engine: string; type: string; sourceIp?: string; destinationIp?: string; description: string; metadata: Record<string,unknown>; }
export interface AuditRecord { sequence: number; at: Date; actor: string; action: string; subject: string; payload: Record<string,unknown>; previousHash: string; hash: string; }
