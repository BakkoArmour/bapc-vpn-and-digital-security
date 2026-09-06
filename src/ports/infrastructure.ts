import type { AccessDecision, MeshNode, NetworkPolicy, SecurityEvent, UUID } from "../domain/types.js";
export interface Clock { now():Date; }
export interface IdGenerator { next():UUID; }
export interface Hasher { digest(value:string):Promise<string>; }
export interface CertificateIssuer { issueNodeCertificate(nodeId:UUID, publicKey:string, ttlMinutes:number):Promise<{serial:string;certificatePem:string;expiresAt:Date}>; revoke(serial:string,reason:string):Promise<void>; }
// publicKey (EnrollmentService's attestationPublicKey — the CSR-verified
// X.509 identity key) is folded into what a real provider verifies a
// signature over, binding the hardware evidence to this specific enrollment's
// identity key — see src/infrastructure/attestation/ for the real
// implementations (Windows TPM, Linux TPM2, Apple Secure Enclave interface,
// and an explicit development/mock provider that AttestationVerifierFactory
// refuses to hand out in production).
export interface AttestationVerifier { verify(hardwareId:string,quote:Uint8Array,publicKey?:string):Promise<boolean>; }
// stage() reports which nodes it actually targeted (the active-node list at
// staging time) so SafeApplyService can verify each of them individually
// afterward instead of only checking the control plane's own database
// health — see RolloutStore below and src/application/safe-apply.ts.
export interface PolicyEnforcer { stage(commitId:UUID,policies:NetworkPolicy[],initiatedBy?:string):Promise<{targetedNodeIds:UUID[]}>; commit(commitId:UUID):Promise<void>; rollback(commitId:UUID):Promise<void>; isolateNode(nodeId:UUID):Promise<void>; restoreNode(nodeId:UUID):Promise<void>; }
export interface ConnectivityProbe { verifyControlPlane():Promise<boolean>; }
export interface EventBus { publish(topic:string,event:unknown):Promise<void>; }
export type NodeRolloutStatus="PENDING"|"SUCCEEDED"|"FAILED"|"TIMED_OUT"|"ROLLED_BACK";
export interface NodeRolloutRecord {nodeId:UUID;status:NodeRolloutStatus;acknowledgedAt?:Date;details:unknown;}
// Backs policy_rollout_nodes (db/018) — per-node verification for a policy
// rollout, so SafeApplyService's commit/rollback decision is based on
// what nodes actually reported, not just the control plane's own database
// health. refresh() pulls the latest real command_acknowledgements for the
// rollout's commitId and updates any still-PENDING rows; finalizeTimeouts()
// closes out whatever is still PENDING once the safety window elapses;
// markRolledBack() records the fleet-wide outcome once PolicyEnforcer.rollback
// actually broadcasts ROLLBACK_FIREWALL to every active node.
export interface RolloutStore {
  start(commitId:UUID,nodeIds:UUID[]):Promise<void>;
  refresh(commitId:UUID):Promise<NodeRolloutRecord[]>;
  finalizeTimeouts(commitId:UUID):Promise<void>;
  markRolledBack(commitId:UUID):Promise<void>;
  summary(commitId:UUID):Promise<NodeRolloutRecord[]>;
}
export interface PeerDistributor { configure(node:MeshNode,peers:MeshNode[]):Promise<void>; remove(nodeId:UUID):Promise<void>; }
export interface DecisionSigner { sign(decision:AccessDecision):Promise<string>; }
export interface ThreatSink { notify(event:SecurityEvent):Promise<void>; }
