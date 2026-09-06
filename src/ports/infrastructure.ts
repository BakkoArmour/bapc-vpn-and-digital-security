import type { AccessDecision, MeshNode, NetworkPolicy, SecurityEvent, UUID } from "../domain/types.js";
export interface Clock { now():Date; }
export interface IdGenerator { next():UUID; }
export interface Hasher { digest(value:string):Promise<string>; }
export interface CertificateIssuer { issueNodeCertificate(nodeId:UUID, publicKey:string, ttlMinutes:number):Promise<{serial:string;certificatePem:string;expiresAt:Date}>; revoke(serial:string,reason:string):Promise<void>; }
export interface AttestationVerifier { verify(hardwareId:string,quote:Uint8Array,publicKey?:string):Promise<boolean>; }
export interface PolicyEnforcer { stage(commitId:UUID,policies:NetworkPolicy[]):Promise<void>; commit(commitId:UUID):Promise<void>; rollback(commitId:UUID):Promise<void>; isolateNode(nodeId:UUID):Promise<void>; restoreNode(nodeId:UUID):Promise<void>; }
export interface ConnectivityProbe { verifyControlPlane():Promise<boolean>; }
export interface EventBus { publish(topic:string,event:unknown):Promise<void>; }
export interface PeerDistributor { configure(node:MeshNode,peers:MeshNode[]):Promise<void>; remove(nodeId:UUID):Promise<void>; }
export interface DecisionSigner { sign(decision:AccessDecision):Promise<string>; }
export interface ThreatSink { notify(event:SecurityEvent):Promise<void>; }
