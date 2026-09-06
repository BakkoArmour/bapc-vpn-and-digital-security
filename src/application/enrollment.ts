import { ConflictError, ValidationError } from "../domain/errors.js";
import type { Device, MeshNode, Platform, SecurityZone } from "../domain/types.js";
import type { DeviceRepository, NodeRepository, UnitOfWork } from "../ports/repositories.js";
import type { AttestationVerifier, CertificateIssuer, Clock, IdGenerator, PeerDistributor } from "../ports/infrastructure.js";
 
export interface EnrollmentRequest { hostname:string; hardwareId:string; platform:Platform; osVersion:string; attestationQuote:Uint8Array; attestationPublicKey:string; wireGuardPublicKey:string; internalIpv4:string; internalIpv6:string; zone:SecurityZone; }
export class EnrollmentService {
 // CERTIFICATE_TTL_MINUTES (config.ts's certificateTtlMinutes) was loaded
 // and validated with nothing anywhere that ever read it — every enrollment
 // certificate got a hard-coded 1440-minute (24h) TTL regardless of what an
 // operator configured. Defaults to 1440 so every existing caller/test that
 // never cared about a custom TTL keeps working unchanged.
 constructor(private d:DeviceRepository,private n:NodeRepository,private u:UnitOfWork,private attest:AttestationVerifier,private certs:CertificateIssuer,private peers:PeerDistributor,private ids:IdGenerator,private clock:Clock,private certificateTtlMinutes=1440){}
 async register(r:EnrollmentRequest){
  if(!r.wireGuardPublicKey || !r.hardwareId) throw new ValidationError("hardware and public keys are required");
  // A WireGuard (Curve25519) key cannot stand in for the X.509 identity
  // certificate's RSA public key — see mesh.proto's csr_der field comment.
  // The transport layer (gRPC's registerNode) is responsible for verifying
  // a real CSR and passing its public key here before this is ever reached.
  if(!r.attestationPublicKey) throw new ValidationError("a verified certificate public key (attestationPublicKey) is required");
  if(await this.d.findByHardwareId(r.hardwareId)) throw new ConflictError("hardware already enrolled");
  if(await this.n.findByPublicKey(r.wireGuardPublicKey)) throw new ConflictError("WireGuard public key already enrolled");
  if(!await this.attest.verify(r.hardwareId,r.attestationQuote,r.attestationPublicKey)) throw new ValidationError("hardware attestation failed");
  const now=this.clock.now(), deviceId=this.ids.next(), nodeId=this.ids.next();
  const posture={osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:now};
  const device:Device={id:deviceId,hostname:r.hostname,hardwareId:r.hardwareId,platform:r.platform,osVersion:r.osVersion,compromised:false,revoked:false,posture,createdAt:now,updatedAt:now,publicAttestationKey:r.attestationPublicKey};
  const node:MeshNode={id:nodeId,deviceId,wireGuardPublicKey:r.wireGuardPublicKey,internalIpv4:r.internalIpv4,internalIpv6:r.internalIpv6,listenPort:51820,nodeType:"SERVER",zone:r.zone,active:true};
  // Device/node must exist before the certificate record does: a real
  // CertificateIssuer (TrustCoreIssuer) persists a row into `certificates`,
  // whose node_id is a real foreign key into mesh_nodes — issuing the
  // certificate first violated that constraint on every real enrollment.
  // Invisible until TrustCoreIssuer replaced DevelopmentCertificateIssuer,
  // which never persisted anything to notice the ordering was wrong.
  await this.u.transaction(async()=>{await this.d.save(device);await this.n.save(node)});
  const certificate=await this.certs.issueNodeCertificate(nodeId,r.attestationPublicKey,this.certificateTtlMinutes);
  const active=(await this.n.list()).filter(x=>x.active&&x.id!==nodeId); await this.peers.configure(node,active);
  return {device,node,certificate,peers:active};
 }
}
