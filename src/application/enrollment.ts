import { ConflictError, ValidationError } from "../domain/errors.js";
import type { Device, MeshNode, Platform, SecurityZone } from "../domain/types.js";
import type { DeviceRepository, NodeRepository, UnitOfWork } from "../ports/repositories.js";
import type { AttestationVerifier, CertificateIssuer, Clock, IdGenerator, PeerDistributor } from "../ports/infrastructure.js";
 
export interface EnrollmentRequest { hostname:string; hardwareId:string; platform:Platform; osVersion:string; attestationQuote:Uint8Array; attestationPublicKey?:string; wireGuardPublicKey:string; internalIpv4:string; internalIpv6:string; zone:SecurityZone; }
export class EnrollmentService {
 constructor(private d:DeviceRepository,private n:NodeRepository,private u:UnitOfWork,private attest:AttestationVerifier,private certs:CertificateIssuer,private peers:PeerDistributor,private ids:IdGenerator,private clock:Clock){}
 async register(r:EnrollmentRequest){
  if(!r.wireGuardPublicKey || !r.hardwareId) throw new ValidationError("hardware and public keys are required");
  if(await this.d.findByHardwareId(r.hardwareId)) throw new ConflictError("hardware already enrolled");
  if(await this.n.findByPublicKey(r.wireGuardPublicKey)) throw new ConflictError("WireGuard public key already enrolled");
  if(!await this.attest.verify(r.hardwareId,r.attestationQuote,r.attestationPublicKey)) throw new ValidationError("hardware attestation failed");
  const now=this.clock.now(), deviceId=this.ids.next(), nodeId=this.ids.next();
  const posture={osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:now};
  const device:Device={id:deviceId,hostname:r.hostname,hardwareId:r.hardwareId,platform:r.platform,osVersion:r.osVersion,compromised:false,revoked:false,posture,createdAt:now,updatedAt:now,...(r.attestationPublicKey?{publicAttestationKey:r.attestationPublicKey}:{})};
  const node:MeshNode={id:nodeId,deviceId,wireGuardPublicKey:r.wireGuardPublicKey,internalIpv4:r.internalIpv4,internalIpv6:r.internalIpv6,listenPort:51820,nodeType:"SERVER",zone:r.zone,active:true};
  const certificate=await this.certs.issueNodeCertificate(nodeId,r.attestationPublicKey??r.wireGuardPublicKey,1440);
  await this.u.transaction(async()=>{await this.d.save(device);await this.n.save(node)});
  const active=(await this.n.list()).filter(x=>x.active&&x.id!==nodeId); await this.peers.configure(node,active);
  return {device,node,certificate,peers:active};
 }
}
