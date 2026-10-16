import {createHash, createPublicKey, randomBytes} from "node:crypto";
import {AuthorizationError, ValidationError} from "../domain/errors.js";
import type {NodeRepository} from "../ports/repositories.js";
import type {Clock} from "../ports/infrastructure.js";
import type {EnrollmentService} from "./enrollment.js";
import {AddressAllocator} from "../../services/mesh-controller/controller.js";
import {publicKeyPemFromCsrDer} from "../infrastructure/csr.js";

// The public, internet-facing way a customer device joins: one HTTPS call
// (through the Cloudflare tunnel in front of control-api) gated by a
// one-time invite the owner minted. Distinct from gRPC registerNode, which
// has no caller authentication of its own and so must stay on a private
// port. Hardware attestation still runs exactly as before, inside
// EnrollmentService.register, against whatever real ATTESTATION_PROVIDER is
// configured — the invite decides WHO may enroll, attestation decides
// WHETHER the device's evidence is acceptable. Neither replaces the other.
//
// Topology is hub-and-spoke, not mesh: a joining device gets exactly one
// peer, the VPN gateway, with a full-tunnel route. Customer devices never
// learn each other's keys or addresses.

export interface EnrollmentInviteStore {
  create(invite:{codeHash:string;expiresAt:Date;createdBy:string;label:string}):Promise<{inviteId:string}>;
  // Atomically marks an unexpired, unused invite as used; null otherwise.
  claim(codeHash:string,now:Date):Promise<string|null>;
  release(inviteId:string):Promise<void>;
  bindNode(inviteId:string,nodeId:string):Promise<void>;
}

export interface VpnGatewayConfig {
  publicKey:string;endpoint:string;ipv4:string;ipv6:string;dns:string[];
}

export interface DeviceJoinRequest {
  inviteCode:string;hostname?:string;hardwareUuid:string;osSignature:string;
  wireguardPublicKey:string;csrDer:string;attestationQuote:string;
}

export interface DeviceJoinResult {
  nodeId:string;
  addresses:{ipv4:string;ipv6:string};
  certificatePem:string;
  gateway:{publicKey:string;endpoint:string;allowedIps:string[];keepaliveSeconds:number};
  dns:string[];
}

// Crockford base32: no I/L/O/U, so a code read aloud or retyped can't be
// confused between 0/O or 1/I/L.
const CROCKFORD="0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const INVITE_BYTES=15; // 120 bits -> 24 base32 characters

export const generateInviteCode=():string=>{
  const bytes=randomBytes(INVITE_BYTES);
  let bits=0,value=0,out="";
  for(const byte of bytes){
    value=(value<<8)|byte;bits+=8;
    while(bits>=5){out+=CROCKFORD[(value>>>(bits-5))&31];bits-=5;}
  }
  return `BAPC-${out.match(/.{6}/g)!.join("-")}`;
};

export const normalizeInviteCode=(code:string):string=>{
  const cleaned=code.toUpperCase().replace(/[^0-9A-Z]/g,"");
  const body=cleaned.length===28&&cleaned.startsWith("BAPC")?cleaned.slice(4):cleaned;
  return body.replace(/O/g,"0").replace(/[IL]/g,"1");
};

export const hashInviteCode=(code:string):string=>
  createHash("sha256").update(normalizeInviteCode(code)).digest("hex");

const WG_KEY_RE=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const BASE64_RE=/^[A-Za-z0-9+/]+={0,2}$/;

const decodeBase64=(value:unknown,field:string,maxBytes:number):Uint8Array=>{
  if(typeof value!=="string"||!BASE64_RE.test(value))throw new ValidationError(`${field} must be base64`);
  const bytes=Buffer.from(value,"base64");
  if(bytes.length===0||bytes.length>maxBytes)throw new ValidationError(`${field} is empty or too large`);
  return new Uint8Array(bytes);
};

const requireString=(value:unknown,field:string,max:number):string=>{
  if(typeof value!=="string"||!value.trim())throw new ValidationError(`${field} is required`);
  if(value.length>max)throw new ValidationError(`${field} is too long`);
  return value.trim();
};

// Shared by the owner-only REST route and the on-server CLI
// (src/runtime/mint-invite.ts). The plaintext code is returned exactly once
// and only its hash is stored.
export const mintInvite=async(
  invites:EnrollmentInviteStore,clock:Clock,createdBy:string,opts:{hours?:number;label?:string}={}
):Promise<{inviteId:string;code:string;expiresAt:Date}>=>{
  const hours=opts.hours??24;
  if(!Number.isFinite(hours)||hours<=0||hours>24*14)throw new ValidationError("invite lifetime must be between 0 and 336 hours");
  const code=generateInviteCode();
  const expiresAt=new Date(clock.now().getTime()+hours*3_600_000);
  const {inviteId}=await invites.create({
    codeHash:hashInviteCode(code),expiresAt,createdBy,label:String(opts.label??"").slice(0,200)
  });
  return {inviteId,code,expiresAt};
};

export class DeviceJoinService {
  constructor(
    private invites:EnrollmentInviteStore,
    private enrollment:EnrollmentService,
    private nodes:NodeRepository,
    private gateway:VpnGatewayConfig|undefined,
    private clock:Clock
  ){}

  mintInvite(createdBy:string,opts:{hours?:number;label?:string}={}){
    return mintInvite(this.invites,this.clock,createdBy,opts);
  }

  // Peers the gateway should have right now: every active node whose
  // device isn't revoked or flagged compromised. A quarantine or revocation
  // drops the device from this list, and the gateway's sync loop drops it
  // from wg0 on its next pass.
  async gatewayPeers(devices:{listAll():Promise<Array<{id:string;revoked:boolean;compromised:boolean}>>}){
    const blocked=new Set((await devices.listAll()).filter(d=>d.revoked||d.compromised).map(d=>d.id));
    return (await this.nodes.list())
      .filter(n=>n.active&&!blocked.has(n.deviceId))
      .map(n=>({nodeId:n.id,publicKey:n.wireGuardPublicKey,allowedIps:[`${n.internalIpv4}/32`,`${n.internalIpv6}/128`]}));
  }

  async join(body:Partial<Record<keyof DeviceJoinRequest,unknown>>):Promise<DeviceJoinResult>{
    if(!this.gateway)throw new Error("VPN gateway is not configured on this control plane (VPN_GATEWAY_PUBLIC_KEY / VPN_GATEWAY_ENDPOINT)");
    const inviteCode=requireString(body.inviteCode,"inviteCode",64);
    const hardwareUuid=requireString(body.hardwareUuid,"hardwareUuid",128);
    const osSignature=requireString(body.osSignature,"osSignature",200);
    const wireguardPublicKey=requireString(body.wireguardPublicKey,"wireguardPublicKey",64);
    if(!WG_KEY_RE.test(wireguardPublicKey))throw new ValidationError("wireguardPublicKey is not a valid WireGuard public key");
    const csrDer=decodeBase64(body.csrDer,"csrDer",16_384);
    const quote=decodeBase64(body.attestationQuote,"attestationQuote",16_384);
    const hostname=(typeof body.hostname==="string"?body.hostname:"").replace(/[^A-Za-z0-9-]/g,"").slice(0,63)
      ||`node-${hardwareUuid.slice(0,8)}`;

    // Checked before the invite is touched, so a malformed request never
    // costs the owner their code. Normalized to Node's own SPKI PEM so a
    // client can reproduce the exact identity-key string the attestation
    // payload binds to (attestationSignedPayload) without depending on
    // node-forge's CRLF line endings.
    let identityPublicKeyPem:string;
    try{
      identityPublicKeyPem=createPublicKey(publicKeyPemFromCsrDer(csrDer)).export({type:"spki",format:"pem"}).toString();
    }catch(error){
      throw new ValidationError(error instanceof Error?error.message:"csrDer is invalid");
    }

    const inviteId=await this.invites.claim(hashInviteCode(inviteCode),this.clock.now());
    if(!inviteId)throw new AuthorizationError("invite code is not valid, has expired, or was already used");

    try{
      const gateway=this.gateway;
      const allocator=new AddressAllocator({
        usedIpv4:async()=>new Set([...(await this.nodes.list()).map(n=>n.internalIpv4),gateway.ipv4]),
        usedIpv6:async()=>new Set([...(await this.nodes.list()).map(n=>n.internalIpv6),gateway.ipv6])
      });
      const lease=await allocator.next();
      const result=await this.enrollment.register({
        hostname,hardwareId:hardwareUuid,
        platform:/windows/i.test(osSignature)?"windows":/darwin|mac/i.test(osSignature)?"macos":"linux",
        osVersion:osSignature,attestationQuote:quote,attestationPublicKey:identityPublicKeyPem,
        wireGuardPublicKey:wireguardPublicKey,internalIpv4:lease.ipv4,internalIpv6:lease.ipv6,
        zone:"ZONE_PROD_APP"
      });
      await this.invites.bindNode(inviteId,result.node.id);
      return {
        nodeId:result.node.id,
        addresses:{ipv4:result.node.internalIpv4,ipv6:result.node.internalIpv6},
        certificatePem:result.certificate.certificatePem,
        gateway:{publicKey:gateway.publicKey,endpoint:gateway.endpoint,allowedIps:["0.0.0.0/0","::/0"],keepaliveSeconds:25},
        dns:gateway.dns
      };
    }catch(error){
      await this.invites.release(inviteId);
      throw error;
    }
  }
}
