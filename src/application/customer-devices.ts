import {generateKeyPairSync, randomUUID} from "node:crypto";
import {ValidationError, AuthorizationError, NotFoundError} from "../domain/errors.js";
import type {DeviceRepository, NodeRepository} from "../ports/repositories.js";
import type {Clock} from "../ports/infrastructure.js";
import type {EnrollmentService} from "./enrollment.js";
import {gatewayPeerFor, leaseAddress, mintInvite, type EnrollmentInviteStore, type VpnGatewayConfig} from "./device-join.js";
import type {AccountAttestedVerifier} from "../infrastructure/attestation/account-attested.js";
import {generateWireGuardKeyPair} from "../../native/shared/wireguard-keys.js";

// What a paying customer can do with their devices from the customer portal
// (src/runtime/customer-portal.ts). Payment itself is BAPC Billing's job;
// this only ever acts on an account the portal has already signed in, and
// suspends/restores devices from whatever Billing reports.

export interface CustomerSession {tokenHash:string;accountId:string;email:string;name:string|null;csrfToken:string;}
export interface CustomerDevice {nodeId:string;name:string;kind:string;createdAt:Date;suspended:boolean;address:string;}

export interface CustomerStore {
  devices(accountId:string):Promise<CustomerDevice[]>;
  record(nodeId:string,account:{accountId:string;email:string;deviceName:string},kind:string):Promise<void>;
  markRemoved(accountId:string,nodeId:string):Promise<boolean>;
  setSuspended(accountId:string,suspended:boolean):Promise<number>;
}

export interface CustomerInviteStore extends EnrollmentInviteStore {
  openForAccount(accountId:string,now:Date):Promise<number>;
}

export const DEVICE_KINDS={
  windows:"Windows PC",iphone:"iPhone or iPad",android:"Android",mac:"Mac",linux:"Linux"
} as const;
export type DeviceKind=keyof typeof DEVICE_KINDS;
export const isDeviceKind=(k:unknown):k is DeviceKind=>typeof k==="string"&&Object.hasOwn(DEVICE_KINDS,k);

export const DEVICE_LIMIT=5;

const cleanName=(name:unknown,kind:DeviceKind)=>
  String(name??"").replace(/[^\p{L}\p{N} '._-]/gu,"").trim().slice(0,40)||DEVICE_KINDS[kind];

export const wireGuardConfig=(c:{privateKey:string;ipv4:string;ipv6:string;dns:string[];gateway:VpnGatewayConfig})=>{
  const peer=gatewayPeerFor(c.gateway);
  return [
    "[Interface]",
    `PrivateKey = ${c.privateKey}`,
    `Address = ${c.ipv4}/32, ${c.ipv6}/128`,
    `DNS = ${c.dns.join(", ")}`,
    "",
    "[Peer]",
    `PublicKey = ${peer.publicKey}`,
    `AllowedIPs = ${peer.allowedIps.join(", ")}`,
    `Endpoint = ${peer.endpoint}`,
    `PersistentKeepalive = ${peer.keepaliveSeconds}`,
    ""
  ].join("\n");
};

export class CustomerDeviceService {
  constructor(
    private store:CustomerStore,
    private invites:CustomerInviteStore,
    private appEnrollment:EnrollmentService,
    private accountAttestation:AccountAttestedVerifier,
    private nodes:NodeRepository,
    private deviceRepo:DeviceRepository,
    private gateway:VpnGatewayConfig|undefined,
    private clock:Clock,
    private limit=DEVICE_LIMIT
  ){}

  list(accountId:string){return this.store.devices(accountId);}

  private async ensureRoom(accountId:string){
    const used=(await this.store.devices(accountId)).length+await this.invites.openForAccount(accountId,this.clock.now());
    if(used>=this.limit)throw new AuthorizationError(`You can have up to ${this.limit} devices. Remove one to add another.`);
  }

  // A Windows PC joins with real TPM attestation through the public join
  // route, so all the portal hands out is a one-time invite tied to the
  // account; the PC lands in the device list when it redeems it.
  async addWindowsDevice(account:{accountId:string;email:string},name:unknown){
    await this.ensureRoom(account.accountId);
    return mintInvite(this.invites,this.clock,`customer:${account.accountId}`,{
      hours:48,label:"customer portal",
      account:{accountId:account.accountId,email:account.email,deviceName:cleanName(name,"windows")}
    });
  }

  // Phones, Macs and Linux use the stock WireGuard app, which can't produce
  // hardware evidence: keys are made here, the device is enrolled as
  // account-attested (see AccountAttestedVerifier), and the private key is
  // handed to the customer once and never stored.
  async addAppDevice(account:{accountId:string;email:string},kind:DeviceKind,name:unknown){
    if(kind==="windows")throw new ValidationError("Windows PCs are added with the installer");
    if(!this.gateway)throw new Error("VPN gateway is not configured");
    await this.ensureRoom(account.accountId);
    const deviceName=cleanName(name,kind);
    const wg=generateWireGuardKeyPair();
    const identity=generateKeyPairSync("rsa",{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});
    const hardwareId=`app-${randomUUID()}`;
    const lease=await leaseAddress(this.nodes,this.gateway);
    const result=await this.appEnrollment.register({
      hostname:`${kind}-${hardwareId.slice(4,12)}`,hardwareId,
      platform:kind==="iphone"?"ios":kind==="mac"?"macos":"linux",
      osVersion:`wireguard-app:${kind}`,
      attestationQuote:this.accountAttestation.proof(hardwareId,identity.publicKey),
      attestationPublicKey:identity.publicKey,wireGuardPublicKey:wg.publicKey,
      internalIpv4:lease.ipv4,internalIpv6:lease.ipv6,zone:"ZONE_PROD_APP"
    });
    await this.store.record(result.node.id,{accountId:account.accountId,email:account.email,deviceName},kind);
    return {
      nodeId:result.node.id,name:deviceName,
      config:wireGuardConfig({privateKey:wg.privateKey,ipv4:lease.ipv4,ipv6:lease.ipv6,dns:this.gateway.dns,gateway:this.gateway})
    };
  }

  // Removal is permanent: the device is revoked, so even its old config
  // can never connect again.
  async removeDevice(accountId:string,nodeId:string){
    if(!await this.store.markRemoved(accountId,nodeId))throw new NotFoundError("device");
    const node=await this.nodes.get(nodeId);
    const device=node?await this.deviceRepo.get(node.deviceId):undefined;
    if(device)await this.deviceRepo.save({...device,revoked:true,updatedAt:this.clock.now()});
  }

  // Billing is the source of truth for "has this person paid": devices are
  // switched off while it says no, and back on as soon as it says yes.
  async applyPaymentState(accountId:string,paid:boolean){
    return this.store.setSuspended(accountId,!paid);
  }
}
