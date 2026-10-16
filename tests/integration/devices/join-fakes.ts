import {generateKeyPairSync, createSign, createPublicKey} from "node:crypto";
import forge from "node-forge";
import type {EnrollmentInviteStore, VpnGatewayConfig, InviteAccount} from "../../../src/application/device-join.js";
import {attestationSignedPayload} from "../../../src/infrastructure/attestation/envelope.js";
import {generateWireGuardKeyPair} from "../../../native/shared/wireguard-keys.js";

// Shared test doubles for the device-join and customer-portal tests. Not a
// *.test.ts file, so importing it never re-registers anyone's tests.

export class MemoryInvites implements EnrollmentInviteStore {
  rows=new Map<string,{inviteId:string;codeHash:string;expiresAt:Date;usedAt:Date|null;nodeId:string|null;account?:InviteAccount}>();
  async create(i:{codeHash:string;expiresAt:Date;account?:InviteAccount}){
    const inviteId=`inv-${this.rows.size+1}`;
    this.rows.set(inviteId,{inviteId,codeHash:i.codeHash,expiresAt:i.expiresAt,usedAt:null,nodeId:null,...(i.account?{account:i.account}:{})});
    return {inviteId};
  }
  async claim(codeHash:string,now:Date){
    const row=[...this.rows.values()].find(r=>r.codeHash===codeHash&&!r.usedAt&&r.expiresAt>now);
    if(!row)return null;
    row.usedAt=now;return {inviteId:row.inviteId,...(row.account?{account:row.account}:{})};
  }
  async openForAccount(accountId:string,now:Date){
    return [...this.rows.values()].filter(r=>r.account?.accountId===accountId&&!r.usedAt&&r.expiresAt>now).length;
  }
  async release(id:string){const r=this.rows.get(id)!;if(!r.nodeId)r.usedAt=null;}
  async bindNode(id:string,nodeId:string){this.rows.get(id)!.nodeId=nodeId;}
}

export const GATEWAY:VpnGatewayConfig={
  publicKey:generateWireGuardKeyPair().publicKey,endpoint:"203.0.113.10:51820",
  ipv4:"10.144.0.1",ipv6:"fd14:4b41:5043::1",dns:["1.1.1.1"]
};

const rsa=()=>generateKeyPairSync("rsa",{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});

export const deviceRequest=(inviteCode:string,opts:{hardwareUuid?:string;tamper?:boolean}={})=>{
  const hardwareUuid=opts.hardwareUuid??"4C4C4544-0042-3510-8051-B4C04F563432";
  const identity=rsa(),ak=rsa();
  const csr=forge.pki.createCertificationRequest();
  csr.publicKey=forge.pki.publicKeyFromPem(identity.publicKey);
  csr.setSubject([{name:"commonName",value:`node-${hardwareUuid}`}]);
  csr.sign(forge.pki.privateKeyFromPem(identity.privateKey),forge.md.sha256.create());
  const csrDer=Buffer.from(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes(),"binary");
  const envelope={provider:"windows-tpm",nonce:"0123456789abcdef",pcrDigest:"a".repeat(64),akPublicKeyPem:ak.publicKey};
  // The exact identity PEM string the server binds to: Node's SPKI export.
  const identityPem=createPublicKey(identity.publicKey).export({type:"spki",format:"pem"}).toString();
  const payload=attestationSignedPayload(opts.tamper?"someone-else":hardwareUuid,envelope,identityPem);
  const signature=createSign("SHA256").update(payload).sign(ak.privateKey,"base64");
  return {
    inviteCode,hostname:"BRYAN-LAPTOP",hardwareUuid,osSignature:"Windows_NT 10.0.19045",
    wireguardPublicKey:generateWireGuardKeyPair().publicKey,csrDer:csrDer.toString("base64"),
    attestationQuote:Buffer.from(JSON.stringify({...envelope,signature})).toString("base64")
  };
};

