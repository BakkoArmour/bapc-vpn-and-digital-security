import forge from "node-forge";
import type {PlatformAdapter} from "../../native/shared/platform-adapter.js";
import {generateWireGuardKeyPair} from "../../native/shared/wireguard-keys.js";

// The gap this closes: nothing in this repository ever brought a new node's
// WireGuard interface up in the first place. agent.ts assumes BAPC_NODE_ID
// already exists and just starts heartbeating — but no enrollment flow ever
// generated a keypair, called gRPC registerNode, or applied the resulting
// config locally. This is that flow's core logic, kept separate from the
// CLI (enroll.ts) so it's testable against a fake gRPC client and a fake
// PlatformAdapter with no real network/filesystem/wg binary involved.

export interface RegisterNodeReply {
  internalIpv4:string;internalIpv6:string;
  initialPeers:Array<{publicKey:string;endpoint:string;allowedIps:string[];keepaliveInterval:number}>;
  signedClientCertificate:Buffer|Uint8Array;assignedZone:string;nodeId:string;
}
export interface EnrollmentGrpcClient {
  registerNode(request:{
    hardwareUuid:string;wireguardPublicKey:string;
    hardwareAttestationQuote:Buffer;osSignature:string;csrDer:Buffer;
  }):Promise<RegisterNodeReply>;
}

export interface EnrollNodeResult {
  nodeId:string;assignedZone:string;
  wireGuardPrivateKey:string;wireGuardPublicKey:string;
  identityPrivateKeyPem:string;certificatePem:string;
}

export {generateWireGuardKeyPair};

// Real self-signed PKCS#10 CSR — proof of possession for the RSA identity
// key this node will use to sign future RotatePeerKey requests (see
// src/api/grpc/server.ts's verifyRotationSignature). The private key is
// returned so the caller can persist it; it must never be sent anywhere.
const generateIdentityCsr=(commonName:string)=>{
  const keys=forge.pki.rsa.generateKeyPair(2048);
  const csr=forge.pki.createCertificationRequest();
  csr.publicKey=keys.publicKey;
  csr.setSubject([{name:"commonName",value:commonName}]);
  csr.sign(keys.privateKey,forge.md.sha256.create());
  const csrDer=Buffer.from(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes(),"binary");
  return {csrDer,privateKeyPem:forge.pki.privateKeyToPem(keys.privateKey)};
};

export const WIREGUARD_LISTEN_PORT=51820;

// hardwareAttestationQuote is sent empty: the only verifier wired anywhere
// in this control plane is AllowAttestation (src/infrastructure/adapters.ts,
// documented there as development-only) — real hardware attestation (a
// signed TPM/Secure Enclave quote) is a separate, already-documented gap
// this doesn't attempt to fake.
export async function enrollNode(
  client:EnrollmentGrpcClient,platform:PlatformAdapter,
  opts:{hardwareUuid:string;osSignature:string}
):Promise<EnrollNodeResult>{
  const wg=generateWireGuardKeyPair();
  const {csrDer,privateKeyPem}=generateIdentityCsr(`node-${opts.hardwareUuid}`);

  const reply=await client.registerNode({
    hardwareUuid:opts.hardwareUuid,wireguardPublicKey:wg.publicKey,
    hardwareAttestationQuote:Buffer.alloc(0),osSignature:opts.osSignature,csrDer
  });
  if(!reply.nodeId)throw new Error("registerNode did not return a node_id — is the control plane running an older mesh.proto?");

  await platform.applyWireGuard({
    privateKeyReference:wg.privateKey,
    addresses:[`${reply.internalIpv4}/32`,`${reply.internalIpv6}/128`],
    listenPort:WIREGUARD_LISTEN_PORT,
    peers:reply.initialPeers.map(p=>({
      publicKey:p.publicKey,allowedIps:p.allowedIps,keepaliveSeconds:p.keepaliveInterval,
      ...(p.endpoint?{endpoint:p.endpoint}:{})
    }))
  });

  return {
    nodeId:reply.nodeId,assignedZone:reply.assignedZone,
    wireGuardPrivateKey:wg.privateKey,wireGuardPublicKey:wg.publicKey,
    identityPrivateKeyPem:privateKeyPem,
    certificatePem:Buffer.from(reply.signedClientCertificate).toString("utf8")
  };
}
