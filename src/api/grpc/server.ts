import {fileURLToPath} from "node:url";
import {dirname, join} from "node:path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import forge from "node-forge";
import {EnrollmentService} from "../../application/enrollment.js";
import type {NodeRepository} from "../../ports/repositories.js";
import type {Platform} from "../../domain/types.js";
import {AddressAllocator, MeshController, type MeshCommandSink} from "../../../services/mesh-controller/controller.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PROTO_PATH=join(__dirname,"..","..","..","..","contracts","mesh.proto");

export interface KeyRotationLedger {
  rotate(nodeId:string,newPublicKey:string,signature:Uint8Array):Promise<{acknowledged:boolean;effectiveEpoch:number}>;
}

export interface GrpcMeshDeps {
  enrollment:EnrollmentService;
  nodes:NodeRepository;
  keyRotation:KeyRotationLedger;
  meshController:MeshController;
}

// Extracts and verifies the node's proof-of-possession CSR: node-forge's
// csr.verify() checks the CSR's self-signature against its own embedded
// public key, confirming the node holds the matching private key without
// that key ever leaving the node or crossing this RPC. See mesh.proto's
// csr_der field comment for why this can't just reuse wireguard_public_key.
const publicKeyPemFromCsrDer=(csrDer:Uint8Array):string=>{
  if(csrDer.length===0)throw new Error("csr_der is required: submit a self-signed PKCS#10 CSR to obtain a certificate");
  let csr:forge.pki.CertificateSigningRequest;
  try{
    const asn1=forge.asn1.fromDer(forge.util.createBuffer(Buffer.from(csrDer).toString("binary")));
    csr=forge.pki.certificationRequestFromAsn1(asn1);
  }catch{
    throw new Error("csr_der could not be parsed as a PKCS#10 CertificationRequest");
  }
  if(!csr.verify())throw new Error("CSR signature does not verify against its own embedded public key");
  return forge.pki.publicKeyToPem(csr.publicKey!);
};

const detectPlatform=(osSignature:string):Platform=>{
  const s=osSignature.toLowerCase();
  if(s.includes("windows"))return "windows";
  if(s.includes("mac")||s.includes("darwin"))return "macos";
  if(s.includes("ipados"))return "ipados";
  if(s.includes("ios"))return "ios";
  return "linux";
};

export const buildMeshGrpcServer=(deps:GrpcMeshDeps):grpc.Server=>{
  const pkgDef=protoLoader.loadSync(PROTO_PATH,{
    keepCase:false,longs:String,enums:String,defaults:true,oneofs:true
  });
  const proto=grpc.loadPackageDefinition(pkgDef) as any;
  const server=new grpc.Server();

  server.addService(proto.bapc.security.v1.MeshOrchestrationService.service,{
    registerNode:async(
      call:grpc.ServerUnaryCall<any,any>,
      callback:grpc.sendUnaryData<any>
    )=>{
      try{
        const req=call.request;
        const allocator=new AddressAllocator({
          usedIpv4:async()=>new Set((await deps.nodes.list()).map(n=>n.internalIpv4)),
          usedIpv6:async()=>new Set((await deps.nodes.list()).map(n=>n.internalIpv6))
        });
        const lease=await allocator.next();
        const platform=detectPlatform(String(req.osSignature??""));
        const attestationPublicKey=publicKeyPemFromCsrDer(new Uint8Array(req.csrDer??[]));
        const result=await deps.enrollment.register({
          hostname:`node-${String(req.hardwareUuid).slice(0,8)}`,
          hardwareId:String(req.hardwareUuid),
          platform,
          osVersion:String(req.osSignature??"unknown"),
          attestationQuote:new Uint8Array(req.hardwareAttestationQuote??[]),
          attestationPublicKey,
          wireGuardPublicKey:String(req.wireguardPublicKey),
          internalIpv4:lease.ipv4,
          internalIpv6:lease.ipv6,
          zone:"ZONE_PROD_APP"
        });
        callback(null,{
          internalIpv4:result.node.internalIpv4,
          internalIpv6:result.node.internalIpv6,
          initialPeers:result.peers.map(p=>({
            publicKey:p.wireGuardPublicKey,endpoint:"",
            allowedIps:[`${p.internalIpv4}/32`,`${p.internalIpv6}/128`],
            keepaliveInterval:25
          })),
          signedClientCertificate:Buffer.from(result.certificate.certificatePem,"utf8"),
          assignedZone:result.node.zone
        });
      }catch(error){
        callback({code:grpc.status.INVALID_ARGUMENT,message:error instanceof Error?error.message:"registration failed"});
      }
    },

    rotatePeerKey:async(
      call:grpc.ServerUnaryCall<any,any>,
      callback:grpc.sendUnaryData<any>
    )=>{
      try{
        const req=call.request;
        const node=await deps.nodes.get(String(req.nodeId));
        if(!node)throw new Error("node not found");
        const existing=await deps.nodes.findByPublicKey(String(req.newPublicKey));
        if(existing)throw new Error("public key already in use");
        const result=await deps.keyRotation.rotate(
          String(req.nodeId),String(req.newPublicKey),new Uint8Array(req.signature??[])
        );
        await deps.nodes.save({...node,wireGuardPublicKey:String(req.newPublicKey)});
        const all=await deps.nodes.list();
        await deps.meshController.reconcile({...node,wireGuardPublicKey:String(req.newPublicKey)},all);
        callback(null,{acknowledged:result.acknowledged,effectiveEpoch:result.effectiveEpoch});
      }catch(error){
        callback({code:grpc.status.FAILED_PRECONDITION,message:error instanceof Error?error.message:"rotation failed"});
      }
    },

    streamHeartbeat:(call:grpc.ServerDuplexStream<any,any>)=>{
      call.on("data",(heartbeat:any)=>{
        call.write({action:"NOOP",payload:Buffer.alloc(0)});
        void heartbeat;
      });
      call.on("end",()=>call.end());
      call.on("error",()=>call.end());
    }
  });

  return server;
};

export class InMemoryKeyRotationLedger implements KeyRotationLedger {
  private epoch=0;
  async rotate(_nodeId:string,_newPublicKey:string,signature:Uint8Array){
    if(signature.length===0)throw new Error("rotation signature required");
    this.epoch+=1;
    return {acknowledged:true,effectiveEpoch:this.epoch};
  }
}

export interface NoopMeshCommandSink extends MeshCommandSink {}
export class LoggingMeshCommandSink implements MeshCommandSink {
  async configure(){/* production binds this to the real PlatformAdapter/agent command queue */}
  async sever(){/* production binds this to the real PlatformAdapter/agent command queue */}
}
