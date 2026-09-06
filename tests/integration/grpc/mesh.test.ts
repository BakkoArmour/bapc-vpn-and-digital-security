import test from "node:test";
import assert from "node:assert/strict";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import forge from "node-forge";
import {fileURLToPath} from "node:url";
import {dirname, join} from "node:path";
import {randomUUID} from "node:crypto";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {AllowAttestation, DevelopmentCertificateIssuer, NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {MeshController} from "../../../services/mesh-controller/controller.js";
import {buildMeshGrpcServer, InMemoryKeyRotationLedger, LoggingMeshCommandSink} from "../../../src/api/grpc/server.js";
import {loadTrustAnchor} from "../../../services/trust-core/trust-anchor.js";
import {TrustCoreIssuer, type CertificateRecordStore} from "../../../services/trust-core/issuer.js";
import {ForgeX509Builder} from "../../../services/trust-core/x509-forge.js";
import {TrustCoreCertificateIssuer} from "../../../services/trust-core/trust-core-certificate-issuer.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PROTO_PATH=join(__dirname,"..","..","..","..","contracts","mesh.proto");

// A real, self-signed PKCS#10 CSR — what a genuine node would generate
// locally and never share the private key for. See mesh.proto's csr_der
// comment: registerNode now requires this instead of accepting the
// WireGuard (Curve25519) key as a stand-in RSA public key.
const generateCsrDer=(commonName:string):Buffer=>{
  const keys=forge.pki.rsa.generateKeyPair(2048);
  const csr=forge.pki.createCertificationRequest();
  csr.publicKey=keys.publicKey;
  csr.setSubject([{name:"commonName",value:commonName}]);
  csr.sign(keys.privateKey,forge.md.sha256.create());
  return Buffer.from(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes(),"binary");
};

const startServer=async()=>{
  const store=new MemoryStore();
  const enrollment=new EnrollmentService(
    store,store,store,new AllowAttestation(),new DevelopmentCertificateIssuer(),
    new NoopPeerDistributor(),new RandomIds(),new SystemClock()
  );
  const server=buildMeshGrpcServer({
    enrollment,nodes:store,devices:store,keyRotation:new InMemoryKeyRotationLedger(),
    meshController:new MeshController(new LoggingMeshCommandSink())
  });
  const port=await new Promise<number>((resolve,reject)=>{
    server.bindAsync("127.0.0.1:0",grpc.ServerCredentials.createInsecure(),(error,boundPort)=>{
      if(error)reject(error); else resolve(boundPort);
    });
  });
  const pkgDef=protoLoader.loadSync(PROTO_PATH,{keepCase:false,longs:String,enums:String,defaults:true,oneofs:true});
  const proto=grpc.loadPackageDefinition(pkgDef) as any;
  const client=new proto.bapc.security.v1.MeshOrchestrationService(
    `127.0.0.1:${port}`,grpc.credentials.createInsecure()
  );
  return {server,client,port};
};

test("gRPC registerNode enrolls a node and returns peers",async()=>{
  const {server,client}=await startServer();
  try{
    const response:any=await new Promise((resolve,reject)=>{
      client.registerNode({
        hardwareUuid:"hw-abc-123",wireguardPublicKey:"pubkey-1",
        hardwareAttestationQuote:Buffer.from("quote"),osSignature:"linux-6.8",
        csrDer:generateCsrDer("node-hw-abc-123")
      },(error:Error|null,res:unknown)=>error?reject(error):resolve(res));
    });
    assert.ok(response.internalIpv4.startsWith("10.144."));
    assert.equal(response.assignedZone,"ZONE_PROD_APP");
    assert.ok(Buffer.from(response.signedClientCertificate).length>0);
  }finally{
    server.forceShutdown();
  }
});

// Closes the gap the CORS/dialog/nonce bugs earlier this session all shared:
// a unit test using a stub (DevelopmentCertificateIssuer, above) can't catch
// a wiring bug that only exists once the real dependency is plugged in. This
// drives the actual gRPC transport, the actual CSR-parsing/verification in
// server.ts, and the actual TrustCoreIssuer/ForgeX509Builder/DevKeyProvider
// pipeline production-server.ts and grpc-server.ts now share via
// trust-anchor.ts — the only thing faked is Postgres itself.
class FakeTrustAnchorDb {
  private anchors=new Map<string,{certificate_pem:string;private_key_pem:string}>();
  private issuerId:string|undefined;
  async query(text:string,values:unknown[]=[]){
    if(text.includes("certificate_issuers")){
      this.issuerId??=randomUUID();
      return {rows:[{issuer_id:this.issuerId}]};
    }
    if(text.includes("SELECT")){
      const row=this.anchors.get(values[0] as string);
      return {rows:row?[row]:[]};
    }
    const [keyReference,,certificatePem,privateKeyPem]=values as string[];
    if(!this.anchors.has(keyReference!))this.anchors.set(keyReference!,{certificate_pem:certificatePem!,private_key_pem:privateKeyPem!});
    return {rows:[]};
  }
}
class MemoryRecordStore implements CertificateRecordStore {
  saved:any[]=[];
  async save(record:any){this.saved.push(record);}
  async revoke(){/* not exercised here */}
}

test("gRPC registerNode with the real TrustCoreIssuer issues a certificate binding the CSR's own public key",async()=>{
  const trustAnchor=await loadTrustAnchor(new FakeTrustAnchorDb() as any);
  const records=new MemoryRecordStore();
  const certificateIssuer=new TrustCoreCertificateIssuer(new TrustCoreIssuer(
    trustAnchor.keys,records,new ForgeX509Builder(),
    {id:"test-anchor",certificatePem:trustAnchor.certificatePem,keyReference:trustAnchor.keyReference,algorithm:trustAnchor.algorithm}
  ));
  const store=new MemoryStore();
  const enrollment=new EnrollmentService(
    store,store,store,new AllowAttestation(),certificateIssuer,
    new NoopPeerDistributor(),new RandomIds(),new SystemClock()
  );
  const server=buildMeshGrpcServer({
    enrollment,nodes:store,devices:store,keyRotation:new InMemoryKeyRotationLedger(),
    meshController:new MeshController(new LoggingMeshCommandSink())
  });
  const port=await new Promise<number>((resolve,reject)=>{
    server.bindAsync("127.0.0.1:0",grpc.ServerCredentials.createInsecure(),(error,boundPort)=>{
      if(error)reject(error); else resolve(boundPort);
    });
  });
  const pkgDef=protoLoader.loadSync(PROTO_PATH,{keepCase:false,longs:String,enums:String,defaults:true,oneofs:true});
  const proto=grpc.loadPackageDefinition(pkgDef) as any;
  const client=new proto.bapc.security.v1.MeshOrchestrationService(`127.0.0.1:${port}`,grpc.credentials.createInsecure());
  try{
    const nodeKeys=forge.pki.rsa.generateKeyPair(2048);
    const csr=forge.pki.createCertificationRequest();
    csr.publicKey=nodeKeys.publicKey;
    csr.setSubject([{name:"commonName",value:"node-real-issuer"}]);
    csr.sign(nodeKeys.privateKey,forge.md.sha256.create());
    const csrDer=Buffer.from(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes(),"binary");

    const response:any=await new Promise((resolve,reject)=>{
      client.registerNode({
        hardwareUuid:"hw-real-issuer",wireguardPublicKey:"wg-pubkey-real",
        hardwareAttestationQuote:Buffer.from("quote"),osSignature:"linux-6.8",csrDer
      },(error:Error|null,res:unknown)=>error?reject(error):resolve(res));
    });

    const certPem=Buffer.from(response.signedClientCertificate).toString("utf8");
    assert.notEqual(certPem,"DEVELOPMENT-ONLY");
    const cert=forge.pki.certificateFromPem(certPem);
    const issuerCert=forge.pki.certificateFromPem(trustAnchor.certificatePem);
    assert.equal(issuerCert.verify(cert),true);
    assert.equal(forge.pki.publicKeyToPem(cert.publicKey),forge.pki.publicKeyToPem(nodeKeys.publicKey));
    assert.equal(records.saved.length,1);
  }finally{
    server.forceShutdown();
  }
});

test("gRPC registerNode rejects a request with no CSR",async()=>{
  const {server,client}=await startServer();
  try{
    await assert.rejects(()=>new Promise((resolve,reject)=>{
      client.registerNode({
        hardwareUuid:"hw-no-csr",wireguardPublicKey:"pubkey-no-csr",
        hardwareAttestationQuote:Buffer.from("quote"),osSignature:"linux-6.8"
      },(error:Error|null,res:unknown)=>error?reject(error):resolve(res));
    }),/csr_der is required/);
  }finally{
    server.forceShutdown();
  }
});

test("gRPC rotatePeerKey rejects an unsigned rotation",async()=>{
  const {server,client}=await startServer();
  try{
    const enrolled:any=await new Promise((resolve,reject)=>{
      client.registerNode({
        hardwareUuid:"hw-xyz-9",wireguardPublicKey:"pubkey-2",
        hardwareAttestationQuote:Buffer.from("quote"),osSignature:"windows-11",
        csrDer:generateCsrDer("node-hw-xyz-9")
      },(error:Error|null,res:unknown)=>error?reject(error):resolve(res));
    });
    void enrolled;
    await assert.rejects(()=>new Promise((resolve,reject)=>{
      client.rotatePeerKey({nodeId:"does-not-exist",newPublicKey:"pubkey-3",signature:Buffer.alloc(0)},
        (error:Error|null,res:unknown)=>error?reject(error):resolve(res));
    }));
  }finally{
    server.forceShutdown();
  }
});

test("gRPC streamHeartbeat replies with a NOOP command per heartbeat",async()=>{
  const {server,client}=await startServer();
  try{
    const call=client.streamHeartbeat();
    const received:any[]=[];
    const done=new Promise<void>((resolve)=>{
      call.on("data",(cmd:any)=>{
        received.push(cmd);
        if(received.length===2){call.end();}
      });
      call.on("end",resolve);
    });
    call.write({nodeId:"n1",timestamp:Date.now(),postureHash:Buffer.alloc(0),bytesTransmitted:0,bytesReceived:0});
    call.write({nodeId:"n1",timestamp:Date.now(),postureHash:Buffer.alloc(0),bytesTransmitted:0,bytesReceived:0});
    await done;
    assert.equal(received.length,2);
    assert.equal(received[0].action,"NOOP");
  }finally{
    server.forceShutdown();
  }
});
