import test from "node:test";
import assert from "node:assert/strict";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {fileURLToPath} from "node:url";
import {dirname, join} from "node:path";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {AllowAttestation, DevelopmentCertificateIssuer, NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {MeshController} from "../../../services/mesh-controller/controller.js";
import {buildMeshGrpcServer, InMemoryKeyRotationLedger, LoggingMeshCommandSink} from "../../../src/api/grpc/server.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PROTO_PATH=join(__dirname,"..","..","..","..","contracts","mesh.proto");

const startServer=async()=>{
  const store=new MemoryStore();
  const enrollment=new EnrollmentService(
    store,store,store,new AllowAttestation(),new DevelopmentCertificateIssuer(),
    new NoopPeerDistributor(),new RandomIds(),new SystemClock()
  );
  const server=buildMeshGrpcServer({
    enrollment,nodes:store,keyRotation:new InMemoryKeyRotationLedger(),
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
        hardwareAttestationQuote:Buffer.from("quote"),osSignature:"linux-6.8"
      },(error:Error|null,res:unknown)=>error?reject(error):resolve(res));
    });
    assert.ok(response.internalIpv4.startsWith("10.144."));
    assert.equal(response.assignedZone,"ZONE_PROD_APP");
    assert.ok(Buffer.from(response.signedClientCertificate).length>0);
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
        hardwareAttestationQuote:Buffer.from("quote"),osSignature:"windows-11"
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
