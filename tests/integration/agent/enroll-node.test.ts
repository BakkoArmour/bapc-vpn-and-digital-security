import test from "node:test";
import assert from "node:assert/strict";
import forge from "node-forge";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {fileURLToPath} from "node:url";
import {dirname, join} from "node:path";
import {enrollNode, generateWireGuardKeyPair, WIREGUARD_LISTEN_PORT, type EnrollmentGrpcClient} from "../../../src/runtime/enroll-node.js";
import {LinuxPlatformAdapter} from "../../../native/linux/adapter.js";
import type {CommandRunner} from "../../../native/shared/command-runner.js";
import type {PlatformAdapter} from "../../../native/shared/platform-adapter.js";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {DevelopmentCertificateIssuer, NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {DevelopmentAttestationProvider} from "../../../src/infrastructure/attestation/providers.js";
import {MeshController} from "../../../services/mesh-controller/controller.js";
import {buildMeshGrpcServer} from "../../../src/api/grpc/server.js";
import {InMemoryCommandQueue, InMemoryKeyRotationLedger, LoggingMeshCommandSink} from "../grpc/mesh-grpc-test-doubles.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PROTO_PATH=join(__dirname,"..","..","..","..","contracts","mesh.proto");

// enrollNode is the core of the enrollment bootstrap flow this session
// added (src/runtime/enroll-node.ts) — previously nothing in this
// repository ever generated a node's keypair, called registerNode, and
// brought its interface up as one flow. These tests cover both the pure
// logic (fake gRPC client, fake PlatformAdapter — no real network) and the
// real path (a real buildMeshGrpcServer, proving the new node_id field and
// the whole round trip actually work end to end).

class FakePlatform implements PlatformAdapter {
  readonly platform="linux" as const;
  applyWireGuardCalls:unknown[]=[];
  async applyWireGuard(input:unknown){this.applyWireGuardCalls.push(input);}
  async applyPeers(){}
  async rotatePrivateKey(){}
  async applyFirewall(){}
  async rollbackFirewall(){}
  async setKillSwitch(){}
  async setDns(){}
  async isolate(){}
  async restore(){}
  async collectPosture(){return {osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false};}
}

test("generateWireGuardKeyPair produces a valid, distinct WireGuard-format keypair every call",()=>{
  const WG_KEY_RE=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
  const a=generateWireGuardKeyPair(),b=generateWireGuardKeyPair();
  assert.match(a.publicKey,WG_KEY_RE);
  assert.match(a.privateKey,WG_KEY_RE);
  assert.notEqual(a.publicKey,b.publicKey);
  assert.notEqual(a.privateKey,a.publicKey);
});

test("a generated WireGuard keypair is accepted by LinuxPlatformAdapter's own key validation",async()=>{
  const wg=generateWireGuardKeyPair();
  const calls:Array<{cmd:string;args:string[]}>=[];
  const fakeRun:CommandRunner=async(cmd,args)=>{
    calls.push({cmd,args});
    if(cmd==="ip"&&args[0]==="link"&&args[1]==="show")throw new Error("no such device");
    return {stdout:"",stderr:""};
  };
  const adapter=new LinuxPlatformAdapter("bapc0",fakeRun);
  await adapter.applyWireGuard({privateKeyReference:wg.privateKey,addresses:["10.144.0.5/32"],peers:[{publicKey:wg.publicKey,allowedIps:["10.144.0.6/32"],keepaliveSeconds:25}]});
  assert.ok(calls.some(c=>c.cmd==="wg"));
});

test("enrollNode registers with the correct request shape and applies the resulting config locally",async()=>{
  const registerNodeCalls:unknown[]=[];
  const client:EnrollmentGrpcClient={
    registerNode:async(request)=>{
      registerNodeCalls.push(request);
      return {
        internalIpv4:"10.144.0.9",internalIpv6:"fd14:4b41:5043::9",
        initialPeers:[{publicKey:"peer-pubkey",endpoint:"relay.example:51820",allowedIps:["10.144.0.2/32"],keepaliveInterval:25}],
        signedClientCertificate:Buffer.from("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n","utf8"),
        assignedZone:"ZONE_PROD_APP",nodeId:"node-123"
      };
    }
  };
  const platform=new FakePlatform();
  const result=await enrollNode(client,platform,{hardwareUuid:"hw-abc",osSignature:"Linux 6.8.0"});

  assert.equal(registerNodeCalls.length,1);
  const req=registerNodeCalls[0] as any;
  assert.equal(req.hardwareUuid,"hw-abc");
  assert.equal(req.osSignature,"Linux 6.8.0");
  assert.equal(req.hardwareAttestationQuote.length,0);
  assert.ok(req.wireguardPublicKey.length>0);
  assert.ok(req.csrDer.length>0);
  const csr=forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(req.csrDer.toString("binary"))));
  assert.equal(csr.verify(),true);

  assert.equal(result.nodeId,"node-123");
  assert.equal(result.assignedZone,"ZONE_PROD_APP");
  assert.match(result.certificatePem,/BEGIN CERTIFICATE/);
  assert.equal(platform.applyWireGuardCalls.length,1);
  const applied=platform.applyWireGuardCalls[0] as any;
  assert.equal(applied.privateKeyReference,result.wireGuardPrivateKey);
  assert.deepEqual(applied.addresses,["10.144.0.9/32","fd14:4b41:5043::9/128"]);
  assert.equal(applied.listenPort,WIREGUARD_LISTEN_PORT);
  assert.equal(applied.peers[0].publicKey,"peer-pubkey");
  assert.equal(applied.peers[0].endpoint,"relay.example:51820");
});

test("enrollNode throws clearly if the control plane doesn't return a node_id (older mesh.proto)",async()=>{
  const client:EnrollmentGrpcClient={
    registerNode:async()=>({
      internalIpv4:"10.144.0.9",internalIpv6:"fd14::9",initialPeers:[],
      signedClientCertificate:Buffer.from(""),assignedZone:"ZONE_PROD_APP",nodeId:""
    })
  };
  await assert.rejects(()=>enrollNode(client,new FakePlatform(),{hardwareUuid:"hw-1",osSignature:"Linux"}),/node_id/);
});

test("enrollNode against a real mesh-grpc server returns a real node_id and applies the config locally",async()=>{
  const store=new MemoryStore();
  const enrollment=new EnrollmentService(
    store,store,store,new DevelopmentAttestationProvider(),new DevelopmentCertificateIssuer(),
    new NoopPeerDistributor(),new RandomIds(),new SystemClock()
  );
  const server=buildMeshGrpcServer({
    enrollment,nodes:store,devices:store,keyRotation:new InMemoryKeyRotationLedger(),
    meshController:new MeshController(new LoggingMeshCommandSink()),commands:new InMemoryCommandQueue()
  });
  const port=await new Promise<number>((resolve,reject)=>{
    server.bindAsync("127.0.0.1:0",grpc.ServerCredentials.createInsecure(),(error,boundPort)=>{
      if(error)reject(error); else resolve(boundPort);
    });
  });
  try{
    const pkgDef=protoLoader.loadSync(PROTO_PATH,{keepCase:false,longs:String,enums:String,defaults:true,oneofs:true});
    const proto=grpc.loadPackageDefinition(pkgDef) as any;
    const rawClient=new proto.bapc.security.v1.MeshOrchestrationService(`127.0.0.1:${port}`,grpc.credentials.createInsecure());
    const client:EnrollmentGrpcClient={
      registerNode:(request)=>new Promise((resolve,reject)=>{
        rawClient.registerNode(request,(error:Error|null,response:unknown)=>error?reject(error):resolve(response as any));
      })
    };
    const platform=new FakePlatform();
    const result=await enrollNode(client,platform,{hardwareUuid:"hw-real-enroll",osSignature:"Linux 6.8.0"});
    assert.ok(result.nodeId.length>0);
    assert.equal(result.assignedZone,"ZONE_PROD_APP");
    assert.equal(platform.applyWireGuardCalls.length,1);
  }finally{
    server.forceShutdown();
  }
});
