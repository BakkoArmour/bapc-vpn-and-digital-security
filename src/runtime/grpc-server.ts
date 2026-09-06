import * as grpc from "@grpc/grpc-js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {TransactionalOutbox} from "../infrastructure/postgres/outbox.js";
import {RandomIds, SystemClock} from "../infrastructure/memory.js";
import {AllowAttestation, DevelopmentCertificateIssuer, NoopPeerDistributor} from "../infrastructure/adapters.js";
import {EnrollmentService} from "../application/enrollment.js";
import {MeshController} from "../../services/mesh-controller/controller.js";
import {buildMeshGrpcServer, InMemoryKeyRotationLedger, LoggingMeshCommandSink} from "../api/grpc/server.js";

const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
void new TransactionalOutbox(db); // reserved for future signed enrollment events over the outbox

// Development-only attestation/certificate/peer adapters. Production deployments
// MUST replace these with hardware attestation, an HSM-backed TrustCoreIssuer and
// a real PeerDistributor bound to the endpoint agent command channel.
const enrollment=new EnrollmentService(
  repo,repo,repo,new AllowAttestation(),new DevelopmentCertificateIssuer(),
  new NoopPeerDistributor(),new RandomIds(),new SystemClock()
);

const grpcServer=buildMeshGrpcServer({
  enrollment,
  nodes:repo,
  keyRotation:new InMemoryKeyRotationLedger(),
  meshController:new MeshController(new LoggingMeshCommandSink())
});

const grpcPort=Number(process.env.GRPC_PORT??50051);
grpcServer.bindAsync(
  `${config.bindHost}:${grpcPort}`,
  grpc.ServerCredentials.createInsecure(),
  (error,port)=>{
    if(error){console.error(JSON.stringify({event:"grpc.bind_failed",error:error.message}));process.exit(1);}
    console.log(JSON.stringify({event:"ready",service:"bapc-mesh-grpc",port}));
  }
);

const shutdown=()=>{grpcServer.tryShutdown(()=>void db.close());};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
