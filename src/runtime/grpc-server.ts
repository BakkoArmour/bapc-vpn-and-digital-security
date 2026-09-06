import * as grpc from "@grpc/grpc-js";
import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {TransactionalOutbox} from "../infrastructure/postgres/outbox.js";
import {RandomIds, SystemClock} from "../infrastructure/memory.js";
import {AllowAttestation, NoopPeerDistributor} from "../infrastructure/adapters.js";
import {EnrollmentService} from "../application/enrollment.js";
import {MeshController} from "../../services/mesh-controller/controller.js";
import {buildMeshGrpcServer, InMemoryKeyRotationLedger, LoggingMeshCommandSink} from "../api/grpc/server.js";
import {loadTrustAnchor} from "../../services/trust-core/trust-anchor.js";
import {TrustCoreIssuer} from "../../services/trust-core/issuer.js";
import {ForgeX509Builder} from "../../services/trust-core/x509-forge.js";
import {TrustCoreCertificateIssuer} from "../../services/trust-core/trust-core-certificate-issuer.js";
import {PgCertificateStore} from "../../services/trust-core/pg-certificate-store.js";

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
void new TransactionalOutbox(db); // reserved for future signed enrollment events over the outbox

// Real X.509 issuance for node enrollment — shares the same AWS KMS key or
// Postgres-persisted ephemeral CA that production-server.ts's CRL/threat-
// response paths use (see trust-anchor.ts), so certificates issued here
// chain-verify against that CRL and against each other. AllowAttestation and
// NoopPeerDistributor remain development-only: production deployments still
// need real hardware attestation and a PeerDistributor bound to the endpoint
// agent command channel.
const trustAnchor=await loadTrustAnchor(db);
const certificateIssuer=new TrustCoreCertificateIssuer(new TrustCoreIssuer(
  trustAnchor.keys,new PgCertificateStore(db),new ForgeX509Builder(),
  {id:trustAnchor.issuerId,certificatePem:trustAnchor.certificatePem,keyReference:trustAnchor.keyReference,algorithm:trustAnchor.algorithm}
));
const enrollment=new EnrollmentService(
  repo,repo,repo,new AllowAttestation(),certificateIssuer,
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
