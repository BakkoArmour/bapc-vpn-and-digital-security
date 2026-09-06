import * as grpc from "@grpc/grpc-js";
import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {TransactionalOutbox} from "../infrastructure/postgres/outbox.js";
import {RandomIds, SystemClock} from "../infrastructure/memory.js";
import {AllowAttestation} from "../infrastructure/adapters.js";
import {EnrollmentService} from "../application/enrollment.js";
import {MeshController} from "../../services/mesh-controller/controller.js";
import {buildMeshGrpcServer} from "../api/grpc/server.js";
import {PgKeyRotationLedger} from "../../services/mesh-controller/pg-key-rotation-ledger.js";
import {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import {PgMeshCommandSink} from "../../services/mesh-controller/pg-mesh-command-sink.js";
import {MeshControllerPeerDistributor} from "../../services/mesh-controller/mesh-controller-peer-distributor.js";
import {loadTrustAnchor} from "../../services/trust-core/trust-anchor.js";
import {TrustCoreIssuer} from "../../services/trust-core/issuer.js";
import {ForgeX509Builder} from "../../services/trust-core/x509-forge.js";
import {TrustCoreCertificateIssuer} from "../../services/trust-core/trust-core-certificate-issuer.js";
import {PgCertificateStore} from "../../services/trust-core/pg-certificate-store.js";
import {PgRelayStore} from "../../services/relay-fleet/pg-relay-store.js";

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
void new TransactionalOutbox(db); // reserved for future signed enrollment events over the outbox

// Real X.509 issuance for node enrollment — shares the same AWS KMS key or
// Postgres-persisted ephemeral CA that production-server.ts's CRL/threat-
// response paths use (see trust-anchor.ts), so certificates issued here
// chain-verify against that CRL and against each other. AllowAttestation
// remains development-only: production deployments still need real
// hardware attestation.
const trustAnchor=await loadTrustAnchor(db);
const certificateIssuer=new TrustCoreCertificateIssuer(new TrustCoreIssuer(
  trustAnchor.keys,new PgCertificateStore(db),new ForgeX509Builder(),
  {id:trustAnchor.issuerId,certificatePem:trustAnchor.certificatePem,keyReference:trustAnchor.keyReference,algorithm:trustAnchor.algorithm}
));

const commandQueue=new PgCommandQueue(db);
// RelayRoutingService existed fully built and tested with no caller
// anywhere — reconcile's relayEndpoint parameter had no real supplier, so
// mesh topology was always DIRECT even when a healthy relay was actually
// registered and heartbeating. PgRelayStore.candidates() is real
// (relays.load_percent/latency_ms/last_heartbeat, previously never
// written to either — see PgRelayStore's own comment).
const meshController=new MeshController(new PgMeshCommandSink(commandQueue),new PgRelayStore(db));
// EnrollmentService.register calls peers.configure(newNode, existingPeers)
// right after enrolling — previously NoopPeerDistributor, so every node
// already active before a new one joined never learned about it. Reuses
// the same MeshController (and therefore the same PgMeshCommandSink
// delivery) registerNode/rotatePeerKey already push topology updates
// through, so a newly-enrolled peer reaches everyone the same way a
// rotation does.
const enrollment=new EnrollmentService(
  repo,repo,repo,new AllowAttestation(),certificateIssuer,
  new MeshControllerPeerDistributor(meshController),new RandomIds(),new SystemClock()
);

const grpcServer=buildMeshGrpcServer({
  enrollment,
  nodes:repo,
  devices:repo,
  keyRotation:new PgKeyRotationLedger(db),
  meshController,
  commands:commandQueue
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
