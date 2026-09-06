import {createServer} from "node:http";
import {randomUUID} from "node:crypto";
import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {HttpError} from "../api/rest/errors.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {TransactionalOutbox} from "../infrastructure/postgres/outbox.js";
import {PgIdempotencyStore} from "../api/rest/idempotency.js";
import {PgReplayStore} from "../api/rest/replay-guard.js";
import {HmacBearerGuard} from "../api/rest/guard.js";
import {RestRouter} from "../api/rest/router.js";
import {JitService} from "../application/jit.js";
import {SocService} from "../application/soc.js";
import {ThreatResponseService} from "../application/threat-response.js";
import {SafeApplyService} from "../application/safe-apply.js";
import {RandomIds,SystemClock} from "../infrastructure/memory.js";
import {NoopThreatSink} from "../infrastructure/adapters.js";
import {PgPolicyEnforcer} from "../infrastructure/pg-policy-enforcer.js";
import {PgControlPlaneProbe} from "../infrastructure/pg-control-plane-probe.js";
import {HeartbeatService} from "../application/heartbeat.js";
import {PolicyDecisionService} from "../application/policy.js";
import {HmacDecisionSigner} from "../infrastructure/hmac-decision-signer.js";
import {EcosystemIntegrationService} from "../application/integrations.js";
import {DiagnosticsClearanceVerifier} from "../../integrations/diagnostics-clearance.js";
import {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import {SecuritySocBackend} from "../../apps/security-soc/backend.js";
import {PgSocData} from "../../apps/security-soc/pg-soc-data.js";
import {PgSocActions} from "../../apps/security-soc/pg-soc-actions.js";
import {loadTrustAnchor} from "../../services/trust-core/trust-anchor.js";
import {TrustCoreIssuer} from "../../services/trust-core/issuer.js";
import {ForgeX509Builder} from "../../services/trust-core/x509-forge.js";
import {TrustCoreCertificateIssuer} from "../../services/trust-core/trust-core-certificate-issuer.js";
import {ForgeCrlBuilder} from "../../services/trust-core/crl-builder.js";
import {PgCertificateStore} from "../../services/trust-core/pg-certificate-store.js";
import {loadRelayFleet} from "../../services/relay-fleet/load-relay-fleet.js";
import {PgRelayStore} from "../../services/relay-fleet/pg-relay-store.js";
import {OobController} from "../../services/oob-controller/controller.js";
import {HttpOobChannel} from "../../services/oob-controller/http-channel.js";
import {PgRecoveryStore} from "../../services/oob-controller/pg-recovery-store.js";
import type {NetworkPolicy} from "../domain/types.js";

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
const bus=new TransactionalOutbox(db);
const ids=new RandomIds(),clock=new SystemClock();
const jit=new JitService(repo,ids,clock,bus);
const soc=new SocService(repo,repo,repo,repo,repo,clock);

// PgPolicyEnforcer.isolateNode/restoreNode enqueue into the same durable
// command queue the REST endpoint-agent heartbeat and the mesh-grpc
// streamHeartbeat both drain (see PgMeshCommandSink, src/api/grpc/server.ts),
// so a quarantine actually reaches the node. stage/rollback broadcast a real
// APPLY_FIREWALL/ROLLBACK_FIREWALL command to every active node the same way.
const commandQueue=new PgCommandQueue(db);
const enforcer=new PgPolicyEnforcer(commandQueue,repo);
// SafeApplyService (src/application/safe-apply.ts) existed with no caller
// anywhere in production — a staged policy set had nowhere to be applied
// from and nothing to auto-rollback against. PgControlPlaneProbe checks the
// one thing synchronously verifiable from here (see its own comment for why
// per-node reachability isn't): the database every command-delivery path
// depends on.
const safeApply=new SafeApplyService(enforcer,new PgControlPlaneProbe(db),bus,ids,clock);
const ecosystem=new EcosystemIntegrationService(config.ecosystemSecrets,bus);
const clearance=new DiagnosticsClearanceVerifier(ecosystem);

// The real X.509 issuer: signs with an AWS KMS key when
// AWS_KMS_INTERMEDIATE_KEY_ID is configured, otherwise an ephemeral CA shared
// (via Postgres) with the mesh-grpc process's enrollment path — see
// trust-anchor.ts and [[user-build-everything-coming-soon]]. This replaces
// DevelopmentCertificateIssuer, which returned the literal string
// "DEVELOPMENT-ONLY" as the "certificate" and was never actually connected
// to TrustCoreIssuer/ForgeX509Builder despite both being fully built.
const certificateStore=new PgCertificateStore(db);
const trustAnchor=await loadTrustAnchor(db);
const certificateIssuer=new TrustCoreCertificateIssuer(new TrustCoreIssuer(
  trustAnchor.keys,certificateStore,new ForgeX509Builder(),
  {id:trustAnchor.issuerId,certificatePem:trustAnchor.certificatePem,keyReference:trustAnchor.keyReference,algorithm:trustAnchor.algorithm}
));
const threatResponse=new ThreatResponseService(
  repo,repo,repo,repo,enforcer,certificateIssuer,bus,new NoopThreatSink(),clearance
);

// OobController/PgRecoveryStore/HttpOobChannel existed fully built and
// tested with no caller anywhere — docs/INCIDENT-RESPONSE-RUNBOOK.md's
// "Lost controller" procedure told an operator to call
// `OobController.rollback(scope)` with no route or CLI that could actually
// reach it. HttpOobChannel talks to the separate oob-server.ts process
// (its own port/secret, by design — see that file's own comment) while
// PgRecoveryStore keeps the durable last-known-good record on this side.
const oobController=new OobController(
  new PgRecoveryStore(db),
  new HttpOobChannel(config.oobControllerUrl,config.oobSharedSecret)
);

const heartbeats=new HeartbeatService(repo,repo,bus,clock);
// The zero-trust Policy Decision Point (item #30 in the feature catalog:
// "Separates Policy Decision Points and Policy Enforcement Points"). Signed
// with the same secret PEPs already hold to call this API — see
// HmacDecisionSigner. Was previously defined but never wired into any API,
// which meant the actual access-decision engine had no caller at all.
const policyDecision=new PolicyDecisionService(repo,repo,ids,clock,new HmacDecisionSigner(config.controlApiTokenSecret));
const socBackend=new SecuritySocBackend(
  new PgSocData(db),new PgSocActions(threatResponse,repo,repo,enforcer,bus,ids,clock)
);

const crlBuilder=new ForgeCrlBuilder();
const relayFleet=loadRelayFleet();
const relayStore=new PgRelayStore(db);

const guard=new HmacBearerGuard(config.controlApiTokenSecret);
const router=new RestRouter(guard,new PgIdempotencyStore(db),true,new PgReplayStore(db));

router.add("GET","/api/v1/status",[],async({claims})=>({
  service:"bapc-vpn-security",version:"0.4.0",subject:claims.sub,
  database:await db.health(),environment:config.environment
}));

router.add("GET","/api/v1/nodes",["security-read"],async()=>repo.list());

router.add("GET","/api/v1/policies",["security-read"],async()=>repo.listActive());

router.add("PUT","/api/v1/policies/:id",["security-approver"],async({params,body})=>{
  const policy:NetworkPolicy={
    id:params.id!,name:String(body.name??params.id),
    sourceZones:body.sourceZones??[],destinationZones:body.destinationZones??[],
    protocols:body.protocols??["ANY"],destinationPorts:body.destinationPorts??[],
    action:body.action??"DENY",requiredRoles:body.requiredRoles??[],
    requiresJit:Boolean(body.requiresJit),priority:Number(body.priority??0),
    version:Number(body.version??1),active:body.active!==false
  };
  await repo.save(policy);
  return policy;
},{idempotent:true});

// Pushes the currently-active policy set to every active node as a real
// firewall commit, auto-rolling back if the control plane's own database
// isn't reachable within the window — see SafeApplyService and
// PgPolicyEnforcer.stage/rollback. Previously SafeApplyService had no caller
// anywhere in this file.
router.add("POST","/api/v1/policies/apply",["security-approver"],async({body})=>{
  const policies=await repo.listActive();
  const timeoutMs=Number(body.timeoutMs??config.safeApplyTimeoutMs);
  return safeApply.apply(policies,timeoutMs);
},{rateLimit:{limit:5,windowMs:60_000}});

router.add("GET","/api/v1/events",["security-read"],async({query})=>
  repo.recent(Number(query.get("limit")??"100"))
);

router.add("GET","/api/v1/soc/snapshot",["security-read"],async()=>soc.snapshot());

router.add("GET","/api/v1/soc/snapshot/full",["security-read"],async()=>socBackend.snapshot());

router.add("POST","/api/v1/soc/emergency-lockdown",["security-owner"],async({claims,body})=>
  socBackend.emergencyLockdown(String(body.reason??""),claims.sub,String(body.confirmation??"")),
  {rateLimit:{limit:2,windowMs:60_000},replayProtected:true}
);

// Out-of-band recovery — see docs/INCIDENT-RESPONSE-RUNBOOK.md's "Lost
// controller" procedure. checkpoint pushes a document to the separate OOB
// channel and records it as last-known-good only once the channel itself
// confirms it (OobController.checkpoint refuses if the channel is
// unhealthy or verification fails). rollback restores the last recorded
// last-known-good for a scope — a significant recovery action, gated the
// same as emergency lockdown.
router.add("POST","/api/v1/oob/checkpoint",["security-approver"],async({claims,body})=>{
  if(!body.scope||body.document===undefined)throw new HttpError(400,"scope and document are required","invalid_request");
  return oobController.checkpoint(String(body.scope),body.document,claims.sub);
});

router.add("POST","/api/v1/oob/rollback",["security-owner"],async({body})=>{
  if(!body.scope)throw new HttpError(400,"scope is required","invalid_request");
  return oobController.rollback(String(body.scope));
},{rateLimit:{limit:2,windowMs:60_000}});

// Real X.509 CRL distribution point. Public by design: relying parties
// checking a certificate's revocation status have no prior relationship
// with this API. See docs/INCIDENT-RESPONSE-RUNBOOK.md's certificate-
// compromise procedure — this is what closes "revocation is a DB flag only".
router.add("GET","/api/v1/certificates/crl",[],async()=>{
  const revoked=await certificateStore.listRevoked();
  const now=clock.now();
  const body=await crlBuilder.build({
    issuerCertificatePem:trustAnchor.certificatePem,
    thisUpdate:now,nextUpdate:new Date(now.getTime()+24*3_600_000),
    revoked,sign:tbs=>trustAnchor.keys.sign(trustAnchor.keyReference,"RS256",tbs)
  });
  return {contentType:"application/pkix-crl",body};
},{public:true,raw:true,rateLimit:{limit:120,windowMs:60_000}});

router.add("POST","/api/v1/jit",["security-user"],async({claims,body})=>
  jit.request(
    claims.sub,String(body.targetResource??""),body.targetZone,
    Number(body.durationMinutes) as 15|30|60,String(body.justification??"")
  ),
  {idempotent:true,rateLimit:{limit:20,windowMs:60_000}}
);

router.add("POST","/api/v1/jit/:id/approve",["security-approver"],async({claims,params})=>
  jit.approve(params.id!,claims.sub,claims.roles)
);

router.add("POST","/api/v1/jit/:id/terminate",["security-approver"],async({params,body})=>
  jit.terminate(params.id!,String(body.reason??"terminated by security operator"))
);

router.add("POST","/api/v1/nodes/:id/quarantine",["security-approver"],async({params,body})=>
  threatResponse.handle({
    id:ids.next(),nodeId:params.id!,at:clock.now(),
    severity:"CRITICAL",engine:"soc-manual",type:"MANUAL_QUARANTINE",
    description:String(body.reason??"manual SOC quarantine"),metadata:{score:90}
  }),
  {rateLimit:{limit:10,windowMs:60_000}}
);

router.add("POST","/api/v1/nodes/:id/restore",["security-approver"],async({params,body})=>
  threatResponse.restore(params.id!,String(body.clearanceToken??""))
);

router.add("POST","/api/v1/agent/heartbeat",["security-agent"],async({body})=>{
  const accepted=await heartbeats.accept({
    nodeId:String(body.nodeId),at:new Date(body.at),posture:body.posture,
    bytesTransmitted:Number(body.bytesTransmitted??0),bytesReceived:Number(body.bytesReceived??0),
    agentVersion:String(body.agentVersion??"unknown")
  });
  const commands=await commandQueue.pending(String(body.nodeId));
  return {...accepted,commands};
});

router.add("POST","/api/v1/agent/commands/:id/ack",["security-agent"],async({params,body})=>{
  await commandQueue.acknowledge(params.id!,body.result);
  return {acknowledged:true};
});

// The Policy Enforcement Point call: "can this identity, on this device,
// connecting from this mesh node, reach this resource, right now?" Device
// and node are looked up server-side by ID rather than trusted from the
// request body — accepting client-supplied posture/compromised flags here
// would let a caller simply lie its way past the zero-trust check.
router.add("POST","/api/v1/access/decide",["security-agent"],async({body})=>{
  const device=await repo.get(String(body.deviceId));
  if(!device||!("hardwareId" in device))throw new Error("device not found");
  const node=await repo.get(String(body.nodeId));
  if(!node||!("wireGuardPublicKey" in node))throw new Error("node not found");
  const identity={
    userId:String(body.userId??""),roles:Array.isArray(body.roles)?body.roles:[],
    attributes:typeof body.attributes==="object"&&body.attributes?body.attributes:{},
    mfa:Boolean(body.mfa),sourceIp:String(body.sourceIp??"")
  };
  const resource={
    resource:String(body.resource?.resource??""),zone:body.resource?.zone,
    protocol:body.resource?.protocol??"ANY",
    ...(body.resource?.port?{port:Number(body.resource.port)}:{})
  };
  return policyDecision.decide(identity,device as any,node as any,resource);
},{rateLimit:{limit:300,windowMs:60_000}});

// Real AWS EC2 relay auto-provisioning — see services/relay-fleet/. Returns
// a clear 501 "coming soon" instead of crashing when no AWS account/AMI is
// configured yet; the existing manually-inserted-relay path is unaffected.
router.add("POST","/api/v1/relays/provision",["security-owner"],async({body})=>{
  if(!relayFleet)throw new HttpError(501,"AWS relay auto-provisioning is not configured yet — set AWS_RELAY_AMI_ID and AWS_RELAY_REGION (coming soon)","not_configured");
  const region=String(body.region??relayFleet.region);
  const instanceType=String(body.instanceType??"t3.small");
  const instance=await relayFleet.provisioner.launch({region,instanceType});
  const relayId=randomUUID();
  await relayStore.insert(relayId,region,instance.endpoint,instance.instanceId);
  return {relayId,...instance};
},{rateLimit:{limit:5,windowMs:60_000}});

router.add("POST","/api/v1/relays/:id/terminate",["security-owner"],async({params})=>{
  if(!relayFleet)throw new HttpError(501,"AWS relay auto-provisioning is not configured yet — set AWS_RELAY_AMI_ID and AWS_RELAY_REGION (coming soon)","not_configured");
  const relay=await relayStore.get(params.id!);
  if(!relay)throw new HttpError(404,"relay not found","not_found");
  if(!relay.instanceId)throw new HttpError(400,"this relay has no associated AWS instance to terminate — it was added manually","invalid_request");
  await relayFleet.provisioner.terminate(relay.instanceId);
  await relayStore.remove(relay.relayId);
  return {terminated:true};
},{rateLimit:{limit:5,windowMs:60_000}});

const server=createServer((req,res)=>void router.handle(req,res));
server.requestTimeout=15_000;
server.headersTimeout=10_000;
server.keepAliveTimeout=5_000;

const shutdown=async(signal:string)=>{
  console.log(JSON.stringify({event:"shutdown",signal}));
  server.close(async()=>{await db.close();process.exit(0);});
  setTimeout(()=>process.exit(1),10_000).unref();
};
process.on("SIGTERM",()=>void shutdown("SIGTERM"));
process.on("SIGINT",()=>void shutdown("SIGINT"));

try{
  await db.health();
}catch(error){
  console.error(JSON.stringify({
    event:"fatal",reason:"database unreachable at startup",
    error:error instanceof Error?error.message:String(error)
  }));
  process.exit(1);
}
server.listen(config.port,config.bindHost,()=>{
  console.log(JSON.stringify({
    event:"ready",service:"bapc-vpn-security",version:"0.4.0",
    host:config.bindHost,port:config.port
  }));
});
