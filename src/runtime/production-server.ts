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
import {AuditService} from "../application/audit.js";
import {RandomIds,SystemClock,Sha256} from "../infrastructure/memory.js";
import {NoopThreatSink} from "../infrastructure/adapters.js";
import {PgPolicyEnforcer} from "../infrastructure/pg-policy-enforcer.js";
import {PgControlPlaneProbe} from "../infrastructure/pg-control-plane-probe.js";
import {HeartbeatService} from "../application/heartbeat.js";
import {PolicyDecisionService} from "../application/policy.js";
import {HmacDecisionSigner} from "../infrastructure/hmac-decision-signer.js";
import {EcosystemIntegrationService} from "../application/integrations.js";
import {DiagnosticsClearanceVerifier} from "../../integrations/diagnostics-clearance.js";
import {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import {PgRolloutStore} from "../infrastructure/pg-rollout-store.js";
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
import {ThreatEngine, type ThreatSignal} from "../../services/threat-engine/engine.js";
import {ThreatCorrelator} from "../../services/threat-engine/correlator.js";
import {PgThreatSignalStore} from "../../services/threat-engine/pg-threat-signal-store.js";
import {PgThreatActionPort} from "../../services/threat-engine/pg-threat-action-port.js";
import {PgIncidentPort} from "../../services/threat-engine/pg-incident-port.js";
import {EgressSelector} from "../../services/egress/selector.js";
import {PgEgressStore} from "../../services/egress/pg-egress-store.js";
import {MeshController} from "../../services/mesh-controller/controller.js";
import {PgMeshCommandSink} from "../../services/mesh-controller/pg-mesh-command-sink.js";
import {PgDesiredStateStore} from "../../services/mesh-controller/pg-desired-state-store.js";
import {NodeReconciliationService} from "../application/node-reconciliation.js";
import type {NetworkPolicy} from "../domain/types.js";

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
const bus=new TransactionalOutbox(db);
const ids=new RandomIds(),clock=new SystemClock();
// AuditService existed fully built and tested with no caller anywhere, and
// AuditRepository.chain() (formerly named list(), colliding with
// NodeRepository/DeviceRepository's own list() on this same repo class —
// see src/ports/repositories.ts) meant verify() silently walked an empty
// array and always returned true even before that. Nothing in this
// process wrote to the tamper-evident audit_chain table at all until now.
const audit=new AuditService(repo,new Sha256(),clock);
const jit=new JitService(repo,ids,clock,bus);
const soc=new SocService(repo,repo,repo,repo,repo,clock);

// PgPolicyEnforcer.isolateNode/restoreNode enqueue into the same durable
// command queue the REST endpoint-agent heartbeat and the mesh-grpc
// streamHeartbeat both drain (see PgMeshCommandSink, src/api/grpc/server.ts),
// so a quarantine actually reaches the node. stage/rollback broadcast a real
// APPLY_FIREWALL/ROLLBACK_FIREWALL command to every active node the same way.
const commandQueue=new PgCommandQueue(db);
const enforcer=new PgPolicyEnforcer(commandQueue,repo,db);
// SafeApplyService (src/application/safe-apply.ts) existed with no caller
// anywhere in production — a staged policy set had nowhere to be applied
// from and nothing to auto-rollback against. PgControlPlaneProbe checks the
// control plane's own database, but success is no longer based on that
// alone: PgRolloutStore verifies each targeted node's real
// command_acknowledgements before a rollout is allowed to commit — see
// SafeApplyService's own comment for why "Postgres is healthy" was never
// sufficient proof that a policy actually reached and applied on any node.
const rolloutStore=new PgRolloutStore(db);
const safeApply=new SafeApplyService(
  enforcer,new PgControlPlaneProbe(db),bus,ids,clock,rolloutStore,config.safeApplyNodeFailureThreshold
);
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

// ThreatEngine/ThreatCorrelator existed fully built and tested (sliding-
// window correlation of repeated weak signals into an escalating
// evaluation) with no caller anywhere — ThreatResponseService above scores
// one event at a time and has no memory across calls, so "5 weak signals in
// 2 minutes" never became anything more than 5 separate low-severity
// results. rotateMeshIdentity is the one action that can't just delegate to
// an existing real implementation: see PgThreatActionPort's own comment for
// why it enqueues a command instead of rotating anything itself.
const threatActionPort=new PgThreatActionPort(repo,repo,enforcer,certificateStore,commandQueue,bus);
const incidentPort=new PgIncidentPort(db,repo,ids,clock);
const threatEngine=new ThreatEngine(threatActionPort,incidentPort);
const THREAT_CORRELATION_WINDOW_MS=300_000;
// PgThreatSignalStore (not the default in-memory one): without it, every
// control-plane restart silently erased any un-escalated signal history a
// node had built up, resetting its correlation window for free — see
// threat-signal-store.ts / db/017_threat_signal_window.sql.
const threatSignalStore=new PgThreatSignalStore(db);
const threatCorrelator=new ThreatCorrelator(threatEngine,THREAT_CORRELATION_WINDOW_MS,{
  record:async(nodeId,dismissedBy,signalCount)=>{await audit.record(dismissedBy,"THREAT_DISMISSED",nodeId,{signalCount});}
},threatSignalStore);

// OobController/PgRecoveryStore/HttpOobChannel existed fully built and
// tested with no caller anywhere — docs/INCIDENT-RESPONSE-RUNBOOK.md's
// "Lost controller" procedure told an operator to call
// `OobController.rollback(scope)` with no route or CLI that could actually
// reach it. HttpOobChannel talks to the separate oob-server.ts process
// (its own port/secret, by design — see that file's own comment) while
// PgRecoveryStore keeps the durable last-known-good record on this side.
const oobChannel=new HttpOobChannel(config.oobControllerUrl,config.oobSharedSecret);
const recoveryStore=new PgRecoveryStore(db);
const oobController=new OobController(recoveryStore,oobChannel);

const heartbeats=new HeartbeatService(repo,repo,bus,clock);
// The zero-trust Policy Decision Point (item #30 in the feature catalog:
// "Separates Policy Decision Points and Policy Enforcement Points"). Signed
// with the same secret PEPs already hold to call this API — see
// HmacDecisionSigner. Was previously defined but never wired into any API,
// which meant the actual access-decision engine had no caller at all.
const policyDecision=new PolicyDecisionService(repo,repo,ids,clock,new HmacDecisionSigner(config.controlApiTokenSecret),config.authorizationRefreshMs);
const socBackend=new SecuritySocBackend(
  new PgSocData(db),new PgSocActions(threatResponse,repo,repo,enforcer,bus,ids,clock)
);

const crlBuilder=new ForgeCrlBuilder();
const relayFleet=loadRelayFleet();
const relayStore=new PgRelayStore(db);
// EgressSelector existed fully built and tested with nothing to select
// from — unlike relays, egress gateways had no registry at all
// (db/014_egress_gateways.sql is new). Modeled directly on the relay
// registration/heartbeat pattern above.
const egressStore=new PgEgressStore(db);
const egressSelector=new EgressSelector();

// RECONCILE (src/agent/reconciler.ts) and its siblings (SET_DNS,
// SET_KILL_SWITCH, APPLY_PEERS, APPLY_FIREWALL) had real, fully-tested node-
// side consumers with no producer anywhere on the control plane: nothing
// ever tracked what a node's routes/DNS/kill-switch/topology/policy version
// SHOULD be, so nothing could ever detect that a node had drifted from it
// and needed a correction. node_desired_state (db/016) is that record;
// NodeReconciliationService is the comparison + correction logic — see its
// own file for exactly what each dimension checks and why. relayStore
// doubles as this MeshController's RelayCandidateSource, same as the
// mesh-grpc process's own MeshController (src/api/grpc/server.ts).
const desiredStateStore=new PgDesiredStateStore(db);
const meshController=new MeshController(new PgMeshCommandSink(commandQueue),relayStore);
const nodeReconciliation=new NodeReconciliationService(repo,repo,desiredStateStore,commandQueue,meshController,db);

const guard=new HmacBearerGuard(config.controlApiTokenSecret);
const router=new RestRouter(guard,new PgIdempotencyStore(db),true,new PgReplayStore(db));

// Was previously registered with an empty roles array and no explicit
// {public:true} — HmacBearerGuard.verify still required a validly-signed,
// unexpired bearer token (so this was never actually reachable
// unauthenticated), but any authenticated caller could reach it regardless
// of role, which is indistinguishable from a real authorization gap without
// reading the guard's own role-check short-circuit. security-read matches
// every other read-only diagnostic route in this file.
router.add("GET","/api/v1/status",["security-read"],async({claims})=>({
  service:"bapc-vpn-security",version:"0.4.0",subject:claims.sub,
  database:await db.health(),environment:config.environment
}));

router.add("GET","/api/v1/nodes",["security-read"],async()=>repo.list());

router.add("GET","/api/v1/policies",["security-read"],async()=>repo.listActive());

router.add("PUT","/api/v1/policies/:id",["security-approver"],async({claims,params,body})=>{
  const policy:NetworkPolicy={
    id:params.id!,name:String(body.name??params.id),
    sourceZones:body.sourceZones??[],destinationZones:body.destinationZones??[],
    protocols:body.protocols??["ANY"],destinationPorts:body.destinationPorts??[],
    action:body.action??"DENY",requiredRoles:body.requiredRoles??[],
    requiresJit:Boolean(body.requiresJit),priority:Number(body.priority??0),
    version:Number(body.version??1),active:body.active!==false
  };
  await repo.save(policy);
  await audit.record(claims.sub,"POLICY_UPDATED",policy.id,{name:policy.name,action:policy.action,active:policy.active});
  return policy;
},{idempotent:true});

// Pushes the currently-active policy set to every active node as a real
// firewall commit, auto-rolling back if the control plane's own database
// isn't reachable within the window — see SafeApplyService and
// PgPolicyEnforcer.stage/rollback. Previously SafeApplyService had no caller
// anywhere in this file.
// config.oobRequired (OOB_REQUIRED) was loaded but never read anywhere —
// docs/SECURITY-RUNBOOK.md's "Establish the OOB channel before applying
// the first mesh firewall policy" and CODE-ADDENDUM-INTEGRATION.md's
// "Establish and verify OOB control before committing production
// firewall/mesh changes" had no code actually enforcing either. A firewall
// push that goes wrong is exactly the scenario the OOB channel exists to
// recover from — pushing one while that channel is already down means a
// bad policy has no independent recovery path at all.
router.add("POST","/api/v1/policies/apply",["security-approver"],async({claims,body})=>{
  if(config.oobRequired&&!(await oobChannel.healthy())){
    throw new HttpError(503,"OOB recovery channel is unreachable — refusing to apply a policy change with no independent recovery path (set OOB_REQUIRED=false to override)","oob_unavailable");
  }
  const policies=await repo.listActive();
  const timeoutMs=Number(body.timeoutMs??config.safeApplyTimeoutMs);
  const result=await safeApply.apply(policies,timeoutMs,claims.sub);
  await audit.record(claims.sub,"POLICY_APPLIED","network-policies",{commitId:result.commitId,status:result.status,policyCount:policies.length});
  return result;
},{rateLimit:{limit:5,windowMs:60_000}});

// Per-node verification detail behind a POLICY_APPLIED result — policy_
// commits.status alone only ever said COMMITTED/ROLLED_BACK at the fleet
// level; this is what the SOC console's policy-commit-status panel reads to
// show which nodes actually applied a rollout versus which one triggered a
// rollback (see PgRolloutStore / policy_rollout_nodes).
router.add("GET","/api/v1/policies/:commitId/rollout",["security-read"],async({params})=>
  rolloutStore.summary(params.commitId!)
);

router.add("GET","/api/v1/events",["security-read"],async({query})=>
  repo.recent(Number(query.get("limit")??"100"))
);

// The tamper-evident hash chain every privileged route above now writes to
// (audit.record) — previously nothing ever wrote to it, and verify() was
// silently broken besides (see AuditRepository.chain()'s comment).
router.add("GET","/api/v1/audit",["security-read"],async()=>repo.chain());
router.add("GET","/api/v1/audit/verify",["security-read"],async()=>({valid:await audit.verify()}));

router.add("GET","/api/v1/soc/snapshot",["security-read"],async()=>soc.snapshot());

router.add("GET","/api/v1/soc/snapshot/full",["security-read"],async()=>socBackend.snapshot());

router.add("POST","/api/v1/soc/emergency-lockdown",["security-owner"],async({claims,body})=>{
  const result=await socBackend.emergencyLockdown(String(body.reason??""),claims.sub,String(body.confirmation??""));
  await audit.record(claims.sub,"EMERGENCY_LOCKDOWN","ecosystem",{reason:String(body.reason??"")});
  return result;
},{rateLimit:{limit:2,windowMs:60_000},replayProtected:true});

// Out-of-band recovery — see docs/INCIDENT-RESPONSE-RUNBOOK.md's "Lost
// controller" procedure. checkpoint pushes a document to the separate OOB
// channel and records it as last-known-good only once the channel itself
// confirms it (OobController.checkpoint refuses if the channel is
// unhealthy or verification fails). rollback restores the last recorded
// last-known-good for a scope — a significant recovery action, gated the
// same as emergency lockdown.
router.add("POST","/api/v1/oob/checkpoint",["security-approver"],async({claims,body})=>{
  if(!body.scope||body.document===undefined)throw new HttpError(400,"scope and document are required","invalid_request");
  const snapshot=await oobController.checkpoint(String(body.scope),body.document,claims.sub);
  await audit.record(claims.sub,"OOB_CHECKPOINT",String(body.scope),{snapshotId:snapshot.id,checksum:snapshot.checksum});
  return snapshot;
});

router.add("POST","/api/v1/oob/rollback",["security-owner"],async({claims,body})=>{
  if(!body.scope)throw new HttpError(400,"scope is required","invalid_request");
  const result=await oobController.rollback(String(body.scope));
  await audit.record(claims.sub,"OOB_ROLLBACK",String(body.scope),result);
  return result;
},{rateLimit:{limit:2,windowMs:60_000}});

// Read-only recovery posture for the SOC console — channel health plus
// every scope's current last-known-good snapshot, without triggering a
// checkpoint or rollback (both of which are real, gated actions above).
router.add("GET","/api/v1/oob/status",["security-read"],async()=>({
  healthy:await oobChannel.healthy(),lastKnownGood:await recoveryStore.listLastKnownGood()
}));

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

router.add("POST","/api/v1/jit/:id/approve",["security-approver"],async({claims,params})=>{
  const result=await jit.approve(params.id!,claims.sub,claims.roles);
  await audit.record(claims.sub,"JIT_APPROVED",params.id!,{});
  return result;
});

router.add("POST","/api/v1/jit/:id/terminate",["security-approver"],async({claims,params,body})=>{
  const reason=String(body.reason??"terminated by security operator");
  const result=await jit.terminate(params.id!,reason);
  await audit.record(claims.sub,"JIT_TERMINATED",params.id!,{reason});
  return result;
});

// mesh_nodes.region (db/019_mesh_node_region.sql) — a geographic placement,
// deliberately separate from `zone` (a security classification). Nothing in
// the enrollment flow (src/api/grpc/server.ts) knows a device's real-world
// location, so this is the only way a node's region is ever set; until an
// operator calls this, RelayRoutingService/MeshController correctly treat
// the node as having no known region rather than guessing one.
router.add("PUT","/api/v1/nodes/:id/region",["security-approver"],async({claims,params,body})=>{
  const region=String(body.region??"").trim();
  if(!region)throw new HttpError(400,"region is required","invalid_request");
  const node=await repo.get(params.id!);
  if(!node||!("wireGuardPublicKey" in node))throw new HttpError(404,"node not found","not_found");
  await repo.save({...(node as any),region});
  await audit.record(claims.sub,"NODE_REGION_SET",params.id!,{region});
  return {nodeId:params.id!,region};
},{idempotent:true});

router.add("POST","/api/v1/nodes/:id/quarantine",["security-approver"],async({claims,params,body})=>{
  const reason=String(body.reason??"manual SOC quarantine");
  const result=await threatResponse.handle({
    id:ids.next(),nodeId:params.id!,at:clock.now(),
    severity:"CRITICAL",engine:"soc-manual",type:"MANUAL_QUARANTINE",
    description:reason,metadata:{score:90}
  });
  await audit.record(claims.sub,"NODE_QUARANTINED",params.id!,{reason});
  return result;
},{rateLimit:{limit:10,windowMs:60_000}});

router.add("POST","/api/v1/nodes/:id/restore",["security-approver"],async({claims,params,body})=>{
  const result=await threatResponse.restore(params.id!,String(body.clearanceToken??""));
  await audit.record(claims.sub,"NODE_RESTORED",params.id!,{});
  return result;
});

// PlatformAdapter.setKillSwitch/setDns and ProductionAgent.execute's
// SET_KILL_SWITCH/SET_DNS cases were fully implemented on the agent side
// with nothing anywhere that ever enqueued either command — a node could
// receive and correctly act on them, but no operator or service could ever
// actually send one.
// controller_commands.node_id is a real foreign key into mesh_nodes — a
// stale/mistyped node id here (an operator's typo, a since-deleted node)
// previously violated it and crashed the request with an opaque 500 instead
// of a clean 404. Found live against the running API. Same existence check
// PUT /api/v1/nodes/:id/desired-state already uses below.
router.add("POST","/api/v1/nodes/:id/kill-switch",["security-approver"],async({claims,params,body})=>{
  const node=await repo.get(params.id!);
  if(!node||!("wireGuardPublicKey" in node))throw new HttpError(404,"node not found","not_found");
  const enabled=Boolean(body.enabled);
  await commandQueue.enqueue(params.id!,"SET_KILL_SWITCH",{enabled});
  await audit.record(claims.sub,"KILL_SWITCH_SET",params.id!,{enabled});
  return {queued:true,enabled};
});

router.add("POST","/api/v1/nodes/:id/dns",["security-approver"],async({claims,params,body})=>{
  const node=await repo.get(params.id!);
  if(!node||!("wireGuardPublicKey" in node))throw new HttpError(404,"node not found","not_found");
  const servers=Array.isArray(body.servers)?body.servers.map(String):[];
  if(servers.length===0)throw new HttpError(400,"servers (non-empty array) is required","invalid_request");
  await commandQueue.enqueue(params.id!,"SET_DNS",{servers});
  await audit.record(claims.sub,"DNS_SET",params.id!,{servers});
  return {queued:true,servers};
});

// node_desired_state (db/016_node_desired_state.sql) — the control plane's
// record of what a node's routes/DNS/kill-switch/integrity files SHOULD be.
// Every field is replaced wholesale (PUT semantics, matching PUT
// /api/v1/policies/:id above) and revision always increments even when the
// new values match the old ones — see PgDesiredStateStore.upsert's own
// comment for why that's deliberate.
router.add("PUT","/api/v1/nodes/:id/desired-state",["security-approver"],async({claims,params,body})=>{
  const node=await repo.get(params.id!);
  if(!node||!("wireGuardPublicKey" in node))throw new HttpError(404,"node not found","not_found");
  const routes=Array.isArray(body.routes)?body.routes:[];
  const dnsServers=Array.isArray(body.dnsServers)?body.dnsServers.map(String):[];
  const integrityFiles=typeof body.integrityFiles==="object"&&body.integrityFiles?body.integrityFiles:{};
  const state=await desiredStateStore.upsert(params.id!,{
    routes,dnsServers,killSwitchEnabled:Boolean(body.killSwitchEnabled),integrityFiles
  },claims.sub);
  await audit.record(claims.sub,"DESIRED_STATE_SET",params.id!,{revision:state.revision});
  return state;
},{idempotent:true});

router.add("GET","/api/v1/nodes/:id/desired-state",["security-read"],async({params})=>{
  const state=await desiredStateStore.get(params.id!);
  if(!state)throw new HttpError(404,"no desired state configured for this node","not_found");
  return state;
});

// On-demand drift check: compares this node's desired state against what it
// last actually reported (via command_acknowledgements) for each dimension
// NodeReconciliationService knows about, and issues whatever corrective
// commands are needed right now rather than waiting for the maintenance
// worker's next periodic pass (src/runtime/maintenance-worker.ts).
router.add("POST","/api/v1/nodes/:id/reconcile",["security-approver"],async({claims,params})=>{
  const result=await nodeReconciliation.checkNode(params.id!);
  const drifted=result.checked.filter(c=>c.drifted);
  if(drifted.length>0){
    await audit.record(claims.sub,"NODE_RECONCILED",params.id!,{
      corrected:drifted.map(d=>({dimension:d.dimension,correctedBy:d.correctedBy}))
    });
  }
  return result;
},{rateLimit:{limit:30,windowMs:60_000}});

router.add("POST","/api/v1/agent/heartbeat",["security-agent"],async({body})=>{
  const accepted=await heartbeats.accept({
    nodeId:String(body.nodeId),at:new Date(body.at),posture:body.posture,
    bytesTransmitted:Number(body.bytesTransmitted??0),bytesReceived:Number(body.bytesReceived??0),
    agentVersion:String(body.agentVersion??"unknown")
  });
  // A single posture failure is rarely urgent on its own — a transient
  // firewall toggle, a delayed OS update — but repeated ones from the same
  // node are exactly the "weak signal, correlate over time" case
  // ThreatCorrelator exists for. weight:15/confidence:1 matches the profile
  // already covered by ThreatCorrelator's own tests: 5 within the window
  // reach CRITICAL (score 75), any single one alone stays INFO (15).
  if(!accepted.compliant){
    await threatCorrelator.ingest({
      nodeId:String(body.nodeId),kind:"posture_failure",confidence:1,weight:15,
      at:clock.now(),metadata:{posture:body.posture}
    });
  }
  const commands=await commandQueue.pending(String(body.nodeId));
  return {...accepted,commands};
});

// A general-purpose ingestion point for anything else that produces a weak
// security signal but runs as its own process and so can't call
// threatCorrelator.ingest() in-process — DNS sinkhole hits
// (src/runtime/dns-server.ts), repeated access-decide denials, etc.
router.add("POST","/api/v1/threats/signal",["security-agent"],async({body})=>{
  const signal:ThreatSignal={
    ...(body.nodeId?{nodeId:String(body.nodeId)}:{}),
    kind:String(body.kind??"unknown"),
    confidence:Math.max(0,Math.min(1,Number(body.confidence??1))),
    weight:Math.max(0,Number(body.weight??10)),
    at:clock.now(),metadata:typeof body.metadata==="object"&&body.metadata?body.metadata:{}
  };
  return threatCorrelator.ingest(signal);
},{rateLimit:{limit:120,windowMs:60_000}});

router.add("POST","/api/v1/threats/:nodeId/dismiss",["security-approver"],async({claims,params})=>
  threatCorrelator.dismiss(params.nodeId!,claims.sub)
);

// The SOC console's Threat Signals panel (apps/security-soc) needs to know
// which nodes currently have an active, un-escalated correlation window
// without polling every enrolled node's activeSignalCount individually —
// PgThreatSignalStore.activeWindows had no route calling it before this.
router.add("GET","/api/v1/threats/active",["security-read"],async()=>
  threatSignalStore.activeWindows(clock.now().getTime()-THREAT_CORRELATION_WINDOW_MS)
);

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

// Every relay including stale/unavailable ones — for diagnosing a relay
// outage (docs/INCIDENT-RESPONSE-RUNBOOK.md); RelayRoutingService itself
// only ever sees the filtered, healthy candidates() view.
router.add("GET","/api/v1/relays",["security-read"],async()=>relayStore.list());

// Real AWS EC2 relay auto-provisioning — see services/relay-fleet/. Returns
// a clear 501 "coming soon" instead of crashing when no AWS account/AMI is
// configured yet; the existing manually-inserted-relay path is unaffected.
router.add("POST","/api/v1/relays/provision",["security-owner"],async({claims,body})=>{
  if(!relayFleet)throw new HttpError(501,"AWS relay auto-provisioning is not configured yet — set AWS_RELAY_AMI_ID and AWS_RELAY_REGION (coming soon)","not_configured");
  const region=String(body.region??relayFleet.region);
  const instanceType=String(body.instanceType??"t3.small");
  const instance=await relayFleet.provisioner.launch({region,instanceType});
  const relayId=randomUUID();
  await relayStore.insert(relayId,region,instance.endpoint,instance.instanceId);
  await audit.record(claims.sub,"RELAY_PROVISIONED",relayId,{region,instanceType,instanceId:instance.instanceId});
  return {relayId,...instance};
},{rateLimit:{limit:5,windowMs:60_000}});

router.add("POST","/api/v1/relays/:id/terminate",["security-owner"],async({claims,params})=>{
  if(!relayFleet)throw new HttpError(501,"AWS relay auto-provisioning is not configured yet — set AWS_RELAY_AMI_ID and AWS_RELAY_REGION (coming soon)","not_configured");
  const relay=await relayStore.get(params.id!);
  if(!relay)throw new HttpError(404,"relay not found","not_found");
  if(!relay.instanceId)throw new HttpError(400,"this relay has no associated AWS instance to terminate — it was added manually","invalid_request");
  await relayFleet.provisioner.terminate(relay.instanceId);
  await relayStore.remove(relay.relayId);
  await audit.record(claims.sub,"RELAY_TERMINATED",params.id!,{instanceId:relay.instanceId});
  return {terminated:true};
},{rateLimit:{limit:5,windowMs:60_000}});

// relays.load_percent/latency_ms/last_heartbeat had no write path at all —
// a relay's recorded health was whatever it was at insert() time, forever.
// A real relay process (services/relay/blind-relay-server.ts or an
// AWS-provisioned instance) calls this periodically; RelayRoutingService
// (via grpc-server.ts's mesh reconciliation) only considers a relay a
// candidate within the 45s freshness window this maintains.
// Distinct from /provision (AWS-specific, security-owner-gated, launches a
// new EC2 instance): this is how a relay process that already exists — the
// fixed blind-relay in docker-compose, or any manually-run relay — makes
// itself a real candidate for RelayRoutingService to select, instead of
// requiring every relay to have come from AWS auto-provisioning. Idempotent
// (PgRelayStore.insert upserts), so a restarting relay just re-registers.
router.add("POST","/api/v1/relays/register",["security-agent"],async({body})=>{
  const relayId=String(body.relayId??"");
  if(!relayId||!body.region||!body.endpoint)throw new HttpError(400,"relayId, region and endpoint are required","invalid_request");
  await relayStore.insert(relayId,String(body.region),String(body.endpoint),undefined,body.capacityMbps!==undefined?Number(body.capacityMbps):undefined);
  return {registered:true,relayId};
},{idempotent:true});

router.add("POST","/api/v1/relays/:id/heartbeat",["security-agent"],async({params,body})=>{
  await relayStore.heartbeat(params.id!,{
    loadPercent:Number(body.loadPercent??0),latencyMs:Number(body.latencyMs??0),
    activeSessions:Number(body.activeSessions??0),throughputBytesPerSec:Number(body.throughputBytesPerSec??0)
  });
  return {acknowledged:true};
},{rateLimit:{limit:120,windowMs:60_000}});

// Every egress gateway including stale/unhealthy ones — mirrors GET
// /api/v1/relays (diagnostic visibility for the SOC console); egress/select
// below only ever sees the filtered, healthy candidates() view.
router.add("GET","/api/v1/egress",["security-read"],async()=>egressStore.list());

// Same pattern as relay registration above — the current fixed
// egress-server.ts process (src/runtime/egress-server.ts) registers itself
// this way, so EgressSelector has at least one real candidate today and
// scales to more without any code change once multiple gateways exist.
router.add("POST","/api/v1/egress/register",["security-agent"],async({body})=>{
  const gatewayId=String(body.gatewayId??"");
  if(!gatewayId||!body.region||!body.fixedIp)throw new HttpError(400,"gatewayId, region and fixedIp are required","invalid_request");
  await egressStore.insert(gatewayId,String(body.region),String(body.fixedIp),body.maxSessions!==undefined?Number(body.maxSessions):undefined);
  return {registered:true,gatewayId};
},{idempotent:true});

router.add("POST","/api/v1/egress/:id/heartbeat",["security-agent"],async({params,body})=>{
  await egressStore.heartbeat(params.id!,{
    loadPercent:Number(body.loadPercent??0),healthy:body.healthy!==false,
    latencyMs:Number(body.latencyMs??0),activeSessions:Number(body.activeSessions??0)
  });
  return {acknowledged:true};
},{rateLimit:{limit:120,windowMs:60_000}});

// The actual consumer: an endpoint agent (or anything else routing traffic
// out) asks which egress gateway to use for a preferred region.
// EgressSelector.select had no real candidate data or caller before this.
router.add("GET","/api/v1/egress/select",["security-agent"],async({query})=>{
  const gateways=await egressStore.candidates();
  let selected;
  try{selected=egressSelector.select(gateways,query.get("region")??"");}
  catch{throw new HttpError(503,"no healthy egress gateway is currently registered","not_configured");}
  return {gatewayId:selected.id,fixedIp:selected.fixedIp,region:selected.region};
});

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
