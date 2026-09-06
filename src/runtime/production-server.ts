import {createServer} from "node:http";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {TransactionalOutbox} from "../infrastructure/postgres/outbox.js";
import {PgIdempotencyStore} from "../api/rest/idempotency.js";
import {HmacBearerGuard} from "../api/rest/guard.js";
import {RestRouter} from "../api/rest/router.js";
import {JitService} from "../application/jit.js";
import {SocService} from "../application/soc.js";
import {ThreatResponseService} from "../application/threat-response.js";
import {RandomIds,SystemClock} from "../infrastructure/memory.js";
import {InMemoryEnforcer, DevelopmentCertificateIssuer, NoopThreatSink} from "../infrastructure/adapters.js";
import {HeartbeatService} from "../application/heartbeat.js";
import {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import type {NetworkPolicy} from "../domain/types.js";

const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
const bus=new TransactionalOutbox(db);
const ids=new RandomIds(),clock=new SystemClock();
const jit=new JitService(repo,ids,clock,bus);
const soc=new SocService(repo,repo,repo,repo,repo,clock);

// InMemoryEnforcer and the development certificate issuer/threat sink below are
// placeholders for the real PlatformAdapter-bound enforcer, TrustCoreIssuer and
// SIEM/ThreatSink integration. See docs/CODE-ADDENDUM-INTEGRATION.md.
const threatResponse=new ThreatResponseService(
  repo,repo,repo,repo,new InMemoryEnforcer(),new DevelopmentCertificateIssuer(),bus,new NoopThreatSink()
);

const heartbeats=new HeartbeatService(repo,repo,bus,clock);
const commandQueue=new PgCommandQueue(db);

const guard=new HmacBearerGuard(config.controlApiTokenSecret);
const router=new RestRouter(guard,new PgIdempotencyStore(db),true);

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

router.add("GET","/api/v1/events",["security-read"],async({query})=>
  repo.recent(Number(query.get("limit")??"100"))
);

router.add("GET","/api/v1/soc/snapshot",["security-read"],async()=>soc.snapshot());

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

await db.health();
server.listen(config.port,config.bindHost,()=>{
  console.log(JSON.stringify({
    event:"ready",service:"bapc-vpn-security",version:"0.4.0",
    host:config.bindHost,port:config.port
  }));
});
