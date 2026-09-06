import {createServer} from "node:http";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {TransactionalOutbox} from "../infrastructure/postgres/outbox.js";
import {HmacBearerGuard} from "../api/rest/guard.js";
import {RestRouter} from "../api/rest/router.js";
import {JitService} from "../application/jit.js";
import {RandomIds,SystemClock} from "../infrastructure/memory.js";

const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
const bus=new TransactionalOutbox(db);
const ids=new RandomIds(),clock=new SystemClock();
const jit=new JitService(repo,ids,clock,bus);
const guard=new HmacBearerGuard(config.controlApiTokenSecret);
const router=new RestRouter(guard);

router.add("GET","/api/v1/status",[],async({claims})=>({
  service:"bapc-vpn-security",version:"0.3.0",subject:claims.sub,
  database:await db.health(),environment:config.environment
}));

router.add("GET","/api/v1/nodes",["security-read"],async()=>repo.list());

router.add("POST","/api/v1/jit",["security-user"],async({claims,body})=>
  jit.request(
    claims.sub,String(body.targetResource??""),body.targetZone,
    Number(body.durationMinutes) as 15|30|60,String(body.justification??"")
  )
);

router.add("POST","/api/v1/jit/:id/approve",["security-approver"],async({claims,params})=>
  jit.approve(params.id!,claims.sub,claims.roles)
);

router.add("POST","/api/v1/jit/:id/terminate",["security-approver"],async({params,body})=>
  jit.terminate(params.id!,String(body.reason??"terminated by security operator"))
);

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
    event:"ready",service:"bapc-vpn-security",version:"0.3.0",
    host:config.bindHost,port:config.port
  }));
});
