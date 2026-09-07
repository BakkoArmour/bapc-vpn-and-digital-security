import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {createHmac} from "node:crypto";
import {request} from "node:http";
import {AddressInfo} from "node:net";
import {HmacBearerGuard} from "../../../src/api/rest/guard.js";
import {RestRouter} from "../../../src/api/rest/router.js";
import {MemoryIdempotencyStore} from "../../../src/api/rest/idempotency.js";

const SECRET="test-secret-that-is-at-least-32-chars-long";

const token=(roles:string[],sub="tester")=>{
  const encoded=Buffer.from(JSON.stringify({sub,roles,exp:Math.floor(Date.now()/1000)+60})).toString("base64url");
  const sig=createHmac("sha256",SECRET).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
};

const startServer=()=>{
  const router=new RestRouter(new HmacBearerGuard(SECRET),new MemoryIdempotencyStore());
  let calls=0;
  router.add("GET","/api/v1/status",[],async()=>({ok:true}));
  router.add("GET","/api/v1/secure",["security-read"],async()=>({secured:true}));
  router.add("POST","/api/v1/create",["security-user"],async({body})=>{calls++;return {calls,body};},{idempotent:true});
  router.add("POST","/api/v1/limited",["security-user"],async()=>({calls:++calls}),{rateLimit:{limit:2,windowMs:60_000}});
  router.add("POST","/api/v1/lockdown",["security-owner"],async()=>({calls:++calls}),{replayProtected:true});
  router.add("GET","/api/v1/boom",[],async()=>{throw new Error("db exploded: constraint violation on foo_bar");});
  const server=createServer((req,res)=>void router.handle(req,res));
  return new Promise<{server:import("node:http").Server;port:number}>(resolve=>{
    server.listen(0,"127.0.0.1",()=>resolve({server,port:(server.address() as AddressInfo).port}));
  });
};

const call=(port:number,method:string,path:string,opts:{token?:string;body?:unknown;idempotencyKey?:string;nonce?:string}={})=>
  new Promise<{status:number;json:any}>((resolve,reject)=>{
    const payload=opts.body!==undefined?JSON.stringify(opts.body):undefined;
    const req=request({
      host:"127.0.0.1",port,path,method,
      headers:{
        ...(opts.token?{authorization:`Bearer ${opts.token}`}:{}),
        ...(payload?{"content-type":"application/json","content-length":Buffer.byteLength(payload)}:{}),
        ...(opts.idempotencyKey?{"idempotency-key":opts.idempotencyKey}:{}),
        ...(opts.nonce?{"x-request-nonce":opts.nonce}:{})
      }
    },res=>{
      const chunks:Buffer[]=[];
      res.on("data",c=>chunks.push(c));
      res.on("end",()=>resolve({status:res.statusCode!,json:JSON.parse(Buffer.concat(chunks).toString("utf8"))}));
    });
    req.on("error",reject);
    if(payload)req.write(payload);
    req.end();
  });

test("a CORS preflight OPTIONS request succeeds with no auth and echoes the Origin",async()=>{
  // Regression: the console (a different origin/port from the API) never
  // actually worked in a real browser until this was added — the browser's
  // preflight OPTIONS request 404d against the route table (no OPTIONS
  // route existed) and the real request was blocked before it was even
  // sent. Static-file-serving tests for the console never caught this
  // because they don't drive a real cross-origin fetch.
  const {server,port}=await startServer();
  try{
    const status=await new Promise<{code:number;headers:import("node:http").IncomingHttpHeaders}>((resolve,reject)=>{
      const req=request({host:"127.0.0.1",port,path:"/api/v1/secure",method:"OPTIONS",
        headers:{origin:"http://127.0.0.1:8090"}},
        res=>{res.resume();res.on("end",()=>resolve({code:res.statusCode!,headers:res.headers}));});
      req.on("error",reject);req.end();
    });
    assert.equal(status.code,204);
    assert.equal(status.headers["access-control-allow-origin"],"http://127.0.0.1:8090");
    assert.match(status.headers["access-control-allow-methods"]??"",/GET/);
    assert.match(status.headers["access-control-allow-headers"]??"",/authorization/);
  }finally{server.close();}
});

test("a real cross-origin response also carries Access-Control-Allow-Origin",async()=>{
  const {server,port}=await startServer();
  try{
    const status=await new Promise<{code:number;headers:import("node:http").IncomingHttpHeaders}>((resolve,reject)=>{
      const req=request({host:"127.0.0.1",port,path:"/api/v1/status",method:"GET",
        headers:{origin:"http://127.0.0.1:8090",authorization:`Bearer ${token([])}`}},
        res=>{res.resume();res.on("end",()=>resolve({code:res.statusCode!,headers:res.headers}));});
      req.on("error",reject);req.end();
    });
    assert.equal(status.code,200);
    assert.equal(status.headers["access-control-allow-origin"],"http://127.0.0.1:8090");
  }finally{server.close();}
});

test("unauthenticated requests to protected routes are rejected",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await call(port,"GET","/api/v1/secure");
    assert.equal(res.status,401);
  }finally{server.close();}
});

test("role-gated route accepts a token with the required role",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await call(port,"GET","/api/v1/secure",{token:token(["security-read"])});
    assert.equal(res.status,200);
    assert.equal(res.json.data.secured,true);
  }finally{server.close();}
});

test("a token missing the required role is forbidden",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await call(port,"GET","/api/v1/secure",{token:token(["security-user"])});
    assert.equal(res.status,403);
  }finally{server.close();}
});

test("idempotency key replays the first response for a repeated request",async()=>{
  const {server,port}=await startServer();
  try{
    const t=token(["security-user"]);
    const first=await call(port,"POST","/api/v1/create",{token:t,body:{x:1},idempotencyKey:"key-1"});
    const second=await call(port,"POST","/api/v1/create",{token:t,body:{x:1},idempotencyKey:"key-1"});
    assert.equal(first.json.data.calls,second.json.data.calls);
  }finally{server.close();}
});

test("idempotency key reused with a different body is a conflict",async()=>{
  const {server,port}=await startServer();
  try{
    const t=token(["security-user"]);
    await call(port,"POST","/api/v1/create",{token:t,body:{x:1},idempotencyKey:"key-2"});
    const conflict=await call(port,"POST","/api/v1/create",{token:t,body:{x:2},idempotencyKey:"key-2"});
    assert.equal(conflict.status,409);
  }finally{server.close();}
});

test("a replay-protected route requires an X-Request-Nonce header",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await call(port,"POST","/api/v1/lockdown",{token:token(["security-owner"])});
    assert.equal(res.status,400);
    assert.equal(res.json.error.code,"nonce_required");
  }finally{server.close();}
});

test("a replay-protected route rejects a reused nonce but allows a fresh one",async()=>{
  const {server,port}=await startServer();
  try{
    const t=token(["security-owner"]);
    const first=await call(port,"POST","/api/v1/lockdown",{token:t,nonce:"nonce-1"});
    assert.equal(first.status,200);
    const replay=await call(port,"POST","/api/v1/lockdown",{token:t,nonce:"nonce-1"});
    assert.equal(replay.status,409);
    assert.equal(replay.json.error.code,"replay_detected");
    const second=await call(port,"POST","/api/v1/lockdown",{token:t,nonce:"nonce-2"});
    assert.equal(second.status,200);
  }finally{server.close();}
});

test("a public route requires no bearer token at all",async()=>{
  const router=new RestRouter(new HmacBearerGuard(SECRET),new MemoryIdempotencyStore());
  router.add("GET","/public/info",[],async()=>({open:true}),{public:true});
  const server=createServer((req,res)=>void router.handle(req,res));
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const port=(server.address() as AddressInfo).port;
  try{
    const res=await call(port,"GET","/public/info");
    assert.equal(res.status,200);
    assert.equal(res.json.data.open,true);
  }finally{server.close();}
});

test("a raw route writes the handler's content-type/body directly, no JSON envelope",async()=>{
  const router=new RestRouter(new HmacBearerGuard(SECRET),new MemoryIdempotencyStore());
  router.add("GET","/raw/blob",[],async()=>({contentType:"application/octet-stream",body:Buffer.from([1,2,3,4])}),{public:true,raw:true});
  const server=createServer((req,res)=>void router.handle(req,res));
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const port=(server.address() as AddressInfo).port;
  try{
    const res=await fetch(`http://127.0.0.1:${port}/raw/blob`);
    assert.equal(res.headers.get("content-type"),"application/octet-stream");
    const bytes=Buffer.from(await res.arrayBuffer());
    assert.deepEqual([...bytes],[1,2,3,4]);
  }finally{server.close();}
});

test("metrics endpoint exposes Prometheus text format when enabled",async()=>{
  const router=new RestRouter(new HmacBearerGuard(SECRET),new MemoryIdempotencyStore(),true);
  router.add("GET","/api/v1/ping",[],async()=>({pong:true}));
  const server=createServer((req,res)=>void router.handle(req,res));
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const port=(server.address() as AddressInfo).port;
  try{
    await call(port,"GET","/api/v1/ping",{token:token([])});
    const res=await fetch(`http://127.0.0.1:${port}/metrics`);
    assert.equal(res.status,200);
    assert.match(res.headers.get("content-type")??"",/text\/plain/);
    const text=await res.text();
    assert.match(text,/bapc_http_requests_total/);
  }finally{server.close();}
});

test("metrics endpoint is absent by default",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await fetch(`http://127.0.0.1:${port}/metrics`);
    assert.equal(res.status,404);
  }finally{server.close();}
});

test("rate limit trips after the configured number of requests",async()=>{
  const {server,port}=await startServer();
  try{
    const t=token(["security-user"]);
    await call(port,"POST","/api/v1/limited",{token:t});
    await call(port,"POST","/api/v1/limited",{token:t});
    const third=await call(port,"POST","/api/v1/limited",{token:t});
    assert.equal(third.status,429);
  }finally{server.close();}
});

// Found live against real Docker Compose: a handler throwing an
// unrecognized error collapses to a generic 500 for the client (by design —
// asHttpError never leaks internals), but before this, that meant the real
// cause existed NOWHERE, not even server-side. An operator had no way to
// diagnose a production 500 short of reproducing it locally.
test("an unhandled handler error is logged server-side, not just returned as a generic 500",async()=>{
  const {server,port}=await startServer();
  const originalError=console.error;
  const logged:string[]=[];
  console.error=(msg:string)=>{logged.push(msg);};
  try{
    const res=await call(port,"GET","/api/v1/boom",{token:token([])});
    assert.equal(res.status,500);
    assert.equal(res.json.error.code,"internal_error");
    assert.equal(res.json.error.message,"internal request failure");
    assert.equal(logged.length,1);
    const entry=JSON.parse(logged[0]!);
    assert.equal(entry.event,"http.internal_error");
    assert.match(entry.error,/db exploded/);
  }finally{console.error=originalError;server.close();}
});
