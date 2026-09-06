import type {IncomingMessage,ServerResponse} from "node:http";
import {randomUUID} from "node:crypto";
import {asHttpError,HttpError} from "./errors.js";
import {HmacBearerGuard} from "./guard.js";
import {MemoryRateLimiter, type RateLimitRule} from "./rate-limit.js";
import {withIdempotency, MemoryIdempotencyStore, type IdempotencyStore} from "./idempotency.js";
import {enforceReplayNonce, MemoryReplayStore, type ReplayStore} from "./replay-guard.js";
import {metrics} from "./metrics.js";

export type JsonHandler=(ctx:{
  request:IncomingMessage; claims:{sub:string;roles:string[]}; body:any;
  params:Record<string,string>; query:URLSearchParams;
})=>Promise<unknown>;
export interface RawResponse {contentType:string; body:Buffer;}
export interface RouteOptions {
  idempotent?:boolean; rateLimit?:RateLimitRule;
  // Skips bearer-token verification entirely. Only for routes that are
  // genuinely public by design (e.g. a CRL distribution point, which relying
  // parties fetch with no prior relationship to this API) — never use this
  // to work around a route that "should" be authenticated.
  public?:boolean;
  // The handler returns a RawResponse (binary content-type) instead of a
  // JSON-serializable value; the router writes it directly with no
  // {requestId,data} envelope.
  raw?:boolean;
  // Requires a one-time-use X-Request-Nonce header (enforceReplayNonce): a
  // captured, still-valid signed request can't be resent to trigger the
  // same side effect twice. Reserve for consequential mutations that aren't
  // already naturally idempotent or idempotency-key-protected.
  replayProtected?:boolean;
}
interface Route {method:string;pattern:RegExp;keys:string[];roles:string[];handler:JsonHandler;options:RouteOptions;}

const DEFAULT_RATE_LIMIT:RateLimitRule={limit:60,windowMs:60_000};

export class RestRouter {
  private routes:Route[]=[];
  private limiter=new MemoryRateLimiter();
  private idempotencyStore:IdempotencyStore;
  private replayStore:ReplayStore;
  constructor(
    private guard:HmacBearerGuard, idempotencyStore?:IdempotencyStore,
    private exposeMetrics=false, replayStore?:ReplayStore
  ){
    this.idempotencyStore=idempotencyStore??new MemoryIdempotencyStore();
    this.replayStore=replayStore??new MemoryReplayStore();
  }
  add(method:string,path:string,roles:string[],handler:JsonHandler,options:RouteOptions={}){
    const keys:string[]=[];
    const pattern=new RegExp("^"+path.replace(/:[^/]+/g,m=>{keys.push(m.slice(1));return "([^/]+)";})+"$");
    this.routes.push({method,pattern,keys,roles,handler,options});
  }
  // Every route in this API is meant to be called from a browser-hosted
  // console/PEP running on a different origin (a different port is a
  // different origin) — the console's own auth is the bearer token, not a
  // cookie, so echoing the caller's Origin back is the standard, safe CORS
  // pattern for a bearer-token API (there's no ambient credential a
  // malicious page could ride along on). Without this, a browser's
  // preflight OPTIONS request 404s against the route table and every real
  // request is silently blocked before it's even sent — exactly what
  // happened the first time the console was driven from a real browser
  // against a real backend instead of just checked for static-file serving.
  private corsHeaders(req:IncomingMessage):Record<string,string>{
    const origin=req.headers.origin;
    if(!origin)return {};
    return {
      "Access-Control-Allow-Origin":origin,
      "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS",
      "Access-Control-Allow-Headers":"authorization,content-type,idempotency-key,x-request-nonce",
      "Access-Control-Max-Age":"600",
      "Vary":"Origin"
    };
  }
  async handle(req:IncomingMessage,res:ServerResponse){
    const requestId=randomUUID();
    const cors=this.corsHeaders(req);
    if(req.method==="OPTIONS"){
      res.writeHead(204,cors);
      res.end();
      return;
    }
    try{
      if(req.url==="/healthz"){this.respond(res,200,{status:"ok",requestId},cors);return;}
      if(this.exposeMetrics&&req.url==="/metrics"){
        res.writeHead(200,{"content-type":"text/plain; version=0.0.4",...cors});
        res.end(metrics.render());
        return;
      }
      const [path,rawQuery]=(req.url??"/").split("?") as [string,string|undefined];
      const query=new URLSearchParams(rawQuery??"");
      const route=this.routes.find(r=>r.method===req.method&&r.pattern.test(path));
      metrics.incrLabeled("bapc_http_requests_total",{method:req.method??"?",path:route?path:"unmatched"});
      if(!route)throw new HttpError(404,"route not found","not_found");
      const match=path.match(route.pattern)!;
      const params=Object.fromEntries(route.keys.map((k,i)=>[k,decodeURIComponent(match[i+1]??"")]));
      const claims=route.options.public?{sub:"anonymous",roles:[]}:this.guard.verify(req,route.roles);

      const rule=route.options.rateLimit??DEFAULT_RATE_LIMIT;
      const rateResult=this.limiter.check(`${claims.sub}:${route.method}:${path}`,rule);
      if(!rateResult.allowed){
        res.setHeader("Retry-After",String(Math.ceil((rateResult.resetAt-Date.now())/1000)));
        throw new HttpError(429,"rate limit exceeded","rate_limited");
      }

      if(route.options.replayProtected){
        await enforceReplayNonce(this.replayStore,req.headers["x-request-nonce"] as string|undefined,claims.sub);
      }

      const body=await this.readJson(req);
      if(route.options.raw){
        const raw=await route.handler({request:req,claims,body,params,query}) as RawResponse;
        res.writeHead(200,{"content-type":raw.contentType,"cache-control":"no-store",...cors});
        res.end(raw.body);
        return;
      }
      const run=()=>route.handler({request:req,claims,body,params,query}).then(data=>({status:200,body:{requestId,data}}));
      const idempotencyKey=route.options.idempotent
        ? (req.headers["idempotency-key"] as string|undefined) : undefined;
      const result=route.options.idempotent
        ? await withIdempotency(this.idempotencyStore,idempotencyKey,claims.sub,body,86_400_000,run)
        : await run();
      this.respond(res,result.status,result.body,cors);
    }catch(error){
      const e=asHttpError(error);
      metrics.incrLabeled("bapc_http_errors_total",{code:e.code,status:String(e.status)});
      this.respond(res,e.status,{requestId,error:{code:e.code,message:e.message}},cors);
    }
  }
  private async readJson(req:IncomingMessage){
    if(req.method==="GET"||req.method==="HEAD")return {};
    const chunks:Buffer[]=[];let size=0;
    for await(const c of req){
      const b=Buffer.from(c);size+=b.length;
      if(size>1_000_000)throw new HttpError(413,"body too large","body_too_large");
      chunks.push(b);
    }
    if(!chunks.length)return {};
    const type=String(req.headers["content-type"]??"");
    if(!type.includes("application/json"))throw new HttpError(415,"application/json required","unsupported_media");
    try{return JSON.parse(Buffer.concat(chunks).toString("utf8"));}
    catch{throw new HttpError(400,"invalid JSON","invalid_json");}
  }
  private respond(res:ServerResponse,status:number,value:unknown,extraHeaders:Record<string,string>={}){
    res.writeHead(status,{
      "content-type":"application/json; charset=utf-8","cache-control":"no-store",
      "x-content-type-options":"nosniff","x-frame-options":"DENY",
      "referrer-policy":"no-referrer","content-security-policy":"default-src 'none'",
      ...extraHeaders
    });
    res.end(JSON.stringify(value));
  }
}
