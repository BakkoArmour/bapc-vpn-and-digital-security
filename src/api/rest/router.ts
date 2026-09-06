import type {IncomingMessage,ServerResponse} from "node:http";
import {randomUUID} from "node:crypto";
import {asHttpError,HttpError} from "./errors.js";
import {HmacBearerGuard} from "./guard.js";

export type JsonHandler=(ctx:{
  request:IncomingMessage; claims:{sub:string;roles:string[]}; body:any; params:Record<string,string>;
})=>Promise<unknown>;
interface Route {method:string;pattern:RegExp;keys:string[];roles:string[];handler:JsonHandler;}

export class RestRouter {
  private routes:Route[]=[];
  constructor(private guard:HmacBearerGuard){}
  add(method:string,path:string,roles:string[],handler:JsonHandler){
    const keys:string[]=[];
    const pattern=new RegExp("^"+path.replace(/:[^/]+/g,m=>{keys.push(m.slice(1));return "([^/]+)";})+"$");
    this.routes.push({method,pattern,keys,roles,handler});
  }
  async handle(req:IncomingMessage,res:ServerResponse){
    const requestId=randomUUID();
    try{
      if(req.url==="/healthz"){this.respond(res,200,{status:"ok",requestId});return;}
      const path=(req.url??"/").split("?")[0]!;
      const route=this.routes.find(r=>r.method===req.method&&r.pattern.test(path));
      if(!route)throw new HttpError(404,"route not found","not_found");
      const match=path.match(route.pattern)!;
      const params=Object.fromEntries(route.keys.map((k,i)=>[k,decodeURIComponent(match[i+1]??"")]));
      const claims=this.guard.verify(req,route.roles);
      const body=await this.readJson(req);
      const value=await route.handler({request:req,claims,body,params});
      this.respond(res,200,{requestId,data:value});
    }catch(error){
      const e=asHttpError(error);
      this.respond(res,e.status,{requestId,error:{code:e.code,message:e.message}});
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
  private respond(res:ServerResponse,status:number,value:unknown){
    res.writeHead(status,{
      "content-type":"application/json; charset=utf-8","cache-control":"no-store",
      "x-content-type-options":"nosniff","x-frame-options":"DENY",
      "referrer-policy":"no-referrer","content-security-policy":"default-src 'none'"
    });
    res.end(JSON.stringify(value));
  }
}
