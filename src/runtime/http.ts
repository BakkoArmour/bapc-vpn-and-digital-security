import type { IncomingMessage, ServerResponse } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
export type Handler=(request:IncomingMessage,response:ServerResponse,body:unknown,claims:Claims)=>Promise<unknown>;
export interface Claims {sub:string;roles:string[];exp:number;}
export class TokenVerifier {constructor(private secret:string){}verify(token:string|undefined):Claims{if(!token)throw new Error("missing token");const [encoded,sig]=token.split(".");if(!encoded||!sig)throw new Error("malformed token");const expected=createHmac("sha256",this.secret).update(encoded).digest("base64url");if(!timingSafeEqual(Buffer.from(expected),Buffer.from(sig)))throw new Error("invalid token");const claims=JSON.parse(Buffer.from(encoded,"base64url").toString()) as Claims;if(claims.exp*1000<Date.now())throw new Error("expired token");return claims;}}
export const json=async(req:IncomingMessage)=>{const chunks:Buffer[]=[];for await(const c of req){chunks.push(Buffer.from(c));if(chunks.reduce((n,x)=>n+x.length,0)>1_000_000)throw new Error("body too large");}return chunks.length?JSON.parse(Buffer.concat(chunks).toString("utf8")):{};};
export const respond=(res:ServerResponse,status:number,value:unknown)=>{res.writeHead(status,{"content-type":"application/json","cache-control":"no-store","x-content-type-options":"nosniff"});res.end(JSON.stringify(value));};
