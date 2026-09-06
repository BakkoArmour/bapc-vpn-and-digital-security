import {createHmac,timingSafeEqual} from "node:crypto";
import type {IncomingMessage} from "node:http";
import {HttpError} from "./errors.js";

export interface ApiClaims {sub:string;roles:string[];exp:number;iat?:number;jti?:string;}
export class HmacBearerGuard {
  constructor(private secret:string){}
  verify(request:IncomingMessage,requiredRoles:string[]=[]):ApiClaims{
    const auth=request.headers.authorization;
    if(!auth?.startsWith("Bearer "))throw new HttpError(401,"missing bearer token","unauthorized");
    const token=auth.slice(7);
    const [encoded,signature]=token.split(".");
    if(!encoded||!signature)throw new HttpError(401,"malformed bearer token","unauthorized");
    const expected=createHmac("sha256",this.secret).update(encoded).digest("base64url");
    const a=Buffer.from(expected),b=Buffer.from(signature);
    if(a.length!==b.length||!timingSafeEqual(a,b))
      throw new HttpError(401,"invalid bearer token","unauthorized");
    const claims=JSON.parse(Buffer.from(encoded,"base64url").toString("utf8")) as ApiClaims;
    if(!claims.sub||!Array.isArray(claims.roles)||!claims.exp)
      throw new HttpError(401,"invalid bearer claims","unauthorized");
    if(claims.exp*1000<=Date.now())throw new HttpError(401,"expired bearer token","unauthorized");
    if(requiredRoles.length&&!requiredRoles.some(r=>claims.roles.includes(r)))
      throw new HttpError(403,"required role missing","forbidden");
    return claims;
  }
}
