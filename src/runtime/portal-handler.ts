import type {IncomingMessage, ServerResponse} from "node:http";
import {timingSafeEqual} from "node:crypto";
import QRCode from "qrcode-svg";
import {DomainError} from "../domain/errors.js";
import {asHttpError} from "../api/rest/errors.js";
import {MemoryRateLimiter, type RateLimitRule} from "../api/rest/rate-limit.js";
import {isDeviceKind, type CustomerDeviceService, type CustomerSession} from "../application/customer-devices.js";
import type {DeviceJoinService} from "../application/device-join.js";
import {randomToken, sha256Hex, type AccessState, type BapcUser} from "../infrastructure/bapc-accounts.js";
import {
  accountPage, appDevicePage, isPlanId, landingPage, messagePage, privacyPage, termsPage, windowsInvitePage
} from "./portal-pages.js";

// The customer-facing site (vpn.bapc.app): marketing + pricing, Sign in
// with BAPC, the account page (plan from BAPC Billing, device list), adding
// and removing devices, and the public device-join API the Windows
// installer calls. Kept separate from control-api's operator REST API: this
// process never exposes any operator route.

export interface PortalSessionStore {
  saveSignIn(state:string,verifier:string,nextPath:string,expiresAt:Date):Promise<void>;
  takeSignIn(state:string):Promise<{verifier:string;nextPath:string}|null>;
  createSession(tokenHash:string,s:Omit<CustomerSession,"tokenHash">,expiresAt:Date):Promise<void>;
  session(tokenHash:string):Promise<CustomerSession|null>;
  deleteSession(tokenHash:string):Promise<void>;
}

export interface PortalDeps {
  origin:string;
  identity:{authorizeUrl(redirectUri:string,state:string,verifier:string):string;exchange(code:string,redirectUri:string,verifier:string):Promise<BapcUser|null>}|null;
  billing:{checkoutUrl(planId:string,accountId:string):string;manageUrl():string;access(accountId:string):Promise<AccessState>}|null;
  sessions:PortalSessionStore;
  devices:Pick<CustomerDeviceService,"list"|"addWindowsDevice"|"addAppDevice"|"removeDevice"|"applyPaymentState">;
  join:Pick<DeviceJoinService,"join">;
  joinScript:()=>string;
}

const COOKIE="bapc_vpn_session";
const SESSION_HOURS=12;
const CSP="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const LIMITS:Record<string,RateLimitRule>={
  join:{limit:10,windowMs:60_000},auth:{limit:30,windowMs:60_000},
  addDevice:{limit:10,windowMs:3_600_000},page:{limit:240,windowMs:60_000}
};

const safeNext=(n:string|null|undefined)=>n&&/^\/[A-Za-z0-9/?=&_.-]*$/.test(n)&&!n.startsWith("//")?n:"/account";
const sameToken=(a:string,b:string)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);};

export const createPortalHandler=(deps:PortalDeps)=>{
  const limiter=new MemoryRateLimiter();
  const secure=deps.origin.startsWith("https:");
  const redirectUri=`${deps.origin}/auth/callback`;

  const send=(res:ServerResponse,status:number,body:string,type="text/html; charset=utf-8",extra:Record<string,string|string[]>={})=>{
    res.writeHead(status,{
      "content-type":type,"cache-control":"no-store","x-content-type-options":"nosniff",
      "referrer-policy":"no-referrer","content-security-policy":CSP,"x-frame-options":"DENY",
      ...(secure?{"strict-transport-security":"max-age=31536000"}:{}),...extra
    });
    res.end(body);
  };
  const redirect=(res:ServerResponse,to:string,cookies:string[]=[])=>{
    res.writeHead(303,{location:to,"cache-control":"no-store",...(cookies.length?{"set-cookie":cookies}:{})});
    res.end();
  };
  const cookie=(token:string,maxAge:number)=>`${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure?"; Secure":""}`;
  const clientIp=(req:IncomingMessage)=>String(req.headers["cf-connecting-ip"]??req.socket.remoteAddress??"?");

  const readBody=async(req:IncomingMessage,max:number)=>{
    const chunks:Buffer[]=[];let size=0;
    for await(const c of req){
      const b=Buffer.from(c);size+=b.length;
      if(size>max)throw Object.assign(new Error("body too large"),{status:413});
      chunks.push(b);
    }
    return Buffer.concat(chunks).toString("utf8");
  };

  const currentSession=async(req:IncomingMessage)=>{
    const m=String(req.headers.cookie??"").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`));
    return m?deps.sessions.session(sha256Hex(m[1]!)):null;
  };

  const checkAccess=async(accountId:string)=>{
    if(!deps.billing)return null;
    try{
      const access=await deps.billing.access(accountId);
      await deps.devices.applyPaymentState(accountId,access.paid);
      return access;
    }catch{return null;}
  };

  const handle=async(req:IncomingMessage,res:ServerResponse)=>{
    const url=new URL(req.url??"/","http://portal");
    const path=url.pathname,method=req.method??"GET";
    const ip=clientIp(req);
    const limit=(name:keyof typeof LIMITS)=>{
      if(!limiter.check(`${ip}:${name}`,LIMITS[name]!).allowed)throw Object.assign(new Error("Too many requests. Wait a minute and try again."),{status:429});
    };

    if(path==="/healthz"){send(res,200,JSON.stringify({status:"ok"}),"application/json");return;}
    if(path==="/robots.txt"){send(res,200,"User-agent: *\nDisallow: /account\nDisallow: /auth/\n","text/plain");return;}

    // --- the Windows installer's API ---
    if(path==="/api/v1/devices/join"&&method==="POST"){
      limit("join");
      if(!String(req.headers["content-type"]??"").includes("application/json"))throw Object.assign(new Error("application/json required"),{status:415});
      let body:unknown;
      try{body=JSON.parse(await readBody(req,64_000));}catch{throw Object.assign(new Error("invalid JSON"),{status:400});}
      const data=await deps.join.join((body??{}) as Record<string,unknown>);
      send(res,200,JSON.stringify({data}),"application/json");
      return;
    }
    if(path==="/install/join-vpn.ps1"&&method==="GET"){send(res,200,deps.joinScript(),"text/plain; charset=utf-8");return;}

    limit("page");
    const s=await currentSession(req);
    if(method==="GET"&&path==="/"){send(res,200,landingPage(!!s));return;}
    if(method==="GET"&&path==="/privacy"){send(res,200,privacyPage(!!s));return;}
    if(method==="GET"&&path==="/terms"){send(res,200,termsPage(!!s));return;}

    // --- Sign in with BAPC ---
    if(method==="GET"&&path==="/auth/start"){
      limit("auth");
      if(!deps.identity){send(res,503,messagePage("Sign-in is coming soon","Accounts open very shortly. Please check back soon."));return;}
      const state=randomToken(),verifier=randomToken(48);
      await deps.sessions.saveSignIn(state,verifier,safeNext(url.searchParams.get("next")),new Date(Date.now()+10*60_000));
      redirect(res,deps.identity.authorizeUrl(redirectUri,state,verifier));
      return;
    }
    if(method==="GET"&&path==="/auth/callback"){
      limit("auth");
      const pending=deps.identity?await deps.sessions.takeSignIn(url.searchParams.get("state")??""):null;
      const code=url.searchParams.get("code");
      if(!pending||!code||!deps.identity){send(res,400,messagePage("That sign-in expired","Please sign in again."));return;}
      const user=await deps.identity.exchange(code,redirectUri,pending.verifier);
      if(!user){send(res,400,messagePage("Sign-in didn't finish","bapc.app couldn't confirm the sign-in. Please try again."));return;}
      if(!user.emailVerified){send(res,403,messagePage("Confirm your email first","Open the confirmation email from bapc.app, then sign in again."));return;}
      const token=randomToken();
      await deps.sessions.createSession(sha256Hex(token),{accountId:user.id,email:user.email.toLowerCase(),name:user.name||null,csrfToken:randomToken()},
        new Date(Date.now()+SESSION_HOURS*3_600_000));
      redirect(res,pending.nextPath,[cookie(token,SESSION_HOURS*3600)]);
      return;
    }
    if(method==="POST"&&path==="/auth/logout"){
      const m=String(req.headers.cookie??"").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`));
      if(m)await deps.sessions.deleteSession(sha256Hex(m[1]!));
      redirect(res,"/",[cookie("",0)]);
      return;
    }

    // --- account (signed in only) ---
    if(path==="/account"||path.startsWith("/account/")){
      if(!s){
        if(method==="GET")redirect(res,`/auth/start?next=${encodeURIComponent(path+url.search)}`);
        else redirect(res,"/auth/start");
        return;
      }
      if(method==="GET"&&path==="/account"){
        const access=await checkAccess(s.accountId);
        const wantPlan=url.searchParams.get("plan");
        send(res,200,accountPage({
          email:s.email,csrf:s.csrfToken,access,devices:await deps.devices.list(s.accountId),
          wantPlan:isPlanId(wantPlan)?wantPlan:null,
          checkoutUrl:plan=>deps.billing!.checkoutUrl(plan,s.accountId),manageUrl:deps.billing?.manageUrl()??"/",
          msg:url.searchParams.get("msg")?.slice(0,200)
        }));
        return;
      }
      if(method!=="POST")throw Object.assign(new Error("not found"),{status:404});
      const form=new URLSearchParams(await readBody(req,8_000));
      if(!sameToken(form.get("csrf")??"",s.csrfToken))throw Object.assign(new Error("This form expired. Go back, reload the page and try again."),{status:403});

      if(path==="/account/devices"){
        limit("addDevice");
        const access=await checkAccess(s.accountId);
        if(!access?.paid){redirect(res,`/account?msg=${encodeURIComponent("Pick a plan first, then add your devices.")}`);return;}
        const kind=form.get("kind");
        if(!isDeviceKind(kind))throw Object.assign(new Error("Pick a kind of device."),{status:400});
        const account={accountId:s.accountId,email:s.email};
        if(kind==="windows"){
          const invite=await deps.devices.addWindowsDevice(account,form.get("name"));
          send(res,200,windowsInvitePage({origin:deps.origin,code:invite.code,expiresAt:invite.expiresAt,name:form.get("name")?.trim()||"Windows PC"}));
          return;
        }
        const added=await deps.devices.addAppDevice(account,kind,form.get("name"));
        const qrSvg=new QRCode({content:added.config,padding:2,ecl:"M",join:true,container:"svg-viewbox"}).svg();
        send(res,200,appDevicePage({kind,name:added.name,config:added.config,qrSvg}));
        return;
      }
      const remove=path.match(/^\/account\/devices\/([0-9a-f-]{36})\/remove$/);
      if(remove){
        await deps.devices.removeDevice(s.accountId,remove[1]!);
        redirect(res,`/account?msg=${encodeURIComponent("Device removed. It can't connect any more.")}`);
        return;
      }
    }
    throw Object.assign(new Error("Page not found"),{status:404});
  };

  return async(req:IncomingMessage,res:ServerResponse)=>{
    try{await handle(req,res);}
    catch(error){
      const explicit=(error as {status?:number}).status;
      const e=explicit?{status:explicit,message:(error as Error).message}:asHttpError(error);
      if(e.status>=500)console.error(JSON.stringify({event:"portal.error",url:req.url,error:error instanceof Error?error.message:String(error)}));
      const message=e.status>=500?"Something went wrong on our side. Please try again in a minute.":e.message;
      if((req.url??"").startsWith("/api/"))send(res,e.status,JSON.stringify({error:{code:error instanceof DomainError?error.code:String(e.status),message}}),"application/json");
      else send(res,e.status,messagePage(e.status===404?"Page not found":"That didn't work",message));
    }
  };
};
