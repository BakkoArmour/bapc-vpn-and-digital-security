import type {IncomingMessage, ServerResponse} from "node:http";
import {createHmac, timingSafeEqual} from "node:crypto";
import QRCode from "qrcode-svg";
import {DomainError} from "../domain/errors.js";
import {asHttpError} from "../api/rest/errors.js";
import {MemoryRateLimiter, type RateLimitRule} from "../api/rest/rate-limit.js";
import {DEVICE_KINDS, isDeviceKind, type CustomerDeviceService, type CustomerSession} from "../application/customer-devices.js";
import type {DeviceJoinService} from "../application/device-join.js";
import {randomToken, sha256Hex, type AccessState, type BapcUser} from "../infrastructure/bapc-accounts.js";
import type {AccountDataStore, AdminStore} from "../application/account-data.js";
import {customerEmails, type CustomerEmail, type SendOutcome} from "../infrastructure/bapc-notifications.js";
import {
  accountPage, adminAccountPage, adminListPage, appDevicePage, helpPage, isPlanId, landingPage, messagePage, privacyPage, termsPage, windowsInvitePage, type TrialDays
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
  devices:Pick<CustomerDeviceService,"list"|"addWindowsDevice"|"addAppDevice"|"removeDevice"|"applyPaymentState"|"revokeAll">;
  join:Pick<DeviceJoinService,"join">;
  joinScript:()=>string;
  // Free-trial days Billing currently gives per plan (cached by the caller); empty = no trial advertised.
  trials?:()=>TrialDays;
  // Audit trail, data export and erasure (db/022). Required in production (customer-portal.ts always passes it).
  accountData:AccountDataStore;
  // Staff admin (/admin) for bapc.app admins. Without it, /admin doesn't exist.
  admin?:AdminStore;
  // Customer email (BAPC Notifications). Optional: without it nothing is sent.
  mail?:{send(to:string,subject:string,text:string):Promise<SendOutcome>};
  // Signing secret for BAPC Billing's plan.changed hook (POST /api/v1/billing/hook). Unset = the route answers 503
  // and payment changes are still picked up by page visits and the 15-minute sync.
  billingHookSecret?:string;
}

const HOOK_MAX_SKEW_S=300;
// Billing's x-bapc-signature: "t=<unix seconds>,v1=<hex HMAC-SHA256 of `${t}.${raw body}`>", within 5 minutes.
export const verifyBillingHook=(secret:string,header:string,raw:string,nowS=Math.floor(Date.now()/1000))=>{
  const parts=Object.fromEntries(header.split(",").map(p=>{const i=p.indexOf("=");return [p.slice(0,i).trim(),p.slice(i+1).trim()];}));
  const t=Number(parts.t),v1=String(parts.v1??"");
  if(!secret||!Number.isInteger(t)||Math.abs(nowS-t)>HOOK_MAX_SKEW_S||!/^[0-9a-f]{64}$/.test(v1))return false;
  return sameToken(createHmac("sha256",secret).update(`${t}.${raw}`).digest("hex"),v1);
};

const COOKIE="bapc_vpn_session";
const SESSION_HOURS=12;
const CSP="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const LIMITS:Record<string,RateLimitRule>={
  join:{limit:10,windowMs:60_000},auth:{limit:30,windowMs:60_000},
  addDevice:{limit:10,windowMs:3_600_000},page:{limit:240,windowMs:60_000},hook:{limit:120,windowMs:60_000},
  export:{limit:10,windowMs:3_600_000},closeAccount:{limit:5,windowMs:3_600_000}
};
export const DELETE_CONFIRMATION="DELETE";

const safeNext=(n:string|null|undefined)=>n&&/^\/[A-Za-z0-9/?=&_.-]*$/.test(n)&&!n.startsWith("//")?n:"/account";
const sameToken=(a:string,b:string)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);};

export const createPortalHandler=(deps:PortalDeps)=>{
  const limiter=new MemoryRateLimiter();
  // Billing retries until it gets a 2xx, so the same event can arrive twice; acting twice is harmless
  // (pausing is idempotent) but it shouldn't be audited or emailed twice.
  const seenHookEvents=new Set<string>();
  const rememberHookEvent=(id:string)=>{seenHookEvents.add(id);if(seenHookEvents.size>5000)seenHookEvents.delete(seenHookEvents.values().next().value!);};
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

  // The audit trail must never take a customer's action down with it: a failed write is logged, not thrown.
  const audit=async(accountId:string,action:string,detail:Record<string,unknown>={},ip:string|null=null,actor:"customer"|"system"|"staff"="customer")=>{
    try{await deps.accountData.audit(accountId,actor,action,detail,ip);}
    catch(error){console.error(JSON.stringify({event:"portal.audit_failed",action,error:error instanceof Error?error.message:String(error)}));}
  };

  // Customer email never takes an action down with it either.
  const email=async(to:string,accountId:string,kind:string,msg:CustomerEmail)=>{
    if(!deps.mail)return;
    const outcome=await deps.mail.send(to,msg.subject,msg.text).catch(()=>"retry" as const);
    if(outcome!=="accepted")console.error(JSON.stringify({event:"portal.email_not_sent",kind,outcome}));
    else await audit(accountId,"email.sent",{kind},null,"system");
  };

  const checkAccess=async(accountId:string,to?:string)=>{
    if(!deps.billing)return null;
    try{
      const access=await deps.billing.access(accountId);
      const changed=await deps.devices.applyPaymentState(accountId,access.paid);
      if(changed){
        await audit(accountId,access.paid?"payment.devices_resumed":"payment.devices_paused",{devices:changed,status:access.status},null,"system");
        if(to)await email(to,accountId,access.paid?"devices_resumed":"devices_paused",access.paid?customerEmails.devicesResumed(changed):customerEmails.devicesPaused(changed));
      }
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

    // --- BAPC Billing tells us a plan changed (signed, retried by Billing until we answer 2xx) ---
    if(path==="/api/v1/billing/hook"&&method==="POST"){
      limit("hook");
      if(!deps.billingHookSecret)throw Object.assign(new Error("billing hook not configured"),{status:503});
      const raw=await readBody(req,32_000);
      if(!verifyBillingHook(deps.billingHookSecret,String(req.headers["x-bapc-signature"]??""),raw))throw Object.assign(new Error("bad signature"),{status:401});
      let ev:{event_id?:unknown;type?:unknown;app?:unknown;account?:unknown;email?:unknown;paid?:unknown;status?:unknown};
      try{ev=JSON.parse(raw);}catch{throw Object.assign(new Error("invalid JSON"),{status:400});}
      const eventId=String(ev.event_id??"");
      if(ev.type!=="plan.changed"||ev.app!=="bapc-vpn"||typeof ev.paid!=="boolean"||!eventId){send(res,200,JSON.stringify({ignored:true}),"application/json");return;}
      if(seenHookEvents.has(eventId)){send(res,200,JSON.stringify({duplicate:true}),"application/json");return;}
      const account=typeof ev.account==="string"&&ev.account?ev.account:null;
      if(!account){send(res,200,JSON.stringify({ignored:"no account"}),"application/json");return;}
      const changed=await deps.devices.applyPaymentState(account,ev.paid);
      rememberHookEvent(eventId);
      await audit(account,"billing.plan_changed",{event_id:eventId,paid:ev.paid,status:String(ev.status??""),devices_changed:changed},null,"system");
      if(changed&&typeof ev.email==="string"&&ev.email.includes("@"))
        await email(ev.email.toLowerCase(),account,ev.paid?"devices_resumed":"devices_paused",ev.paid?customerEmails.devicesResumed(changed):customerEmails.devicesPaused(changed));
      send(res,200,JSON.stringify({ok:true,devices_changed:changed}),"application/json");
      return;
    }

    limit("page");
    const s=await currentSession(req);
    if(method==="GET"&&path==="/"){send(res,200,landingPage(!!s,deps.trials?.()??{}));return;}
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
      await deps.sessions.createSession(sha256Hex(token),{accountId:user.id,email:user.email.toLowerCase(),name:user.name||null,csrfToken:randomToken(),role:user.role==="admin"?"admin":"user"},
        new Date(Date.now()+SESSION_HOURS*3_600_000));
      const firstVisit=!(await deps.accountData.hasSignedInBefore(user.id).catch(()=>true));
      await audit(user.id,"auth.signed_in",{},ip);
      if(firstVisit)await email(user.email.toLowerCase(),user.id,"welcome",customerEmails.welcome(user.name||null));
      redirect(res,pending.nextPath,[cookie(token,SESSION_HOURS*3600)]);
      return;
    }
    if(method==="POST"&&path==="/auth/logout"){
      const m=String(req.headers.cookie??"").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`));
      if(m)await deps.sessions.deleteSession(sha256Hex(m[1]!));
      if(s)await audit(s.accountId,"auth.signed_out",{},ip);
      redirect(res,"/",[cookie("",0)]);
      return;
    }

    // --- staff admin: bapc.app admins only. Everyone else (signed out, or a customer) gets a plain 404, so the
    // area doesn't even show it exists. Re-checked on every request from the session's stored role. ---
    if(path==="/admin"||path.startsWith("/admin/")){
      if(!deps.admin||!s||s.role!=="admin")throw Object.assign(new Error("Page not found"),{status:404});
      const staff={staff:s.email};
      if(method==="GET"&&path==="/admin"){
        const search=(url.searchParams.get("q")??"").slice(0,200);
        const page=Math.max(1,Math.min(10_000,Number(url.searchParams.get("page"))||1)),pageSize=50;
        const {rows,total}=await deps.admin.listAccounts({search,page,pageSize});
        send(res,200,adminListPage({rows,total,page,pageSize,search,staff:s.email}));
        return;
      }
      const m=path.match(/^\/admin\/accounts\/([^/]{1,200})(\/.*)?$/);
      if(!m)throw Object.assign(new Error("Page not found"),{status:404});
      const accountId=decodeURIComponent(m[1]!),rest=m[2]??"";
      const back=(msg:string)=>redirect(res,`/admin/accounts/${encodeURIComponent(accountId)}?msg=${encodeURIComponent(msg)}`);
      if(method==="GET"&&rest===""){
        const detail=await deps.admin.accountDetail(accountId);
        if(!detail)throw Object.assign(new Error("No such account"),{status:404});
        const access=deps.billing?await deps.billing.access(accountId).catch(()=>null):null;
        send(res,200,adminAccountPage({detail,access,csrf:s.csrfToken,msg:url.searchParams.get("msg")?.slice(0,200)}));
        return;
      }
      if(method!=="POST")throw Object.assign(new Error("Page not found"),{status:404});
      const form=new URLSearchParams(await readBody(req,8_000));
      if(!sameToken(form.get("csrf")??"",s.csrfToken))throw Object.assign(new Error("This form expired. Go back, reload the page and try again."),{status:403});
      const detail=await deps.admin.accountDetail(accountId);
      if(!detail)throw Object.assign(new Error("No such account"),{status:404});
      const revoke=rest.match(/^\/devices\/([0-9a-f-]{36})\/revoke$/);
      if(revoke){
        await deps.devices.removeDevice(accountId,revoke[1]!);
        await audit(accountId,"staff.device_revoked",{...staff,node_id:revoke[1]},ip,"staff");
        back("Device revoked. It can't connect any more.");return;
      }
      if(rest==="/recheck"){
        const access=await checkAccess(accountId,detail.email??undefined);
        await audit(accountId,"staff.payment_rechecked",{...staff,paid:access?.paid??null},ip,"staff");
        back(access?`Billing says: ${access.paid?"paid":"not paid"} (${access.status}). Devices updated to match.`:"BAPC Billing couldn't be reached; nothing changed.");return;
      }
      if(rest==="/close"){
        limit("closeAccount");
        const reason=(form.get("reason")??"").trim().slice(0,300);
        if((form.get("confirm")??"").trim()!==DELETE_CONFIRMATION||!reason){back(`Type ${DELETE_CONFIRMATION} and give a reason to close the account.`);return;}
        const access=deps.billing?await checkAccess(accountId):{paid:false,cancelAtPeriodEnd:false} as Pick<AccessState,"paid"|"cancelAtPeriodEnd">;
        if(access===null){back("BAPC Billing couldn't be reached, so nothing was deleted.");return;}
        if(access.paid&&!access.cancelAtPeriodEnd){back("Their plan would still renew. Cancel it in BAPC Billing first; nothing was deleted.");return;}
        const revoked=await deps.devices.revokeAll(accountId);
        await audit(accountId,"staff.account_closed",{...staff,reason,devices_revoked:revoked},ip,"staff");
        if(detail.email)await email(detail.email,accountId,"account_closed",customerEmails.accountClosed());
        const erased=await deps.accountData.eraseAccount(accountId);
        console.log(JSON.stringify({event:"portal.account_closed_by_staff",staff:s.email,devicesRevoked:revoked,...erased}));
        redirect(res,`/admin?q=&page=1`);return;
      }
      throw Object.assign(new Error("Page not found"),{status:404});
    }

    // --- account (signed in only) ---
    if(path==="/account"||path.startsWith("/account/")){
      if(!s){
        if(method==="GET")redirect(res,`/auth/start?next=${encodeURIComponent(path+url.search)}`);
        else redirect(res,"/auth/start");
        return;
      }
      if(method==="GET"&&path==="/account"){
        const access=await checkAccess(s.accountId,s.email);
        const wantPlan=url.searchParams.get("plan");
        send(res,200,accountPage({
          email:s.email,csrf:s.csrfToken,access,devices:await deps.devices.list(s.accountId),
          wantPlan:isPlanId(wantPlan)?wantPlan:null,
          checkoutUrl:plan=>deps.billing!.checkoutUrl(plan,s.accountId),manageUrl:deps.billing?.manageUrl()??"/",
          msg:url.searchParams.get("msg")?.slice(0,200),trials:deps.trials?.()??{}
        }));
        return;
      }
      // Everything the portal holds about this account, as a file (GDPR/CCPA access and portability).
      if(method==="GET"&&path==="/account/export"){
        limit("export");
        const data=await deps.accountData.exportAccount(s.accountId);
        const access=await checkAccess(s.accountId,s.email);
        await audit(s.accountId,"account.exported",{},ip);
        const body={
          exported_at:new Date().toISOString(),service:"BAPC VPN (vpn.bapc.app)",
          account:{bapc_account_id:s.accountId,email:s.email,name:s.name},
          plan:access?{paid:access.paid,plan:access.plan,status:access.status,renews_or_ends:access.renewsOrEnds,cancel_at_period_end:access.cancelAtPeriodEnd}:"BAPC Billing could not be reached; see https://billing.bapc.app",
          devices:data.devices,device_invites:data.invites,activity:data.activity,
          not_included:{
            payments_and_invoices:"held by BAPC Billing: https://billing.bapc.app",
            sign_in_account:"held by bapc.app: https://bapc.app/account",
            device_private_keys:"never stored: each device's private key was shown to you once and only lives on that device",
            browsing_activity:"never recorded: BAPC VPN keeps no logs of sites visited, DNS lookups or traffic content"
          }
        };
        send(res,200,JSON.stringify(body,null,2),"application/json; charset=utf-8",
          {"content-disposition":`attachment; filename="bapc-vpn-data-${new Date().toISOString().slice(0,10)}.json"`});
        return;
      }
      if(method!=="POST")throw Object.assign(new Error("not found"),{status:404});
      const form=new URLSearchParams(await readBody(req,8_000));
      if(!sameToken(form.get("csrf")??"",s.csrfToken))throw Object.assign(new Error("This form expired. Go back, reload the page and try again."),{status:403});

      if(path==="/account/devices"){
        limit("addDevice");
        const access=await checkAccess(s.accountId,s.email);
        if(!access?.paid){redirect(res,`/account?msg=${encodeURIComponent("Pick a plan first, then add your devices.")}`);return;}
        const kind=form.get("kind");
        if(!isDeviceKind(kind))throw Object.assign(new Error("Pick a kind of device."),{status:400});
        const account={accountId:s.accountId,email:s.email};
        if(kind==="windows"){
          const invite=await deps.devices.addWindowsDevice(account,form.get("name"));
          await audit(s.accountId,"device.windows_invite_created",{expires_at:invite.expiresAt},ip);
          send(res,200,windowsInvitePage({origin:deps.origin,code:invite.code,expiresAt:invite.expiresAt,name:form.get("name")?.trim()||"Windows PC"}));
          return;
        }
        const added=await deps.devices.addAppDevice(account,kind,form.get("name"));
        await audit(s.accountId,"device.added",{node_id:added.nodeId,kind,name:added.name},ip);
        await email(s.email,s.accountId,"device_added",customerEmails.deviceAdded(added.name,DEVICE_KINDS[kind]));
        const qrSvg=new QRCode({content:added.config,padding:2,ecl:"M",join:true,container:"svg-viewbox"}).svg();
        send(res,200,appDevicePage({kind,name:added.name,config:added.config,qrSvg}));
        return;
      }
      const remove=path.match(/^\/account\/devices\/([0-9a-f-]{36})\/remove$/);
      if(remove){
        await deps.devices.removeDevice(s.accountId,remove[1]!);
        await audit(s.accountId,"device.removed",{node_id:remove[1]},ip);
        redirect(res,`/account?msg=${encodeURIComponent("Device removed. It can't connect any more.")}`);
        return;
      }
      // Close the account (GDPR/CCPA erasure). A plan that would still renew must be cancelled in Billing first,
      // so nobody is charged for an account that no longer exists; if Billing can't be reached, nothing is deleted.
      if(path==="/account/delete"){
        limit("closeAccount");
        if((form.get("confirm")??"").trim()!==DELETE_CONFIRMATION){
          redirect(res,`/account?msg=${encodeURIComponent(`To close your account, type ${DELETE_CONFIRMATION} in the box.`)}#your-data`);return;
        }
        const access=deps.billing?await checkAccess(s.accountId,s.email):{paid:false,cancelAtPeriodEnd:false} as Pick<AccessState,"paid"|"cancelAtPeriodEnd">;
        if(access===null){redirect(res,`/account?msg=${encodeURIComponent("We couldn't check your plan with BAPC Billing just now, so nothing was deleted. Try again in a minute.")}#your-data`);return;}
        if(access.paid&&!access.cancelAtPeriodEnd){
          redirect(res,`/account?msg=${encodeURIComponent("Cancel your plan in BAPC Billing first (Manage or cancel), then close your account. Nothing was deleted.")}#your-data`);return;
        }
        const revoked=await deps.devices.revokeAll(s.accountId);
        await audit(s.accountId,"account.closed",{devices_revoked:revoked},ip);
        await email(s.email,s.accountId,"account_closed",customerEmails.accountClosed());
        const erased=await deps.accountData.eraseAccount(s.accountId);
        console.log(JSON.stringify({event:"portal.account_closed",devicesRevoked:revoked,...erased}));
        send(res,200,messagePage("Your BAPC VPN account is closed",
          `Your ${revoked===1?"device was":`${revoked} devices were`} switched off for good and your BAPC VPN data was deleted. Your sign-in account at bapc.app and your payment records at BAPC Billing are separate; manage or delete those at bapc.app/account and billing.bapc.app.`),
          "text/html; charset=utf-8",{"set-cookie":cookie("",0)});
        return;
      }
    }
    if(method==="GET"&&path==="/help"){send(res,200,helpPage(!!s));return;}
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
