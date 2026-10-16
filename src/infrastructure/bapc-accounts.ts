import {createHash, randomBytes} from "node:crypto";

// Clients for the two shared BAPC services the customer portal relies on:
// "Sign in with BAPC" (bapc.app, OAuth 2 authorization code + PKCE, same as
// BAPC Billing's own sign-in) and BAPC Billing (billing.bapc.app: plans,
// Stripe checkout, and the "has this account paid?" check).

export const BILLING_APP_ID="bapc-vpn";
export const IDENTITY_CLIENT_ID="bapc-vpn";

const b64url=(b:Buffer)=>b.toString("base64url");
export const randomToken=(bytes=32)=>b64url(randomBytes(bytes));
export const sha256Hex=(s:string)=>createHash("sha256").update(s).digest("hex");
export const pkceChallenge=(verifier:string)=>b64url(createHash("sha256").update(verifier).digest());

export interface BapcUser {id:string;email:string;name:string;role:string;emailVerified:boolean;}

type Fetch=typeof fetch;

export class BapcIdentityClient {
  constructor(private baseUrl:string,private clientSecret:string,private fetchImpl:Fetch=fetch){}

  authorizeUrl(redirectUri:string,state:string,verifier:string):string{
    const u=new URL("/oauth/authorize",this.baseUrl);
    u.searchParams.set("response_type","code");
    u.searchParams.set("client_id",IDENTITY_CLIENT_ID);
    u.searchParams.set("redirect_uri",redirectUri);
    u.searchParams.set("state",state);
    u.searchParams.set("code_challenge",pkceChallenge(verifier));
    u.searchParams.set("code_challenge_method","S256");
    return u.toString();
  }

  async exchange(code:string,redirectUri:string,verifier:string):Promise<BapcUser|null>{
    const r=await this.fetchImpl(new URL("/oauth/token",this.baseUrl),{
      method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
      body:new URLSearchParams({
        grant_type:"authorization_code",client_id:IDENTITY_CLIENT_ID,client_secret:this.clientSecret,
        code,redirect_uri:redirectUri,code_verifier:verifier
      }),
      signal:AbortSignal.timeout(10_000)
    }).catch(()=>null);
    if(!r?.ok)return null;
    const body=await r.json().catch(()=>null) as {user?:BapcUser}|null;
    const u=body?.user;
    return u&&typeof u.id==="string"&&typeof u.email==="string"?u:null;
  }
}

export interface AccessState {paid:boolean;plan:string|null;status:string;renewsOrEnds:string|null;cancelAtPeriodEnd:boolean;}

export class BapcBillingClient {
  constructor(private baseUrl:string,private appKey:string,private fetchImpl:Fetch=fetch){}

  checkoutUrl(planId:string,accountId:string):string{
    const u=new URL("/checkout",this.baseUrl);
    u.searchParams.set("app",BILLING_APP_ID);
    u.searchParams.set("plan",planId);
    u.searchParams.set("account",accountId);
    return u.toString();
  }

  manageUrl():string{return new URL("/",this.baseUrl).toString();}

  // Throws when Billing can't be reached or refuses the app key, so callers
  // never mistake "couldn't check" for "hasn't paid" and switch a paying
  // customer's devices off because of an outage.
  async access(accountId:string):Promise<AccessState>{
    const u=new URL("/api/v1/access",this.baseUrl);
    u.searchParams.set("app",BILLING_APP_ID);
    u.searchParams.set("account",accountId);
    const r=await this.fetchImpl(u,{headers:{authorization:`Bearer ${this.appKey}`},signal:AbortSignal.timeout(10_000)});
    if(!r.ok)throw new Error(`BAPC Billing answered ${r.status}`);
    const b=await r.json() as {paid?:unknown;plan?:unknown;status?:unknown;renews_or_ends?:unknown;cancel_at_period_end?:unknown};
    if(typeof b.paid!=="boolean")throw new Error("BAPC Billing gave an unexpected answer");
    return {
      paid:b.paid,plan:typeof b.plan==="string"?b.plan:null,status:String(b.status??"none"),
      renewsOrEnds:typeof b.renews_or_ends==="string"?b.renews_or_ends:null,cancelAtPeriodEnd:b.cancel_at_period_end===true
    };
  }
}
