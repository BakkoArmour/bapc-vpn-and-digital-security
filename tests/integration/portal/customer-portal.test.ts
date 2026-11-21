import test from "node:test";
import assert from "node:assert/strict";
import {createServer, type Server} from "node:http";
import type {AddressInfo} from "node:net";
import {createHmac, generateKeyPairSync} from "node:crypto";
import {MemoryInvites, GATEWAY, deviceRequest} from "../devices/join-fakes.js";
import {DeviceJoinService, type InviteAccount} from "../../../src/application/device-join.js";
import {CustomerDeviceService, DEVICE_LIMIT, type CustomerDevice, type CustomerSession, type CustomerStore} from "../../../src/application/customer-devices.js";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {WindowsTpmAttestationProvider} from "../../../src/infrastructure/attestation/providers.js";
import {AccountAttestedVerifier} from "../../../src/infrastructure/attestation/account-attested.js";
import {BapcBillingClient, type AccessState} from "../../../src/infrastructure/bapc-accounts.js";
import {createPortalHandler, verifyBillingHook, type PortalSessionStore} from "../../../src/runtime/portal-handler.js";
import {AuthorizationError} from "../../../src/domain/errors.js";
import type {AccountDataStore, AccountExport, AdminAccountDetail, AdminStore} from "../../../src/application/account-data.js";
import {BapcNotifier} from "../../../src/infrastructure/bapc-notifications.js";

// The customer portal end to end against in-memory stores: account-attested
// app devices, account-bound Windows invites redeemed through the real TPM
// join path, the device limit, removal, payment-driven pausing, and the HTTP
// layer (sign-in, CSRF, plan gating).

class MemoryCustomers implements CustomerStore, PortalSessionStore {
  rows=new Map<string,{account:InviteAccount;kind:string;suspended:boolean;removed:boolean;createdAt:Date}>();
  signIns=new Map<string,{verifier:string;nextPath:string}>();
  sessionsByHash=new Map<string,CustomerSession>();
  constructor(private nodes:MemoryStore){}
  async record(nodeId:string,account:InviteAccount,kind:string){this.rows.set(nodeId,{account,kind,suspended:false,removed:false,createdAt:new Date()});}
  async devices(accountId:string):Promise<CustomerDevice[]>{
    return [...this.rows.entries()].filter(([,r])=>r.account.accountId===accountId&&!r.removed)
      .map(([nodeId,r])=>({nodeId,name:r.account.deviceName,kind:r.kind,createdAt:r.createdAt,suspended:r.suspended,address:this.nodes.nodes.get(nodeId)!.internalIpv4}));
  }
  async markRemoved(accountId:string,nodeId:string){
    const r=this.rows.get(nodeId);
    if(!r||r.removed||r.account.accountId!==accountId)return false;
    r.removed=true;return true;
  }
  async setSuspended(accountId:string,suspended:boolean){
    let n=0;for(const r of this.rows.values())if(r.account.accountId===accountId&&!r.removed&&r.suspended!==suspended){r.suspended=suspended;n++;}
    return n;
  }
  async suspendedNodeIds(){return new Set([...this.rows.entries()].filter(([,r])=>r.suspended||r.removed).map(([id])=>id));}
  async saveSignIn(state:string,verifier:string,nextPath:string){this.signIns.set(state,{verifier,nextPath});}
  async takeSignIn(state:string){const v=this.signIns.get(state)??null;this.signIns.delete(state);return v;}
  async createSession(tokenHash:string,s:Omit<CustomerSession,"tokenHash">){this.sessionsByHash.set(tokenHash,{tokenHash,...s});}
  async session(tokenHash:string){return this.sessionsByHash.get(tokenHash)??null;}
  async deleteSession(tokenHash:string){this.sessionsByHash.delete(tokenHash);}
}

class MemoryAccountData implements AccountDataStore {
  log:{accountId:string;actor:"customer"|"system"|"staff";action:string;detail:Record<string,unknown>;ip:string|null;at:Date}[]=[];
  constructor(private customers:MemoryCustomers){}
  async audit(accountId:string,actor:"customer"|"system"|"staff",action:string,detail:Record<string,unknown>={},ip:string|null=null){this.log.push({accountId,actor,action,detail,ip,at:new Date()});}
  async hasSignedInBefore(accountId:string){return this.log.some(e=>e.accountId===accountId&&e.action==="auth.signed_in");}
  async exportAccount(accountId:string):Promise<AccountExport>{
    return {
      devices:[...this.customers.rows.values()].filter(r=>r.account.accountId===accountId)
        .map(r=>({name:r.account.deviceName,kind:r.kind,address:"",createdAt:r.createdAt,suspended:r.suspended,removedAt:r.removed?new Date():null,lastHandshake:null})),
      invites:[],
      activity:this.log.filter(e=>e.accountId===accountId).map(({accountId:_a,...e})=>e)
    };
  }
  async eraseAccount(accountId:string){
    let devices=0,sessions=0,auditRows=0;
    for(const r of this.customers.rows.values())if(r.account.accountId===accountId){r.account={accountId:"erased",email:"",deviceName:"Removed device"};r.removed=true;devices++;}
    for(const [h,s] of this.customers.sessionsByHash)if(s.accountId===accountId){this.customers.sessionsByHash.delete(h);sessions++;}
    for(const e of this.log)if(e.accountId===accountId){e.accountId="erased";e.detail={};e.ip=null;auditRows++;}
    return {devices,invites:0,sessions,auditRows};
  }
}

// Staff view over the same in-memory stores.
class MemoryAdmin implements AdminStore {
  constructor(private customers:MemoryCustomers,private data:MemoryAccountData){}
  private ids(){return [...new Set([...[...this.customers.rows.values()].map(r=>r.account.accountId),...this.data.log.filter(e=>e.action==="auth.signed_in").map(e=>e.accountId)])].filter(a=>a!=="erased");}
  private email(id:string){return [...this.customers.rows.values()].find(r=>r.account.accountId===id)?.account.email??[...this.customers.sessionsByHash.values()].find(x=>x.accountId===id)?.email??"";}
  async listAccounts(q:{search?:string;page:number;pageSize:number}){
    const search=(q.search??"").toLowerCase();
    const all=this.ids().map(id=>({accountId:id,email:this.email(id),
      activeDevices:[...this.customers.rows.values()].filter(r=>r.account.accountId===id&&!r.removed&&!r.suspended).length,
      pausedDevices:[...this.customers.rows.values()].filter(r=>r.account.accountId===id&&!r.removed&&r.suspended).length,
      lastSignIn:null,firstSeen:null})).filter(r=>!search||r.email.includes(search)||r.accountId===search);
    return {rows:all.slice((q.page-1)*q.pageSize,q.page*q.pageSize),total:all.length};
  }
  async accountDetail(id:string):Promise<AdminAccountDetail|null>{
    if(!this.ids().includes(id))return null;
    return {accountId:id,email:this.email(id)||null,
      devices:[...this.customers.rows.entries()].filter(([,r])=>r.account.accountId===id).map(([nodeId,r])=>({nodeId,name:r.account.deviceName,kind:r.kind,address:"",createdAt:r.createdAt,suspended:r.suspended,removedAt:r.removed?new Date():null,lastHandshake:null})),
      activity:this.data.log.filter(e=>e.accountId===id).map(({accountId:_a,...e})=>e)};
  }
}

const SECRET="x".repeat(40);
const ACCOUNT={accountId:"user-1",email:"pat@example.com"};

const setup=()=>{
  const repo=new MemoryStore(),clock=new SystemClock(),invites=new MemoryInvites(),customers=new MemoryCustomers(repo);
  const certs={issueNodeCertificate:async(nodeId:string)=>({serial:nodeId,certificatePem:"CERT",expiresAt:new Date()}),revoke:async()=>{}};
  const enrollment=(v:ConstructorParameters<typeof EnrollmentService>[3])=>new EnrollmentService(repo,repo,repo,v,certs,new NoopPeerDistributor(),new RandomIds(),clock);
  const attestation=new AccountAttestedVerifier(SECRET);
  const join=new DeviceJoinService(invites,enrollment(new WindowsTpmAttestationProvider()),repo,GATEWAY,clock,customers);
  const devices=new CustomerDeviceService(customers,invites,enrollment(attestation),attestation,repo,repo,GATEWAY,clock);
  return {repo,invites,customers,join,devices,attestation};
};

test("account attestation proofs are bound to the hardware id and identity key, and can't be forged",async()=>{
  const v=new AccountAttestedVerifier(SECRET);
  const key=generateKeyPairSync("rsa",{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}}).publicKey;
  const proof=v.proof("app-1",key);
  assert.equal(await v.verify("app-1",proof,key),true);
  assert.equal(await v.verify("app-2",proof,key),false);
  assert.equal(await v.verify("app-1",proof,key.replace("A","B")),false);
  assert.equal(await new AccountAttestedVerifier("y".repeat(40)).verify("app-1",proof,key),false);
  assert.equal(await v.verify("app-1",new Uint8Array(0),key),false);
  assert.throws(()=>new AccountAttestedVerifier("short"));
});

test("a phone is enrolled for a paying account and gets a full-tunnel config pointed at the gateway",async()=>{
  const {repo,devices}=setup();
  const added=await devices.addAppDevice(ACCOUNT,"iphone","Pat's iPhone");
  assert.match(added.config,/^\[Interface\]\nPrivateKey = [A-Za-z0-9+/]{43}=\nAddress = 10\.144\.10\.3\/32, fd14:4b41:5043::2\/128/);
  assert.match(added.config,new RegExp(`PublicKey = ${GATEWAY.publicKey.replace(/[+/]/g,"\\$&")}`));
  assert.match(added.config,/AllowedIPs = 0\.0\.0\.0\/0, ::\/0\nEndpoint = 203\.0\.113\.10:51820/);
  const listed=await devices.list(ACCOUNT.accountId);
  assert.deepEqual(listed.map(d=>[d.name,d.kind]),[["Pat's iPhone","iphone"]]);
  assert.equal(repo.devices.get(repo.nodes.get(added.nodeId)!.deviceId)!.platform,"ios");
});

test("a Windows invite minted in the portal lands the PC in that customer's device list when redeemed",async()=>{
  const {join,devices}=setup();
  const invite=await devices.addWindowsDevice(ACCOUNT,"Office PC");
  const joined=await join.join(deviceRequest(invite.code));
  assert.deepEqual((await devices.list(ACCOUNT.accountId)).map(d=>[d.nodeId,d.name,d.kind]),[[joined.nodeId,"Office PC","windows"]]);
});

test("each account is limited to five devices, counting unredeemed Windows invites",async()=>{
  const {devices}=setup();
  for(let i=0;i<DEVICE_LIMIT-1;i++)await devices.addAppDevice(ACCOUNT,"android",`phone ${i}`);
  await devices.addWindowsDevice(ACCOUNT,"pc");
  await assert.rejects(devices.addAppDevice(ACCOUNT,"mac","one too many"),AuthorizationError);
  await assert.rejects(devices.addWindowsDevice(ACCOUNT,"pc2"),AuthorizationError);
  await devices.addAppDevice({accountId:"someone-else",email:"x@example.com"},"mac","theirs");
});

test("removing a device revokes it for good and frees a slot",async()=>{
  const {repo,join,devices,customers}=setup();
  const a=await devices.addAppDevice(ACCOUNT,"android","old phone");
  await assert.rejects(devices.removeDevice("someone-else",a.nodeId));
  await devices.removeDevice(ACCOUNT.accountId,a.nodeId);
  assert.equal(repo.devices.get(repo.nodes.get(a.nodeId)!.deviceId)!.revoked,true);
  assert.deepEqual(await devices.list(ACCOUNT.accountId),[]);
  assert.deepEqual((await join.gatewayPeers(repo,await customers.suspendedNodeIds())).map(p=>p.nodeId),[]);
});

test("a lapsed payment pauses the account's devices on the gateway, and paying resumes them",async()=>{
  const {repo,join,devices,customers}=setup();
  const mine=await devices.addAppDevice(ACCOUNT,"android","phone");
  const theirs=await devices.addAppDevice({accountId:"other",email:"o@example.com"},"android","phone");
  assert.equal(await devices.applyPaymentState(ACCOUNT.accountId,false),1);
  const peers=async()=>(await join.gatewayPeers(repo,await customers.suspendedNodeIds())).map(p=>p.nodeId).sort();
  assert.deepEqual(await peers(),[theirs.nodeId]);
  assert.equal(await devices.applyPaymentState(ACCOUNT.accountId,true),1);
  assert.deepEqual(await peers(),[mine.nodeId,theirs.nodeId].sort());
});

test("BapcBillingClient never mistakes an outage for an unpaid account",async()=>{
  const down=new BapcBillingClient("https://billing.example","k".repeat(40),(async()=>new Response("nope",{status:502})) as typeof fetch);
  await assert.rejects(down.access("user-1"));
  let seen="";
  const up=new BapcBillingClient("https://billing.example","k".repeat(40),(async(u:URL,init?:RequestInit)=>{
    seen=`${u} ${(init?.headers as Record<string,string>).authorization}`;
    return Response.json({paid:true,plan:"yearly",status:"active",renews_or_ends:"2027-10-16T00:00:00Z",cancel_at_period_end:false});
  }) as typeof fetch);
  assert.deepEqual(await up.access("user-1"),{paid:true,plan:"yearly",status:"active",renewsOrEnds:"2027-10-16T00:00:00Z",cancelAtPeriodEnd:false});
  assert.equal(seen,`https://billing.example/api/v1/access?app=bapc-vpn&account=user-1 Bearer ${"k".repeat(40)}`);
  assert.equal(up.checkoutUrl("monthly","user-1"),"https://billing.example/checkout?app=bapc-vpn&plan=monthly&account=user-1");
});

// --- HTTP layer ---

const startPortal=async(paid:{value:boolean},opts:{trials?:Record<string,number>;status?:string;renews?:string;cancelAtPeriodEnd?:boolean;billingDown?:{value:boolean};hookSecret?:string}={})=>{
  const ctx=setup();
  const accountData=new MemoryAccountData(ctx.customers);
  const sent:{to:string;subject:string;text:string}[]=[];
  const mail={send:async(to:string,subject:string,text:string)=>{sent.push({to,subject,text});return "accepted" as const;}};
  const handler=createPortalHandler({
    origin:"http://portal.test",
    identity:{
      authorizeUrl:(redirectUri,state)=>`https://bapc.example/oauth/authorize?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
      exchange:async(code)=>code==="good"?{id:ACCOUNT.accountId,email:"Pat@Example.com",name:"Pat",role:"user",emailVerified:true}:code==="admin"?{id:"staff-1",email:"Boss@BAPC.app",name:"Boss",role:"admin",emailVerified:true}:null
    },
    billing:{
      checkoutUrl:(plan,account)=>`https://billing.example/checkout?plan=${plan}&account=${account}`,
      manageUrl:()=>"https://billing.example/",
      access:async():Promise<AccessState>=>{
        if(opts.billingDown?.value)throw new Error("BAPC Billing answered 502");
        return {paid:paid.value,plan:paid.value?"monthly":null,status:paid.value?(opts.status??"active"):"none",renewsOrEnds:opts.renews??null,cancelAtPeriodEnd:opts.cancelAtPeriodEnd??false};
      }
    },
    sessions:ctx.customers,devices:ctx.devices,join:ctx.join,joinScript:()=>"# script",
    trials:()=>opts.trials??{},accountData,mail,admin:new MemoryAdmin(ctx.customers,accountData),...(opts.hookSecret?{billingHookSecret:opts.hookSecret}:{})
  });
  const server:Server=createServer((q,s)=>void handler(q,s));
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const base=`http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {...ctx,server,base,accountData,sent};
};

const signIn=async(base:string)=>{
  const start=await fetch(`${base}/auth/start?next=/account`,{redirect:"manual"});
  const state=new URL(start.headers.get("location")!).searchParams.get("state")!;
  const cb=await fetch(`${base}/auth/callback?state=${state}&code=good`,{redirect:"manual"});
  assert.equal(cb.status,303);
  assert.equal(cb.headers.get("location"),"/account");
  return cb.headers.get("set-cookie")!.split(";")[0]!;
};

test("the public pages render with a strict content security policy and no account needed",async()=>{
  const {server,base}=await startPortal({value:false});
  try{
    const home=await fetch(base);
    assert.equal(home.status,200);
    assert.match(home.headers.get("content-security-policy")!,/default-src 'none'/);
    const html=await home.text();
    assert.match(html,/\$8\.99/);assert.match(html,/\$2\.99/);assert.doesNotMatch(html,/<script/i);
    for(const p of ["/privacy","/terms"])assert.equal((await fetch(base+p)).status,200);
    assert.equal(await (await fetch(`${base}/install/join-vpn.ps1`)).text(),"# script");
    const account=await fetch(`${base}/account`,{redirect:"manual"});
    assert.equal(account.status,303);
    assert.match(account.headers.get("location")!,/^\/auth\/start\?next=/);
  }finally{server.close();}
});

test("BapcBillingClient reads free-trial days from Billing's public plan list, ignoring junk",async()=>{
  let seen="";
  const c=new BapcBillingClient("https://billing.example","",(async(u:URL,init?:RequestInit)=>{
    seen=`${u} ${JSON.stringify(init?.headers??null)}`;
    return Response.json({app:"bapc-vpn",plans:[{id:"monthly",trial_days:7},{id:"yearly",trial_days:0},{id:"odd",trial_days:"lots"},{id:"huge",trial_days:90}]});
  }) as typeof fetch);
  assert.deepEqual(await c.trialDays(),{monthly:7});
  assert.equal(seen,"https://billing.example/api/v1/plans?app=bapc-vpn null"); // public: no key sent
  const down=new BapcBillingClient("https://billing.example","",(async()=>new Response("x",{status:503})) as typeof fetch);
  await assert.rejects(down.trialDays());
});

test("a free trial is advertised only when Billing gives one",async()=>{
  const none=await startPortal({value:false});
  try{
    const html=await (await fetch(none.base)).text();
    assert.doesNotMatch(html,/free trial/i);
    assert.match(html,/Get BAPC VPN/);
  }finally{none.server.close();}
  const withTrial=await startPortal({value:false},{trials:{monthly:7,yearly:7}});
  try{
    const html=await (await fetch(withTrial.base)).text();
    assert.match(html,/Try it free for 7 days/);
    assert.match(html,/7-day free trial/);
    assert.match(html,/Free for 7 days, then \$8\.99 a month/);
    assert.match(html,/Free for 7 days, then \$35\.88 a year/);
    assert.match(html,/nothing is charged until the trial ends/);
    const terms=await (await fetch(`${withTrial.base}/terms`)).text();
    assert.match(terms,/Free trial/);
    const cookie=await signIn(withTrial.base);
    const account=await (await fetch(`${withTrial.base}/account`,{headers:{cookie}})).text();
    assert.match(account,/Start 7-day free trial/);
    assert.match(account,/New customers only/);
  }finally{withTrial.server.close();}
});

test("during a free trial the account page says when it ends and what it costs after",async()=>{
  const {server,base}=await startPortal({value:true},{trials:{monthly:7},status:"trialing",renews:"2026-11-28T00:00:00Z"});
  try{
    const cookie=await signIn(base);
    const html=await (await fetch(`${base}/account`,{headers:{cookie}})).text();
    assert.match(html,/Your free trial is on/);
    assert.match(html,/It ends November 28, 2026; after that your card is charged \$8\.99 a month unless you cancel/);
  }finally{server.close();}
});

test("a forged or replayed sign-in is refused",async()=>{
  const {server,base}=await startPortal({value:false});
  try{
    assert.equal((await fetch(`${base}/auth/callback?state=made-up&code=good`)).status,400);
    const start=await fetch(`${base}/auth/start`,{redirect:"manual"});
    const state=new URL(start.headers.get("location")!).searchParams.get("state")!;
    assert.equal((await fetch(`${base}/auth/callback?state=${state}&code=bad`)).status,400);
    assert.equal((await fetch(`${base}/auth/callback?state=${state}&code=good`)).status,400);
  }finally{server.close();}
});

test("without a plan the account page offers checkout and won't add devices",async()=>{
  const {server,base,customers}=await startPortal({value:false});
  try{
    const cookie=await signIn(base);
    const html=await (await fetch(`${base}/account`,{headers:{cookie}})).text();
    assert.match(html,/pat@example\.com/);
    assert.match(html,/billing\.example\/checkout\?plan=yearly&amp;account=user-1/);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    const add=await fetch(`${base}/account/devices`,{method:"POST",redirect:"manual",headers:{cookie,"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({csrf,kind:"iphone"})});
    assert.equal(add.status,303);
    assert.match(add.headers.get("location")!,/Pick%20a%20plan/);
  }finally{server.close();}
});

test("a paying customer adds a phone and sees its QR code; a missing CSRF token is refused",async()=>{
  const {server,base,customers}=await startPortal({value:true});
  try{
    const cookie=await signIn(base);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    const post=(body:Record<string,string>)=>fetch(`${base}/account/devices`,{method:"POST",redirect:"manual",headers:{cookie,"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams(body)});
    assert.equal((await post({kind:"iphone"})).status,403);
    const page=await post({csrf,kind:"iphone",name:"My iPhone"});
    assert.equal(page.status,200);
    const html=await page.text();
    assert.match(html,/<svg/);assert.match(html,/Scan from QR code/);
    const win=await (await post({csrf,kind:"windows",name:"PC"})).text();
    assert.match(win,/irm http:\/\/portal\.test\/install\/join-vpn\.ps1 -OutFile/);
    assert.match(win,/-InviteCode BAPC-[0-9A-Z]{6}-/);
    const account=await (await fetch(`${base}/account`,{headers:{cookie}})).text();
    assert.match(account,/My iPhone/);
    assert.match(account,/Your plan is active/);
  }finally{server.close();}
});

test("the join API answers the Windows installer in JSON, including refusals",async()=>{
  const {server,base}=await startPortal({value:true});
  try{
    const r=await fetch(`${base}/api/v1/devices/join`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(deviceRequest("BAPC-000000-000000-000000-000000"))});
    assert.equal(r.status,403);
    assert.match((await r.json() as {error:{message:string}}).error.message,/invite code is not valid/);
  }finally{server.close();}
});

// --- audit trail, data export, account closure (Enterprise Standard: audit log; GDPR/CCPA export and delete) ---

const formPost=(base:string,cookie:string,path:string,body:Record<string,string>)=>
  fetch(`${base}${path}`,{method:"POST",redirect:"manual",headers:{cookie,"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams(body)});

test("sign-in, adding and removing a device and sign-out are all in the audit trail, with who, what and when",async()=>{
  const {server,base,customers,accountData}=await startPortal({value:true});
  try{
    const cookie=await signIn(base);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    await formPost(base,cookie,"/account/devices",{csrf,kind:"android",name:"Pixel"});
    const nodeId=[...customers.rows.keys()][0]!;
    await formPost(base,cookie,`/account/devices/${nodeId}/remove`,{csrf});
    await formPost(base,cookie,"/auth/logout",{});
    const actions=accountData.log.filter(e=>e.actor==="customer").map(e=>`${e.actor}:${e.action}`);
    assert.deepEqual(actions,["customer:auth.signed_in","customer:device.added","customer:device.removed","customer:auth.signed_out"]);
    assert.ok(accountData.log.filter(e=>e.actor==="customer").every(e=>e.accountId===ACCOUNT.accountId&&e.at instanceof Date&&e.ip));
    assert.equal(accountData.log.find(e=>e.action==="device.added")!.detail.kind,"android");
  }finally{server.close();}
});

test("a lapsed payment is audited as a system action when devices pause",async()=>{
  const paid={value:true};
  const {server,base,customers,accountData}=await startPortal(paid);
  try{
    const cookie=await signIn(base);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    await formPost(base,cookie,"/account/devices",{csrf,kind:"iphone"});
    paid.value=false;
    await fetch(`${base}/account`,{headers:{cookie}});
    const pause=accountData.log.find(e=>e.action==="payment.devices_paused");
    assert.equal(pause?.actor,"system");assert.equal(pause?.detail.devices,1);
  }finally{server.close();}
});

test("Download my data returns everything held about the account as a JSON file, and never a private key",async()=>{
  const {server,base,customers}=await startPortal({value:true});
  try{
    const cookie=await signIn(base);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    const setup=await (await formPost(base,cookie,"/account/devices",{csrf,kind:"mac",name:"Work Mac"})).text();
    const config=Buffer.from(setup.match(/data:application\/octet-stream;base64,([A-Za-z0-9+/=]+)/)?.[1]??"","base64").toString("utf8");
    const privateKey=config.match(/PrivateKey = ([A-Za-z0-9+/=]{44})/)?.[1];
    assert.ok(privateKey,"setup page shows the key once");
    const account=await (await fetch(`${base}/account`,{headers:{cookie}})).text();
    assert.match(account,/Download my data/);assert.match(account,/Close my account/);
    const r=await fetch(`${base}/account/export`,{headers:{cookie}});
    assert.equal(r.status,200);
    assert.match(r.headers.get("content-disposition")!,/attachment; filename="bapc-vpn-data-\d{4}-\d{2}-\d{2}\.json"/);
    const text=await r.text();
    const data=JSON.parse(text) as {account:{email:string};devices:{name:string;kind:string}[];activity:{action:string}[];plan:{paid:boolean};not_included:Record<string,string>};
    assert.equal(data.account.email,"pat@example.com");
    assert.deepEqual(data.devices.map(d=>[d.name,d.kind]),[["Work Mac","mac"]]);
    assert.ok(data.activity.some(a=>a.action==="device.added"));
    assert.equal(data.plan.paid,true);
    assert.ok(data.not_included.device_private_keys);
    assert.ok(!text.includes(privateKey!),"the export never contains a device private key");
    assert.equal((await fetch(`${base}/account/export`,{redirect:"manual"})).status,303,"signed-out export goes to sign-in");
  }finally{server.close();}
});

test("closing the account needs DELETE typed, a cancelled plan and a reachable Billing; then devices are revoked and data erased",async()=>{
  const paid={value:true},billingDown={value:false};
  const {server,base,customers,accountData,repo}=await startPortal(paid,{billingDown});
  try{
    const cookie=await signIn(base);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    await formPost(base,cookie,"/account/devices",{csrf,kind:"android",name:"Phone"});
    const nodeId=[...customers.rows.keys()][0]!;
    const noCsrf=await formPost(base,cookie,"/account/delete",{confirm:"DELETE"});
    assert.equal(noCsrf.status,403);
    const noWord=await formPost(base,cookie,"/account/delete",{csrf,confirm:"delete please"});
    assert.match(decodeURIComponent(noWord.headers.get("location")!),/type DELETE/);
    const stillPaying=await formPost(base,cookie,"/account/delete",{csrf,confirm:"DELETE"});
    assert.match(decodeURIComponent(stillPaying.headers.get("location")!),/Cancel your plan in BAPC Billing first/);
    billingDown.value=true;
    const down=await formPost(base,cookie,"/account/delete",{csrf,confirm:"DELETE"});
    assert.match(decodeURIComponent(down.headers.get("location")!),/nothing was deleted/);
    assert.equal(customers.rows.get(nodeId)!.removed,false,"nothing happened before the checks passed");
    billingDown.value=false;paid.value=false;
    const done=await formPost(base,cookie,"/account/delete",{csrf,confirm:"DELETE"});
    assert.equal(done.status,200);
    assert.match(await done.text(),/Your BAPC VPN account is closed/);
    assert.match(done.headers.get("set-cookie")!,/Max-Age=0/);
    const node=repo.nodes.get(nodeId)!;
    assert.equal((await repo.get(node.deviceId))!.revoked,true,"the device can never connect again");
    const row=customers.rows.get(nodeId)!;
    assert.equal(row.account.email,"");assert.notEqual(row.account.accountId,ACCOUNT.accountId);
    assert.equal(customers.sessionsByHash.size,0,"signed out everywhere");
    assert.ok(accountData.log.every(e=>e.accountId!==ACCOUNT.accountId&&e.ip===null),"audit rows no longer identify the person");
    assert.ok(accountData.log.some(e=>e.action==="account.closed"));
    assert.equal((await fetch(`${base}/account`,{headers:{cookie},redirect:"manual"})).status,303,"the old cookie no longer works");
  }finally{server.close();}
});

test("help, privacy and terms point to BAPC Support, explain the one cookie, and never show a personal address",async()=>{
  const {server,base}=await startPortal({value:false});
  try{
    for(const p of ["/","/help","/privacy","/terms"]){
      const html=await (await fetch(base+p)).text();
      assert.match(html,/support\.bapc\.app/,p);
      assert.match(html,/one sign-in cookie/,p);
      assert.doesNotMatch(html,/gmail\.com/,p);
    }
    const help=await (await fetch(`${base}/help`)).text();
    assert.match(help,/It isn't connecting/);assert.match(help,/support@bapc\.app/);
    assert.match(await (await fetch(`${base}/privacy`)).text(),/bapc_vpn_session/);
  }finally{server.close();}
});

// --- customer email (BAPC Notifications) ---

test("BapcNotifier posts to BAPC Notifications with the app key, and reports outcomes instead of throwing",async()=>{
  let seen:{url:string;auth:string;body:Record<string,string>}|null=null;
  const ok=new BapcNotifier("n".repeat(40),"https://notifications.example",(async(u:URL,init?:RequestInit)=>{
    seen={url:String(u),auth:(init!.headers as Record<string,string>).authorization!,body:JSON.parse(String(init!.body))};
    return Response.json({messageId:"m1"},{status:202});
  }) as typeof fetch);
  assert.equal(await ok.send("pat@example.com","Hi","Body"),"accepted");
  assert.equal(seen!.url,"https://notifications.example/v1/email");
  assert.equal(seen!.auth,`Bearer ${"n".repeat(40)}`);
  assert.deepEqual(seen!.body,{from:"BAPC VPN <no-reply@bapc.app>",to:"pat@example.com",subject:"Hi",text:"Body",replyTo:"support@bapc.app"});
  assert.equal(await new BapcNotifier("").send("a@b.c","s","t"),"not_connected");
  const status=(n:number)=>new BapcNotifier("n".repeat(40),"https://n.example",(async()=>new Response("{}",{status:n})) as typeof fetch);
  assert.equal(await status(400).send("a@b.c","s","t"),"rejected");
  assert.equal(await status(503).send("a@b.c","s","t"),"retry");
  assert.equal(await new BapcNotifier("n".repeat(40),"https://n.example",(async()=>{throw new Error("down");}) as typeof fetch).send("a@b.c","s","t"),"retry");
});

test("customers are emailed: welcome once, each new device, paused and resumed devices, and account closed",async()=>{
  const paid={value:true};
  const {server,base,customers,sent}=await startPortal(paid);
  try{
    const cookie=await signIn(base);
    await signIn(base); // a second sign-in doesn't send a second welcome
    assert.deepEqual(sent.map(m=>m.subject),["Welcome to BAPC VPN"]);
    assert.equal(sent[0]!.to,"pat@example.com");
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    await formPost(base,cookie,"/account/devices",{csrf,kind:"iphone",name:"Pat's iPhone"});
    assert.equal(sent.at(-1)!.subject,"New device on your BAPC VPN: Pat's iPhone");
    assert.match(sent.at(-1)!.text,/If this wasn't you, remove it now/);
    assert.doesNotMatch(sent.at(-1)!.text,/PrivateKey|BAPC-[0-9A-Z]{6}-/,"never a key or setup code in email");
    paid.value=false;
    await fetch(`${base}/account`,{headers:{cookie}});
    assert.equal(sent.at(-1)!.subject,"Your BAPC VPN devices are paused");
    await fetch(`${base}/account`,{headers:{cookie}});
    assert.equal(sent.filter(m=>m.subject.includes("paused")).length,1,"no repeat while nothing changes");
    paid.value=true;
    await fetch(`${base}/account`,{headers:{cookie}});
    assert.equal(sent.at(-1)!.subject,"Your BAPC VPN devices are back on");
    paid.value=false;
    await formPost(base,cookie,"/account/delete",{csrf,confirm:"DELETE"});
    assert.equal(sent.at(-1)!.subject,"Your BAPC VPN account is closed");
  }finally{server.close();}
});

// --- BAPC Billing plan.changed hook ---

const HOOK_SECRET=`bhk_${"a".repeat(64)}`;
const signHook=(raw:string,secret=HOOK_SECRET,t=Math.floor(Date.now()/1000))=>`t=${t},v1=${createHmac("sha256",secret).update(`${t}.${raw}`).digest("hex")}`;
const postHook=(base:string,body:Record<string,unknown>,sig?:string)=>{
  const raw=JSON.stringify(body);
  return fetch(`${base}/api/v1/billing/hook`,{method:"POST",headers:{"content-type":"application/json","x-bapc-signature":sig??signHook(raw)},body:raw});
};

test("verifyBillingHook accepts only Billing's signature, fresh, over the exact body",()=>{
  const raw='{"a":1}',now=Math.floor(Date.now()/1000);
  assert.equal(verifyBillingHook(HOOK_SECRET,signHook(raw),raw),true);
  assert.equal(verifyBillingHook(HOOK_SECRET,signHook(raw,"bhk_other"),raw),false);
  assert.equal(verifyBillingHook(HOOK_SECRET,signHook(raw),'{"a":2}'),false);
  assert.equal(verifyBillingHook(HOOK_SECRET,signHook(raw,HOOK_SECRET,now-3600),raw,now),false,"an old (replayed) event is refused");
  assert.equal(verifyBillingHook(HOOK_SECRET,"garbage",raw),false);
  assert.equal(verifyBillingHook("",signHook(raw,""),raw),false);
});

test("a signed plan.changed from Billing pauses and resumes devices at once, emails and audits once per event",async()=>{
  const {server,base,customers,accountData,sent}=await startPortal({value:true},{hookSecret:HOOK_SECRET});
  try{
    const cookie=await signIn(base);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    await formPost(base,cookie,"/account/devices",{csrf,kind:"android"});
    const nodeId=[...customers.rows.keys()][0]!;
    const lapsed={event_id:"bevt_1",type:"plan.changed",app:"bapc-vpn",account:ACCOUNT.accountId,email:"pat@example.com",paid:false,status:"past_due"};
    assert.equal((await postHook(base,lapsed,"t=1,v1=00")).status,401,"unsigned or forged events are refused");
    assert.equal(customers.rows.get(nodeId)!.suspended,false);
    const r=await postHook(base,lapsed);
    assert.equal(r.status,200);
    assert.deepEqual(await r.json(),{ok:true,devices_changed:1});
    assert.equal(customers.rows.get(nodeId)!.suspended,true,"paused without waiting for the 15-minute sync");
    assert.equal(sent.at(-1)!.subject,"Your BAPC VPN devices are paused");
    assert.deepEqual(await (await postHook(base,lapsed)).json(),{duplicate:true});
    assert.equal(sent.filter(m=>m.subject.includes("paused")).length,1,"a retried event isn't emailed twice");
    assert.equal(accountData.log.filter(e=>e.action==="billing.plan_changed").length,1);
    await postHook(base,{...lapsed,event_id:"bevt_2",paid:true,status:"active"});
    assert.equal(customers.rows.get(nodeId)!.suspended,false);
    assert.equal(sent.at(-1)!.subject,"Your BAPC VPN devices are back on");
    assert.deepEqual(await (await postHook(base,{...lapsed,event_id:"bevt_3",app:"some-other-app"})).json(),{ignored:true});
  }finally{server.close();}
});

test("without a hook secret the route says it isn't configured",async()=>{
  const {server,base}=await startPortal({value:true});
  try{assert.equal((await postHook(base,{event_id:"e",type:"plan.changed",app:"bapc-vpn",account:"a",paid:true})).status,503);}
  finally{server.close();}
});

// --- staff admin (/admin) ---

const signInAs=async(base:string,code:string)=>{
  const start=await fetch(`${base}/auth/start?next=/admin`,{redirect:"manual"});
  const state=new URL(start.headers.get("location")!).searchParams.get("state")!;
  const cb=await fetch(`${base}/auth/callback?state=${state}&code=${code}`,{redirect:"manual"});
  return cb.headers.get("set-cookie")!.split(";")[0]!;
};

test("the admin area is invisible to customers and signed-out visitors (404 everywhere, even for POST)",async()=>{
  const {server,base,customers}=await startPortal({value:true});
  try{
    assert.equal((await fetch(`${base}/admin`,{redirect:"manual"})).status,404);
    const cookie=await signIn(base);
    for(const p of ["/admin","/admin/accounts/user-1"])assert.equal((await fetch(base+p,{headers:{cookie}})).status,404,p);
    const csrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    assert.equal((await formPost(base,cookie,"/admin/accounts/user-1/close",{csrf,confirm:"DELETE",reason:"x"})).status,404);
  }finally{server.close();}
});

test("a BAPC admin lists and searches customers, opens one, revokes a device and closes the account, all audited as staff",async()=>{
  const paid={value:true};
  const {server,base,customers,accountData,repo}=await startPortal(paid);
  try{
    const pat=await signIn(base);
    const patCsrf=[...customers.sessionsByHash.values()][0]!.csrfToken;
    await formPost(base,pat,"/account/devices",{csrf:patCsrf,kind:"android",name:"Pat phone"});
    await formPost(base,pat,"/account/devices",{csrf:patCsrf,kind:"iphone",name:"Pat iPad"});
    const boss=await signInAs(base,"admin");
    const bossCsrf=[...customers.sessionsByHash.values()].find(x=>x.email==="boss@bapc.app")!.csrfToken;
    const list=await (await fetch(`${base}/admin`,{headers:{cookie:boss}})).text();
    assert.match(list,/pat@example\.com/);assert.match(list,/2 accounts/);assert.match(list,/admin\/accounts\/staff-1/,"anyone who signed in is listed, staff too (as in the real store)");
    assert.match(await (await fetch(`${base}/admin?q=nobody`,{headers:{cookie:boss}})).text(),/No accounts match/);
    assert.match(await (await fetch(`${base}/admin?q=PAT`,{headers:{cookie:boss}})).text(),/pat@example\.com/);
    const page=await (await fetch(`${base}/admin/accounts/user-1`,{headers:{cookie:boss}})).text();
    assert.match(page,/Pat phone/);assert.match(page,/Pat iPad/);assert.match(page,/Paying/);assert.match(page,/device\.added/);
    assert.equal((await fetch(`${base}/admin/accounts/nope`,{headers:{cookie:boss}})).status,404);
    const nodeId=[...customers.rows.entries()].find(([,r])=>r.account.deviceName==="Pat phone")![0];
    assert.equal((await formPost(base,boss,`/admin/accounts/user-1/devices/${nodeId}/revoke`,{confirm:"x"})).status,403,"CSRF required");
    const rv=await formPost(base,boss,`/admin/accounts/user-1/devices/${nodeId}/revoke`,{csrf:bossCsrf});
    assert.match(decodeURIComponent(rv.headers.get("location")!),/Device revoked/);
    assert.equal((await repo.get(repo.nodes.get(nodeId)!.deviceId))!.revoked,true);
    const rc=await formPost(base,boss,"/admin/accounts/user-1/recheck",{csrf:bossCsrf});
    assert.match(decodeURIComponent(rc.headers.get("location")!),/Billing says: paid/);
    const noReason=await formPost(base,boss,"/admin/accounts/user-1/close",{csrf:bossCsrf,confirm:"DELETE"});
    assert.match(decodeURIComponent(noReason.headers.get("location")!),/give a reason/);
    const renewing=await formPost(base,boss,"/admin/accounts/user-1/close",{csrf:bossCsrf,confirm:"DELETE",reason:"asked by email"});
    assert.match(decodeURIComponent(renewing.headers.get("location")!),/Cancel it in BAPC Billing first/);
    const staffActions=accountData.log.filter(e=>e.actor==="staff");
    assert.deepEqual(staffActions.map(e=>e.action),["staff.device_revoked","staff.payment_rechecked"]);
    assert.ok(staffActions.every(e=>e.detail.staff==="boss@bapc.app"&&e.ip));
    paid.value=false;
    const closed=await formPost(base,boss,"/admin/accounts/user-1/close",{csrf:bossCsrf,confirm:"DELETE",reason:"asked by email, ticket 42"});
    assert.equal(closed.status,303);
    assert.ok([...customers.rows.values()].every(r=>r.removed&&r.account.email===""),"devices revoked and data erased");
    assert.ok(accountData.log.some(e=>e.action==="staff.account_closed"),"closure recorded (pseudonymised with the rest)");
  }finally{server.close();}
});
