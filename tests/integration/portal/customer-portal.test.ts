import test from "node:test";
import assert from "node:assert/strict";
import {createServer, type Server} from "node:http";
import type {AddressInfo} from "node:net";
import {generateKeyPairSync} from "node:crypto";
import {MemoryInvites, GATEWAY, deviceRequest} from "../devices/join-fakes.js";
import {DeviceJoinService, type InviteAccount} from "../../../src/application/device-join.js";
import {CustomerDeviceService, DEVICE_LIMIT, type CustomerDevice, type CustomerSession, type CustomerStore} from "../../../src/application/customer-devices.js";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {WindowsTpmAttestationProvider} from "../../../src/infrastructure/attestation/providers.js";
import {AccountAttestedVerifier} from "../../../src/infrastructure/attestation/account-attested.js";
import {BapcBillingClient, type AccessState} from "../../../src/infrastructure/bapc-accounts.js";
import {createPortalHandler, type PortalSessionStore} from "../../../src/runtime/portal-handler.js";
import {AuthorizationError} from "../../../src/domain/errors.js";

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

const startPortal=async(paid:{value:boolean})=>{
  const ctx=setup();
  const handler=createPortalHandler({
    origin:"http://portal.test",
    identity:{
      authorizeUrl:(redirectUri,state)=>`https://bapc.example/oauth/authorize?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
      exchange:async(code)=>code==="good"?{id:ACCOUNT.accountId,email:"Pat@Example.com",name:"Pat",role:"user",emailVerified:true}:null
    },
    billing:{
      checkoutUrl:(plan,account)=>`https://billing.example/checkout?plan=${plan}&account=${account}`,
      manageUrl:()=>"https://billing.example/",
      access:async():Promise<AccessState>=>({paid:paid.value,plan:paid.value?"monthly":null,status:paid.value?"active":"none",renewsOrEnds:null,cancelAtPeriodEnd:false})
    },
    sessions:ctx.customers,devices:ctx.devices,join:ctx.join,joinScript:()=>"# script"
  });
  const server:Server=createServer((q,s)=>void handler(q,s));
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const base=`http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {...ctx,server,base};
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
