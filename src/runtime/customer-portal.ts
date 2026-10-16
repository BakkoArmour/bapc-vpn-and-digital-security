import {createServer} from "node:http";
import {createHmac} from "node:crypto";
import {readFileSync} from "node:fs";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {RandomIds, SystemClock} from "../infrastructure/memory.js";
import {NoopPeerDistributor} from "../infrastructure/adapters.js";
import {buildAttestationVerifier} from "../infrastructure/attestation/attestation-verifier.js";
import {AccountAttestedVerifier} from "../infrastructure/attestation/account-attested.js";
import {PgEnrollmentInviteStore} from "../infrastructure/pg-enrollment-invites.js";
import {PgCustomerStore} from "../infrastructure/pg-customer-store.js";
import {BapcBillingClient, BapcIdentityClient} from "../infrastructure/bapc-accounts.js";
import {EnrollmentService} from "../application/enrollment.js";
import {DeviceJoinService} from "../application/device-join.js";
import {CustomerDeviceService} from "../application/customer-devices.js";
import {loadTrustAnchor} from "../../services/trust-core/trust-anchor.js";
import {TrustCoreIssuer} from "../../services/trust-core/issuer.js";
import {ForgeX509Builder} from "../../services/trust-core/x509-forge.js";
import {TrustCoreCertificateIssuer} from "../../services/trust-core/trust-core-certificate-issuer.js";
import {PgCertificateStore} from "../../services/trust-core/pg-certificate-store.js";
import {createPortalHandler} from "./portal-handler.js";

// vpn.bapc.app — the customer portal (see portal-handler.ts). Env:
//   PORTAL_PUBLIC_ORIGIN  https://vpn.bapc.app
//   BAPC_IDENTITY_URL / BAPC_CLIENT_SECRET   Sign in with BAPC (client id bapc-vpn)
//   BAPC_BILLING_URL / BAPC_BILLING_KEY      BAPC Billing (app id bapc-vpn)
// Without the BAPC_* secrets the public pages still work and sign-in says
// "coming soon" rather than failing.

const __dirname=dirname(fileURLToPath(import.meta.url));
const JOIN_SCRIPT_PATH=join(__dirname,"..","..","..","installers","windows","join-vpn.ps1");
const SYNC_INTERVAL_MS=15*60_000;

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);
const clock=new SystemClock(),ids=new RandomIds();
const env=process.env;

const trustAnchor=await loadTrustAnchor(db);
const certificateIssuer=new TrustCoreCertificateIssuer(new TrustCoreIssuer(
  trustAnchor.keys,new PgCertificateStore(db),new ForgeX509Builder(),
  {id:trustAnchor.issuerId,certificatePem:trustAnchor.certificatePem,keyReference:trustAnchor.keyReference,algorithm:trustAnchor.algorithm}
));
const customers=new PgCustomerStore(db);
const invites=new PgEnrollmentInviteStore(db);
// Derived, not a new secret to manage: only this process ever computes it.
const accountAttestation=new AccountAttestedVerifier(
  createHmac("sha256",config.controlApiTokenSecret).update("bapc-vpn/account-attested-enrollment/v1").digest("hex")
);
const enrollmentWith=(verifier:ConstructorParameters<typeof EnrollmentService>[3])=>new EnrollmentService(
  repo,repo,repo,verifier,certificateIssuer,new NoopPeerDistributor(),ids,clock,config.certificateTtlMinutes
);
const deviceJoin=new DeviceJoinService(
  invites,enrollmentWith(buildAttestationVerifier(config.attestationProvider,config.environment)),
  repo,config.vpnGateway,clock,customers
);
const devices=new CustomerDeviceService(
  customers,invites,enrollmentWith(accountAttestation),accountAttestation,repo,repo,config.vpnGateway,clock
);
const identity=env.BAPC_CLIENT_SECRET&&env.BAPC_CLIENT_SECRET.length>=32
  ?new BapcIdentityClient(env.BAPC_IDENTITY_URL??"https://bapc.app",env.BAPC_CLIENT_SECRET):null;
const billing=env.BAPC_BILLING_KEY&&env.BAPC_BILLING_KEY.length>=32
  ?new BapcBillingClient(env.BAPC_BILLING_URL??"https://billing.bapc.app",env.BAPC_BILLING_KEY):null;

const joinScript=readFileSync(JOIN_SCRIPT_PATH,"utf8");
const handler=createPortalHandler({
  origin:(env.PORTAL_PUBLIC_ORIGIN??"https://vpn.bapc.app").replace(/\/$/,""),
  identity,billing,sessions:customers,devices,join:deviceJoin,joinScript:()=>joinScript
});

// Billing is checked whenever a customer opens their account, and here on a
// timer for everyone else, so a lapsed plan pauses its devices (and a
// renewed one resumes them) without anyone having to visit the site. An
// account Billing can't answer for right now is left exactly as it is.
const syncPayments=async()=>{
  if(!billing)return;
  for(const accountId of await customers.accountsWithDevices()){
    try{
      const access=await billing.access(accountId);
      const changed=await devices.applyPaymentState(accountId,access.paid);
      if(changed)console.log(JSON.stringify({event:"portal.payment_state",accountId,paid:access.paid,devices:changed}));
    }catch(error){
      console.error(JSON.stringify({event:"portal.payment_check_failed",accountId,error:error instanceof Error?error.message:String(error)}));
    }
  }
};
const timer=setInterval(()=>void syncPayments().catch(()=>{}),SYNC_INTERVAL_MS);

const server=createServer((req,res)=>void handler(req,res));
server.requestTimeout=20_000;server.headersTimeout=10_000;server.keepAliveTimeout=5_000;
const port=Number(env.PORTAL_PORT??8095),host=env.PORTAL_BIND_HOST??"127.0.0.1";
server.listen(port,host,()=>console.log(JSON.stringify({
  event:"ready",service:"bapc-vpn-portal",host,port,signIn:!!identity,billing:!!billing,gateway:!!config.vpnGateway
})));

const shutdown=()=>{clearInterval(timer);server.close(()=>void db.close().then(()=>process.exit(0)));setTimeout(()=>process.exit(1),10_000).unref();};
process.on("SIGTERM",shutdown);process.on("SIGINT",shutdown);
