export interface SecurityConfig {
  environment:"development"|"test"|"production";
  databaseUrl:string;
  certificateTtlMinutes:number;
  keyRotationDays:number;
  safeApplyTimeoutMs:number;
  safeApplyNodeFailureThreshold:number;
  authorizationRefreshMs:number;
  controlApiTokenSecret:string;
  eventSigningSecret:string;
  bindHost:string;
  port:number;
  oobRequired:boolean;
  oobControllerUrl:string;
  oobSharedSecret:string;
  ecosystemSecrets:{
    diagnostics:string; headquarters:string;
    "cloud-deployment":string; integration:string;
  };
}
const int=(v:string|undefined,d:number)=>{
  const n=Number(v??d);
  if(!Number.isFinite(n)||n<=0) throw new Error("invalid numeric configuration");
  return n;
};
const bool=(v:string|undefined,d:boolean)=>v===undefined?d:/^(1|true|yes)$/i.test(v);
const fraction=(v:string|undefined,d:number)=>{
  const n=Number(v??d);
  if(!Number.isFinite(n)||n<0||n>1)throw new Error("invalid fractional configuration (must be between 0 and 1)");
  return n;
};
const ecosystemSecret=(v:string|undefined,name:string,production:boolean)=>{
  if(production&&(!v||v.length<32))
    throw new Error(`production ${name} shared secret must be set and at least 32 characters`);
  return v||`development-${name}-secret-change-me`;
};
export const loadConfig=(env:NodeJS.ProcessEnv=process.env):SecurityConfig=>{
  const environment=(env.NODE_ENV as SecurityConfig["environment"])??"development";
  const secret=env.CONTROL_API_TOKEN_SECRET??"";
  const eventSecret=env.EVENT_SIGNING_SECRET??"";
  const oobSecret=env.OOB_SHARED_SECRET??"";
  if(environment==="production"&&(secret.length<32||eventSecret.length<32||oobSecret.length<32))
    throw new Error("production control/event signing/OOB shared secrets must be at least 32 characters");
  const production=environment==="production";
  return {
    environment,
    databaseUrl:env.DATABASE_URL??"postgres://localhost/bapc_security_core",
    certificateTtlMinutes:int(env.CERTIFICATE_TTL_MINUTES,1440),
    keyRotationDays:int(env.KEY_ROTATION_DAYS,30),
    safeApplyTimeoutMs:int(env.SAFE_APPLY_TIMEOUT_MS,60_000),
    // 0 (the default) means: any targeted node that explicitly fails or
    // never checks in within the window rolls back the whole rollout — see
    // SafeApplyService's own comment for why that's the safe default.
    safeApplyNodeFailureThreshold:fraction(env.SAFE_APPLY_NODE_FAILURE_THRESHOLD,0),
    authorizationRefreshMs:int(env.AUTH_REFRESH_MS,30_000),
    controlApiTokenSecret:secret||"development-only-change-me",
    eventSigningSecret:eventSecret||"development-event-secret-change-me",
    bindHost:env.BIND_HOST??(environment==="production"?"0.0.0.0":"127.0.0.1"),
    port:int(env.PORT,8080),
    oobRequired:bool(env.OOB_REQUIRED,true),
    oobControllerUrl:env.OOB_CONTROLLER_URL??"http://127.0.0.1:8181",
    oobSharedSecret:env.OOB_SHARED_SECRET||"development-oob-shared-secret-change-me",
    ecosystemSecrets:{
      diagnostics:ecosystemSecret(env.DIAGNOSTICS_SHARED_SECRET,"diagnostics",production),
      headquarters:ecosystemSecret(env.HEADQUARTERS_SHARED_SECRET,"headquarters",production),
      "cloud-deployment":ecosystemSecret(env.CLOUD_DEPLOYMENT_SHARED_SECRET,"cloud-deployment",production),
      integration:ecosystemSecret(env.INTEGRATION_SHARED_SECRET,"integration",production)
    }
  };
};
