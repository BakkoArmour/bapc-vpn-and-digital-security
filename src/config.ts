export interface SecurityConfig {
  environment:"development"|"test"|"production";
  databaseUrl:string;
  certificateTtlMinutes:number;
  keyRotationDays:number;
  safeApplyTimeoutMs:number;
  authorizationRefreshMs:number;
  controlApiTokenSecret:string;
  eventSigningSecret:string;
  bindHost:string;
  port:number;
  oobRequired:boolean;
}
const int=(v:string|undefined,d:number)=>{
  const n=Number(v??d);
  if(!Number.isFinite(n)||n<=0) throw new Error("invalid numeric configuration");
  return n;
};
const bool=(v:string|undefined,d:boolean)=>v===undefined?d:/^(1|true|yes)$/i.test(v);
export const loadConfig=(env:NodeJS.ProcessEnv=process.env):SecurityConfig=>{
  const environment=(env.NODE_ENV as SecurityConfig["environment"])??"development";
  const secret=env.CONTROL_API_TOKEN_SECRET??"";
  const eventSecret=env.EVENT_SIGNING_SECRET??"";
  if(environment==="production"&&(secret.length<32||eventSecret.length<32))
    throw new Error("production control/event signing secrets must be at least 32 characters");
  return {
    environment,
    databaseUrl:env.DATABASE_URL??"postgres://localhost/bapc_security_core",
    certificateTtlMinutes:int(env.CERTIFICATE_TTL_MINUTES,1440),
    keyRotationDays:int(env.KEY_ROTATION_DAYS,30),
    safeApplyTimeoutMs:int(env.SAFE_APPLY_TIMEOUT_MS,60_000),
    authorizationRefreshMs:int(env.AUTH_REFRESH_MS,30_000),
    controlApiTokenSecret:secret||"development-only-change-me",
    eventSigningSecret:eventSecret||"development-event-secret-change-me",
    bindHost:env.BIND_HOST??(environment==="production"?"0.0.0.0":"127.0.0.1"),
    port:int(env.PORT,8080),
    oobRequired:bool(env.OOB_REQUIRED,true)
  };
};
