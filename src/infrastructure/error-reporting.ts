import {basename} from "node:path";
import {reportError} from "./obop-errors.js";

// Sends this process's errors to BAPC Observability & Operations (telemetry.bapc.app) without touching the many
// places that already log them: every service writes one-line JSON to stderr ({"event":"…","error":"…"}), so
// console.error is wrapped and any line that is an error is also reported (obop-errors.ts scrubs it, caps it at
// 20 a minute and never throws). Crashes and unhandled promise failures are reported as critical, then the
// process exits so Docker restarts it. Without OBOP_INGEST_TOKEN / OBOP_SYSTEM_ID it only logs, as before.
//
// One token covers the whole stack: every process reports as service "web" (OBOP_SERVICE_KEY), with its own
// name in the app.process attribute, because an Observability token is scoped to the services it was issued for.

let installed=false;
const RELEASE=process.env.BAPC_RELEASE??process.env.npm_package_version??"unknown";
const ERRORISH=/(error|fail|fatal|crash|refused|denied|timeout)/i;

// Which stderr lines are errors worth reporting: JSON with an "error" field, or an event name that says so.
// Expected, customer-caused outcomes (a wrong sign-in, a refused invite) are logged at info level elsewhere.
export const errorFromLogLine=(line:string):{event:string;message:string;attributes:Record<string,string|number|boolean>}|null=>{
  const t=line.trim();
  if(!t.startsWith("{"))return null;
  let o:Record<string,unknown>;
  try{o=JSON.parse(t) as Record<string,unknown>;}catch{return null;}
  const event=typeof o.event==="string"?o.event:"";
  const err=o.error;
  if(err===undefined&&!ERRORISH.test(event))return null;
  const message=typeof err==="string"?err:err===undefined?event:JSON.stringify(err);
  const attributes:Record<string,string|number|boolean>={};
  for(const [k,v] of Object.entries(o)){
    if(k==="error"||k==="event"||!/^[A-Za-z0-9_.-]{1,64}$/.test(k))continue;
    if(typeof v==="string"||typeof v==="boolean"||(typeof v==="number"&&Number.isFinite(v)))attributes[`log.${k}`]=v;
    if(Object.keys(attributes).length>=20)break;
  }
  return {event:event||"error",message,attributes};
};

export const installErrorReporting=(processName=basename(process.argv[1]??"node").replace(/\.js$/,""))=>{
  if(installed)return;installed=true;
  const env=process.env;
  const connected=!!env.OBOP_INGEST_TOKEN&&!!env.OBOP_SYSTEM_ID;
  const base={release:RELEASE};
  const send=(error:unknown,route:string,severity:"high"|"critical",attributes:Record<string,string|number|boolean>={})=>
    connected?reportError(env,error,{...base,route,severity,attributes:{"app.process":processName,...attributes}}).catch(()=>false):Promise.resolve(false);

  const original=console.error.bind(console);
  console.error=(...args:unknown[])=>{
    original(...args);
    if(!connected||args.length!==1||typeof args[0]!=="string")return;
    const e=errorFromLogLine(args[0]);
    if(e)void send(Object.assign(new Error(e.message),{name:e.event}),e.event,/fatal|crash/i.test(e.event)?"critical":"high",e.attributes);
  };

  const die=(kind:string)=>async(error:unknown)=>{
    original(JSON.stringify({event:`process.${kind}`,process:processName,error:error instanceof Error?`${error.name}: ${error.message}`:String(error)}));
    await send(error,`process.${kind}`,"critical");
    process.exit(1);
  };
  process.on("uncaughtException",die("uncaught_exception"));
  process.on("unhandledRejection",die("unhandled_rejection"));
  if(connected)console.log(JSON.stringify({event:"observability.connected",process:processName,system:env.OBOP_SYSTEM_ID}));
};
