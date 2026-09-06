import {BlindRelayServer} from "../../services/relay/relay-server.js";
import {CpuLoadSampler, ThroughputSampler} from "../../native/shared/process-metrics.js";

const port=Number(process.env.RELAY_PORT??51900);
const host=process.env.RELAY_BIND_HOST??"0.0.0.0";
const maxSessions=Number(process.env.RELAY_MAX_SESSIONS??500);
const relay=new BlindRelayServer();
await relay.start(port,host);
console.log(JSON.stringify({event:"ready",service:"bapc-blind-relay",host,port}));

// Real self-registration/heartbeat against the control plane's
// POST /api/v1/relays/register and /:id/heartbeat — previously this file's
// own comment said session registration was "driven by the control plane"
// but nothing on either side ever actually did it, so RelayRoutingService
// (services/mesh-controller/controller.ts's MeshController) never had a
// real candidate to select regardless of how healthy this relay was.
// Entirely optional: every required env var below has to be set for this
// to run at all, and the relay itself still forwards datagrams fine
// without it — this only affects whether the control plane knows this
// relay exists as a routing candidate.
const relayId=process.env.RELAY_ID;
const relayRegion=process.env.RELAY_REGION;
const relayPublicEndpoint=process.env.RELAY_PUBLIC_ENDPOINT;
const controllerUrl=process.env.BAPC_CONTROLLER_URL;
const agentToken=process.env.BAPC_AGENT_TOKEN;

let heartbeatTimer:ReturnType<typeof setInterval>|undefined;
if(relayId&&relayRegion&&relayPublicEndpoint&&controllerUrl&&agentToken){
  const call=async(path:string,body:unknown)=>{
    const res=await fetch(`${controllerUrl}${path}`,{
      method:"POST",headers:{authorization:`Bearer ${agentToken}`,"content-type":"application/json"},
      body:JSON.stringify(body)
    });
    if(!res.ok)throw new Error(`${path} failed (${res.status})`);
  };
  const cpu=new CpuLoadSampler();
  const throughput=new ThroughputSampler();
  // register() is an idempotent upsert (PgRelayStore.insert), so re-running
  // it every tick alongside the heartbeat is safe and self-healing: if
  // control-api isn't up yet when this container starts (a real startup
  // race in compose — migrate/control-api can still be starting after this
  // relay is already listening), the very next tick just retries both
  // instead of this relay silently never becoming a routing candidate for
  // the rest of its process lifetime.
  const registerAndHeartbeat=async()=>{
    try{
      // capacity_mbps*20 is the sessions-per-Mbps convention this schema
      // already used for the now-deleted RelayRegistry — reporting our own
      // RELAY_MAX_SESSIONS back through it keeps that convention honest
      // instead of leaving every relay at the generic default forever.
      await call("/api/v1/relays/register",{relayId,region:relayRegion,endpoint:relayPublicEndpoint,capacityMbps:Math.max(1,Math.round(maxSessions/20))});
      // Real measurements: activeSessions/throughput from the actual
      // relay's live state, loadPercent from this process's own CPU usage
      // since the last tick, latencyMs from this very heartbeat call's
      // round trip to the control plane — no more hardcoded 0s.
      const activeSessions=relay.activeSessionCount;
      const loadPercent=cpu.sample();
      const throughputBytesPerSec=throughput.sample(relay.totalBytesRelayed);
      const heartbeatStart=Date.now();
      await call(`/api/v1/relays/${encodeURIComponent(relayId)}/heartbeat`,{
        loadPercent,latencyMs:Date.now()-heartbeatStart,activeSessions,throughputBytesPerSec
      });
      console.log(JSON.stringify({event:"relay.registered",relayId,region:relayRegion,activeSessions,loadPercent}));
    }catch(error){
      console.error(JSON.stringify({event:"relay.registration_failed",error:error instanceof Error?error.message:String(error)}));
    }
  };
  await registerAndHeartbeat();
  heartbeatTimer=setInterval(registerAndHeartbeat,30_000);
}else{
  console.log(JSON.stringify({
    event:"relay.registration_skipped",
    reason:"RELAY_ID/RELAY_REGION/RELAY_PUBLIC_ENDPOINT/BAPC_CONTROLLER_URL/BAPC_AGENT_TOKEN not all set — this relay forwards traffic fine but won't be selected by RelayRoutingService"
  }));
}

const shutdown=async()=>{if(heartbeatTimer)clearInterval(heartbeatTimer);await relay.stop();process.exit(0);};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
