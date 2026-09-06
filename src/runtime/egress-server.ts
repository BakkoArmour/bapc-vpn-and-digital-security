import {Socks5EgressProxy} from "../../services/egress/socks5-proxy.js";

const port=Number(process.env.EGRESS_PORT??1080);
const host=process.env.EGRESS_BIND_HOST??"0.0.0.0";
const allowlistEnv=process.env.EGRESS_ALLOWLIST; // comma-separated host:port or host

const proxy=new Socks5EgressProxy(allowlistEnv?{
  async isAllowed(host,port){
    const entries=allowlistEnv.split(",").map(e=>e.trim());
    return entries.includes(host)||entries.includes(`${host}:${port}`);
  }
}:undefined);

await proxy.start(port,host);
console.log(JSON.stringify({event:"ready",service:"bapc-egress-gateway",host,port}));

// Real self-registration/heartbeat against the control plane's
// POST /api/v1/egress/register and /:id/heartbeat — EgressSelector existed
// fully built and tested with no registry to select from at all. Entirely
// optional (every env var below has to be set), mirroring
// src/runtime/relay-server.ts exactly, including retrying registration on
// every heartbeat tick rather than giving up permanently if control-api
// isn't up yet on the first attempt.
const gatewayId=process.env.EGRESS_ID;
const gatewayRegion=process.env.EGRESS_REGION;
const gatewayFixedIp=process.env.EGRESS_FIXED_IP;
const controllerUrl=process.env.BAPC_CONTROLLER_URL;
const agentToken=process.env.BAPC_AGENT_TOKEN;

let heartbeatTimer:ReturnType<typeof setInterval>|undefined;
if(gatewayId&&gatewayRegion&&gatewayFixedIp&&controllerUrl&&agentToken){
  const call=async(path:string,body:unknown)=>{
    const res=await fetch(`${controllerUrl}${path}`,{
      method:"POST",headers:{authorization:`Bearer ${agentToken}`,"content-type":"application/json"},
      body:JSON.stringify(body)
    });
    if(!res.ok)throw new Error(`${path} failed (${res.status})`);
  };
  const registerAndHeartbeat=async()=>{
    try{
      await call("/api/v1/egress/register",{gatewayId,region:gatewayRegion,fixedIp:gatewayFixedIp});
      await call(`/api/v1/egress/${encodeURIComponent(gatewayId)}/heartbeat`,{
        loadPercent:0,healthy:true // real load sampling is a separate, deeper metrics gap — see docs
      });
      console.log(JSON.stringify({event:"egress.registered",gatewayId,region:gatewayRegion}));
    }catch(error){
      console.error(JSON.stringify({event:"egress.registration_failed",error:error instanceof Error?error.message:String(error)}));
    }
  };
  await registerAndHeartbeat();
  heartbeatTimer=setInterval(registerAndHeartbeat,30_000);
}else{
  console.log(JSON.stringify({
    event:"egress.registration_skipped",
    reason:"EGRESS_ID/EGRESS_REGION/EGRESS_FIXED_IP/BAPC_CONTROLLER_URL/BAPC_AGENT_TOKEN not all set — this gateway proxies traffic fine but won't be selected by EgressSelector"
  }));
}

const shutdown=async()=>{if(heartbeatTimer)clearInterval(heartbeatTimer);await proxy.stop();process.exit(0);};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
