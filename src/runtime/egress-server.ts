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

const shutdown=async()=>{await proxy.stop();process.exit(0);};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
