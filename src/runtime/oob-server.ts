import {OobServer} from "../../services/oob-controller/oob-server.js";
import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";

await hydrateSecretsFromAws();
const secret=process.env.OOB_SHARED_SECRET;
if(!secret||secret.length<32){
  console.error(JSON.stringify({event:"fatal",error:"OOB_SHARED_SECRET must be set and at least 32 characters"}));
  process.exit(1);
}

const port=Number(process.env.OOB_PORT??8181);
const host=process.env.OOB_BIND_HOST??"127.0.0.1";
const server=new OobServer(secret);
await server.start(port,host);
console.log(JSON.stringify({event:"ready",service:"bapc-oob-controller",host,port}));

const shutdown=async()=>{await server.stop();process.exit(0);};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
