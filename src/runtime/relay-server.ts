import {BlindRelayServer} from "../../services/relay/relay-server.js";

const port=Number(process.env.RELAY_PORT??51900);
const host=process.env.RELAY_BIND_HOST??"0.0.0.0";
const relay=new BlindRelayServer();
await relay.start(port,host);
console.log(JSON.stringify({event:"ready",service:"bapc-blind-relay",host,port}));

// Session registration is driven by the control plane (mesh-controller /
// RelayRegistry) over the gRPC/REST APIs in production; this process only
// forwards datagrams for sessions it has been told about. Wiring that
// control channel in is tracked alongside the relay/egress deployment
// workstream in docs/PRODUCTION-ADAPTERS.md.

const shutdown=async()=>{await relay.stop();process.exit(0);};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
