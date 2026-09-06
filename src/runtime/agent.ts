import {ProductionAgent} from "../../agents/shared/production-agent.js";
import {RestAgentController} from "../../services/mesh-controller/rest-agent-controller.js";
import {LinuxPlatformAdapter} from "../../native/linux/adapter.js";
import {WindowsPlatformAdapter} from "../../native/windows/adapter.js";
import type {PlatformAdapter} from "../../native/shared/platform-adapter.js";

const require=(name:string):string=>{
  const value=process.env[name];
  if(!value)throw new Error(`${name} environment variable is required to run the agent`);
  return value;
};

const nodeId=require("BAPC_NODE_ID");
const controllerUrl=require("BAPC_CONTROLLER_URL");
const agentToken=require("BAPC_AGENT_TOKEN");
const agentVersion=process.env.BAPC_AGENT_VERSION??"0.4.0";
const intervalMs=Number(process.env.BAPC_HEARTBEAT_INTERVAL_MS??30_000);

let platform:PlatformAdapter;
if(process.platform==="win32")platform=new WindowsPlatformAdapter();
else if(process.platform==="linux")platform=new LinuxPlatformAdapter();
else throw new Error(
  `no PlatformAdapter for process.platform=${process.platform}. `+
  `macOS/iOS/iPadOS require a native Swift NetworkExtension — see native/apple/adapter.ts.`
);

const controller=new RestAgentController(controllerUrl,agentToken);
const agent=new ProductionAgent(nodeId,agentVersion,platform,controller,intervalMs);

process.on("SIGTERM",()=>{agent.stop();process.exit(0);});
process.on("SIGINT",()=>{agent.stop();process.exit(0);});

console.log(JSON.stringify({event:"ready",service:"bapc-security-agent",nodeId,platform:platform.platform}));
await agent.run();
