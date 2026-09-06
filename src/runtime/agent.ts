import {existsSync} from "node:fs";
import {ProductionAgent} from "../../agents/shared/production-agent.js";
import {RestAgentController} from "../../services/mesh-controller/rest-agent-controller.js";
import {GrpcMeshRotationClient} from "../../services/mesh-controller/grpc-rotation-client.js";
import {FileIdentitySigner} from "../../agents/shared/identity-signer.js";
import {LinuxPlatformAdapter} from "../../native/linux/adapter.js";
import {WindowsPlatformAdapter} from "../../native/windows/adapter.js";
import type {PlatformAdapter} from "../../native/shared/platform-adapter.js";
import {AgentReconciler} from "../agent/reconciler.js";

const requireEnv=(name:string):string=>{
  const value=process.env[name];
  if(!value)throw new Error(`${name} environment variable is required to run the agent`);
  return value;
};

try{
  const nodeId=requireEnv("BAPC_NODE_ID");
  const controllerUrl=requireEnv("BAPC_CONTROLLER_URL");
  const agentToken=requireEnv("BAPC_AGENT_TOKEN");
  const agentVersion=process.env.BAPC_AGENT_VERSION??"0.4.0";
  const intervalMs=Number(process.env.BAPC_HEARTBEAT_INTERVAL_MS??30_000);

  let platform:PlatformAdapter;
  let reconciler:AgentReconciler|undefined;
  if(process.platform==="win32"){
    const adapter=new WindowsPlatformAdapter();
    platform=adapter; reconciler=new AgentReconciler(adapter);
  }else if(process.platform==="linux"){
    const adapter=new LinuxPlatformAdapter();
    platform=adapter; reconciler=new AgentReconciler(adapter);
  }else throw new Error(
    `no PlatformAdapter for process.platform=${process.platform}. `+
    `macOS/iOS/iPadOS require a native Swift NetworkExtension — see native/apple/adapter.ts.`
  );

  const controller=new RestAgentController(controllerUrl,agentToken);

  // Both optional: ROTATE_IDENTITY_REQUIRED (ThreatEngine's emergency-tier
  // response) only works when the agent knows where to reach the gRPC mesh
  // service and where enroll.ts wrote this node's identity private key. If
  // either is missing, the agent still runs fine — that one command type
  // fails cleanly with a clear error (see ProductionAgent.execute) instead
  // of anything else being affected.
  const controllerGrpcUrl=process.env.BAPC_CONTROLLER_GRPC_URL;
  const identityKeyPath=process.env.BAPC_IDENTITY_KEY_PATH;
  const rotationClient=controllerGrpcUrl?new GrpcMeshRotationClient(controllerGrpcUrl):undefined;
  const identitySigner=(identityKeyPath&&existsSync(identityKeyPath))?new FileIdentitySigner(identityKeyPath):undefined;

  const agent=new ProductionAgent(nodeId,agentVersion,platform,controller,intervalMs,reconciler,rotationClient,identitySigner);

  process.on("SIGTERM",()=>{agent.stop();process.exit(0);});
  process.on("SIGINT",()=>{agent.stop();process.exit(0);});

  console.log(JSON.stringify({event:"ready",service:"bapc-security-agent",nodeId,platform:platform.platform}));
  await agent.run();
}catch(error){
  console.error(JSON.stringify({event:"fatal",error:error instanceof Error?error.message:String(error)}));
  process.exit(1);
}
