import {existsSync, mkdirSync, readFileSync, writeFileSync} from "node:fs";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {platform as osPlatform, release as osRelease, type as osType} from "node:os";
import {randomUUID} from "node:crypto";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {LinuxPlatformAdapter} from "../../native/linux/adapter.js";
import {WindowsPlatformAdapter} from "../../native/windows/adapter.js";
import type {PlatformAdapter} from "../../native/shared/platform-adapter.js";
import {systemCommandRunner} from "../../native/shared/command-runner.js";
import {enrollNode, type EnrollmentGrpcClient} from "./enroll-node.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PROTO_PATH=join(__dirname,"..","..","..","contracts","mesh.proto");

const argOf=(name:string):string|undefined=>{
  const flag=`--${name}`;
  const i=process.argv.indexOf(flag);
  return i!==-1?process.argv[i+1]:undefined;
};

// Best-effort real hardware identifier: /etc/machine-id on Linux (present on
// every systemd host), the SMBIOS system UUID via WMI on Windows. Falls back
// to a random id with a loud warning rather than silently reusing "unknown"
// across every host — a real deployment should pass --hardware-uuid from a
// TPM-backed identifier when one is available.
const detectHardwareUuid=async():Promise<string>=>{
  const override=argOf("hardware-uuid");
  if(override)return override;
  if(osPlatform()==="linux"&&existsSync("/etc/machine-id")){
    const id=readFileSync("/etc/machine-id","utf8").trim();
    if(id)return id;
  }
  if(osPlatform()==="win32"){
    try{
      const {stdout}=await systemCommandRunner("powershell.exe",[
        "-NoProfile","-NonInteractive","-Command",
        "(Get-CimInstance Win32_ComputerSystemProduct).UUID"
      ]);
      const id=stdout.trim();
      if(id)return id;
    }catch{/* fall through to the random id below */}
  }
  const random=randomUUID();
  console.error(JSON.stringify({
    event:"enroll.hardware_uuid_fallback",
    warning:"could not read a real hardware identifier — using a random id. Pass --hardware-uuid to fix this for a real deployment.",
    hardwareUuid:random
  }));
  return random;
};

const buildGrpcClient=(controllerGrpcUrl:string):EnrollmentGrpcClient=>{
  const pkgDef=protoLoader.loadSync(PROTO_PATH,{keepCase:false,longs:String,enums:String,defaults:true,oneofs:true});
  const proto=grpc.loadPackageDefinition(pkgDef) as any;
  const client=new proto.bapc.security.v1.MeshOrchestrationService(controllerGrpcUrl,grpc.credentials.createInsecure());
  return {
    registerNode:(request)=>new Promise((resolve,reject)=>{
      client.registerNode(request,(error:Error|null,response:unknown)=>error?reject(error):resolve(response as any));
    })
  };
};

// Where enrollment output is written. Matches the existing installers'
// conventions (installers/linux/install.sh's CONFIG_DIR, installers/windows/
// install.ps1's $installDir) so the endpoint-agent service picks it up from
// the same place an operator already expects agent state to live.
const defaultOutDir=()=>osPlatform()==="win32"?"C:\\Program Files\\BapcSecurityAgent":"/etc/bapc-security";

// Linux only: agent.env is a simple KEY=VALUE file systemd loads via
// EnvironmentFile= (installers/linux/bapc-security-agent.service) — safe to
// upsert a single line in place. Windows' WinSW service XML isn't touched
// here; see the printed instructions instead, to avoid corrupting a
// hand-tuned service definition.
const upsertEnvLine=(path:string,key:string,value:string)=>{
  const existing=existsSync(path)?readFileSync(path,"utf8"):"";
  const line=`${key}=${value}`;
  const pattern=new RegExp(`^${key}=.*$`,"m");
  const updated=pattern.test(existing)?existing.replace(pattern,line):`${existing.trimEnd()}\n${line}\n`;
  writeFileSync(path,updated.replace(/^\n+/,""));
};

try{
  const outDir=argOf("out-dir")??defaultOutDir();
  const controllerGrpcUrl=argOf("controller-grpc-url")??process.env.BAPC_CONTROLLER_GRPC_URL??"127.0.0.1:50051";
  mkdirSync(outDir,{recursive:true});

  let platform:PlatformAdapter;
  if(osPlatform()==="win32")platform=new WindowsPlatformAdapter();
  else if(osPlatform()==="linux")platform=new LinuxPlatformAdapter();
  else throw new Error(
    `no PlatformAdapter for os.platform()=${osPlatform()}. `+
    `macOS/iOS/iPadOS require a native Swift NetworkExtension — see native/apple/adapter.ts.`
  );

  const hardwareUuid=await detectHardwareUuid();
  const osSignature=`${osType()} ${osRelease()}`;
  const client=buildGrpcClient(controllerGrpcUrl);

  const result=await enrollNode(client,platform,{hardwareUuid,osSignature});

  writeFileSync(join(outDir,"wg-private.key"),result.wireGuardPrivateKey,{mode:0o600});
  writeFileSync(join(outDir,"identity-key.pem"),result.identityPrivateKeyPem,{mode:0o600});
  writeFileSync(join(outDir,"client-cert.pem"),result.certificatePem);

  if(osPlatform()==="linux"){
    upsertEnvLine(join(outDir,"agent.env"),"BAPC_NODE_ID",result.nodeId);
  }

  console.log(JSON.stringify({
    event:"enroll.complete",nodeId:result.nodeId,assignedZone:result.assignedZone,
    wireGuardPublicKey:result.wireGuardPublicKey,outDir
  }));
  if(osPlatform()==="win32"){
    console.log(JSON.stringify({
      event:"enroll.manual_step_required",
      instruction:`Add <env name="BAPC_NODE_ID" value="${result.nodeId}"/> to the WinSW service XML, then restart the service.`
    }));
  }
  console.log(JSON.stringify({
    event:"enroll.manual_step_required",
    instruction:"BAPC_CONTROLLER_URL and BAPC_AGENT_TOKEN are operational credentials this flow does not mint — set them in agent.env (Linux) or the service XML (Windows) before starting the agent."
  }));
}catch(error){
  console.error(JSON.stringify({event:"fatal",error:error instanceof Error?error.message:String(error)}));
  process.exit(1);
}
