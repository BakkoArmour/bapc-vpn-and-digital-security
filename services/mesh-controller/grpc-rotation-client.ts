import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PROTO_PATH=join(__dirname,"..","..","contracts","mesh.proto");

export interface MeshRotationClient {
  rotatePeerKey(nodeId:string,newPublicKey:string,signature:Buffer):Promise<{acknowledged:boolean;effectiveEpoch:number}>;
}

// Real gRPC client for the same RotatePeerKey RPC src/api/grpc/server.ts
// verifies (real signature check against the node's enrolled identity key —
// see this session's key-rotation work). The endpoint agent previously only
// ever spoke REST (services/mesh-controller/rest-agent-controller.ts); this
// is the one thing it needs gRPC for — a threat-triggered identity rotation
// it must initiate itself, since the control plane can't sign on its
// behalf.
export class GrpcMeshRotationClient implements MeshRotationClient {
  private client:any;
  constructor(controllerGrpcUrl:string){
    const pkgDef=protoLoader.loadSync(PROTO_PATH,{keepCase:false,longs:String,enums:String,defaults:true,oneofs:true});
    const proto=grpc.loadPackageDefinition(pkgDef) as any;
    this.client=new proto.bapc.security.v1.MeshOrchestrationService(controllerGrpcUrl,grpc.credentials.createInsecure());
  }
  rotatePeerKey(nodeId:string,newPublicKey:string,signature:Buffer):Promise<{acknowledged:boolean;effectiveEpoch:number}>{
    return new Promise((resolve,reject)=>{
      this.client.rotatePeerKey({nodeId,newPublicKey,signature},(error:Error|null,response:unknown)=>
        error?reject(error):resolve(response as {acknowledged:boolean;effectiveEpoch:number})
      );
    });
  }
}
