import type {CommandQueue, KeyRotationLedger} from "../../../src/api/grpc/server.js";
import type {MeshCommandSink} from "../../../services/mesh-controller/controller.js";

// These three were previously exported from src/api/grpc/server.ts itself —
// production source shipping test-only doubles alongside the real
// buildMeshGrpcServer. InMemoryKeyRotationLedger was literally the old
// production implementation before PgKeyRotationLedger replaced it
// (services/mesh-controller/pg-key-rotation-ledger.ts's own comment);
// InMemoryCommandQueue/LoggingMeshCommandSink were always test-only stand-ins
// for PgCommandQueue/PgMeshCommandSink. Moved here so the production file
// only exports what production actually uses.

export class InMemoryKeyRotationLedger implements KeyRotationLedger {
  private epoch=0;
  async rotate(_nodeId:string,_newPublicKey:string,signature:Uint8Array){
    if(signature.length===0)throw new Error("rotation signature required");
    this.epoch+=1;
    return {acknowledged:true,effectiveEpoch:this.epoch};
  }
}

// Mirrors PgCommandQueue's semantics (FIFO per node, removed once
// acknowledged) without a real Postgres.
export class InMemoryCommandQueue implements CommandQueue {
  private byNode=new Map<string,{id:string;type:string;payload:unknown}[]>();
  private nextId=0;
  enqueue(nodeId:string,type:string,payload:unknown):void{
    const list=this.byNode.get(nodeId)??[];
    list.push({id:String(++this.nextId),type,payload});
    this.byNode.set(nodeId,list);
  }
  async pending(nodeId:string,limit=20){return (this.byNode.get(nodeId)??[]).slice(0,limit);}
  async acknowledge(commandId:string):Promise<void>{
    for(const [nodeId,list] of this.byNode)this.byNode.set(nodeId,list.filter(c=>c.id!==commandId));
  }
}

export class LoggingMeshCommandSink implements MeshCommandSink {
  async configure(){/* production binds this to the real PlatformAdapter/agent command queue */}
  async sever(){/* production binds this to the real PlatformAdapter/agent command queue */}
}
