import {createHash} from "node:crypto";
import type {PlatformAdapter} from "../../native/shared/platform-adapter.js";

export interface AgentController {
  heartbeat(input:{
    nodeId:string;at:string;posture:unknown;postureHash:string;
    agentVersion:string;bytesTransmitted:number;bytesReceived:number;
  }):Promise<{commands:Array<{id:string;type:string;payload:any}>}>;
  acknowledge(id:string,result:unknown):Promise<void>;
}
export class ProductionAgent {
  private stopped=false;
  constructor(
    private nodeId:string,private version:string,private platform:PlatformAdapter,
    private controller:AgentController,private intervalMs=30_000
  ){}
  stop(){this.stopped=true;}
  async run(){
    while(!this.stopped){
      const posture=await this.platform.collectPosture();
      const postureHash=createHash("sha256").update(JSON.stringify(posture)).digest("hex");
      const reply=await this.controller.heartbeat({
        nodeId:this.nodeId,at:new Date().toISOString(),posture,postureHash,
        agentVersion:this.version,bytesTransmitted:0,bytesReceived:0
      });
      for(const c of reply.commands)await this.execute(c);
      await new Promise(r=>setTimeout(r,this.intervalMs));
    }
  }
  private async execute(c:{id:string;type:string;payload:any}){
    try{
      switch(c.type){
        case "SET_KILL_SWITCH": await this.platform.setKillSwitch(Boolean(c.payload.enabled));break;
        case "SET_DNS": await this.platform.setDns(c.payload.servers);break;
        case "APPLY_WIREGUARD": await this.platform.applyWireGuard(c.payload);break;
        case "APPLY_FIREWALL": await this.platform.applyFirewall(c.payload);break;
        case "ROLLBACK_FIREWALL": await this.platform.rollbackFirewall(c.payload.commitId);break;
        case "QUARANTINE": await this.platform.isolate(c.payload.reason??"controller quarantine");break;
        case "RESTORE": await this.platform.restore();break;
        default: throw new Error(`unsupported controller command ${c.type}`);
      }
      await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString()});
    }catch(error){
      await this.controller.acknowledge(c.id,{ok:false,error:error instanceof Error?error.message:String(error)});
    }
  }
}
