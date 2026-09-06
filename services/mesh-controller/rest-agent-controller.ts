import type {AgentController} from "../../agents/shared/production-agent.js";

export class RestAgentController implements AgentController {
  constructor(private baseUrl:string,private bearerToken:string){}

  private async call(path:string,body:unknown){
    const res=await fetch(`${this.baseUrl}${path}`,{
      method:"POST",
      headers:{authorization:`Bearer ${this.bearerToken}`,"content-type":"application/json"},
      body:JSON.stringify(body)
    });
    const parsed=await res.json();
    if(!res.ok)throw new Error(parsed?.error?.message??`agent request to ${path} failed (${res.status})`);
    return parsed.data;
  }

  async heartbeat(input:{
    nodeId:string;at:string;posture:unknown;postureHash:string;
    agentVersion:string;bytesTransmitted:number;bytesReceived:number;
  }){
    return this.call("/api/v1/agent/heartbeat",input);
  }

  async acknowledge(id:string,result:unknown){
    await this.call(`/api/v1/agent/commands/${encodeURIComponent(id)}/ack`,{result});
  }
}
