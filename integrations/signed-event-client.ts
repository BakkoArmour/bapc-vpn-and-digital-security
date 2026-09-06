import {createHmac,randomUUID} from "node:crypto";
export class SignedEventClient {
  constructor(
    private source:"diagnostics"|"headquarters"|"cloud-deployment"|"integration",
    private secret:string,private send:(event:unknown)=>Promise<void>
  ){}
  async publish(type:string,payload:Record<string,unknown>){
    const unsigned={source:this.source,type,at:new Date().toISOString(),nonce:randomUUID(),payload};
    const signature=createHmac("sha256",this.secret).update(JSON.stringify(unsigned)).digest("hex");
    await this.send({...unsigned,signature});
  }
}
