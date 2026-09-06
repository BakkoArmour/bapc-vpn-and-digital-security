import type {OobChannel} from "./controller.js";

export class HttpOobChannel implements OobChannel {
  constructor(private baseUrl:string,private sharedSecret:string,private timeoutMs=5_000){}

  private headers(){return {authorization:`Bearer ${this.sharedSecret}`,"content-type":"application/json"};}
  private async withTimeout<T>(fn:(signal:AbortSignal)=>Promise<T>):Promise<T>{
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),this.timeoutMs);
    try{return await fn(controller.signal);}finally{clearTimeout(timer);}
  }

  async healthy():Promise<boolean>{
    try{
      const res=await this.withTimeout(signal=>fetch(`${this.baseUrl}/healthz`,{signal}));
      return res.ok;
    }catch{return false;}
  }

  async push(scope:string,document:unknown):Promise<void>{
    const res=await this.withTimeout(signal=>fetch(
      `${this.baseUrl}/oob/documents/${encodeURIComponent(scope)}`,
      {method:"PUT",headers:this.headers(),body:JSON.stringify(document),signal}
    ));
    if(!res.ok)throw new Error(`OOB push failed: ${res.status}`);
  }

  async verify(scope:string,checksum:string):Promise<boolean>{
    try{
      const res=await this.withTimeout(signal=>fetch(
        `${this.baseUrl}/oob/documents/${encodeURIComponent(scope)}`,
        {headers:this.headers(),signal}
      ));
      if(!res.ok)return false;
      const body=await res.json() as {checksum:string};
      return body.checksum===checksum;
    }catch{return false;}
  }
}
