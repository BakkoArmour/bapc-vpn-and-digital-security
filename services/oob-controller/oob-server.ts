import {createServer, type Server} from "node:http";
import {createHash, timingSafeEqual} from "node:crypto";

/**
 * The out-of-band channel's own server: a deliberately separate process/port
 * (and, in production, a separate network path/credential) from the main
 * control-plane API — see the non-negotiable rule in
 * docs/build-source/BAPC.Security.Production.Completion.Addendum.docx:
 * "The OOB path uses independent endpoints, credentials and policy scope so
 * a faulty mesh rule cannot disable recovery." A bug or quarantine action on
 * the primary control plane must not be able to take this down too.
 */
export class OobServer {
  private server:Server|undefined;
  private documents=new Map<string,{checksum:string;document:unknown}>();
  constructor(private sharedSecret:string){
    if(sharedSecret.length<32)throw new Error("OOB shared secret must be at least 32 characters");
  }

  private authorized(header:string|undefined){
    if(!header?.startsWith("Bearer "))return false;
    const provided=Buffer.from(header.slice(7));
    const expected=Buffer.from(this.sharedSecret);
    return provided.length===expected.length&&timingSafeEqual(provided,expected);
  }

  start(port:number,host="127.0.0.1"):Promise<void>{
    this.server=createServer((req,res)=>void this.handle(req,res));
    return new Promise((resolve,reject)=>{
      this.server!.once("error",reject);
      this.server!.listen(port,host,()=>resolve());
    });
  }
  async stop(){return new Promise<void>(resolve=>{if(!this.server)return resolve();this.server.close(()=>resolve());});}
  address(){return this.server?.address();}

  private async handle(req:import("node:http").IncomingMessage,res:import("node:http").ServerResponse){
    const json=(status:number,body:unknown)=>{
      res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify(body));
    };
    if(req.url==="/healthz"){json(200,{status:"ok"});return;}
    if(!this.authorized(req.headers.authorization)){json(401,{error:"unauthorized"});return;}

    const match=req.url?.match(/^\/oob\/documents\/([^/]+)$/);
    if(!match){json(404,{error:"not_found"});return;}
    const scope=decodeURIComponent(match[1]!);

    if(req.method==="GET"){
      const entry=this.documents.get(scope);
      if(!entry){json(404,{error:"no document for scope"});return;}
      json(200,entry);
      return;
    }
    if(req.method==="PUT"){
      const chunks:Buffer[]=[];
      for await(const c of req)chunks.push(Buffer.from(c));
      const document=JSON.parse(Buffer.concat(chunks).toString("utf8")||"null");
      const checksum=createHash("sha256").update(JSON.stringify(document)).digest("hex");
      this.documents.set(scope,{checksum,document});
      json(200,{checksum});
      return;
    }
    json(405,{error:"method_not_allowed"});
  }
}
