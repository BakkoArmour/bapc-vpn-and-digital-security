import {createServer, createConnection, type Server, type Socket} from "node:net";

export interface EgressPolicy {
  isAllowed(host:string,port:number):Promise<boolean>;
}

const ALLOW_ALL:EgressPolicy={async isAllowed(){return true;}};

// A real, minimal SOCKS5 server (RFC 1928): no-auth handshake + CONNECT
// command only (no BIND, no UDP ASSOCIATE — those aren't needed for a
// fixed-egress outbound gateway). Every connection funnels through this one
// process, which is what gives the egress gateway its single, allowlistable
// outbound source IP. EgressPolicy is the hook production deployments use to
// enforce destination allowlists/abuse controls before a CONNECT proceeds.
export class Socks5EgressProxy {
  private server:Server|undefined;
  private activeConnections=0;
  private bytesProxied=0;
  constructor(private policy:EgressPolicy=ALLOW_ALL){}

  start(port:number,host="127.0.0.1"):Promise<void>{
    this.server=createServer(client=>this.handleClient(client));
    return new Promise((resolve,reject)=>{
      this.server!.once("error",reject);
      this.server!.listen(port,host,()=>resolve());
    });
  }
  async stop(){return new Promise<void>(resolve=>{if(!this.server)return resolve();this.server.close(()=>resolve());});}
  address(){return this.server?.address();}
  // Real, live counts — used by src/runtime/egress-server.ts to report
  // actual active sessions/throughput on every heartbeat instead of the
  // hardcoded 0 values it used to send.
  get activeSessionCount(){return this.activeConnections;}
  get totalBytesProxied(){return this.bytesProxied;}

  private handleClient(client:Socket){
    this.activeConnections++;
    let closed=false;
    const onClose=()=>{if(closed)return;closed=true;this.activeConnections--;};
    client.on("close",onClose);
    client.on("error",onClose);
    client.once("data",greeting=>{
      if(greeting[0]!==0x05){client.destroy();return;}
      client.write(Buffer.from([0x05,0x00])); // version 5, no authentication required
      client.once("data",req=>void this.handleRequest(client,req));
    });
    client.on("error",()=>client.destroy());
  }

  private async handleRequest(client:Socket,req:Buffer){
    if(req.length<7||req[0]!==0x05||req[1]!==0x01){ // version 5, CMD=CONNECT only
      client.end(Buffer.from([0x05,0x07,0x00,0x01,0,0,0,0,0,0])); // 0x07 = command not supported
      return;
    }
    const atyp=req[3];
    let host:string, offset:number;
    if(atyp===0x01){ // IPv4
      host=`${req[4]}.${req[5]}.${req[6]}.${req[7]}`; offset=8;
    }else if(atyp===0x03){ // domain name
      const len=req[4]!; host=req.subarray(5,5+len).toString("ascii"); offset=5+len;
    }else{
      client.end(Buffer.from([0x05,0x08,0x00,0x01,0,0,0,0,0,0])); // 0x08 = address type not supported
      return;
    }
    const port=req.readUInt16BE(offset);

    const allowed=await this.policy.isAllowed(host,port);
    if(!allowed){
      client.end(Buffer.from([0x05,0x02,0x00,0x01,0,0,0,0,0,0])); // 0x02 = connection not allowed by ruleset
      return;
    }

    const upstream=createConnection({host,port},()=>{
      client.write(Buffer.from([0x05,0x00,0x00,0x01,0,0,0,0,0,0])); // 0x00 = succeeded
      upstream.on("data",chunk=>{this.bytesProxied+=chunk.length;});
      client.on("data",chunk=>{this.bytesProxied+=chunk.length;});
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on("error",()=>{
      client.end(Buffer.from([0x05,0x05,0x00,0x01,0,0,0,0,0,0])); // 0x05 = connection refused
    });
  }
}
