import {createSocket, type Socket, type RemoteInfo} from "node:dgram";

export interface RelaySession {sessionId:string; a:{host:string;port:number}; b:{host:string;port:number};}

// A real "blind" UDP relay: it forwards raw datagrams between the two
// endpoints of a registered session without inspecting or decrypting the
// payload (WireGuard traffic is already encrypted end-to-end — the relay's
// only job is NAT traversal fallback when a direct peer-to-peer path fails).
// Endpoints are matched by source address:port, so each side must actually
// send from the address it registered.
export class BlindRelayServer {
  private socket:Socket|undefined;
  private sessions=new Map<string,RelaySession>();
  private byEndpoint=new Map<string,RelaySession>();
  private bytesRelayed=0;

  private key(host:string,port:number){return `${host}:${port}`;}

  register(session:RelaySession){
    this.sessions.set(session.sessionId,session);
    this.byEndpoint.set(this.key(session.a.host,session.a.port),session);
    this.byEndpoint.set(this.key(session.b.host,session.b.port),session);
  }

  unregister(sessionId:string){
    const session=this.sessions.get(sessionId);
    if(!session)return;
    this.byEndpoint.delete(this.key(session.a.host,session.a.port));
    this.byEndpoint.delete(this.key(session.b.host,session.b.port));
    this.sessions.delete(sessionId);
  }

  start(port:number,host="0.0.0.0"):Promise<void>{
    this.socket=createSocket("udp4");
    this.socket.on("message",(msg,rinfo)=>this.forward(msg,rinfo));
    return new Promise((resolve,reject)=>{
      this.socket!.once("error",reject);
      this.socket!.bind(port,host,()=>resolve());
    });
  }

  async stop(){return new Promise<void>(resolve=>{if(!this.socket)return resolve();this.socket.close(()=>resolve());});}
  address(){return this.socket?.address();}
  get totalBytesRelayed(){return this.bytesRelayed;}
  // Real, live counts — used by src/runtime/relay-server.ts to report
  // actual active sessions/throughput on every heartbeat instead of the
  // hardcoded 0 values it used to send.
  get activeSessionCount(){return this.sessions.size;}

  private forward(msg:Buffer,from:RemoteInfo){
    const session=this.byEndpoint.get(this.key(from.address,from.port));
    if(!session)return; // unregistered sender: drop silently, same as a firewall would
    const isA=from.address===session.a.host&&from.port===session.a.port;
    const to=isA?session.b:session.a;
    this.socket!.send(msg,to.port,to.host);
    this.bytesRelayed+=msg.length;
  }
}
