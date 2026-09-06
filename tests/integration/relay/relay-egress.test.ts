import test from "node:test";
import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {createServer, createConnection} from "node:net";
import {randomUUID} from "node:crypto";
import {BlindRelayServer} from "../../../services/relay/relay-server.js";
import {Socks5EgressProxy} from "../../../services/egress/socks5-proxy.js";

test("BlindRelayServer forwards datagrams between the two registered endpoints",async()=>{
  const relay=new BlindRelayServer();
  await relay.start(0,"127.0.0.1");
  const relayAddr=relay.address() as any;

  const a=createSocket("udp4"), b=createSocket("udp4");
  await new Promise<void>(r=>a.bind(0,"127.0.0.1",r));
  await new Promise<void>(r=>b.bind(0,"127.0.0.1",r));
  const aAddr=a.address(), bAddr=b.address();

  relay.register({
    sessionId:randomUUID(),
    a:{host:"127.0.0.1",port:aAddr.port},
    b:{host:"127.0.0.1",port:bAddr.port}
  });

  const bReceived=new Promise<Buffer>(resolve=>b.once("message",msg=>resolve(msg)));
  a.send(Buffer.from("hello-from-a"),relayAddr.port,"127.0.0.1");
  assert.equal((await bReceived).toString(),"hello-from-a");

  const aReceived=new Promise<Buffer>(resolve=>a.once("message",msg=>resolve(msg)));
  b.send(Buffer.from("hello-from-b"),relayAddr.port,"127.0.0.1");
  assert.equal((await aReceived).toString(),"hello-from-b");

  a.close();b.close();await relay.stop();
});

test("BlindRelayServer drops datagrams from an unregistered sender",async()=>{
  const relay=new BlindRelayServer();
  await relay.start(0,"127.0.0.1");
  const relayAddr=relay.address() as any;
  const stranger=createSocket("udp4");
  await new Promise<void>(r=>stranger.bind(0,"127.0.0.1",r));

  let forwarded=false;
  stranger.on("message",()=>{forwarded=true;});
  stranger.send(Buffer.from("uninvited"),relayAddr.port,"127.0.0.1");
  await new Promise(r=>setTimeout(r,150));
  assert.equal(forwarded,false);
  assert.equal(relay.totalBytesRelayed,0);

  stranger.close();await relay.stop();
});

const startEchoServer=()=>new Promise<{port:number;close:()=>Promise<void>}>(resolve=>{
  const server=createServer(socket=>socket.pipe(socket));
  server.listen(0,"127.0.0.1",()=>{
    const port=(server.address() as any).port;
    resolve({port,close:()=>new Promise(r=>server.close(()=>r()))});
  });
});

const socks5Connect=(proxyPort:number,targetHost:string,targetPort:number)=>new Promise<import("node:net").Socket>((resolve,reject)=>{
  const socket=createConnection({host:"127.0.0.1",port:proxyPort},()=>{
    socket.write(Buffer.from([0x05,0x01,0x00])); // version 5, 1 method, no-auth
  });
  socket.once("data",greetingReply=>{
    if(greetingReply[1]!==0x00)return reject(new Error("proxy rejected handshake"));
    const [a,b,c,d]=targetHost.split(".").map(Number);
    const req=Buffer.from([0x05,0x01,0x00,0x01,a!,b!,c!,d!,(targetPort>>8)&0xff,targetPort&0xff]);
    socket.write(req);
    socket.once("data",connectReply=>{
      if(connectReply[1]!==0x00)return reject(new Error(`CONNECT failed: reply code ${connectReply[1]}`));
      resolve(socket);
    });
  });
  socket.on("error",reject);
});

test("Socks5EgressProxy relays a real TCP round trip through CONNECT",async()=>{
  const echo=await startEchoServer();
  const proxy=new Socks5EgressProxy();
  await proxy.start(0,"127.0.0.1");
  const proxyPort=(proxy.address() as any).port;

  const socket=await socks5Connect(proxyPort,"127.0.0.1",echo.port);
  const reply=new Promise<Buffer>(resolve=>socket.once("data",resolve));
  socket.write("ping-through-egress");
  assert.equal((await reply).toString(),"ping-through-egress");

  socket.destroy();
  await proxy.stop();await echo.close();
});

test("Socks5EgressProxy rejects a destination denied by EgressPolicy",async()=>{
  const echo=await startEchoServer();
  const proxy=new Socks5EgressProxy({async isAllowed(){return false;}});
  await proxy.start(0,"127.0.0.1");
  const proxyPort=(proxy.address() as any).port;

  await assert.rejects(()=>socks5Connect(proxyPort,"127.0.0.1",echo.port),/CONNECT failed/);

  await proxy.stop();await echo.close();
});
