import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {RestAgentController} from "../../../services/mesh-controller/rest-agent-controller.js";
import {PgCommandQueue} from "../../../services/mesh-controller/pg-command-queue.js";

// A minimal stand-in for the two production-server.ts agent endpoints, so the
// REST client (RestAgentController) is exercised over a real HTTP round trip
// without requiring a live Postgres-backed control plane for this test.
const startFakeControlPlane=()=>{
  const acked:Array<{id:string;result:unknown}>=[];
  const server=createServer(async(req,res)=>{
    const chunks:Buffer[]=[];
    for await(const c of req)chunks.push(Buffer.from(c));
    const body=chunks.length?JSON.parse(Buffer.concat(chunks).toString("utf8")):{};
    const json=(status:number,data:unknown)=>{res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify({data}));};
    if(req.url==="/api/v1/agent/heartbeat"&&req.method==="POST"){
      json(200,{accepted:true,compliant:true,commands:[{id:"cmd-1",type:"SET_KILL_SWITCH",payload:{enabled:true}}]});
      return;
    }
    const ackMatch=req.url?.match(/^\/api\/v1\/agent\/commands\/([^/]+)\/ack$/);
    if(ackMatch&&req.method==="POST"){
      acked.push({id:ackMatch[1]!,result:body.result});
      json(200,{acknowledged:true});
      return;
    }
    res.writeHead(404);res.end();
  });
  return new Promise<{server:import("node:http").Server;port:number;acked:typeof acked}>(resolve=>{
    server.listen(0,"127.0.0.1",()=>resolve({server,port:(server.address() as any).port,acked}));
  });
};

test("RestAgentController.heartbeat returns the commands the control plane issued",async()=>{
  const {server,port}=await startFakeControlPlane();
  try{
    const controller=new RestAgentController(`http://127.0.0.1:${port}`,"agent-token");
    const reply=await controller.heartbeat({
      nodeId:"n1",at:new Date().toISOString(),posture:{},postureHash:"h",
      agentVersion:"0.4.0",bytesTransmitted:0,bytesReceived:0
    });
    assert.equal(reply.commands.length,1);
    assert.equal(reply.commands[0].type,"SET_KILL_SWITCH");
  }finally{server.close();}
});

test("RestAgentController.acknowledge posts the result back",async()=>{
  const {server,port,acked}=await startFakeControlPlane();
  try{
    const controller=new RestAgentController(`http://127.0.0.1:${port}`,"agent-token");
    await controller.acknowledge("cmd-1",{ok:true});
    assert.deepEqual(acked,[{id:"cmd-1",result:{ok:true}}]);
  }finally{server.close();}
});

test("PgCommandQueue issues the expected enqueue/pending/acknowledge SQL",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const pendingRows:any[]=[{command_id:"cmd-1",command_type:"SET_DNS",payload:{servers:["1.1.1.1"]}}];
  const updateReturnRows:any[]=[{node_id:"n1",command_type:"SET_DNS",issued_at:"2026-01-01T00:00:00.000Z"}];
  const queue=new PgCommandQueue({
    query:async(text,values=[])=>{
      queries.push({text,values});
      if(text.startsWith("SELECT"))return {rows:pendingRows};
      if(text.includes("RETURNING"))return {rows:updateReturnRows};
      return {rows:[]};
    }
  });
  await queue.enqueue("n1","SET_DNS",{servers:["1.1.1.1"]});
  const pending=await queue.pending("n1");
  await queue.acknowledge("cmd-1",{ok:true});

  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.controller_commands/);
  assert.match(queries[1]!.text,/SELECT command_id,command_type,payload/);
  assert.match(queries[2]!.text,/UPDATE bapc_security_core\.controller_commands/);
  assert.deepEqual(pending,[{id:"cmd-1",type:"SET_DNS",payload:{servers:["1.1.1.1"]}}]);

  // command_acknowledgements existed with no write path at all —
  // controller_commands only ever gets updated in place, so this is the
  // one permanent record of an acknowledgement that survives even if that
  // row is later pruned.
  assert.match(queries[3]!.text,/INSERT INTO bapc_security_core\.command_acknowledgements/);
  assert.deepEqual(queries[3]!.values,["cmd-1","n1","SET_DNS","2026-01-01T00:00:00.000Z","SUCCEEDED",{ok:true}]);
});

test("PgCommandQueue.acknowledge derives FAILED/ACKNOWLEDGED status from the result shape",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const updateReturnRows:any[]=[{node_id:"n1",command_type:"QUARANTINE",issued_at:"2026-01-01T00:00:00.000Z"}];
  const queue=new PgCommandQueue({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:text.includes("RETURNING")?updateReturnRows:[]};
    }
  });
  await queue.acknowledge("cmd-2",{ok:false,error:"boom"});
  assert.equal(queries[1]!.values[4],"FAILED");

  queries.length=0;
  await queue.acknowledge("cmd-3",{deliveredAt:"now",via:"grpc-stream-heartbeat"});
  assert.equal(queries[1]!.values[4],"ACKNOWLEDGED");
});

test("PgCommandQueue.acknowledge is a no-op if the command id doesn't exist",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const queue=new PgCommandQueue({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await queue.acknowledge("missing",{ok:true});
  assert.equal(queries.length,1); // only the UPDATE ran; no INSERT for a row that was never found
});
