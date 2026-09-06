import test from "node:test";
import assert from "node:assert/strict";
import {createServer, request as httpRequest} from "node:http";
import {fileURLToPath} from "node:url";
import {dirname, join} from "node:path";
import {createAdminConsoleHandler} from "../../../src/runtime/admin-console-server.js";

const __dirname=dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR=join(__dirname,"..","..","..","..","apps","security-soc","public");

const startServer=async()=>{
  const server=createServer((req,res)=>void createAdminConsoleHandler(PUBLIC_DIR)(req,res));
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const port=(server.address() as any).port;
  return {server,port};
};

test("serves index.html at the root path",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(res.status,200);
    const text=await res.text();
    assert.match(text,/BAPC Security Operations Center/);
  }finally{server.close();}
});

test("rejects path traversal attempts",async()=>{
  // fetch()/URL normalize ".." out of a path client-side before the request
  // is ever sent, so this uses http.request's raw `path` (sent verbatim on
  // the request line, unnormalized) to actually exercise the server's own
  // defense-in-depth check against a client that doesn't normalize for it.
  const {server,port}=await startServer();
  try{
    const status=await new Promise<number>((resolve,reject)=>{
      const req=httpRequest({host:"127.0.0.1",port,path:"/../../../etc/passwd"},res=>{
        res.resume();resolve(res.statusCode!);
      });
      req.on("error",reject);req.end();
    });
    assert.equal(status,400);
  }finally{server.close();}
});

test("404s for a missing asset",async()=>{
  const {server,port}=await startServer();
  try{
    const res=await fetch(`http://127.0.0.1:${port}/does-not-exist.js`);
    assert.equal(res.status,404);
  }finally{server.close();}
});
