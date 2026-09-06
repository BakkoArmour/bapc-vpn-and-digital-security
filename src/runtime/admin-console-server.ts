import {createServer} from "node:http";
import {readFile} from "node:fs/promises";
import {join, extname} from "node:path";
import type {IncomingMessage, ServerResponse} from "node:http";

const CONTENT_TYPES:Record<string,string>={".html":"text/html; charset=utf-8",".js":"text/javascript",".css":"text/css"};

// Static file server for the SOC/admin console. Deliberately holds no
// credentials of its own — the page collects a bearer token from the
// operator and calls the authenticated Control API directly from the
// browser, so this server never needs privileged access.
export const createAdminConsoleHandler=(publicDir:string)=>
  async(req:IncomingMessage,res:ServerResponse)=>{
    const path=(req.url==="/"?"/index.html":req.url)?.split("?")[0]??"/index.html";
    if(path.includes("..")){res.writeHead(400);res.end();return;}
    try{
      const filePath=join(publicDir,path);
      const body=await readFile(filePath);
      res.writeHead(200,{"content-type":CONTENT_TYPES[extname(filePath)]??"application/octet-stream"});
      res.end(body);
    }catch{
      res.writeHead(404);res.end("not found");
    }
  };

if(process.argv[1]?.endsWith("admin-console-server.js")){
  const {dirname}=await import("node:path");
  const {fileURLToPath}=await import("node:url");
  const __dirname=dirname(fileURLToPath(import.meta.url));
  const publicDir=join(__dirname,"..","..","..","apps","security-soc","public");
  const server=createServer((req,res)=>void createAdminConsoleHandler(publicDir)(req,res));
  const port=Number(process.env.ADMIN_CONSOLE_PORT??8090);
  // Matches src/config.ts's NODE_ENV-aware default: loopback-only in dev,
  // all-interfaces in production (e.g. so a container's published port
  // actually reaches this process) — this file doesn't use loadConfig()
  // since it needs no database/secrets, but should still default sanely.
  const host=process.env.ADMIN_CONSOLE_BIND_HOST??(process.env.NODE_ENV==="production"?"0.0.0.0":"127.0.0.1");
  server.listen(port,host,()=>{
    console.log(JSON.stringify({event:"ready",service:"bapc-security-soc-console",host,port}));
  });
  process.on("SIGTERM",()=>server.close(()=>process.exit(0)));
  process.on("SIGINT",()=>server.close(()=>process.exit(0)));
}
