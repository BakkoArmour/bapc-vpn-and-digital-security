import { createServer } from "node:http";
import { json, respond, TokenVerifier } from "./http.js";
import { loadConfig } from "../config.js";
const config=loadConfig(),verifier=new TokenVerifier(process.env.CONTROL_API_TOKEN_SECRET??"development-only-change-me");
const server=createServer(async(req,res)=>{try{if(req.url==="/healthz"){respond(res,200,{status:"ok",environment:config.environment});return;}const claims=verifier.verify(req.headers.authorization?.replace(/^Bearer /,""));const body=await json(req);if(req.url==="/api/v1/status"&&req.method==="GET")respond(res,200,{service:"bapc-vpn-security",version:"0.2.0",subject:claims.sub});else respond(res,404,{error:"not found",path:req.url,received:body});}catch(error){respond(res,401,{error:error instanceof Error?error.message:"request failed"});}});
const port=Number(process.env.PORT??8080);server.listen(port,"127.0.0.1",()=>console.log(`BAPC security control API listening on ${port}`));
