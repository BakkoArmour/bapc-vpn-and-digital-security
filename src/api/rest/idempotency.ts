import {createHash} from "node:crypto";
import {HttpError} from "./errors.js";

export interface StoredResponse {status:number; body:unknown;}
export interface IdempotencyStore {
  get(key:string):Promise<{requestHash:string; response:StoredResponse}|undefined>;
  put(key:string,actor:string,requestHash:string,response:StoredResponse,ttlMs:number):Promise<void>;
}

export const hashRequestBody=(value:unknown)=>createHash("sha256")
  .update(JSON.stringify(value??null)).digest("hex");

export class MemoryIdempotencyStore implements IdempotencyStore {
  private rows=new Map<string,{requestHash:string;response:StoredResponse;expiresAt:number}>();
  async get(key:string){
    const row=this.rows.get(key);
    if(!row)return undefined;
    if(row.expiresAt<Date.now()){this.rows.delete(key);return undefined;}
    return {requestHash:row.requestHash,response:row.response};
  }
  async put(key:string,_actor:string,requestHash:string,response:StoredResponse,ttlMs:number){
    this.rows.set(key,{requestHash,response,expiresAt:Date.now()+ttlMs});
  }
}

export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rows:any[]}>;
}
export class PgIdempotencyStore implements IdempotencyStore {
  constructor(private db:PgQueryable){}
  async get(key:string){
    const r=await this.db.query(
      `SELECT request_hash,response_status,response_body FROM bapc_security_core.api_idempotency
       WHERE idempotency_key=$1 AND expires_at>now()`,[key]
    );
    if(!r.rows.length)return undefined;
    const row=r.rows[0];
    return {requestHash:row.request_hash,response:{status:row.response_status,body:row.response_body}};
  }
  async put(key:string,actor:string,requestHash:string,response:StoredResponse,ttlMs:number){
    await this.db.query(
      `INSERT INTO bapc_security_core.api_idempotency
         (idempotency_key,actor,request_hash,response_status,response_body,expires_at)
       VALUES($1,$2,$3,$4,$5,now()+make_interval(secs=>$6))
       ON CONFLICT (idempotency_key) DO NOTHING`,
      [key,actor,requestHash,response.status,response.body,ttlMs/1000]
    );
  }
}

// Runs `compute` at most once per idempotency key + request-body hash within
// the store's TTL. A retried request with the SAME body replays the stored
// response; the SAME key with a DIFFERENT body is rejected as a conflict.
export const withIdempotency=async(
  store:IdempotencyStore, key:string|undefined, actor:string, body:unknown,
  ttlMs:number, compute:()=>Promise<StoredResponse>
):Promise<StoredResponse>=>{
  if(!key)return compute();
  const requestHash=hashRequestBody(body);
  const existing=await store.get(key);
  if(existing){
    if(existing.requestHash!==requestHash){
      throw new HttpError(409,"idempotency key reused with a different request body","idempotency_conflict");
    }
    return existing.response;
  }
  const response=await compute();
  await store.put(key,actor,requestHash,response,ttlMs);
  return response;
};
