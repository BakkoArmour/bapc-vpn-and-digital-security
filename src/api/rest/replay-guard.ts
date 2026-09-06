import {HttpError} from "./errors.js";

export interface ReplayStore {
  claim(nonce:string,actor:string,ttlMs:number):Promise<boolean>; // true = first use, false = replay
}

export class MemoryReplayStore implements ReplayStore {
  private seen=new Map<string,number>();
  async claim(nonce:string,_actor:string,ttlMs:number){
    const now=Date.now();
    const expiresAt=this.seen.get(nonce);
    if(expiresAt!==undefined&&expiresAt>now)return false;
    this.seen.set(nonce,now+ttlMs);
    return true;
  }
}

export interface PgQueryable {
  query(text:string,values?:unknown[]):Promise<{rowCount:number|null}>;
}
export class PgReplayStore implements ReplayStore {
  constructor(private db:PgQueryable){}
  async claim(nonce:string,actor:string,ttlMs:number){
    const r=await this.db.query(
      `INSERT INTO bapc_security_core.replay_nonces(nonce,actor,expires_at)
       VALUES($1,$2,now()+make_interval(secs=>$3))
       ON CONFLICT (nonce) DO NOTHING`,
      [nonce,actor,ttlMs/1000]
    );
    return (r.rowCount??0)>0;
  }
}

export const enforceReplayNonce=async(
  store:ReplayStore, nonce:string|undefined, actor:string, ttlMs=300_000
)=>{
  if(!nonce)throw new HttpError(400,"X-Request-Nonce header is required for this operation","nonce_required");
  const first=await store.claim(nonce,actor,ttlMs);
  if(!first)throw new HttpError(409,"nonce already used (possible replay)","replay_detected");
};
