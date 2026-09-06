import type { AuditRecord } from "../domain/types.js";
import type { Clock, Hasher } from "../ports/infrastructure.js";
import type { AuditRepository } from "../ports/repositories.js";
import { canonicalJson as canonical } from "../infrastructure/canonical-json.js";
export class AuditService {constructor(private repo:AuditRepository,private hash:Hasher,private clock:Clock){}
 async record(actor:string,action:string,subject:string,payload:Record<string,unknown>){const last=await this.repo.last(),previousHash=last?.hash??"GENESIS",sequence=(last?.sequence??0)+1,at=this.clock.now();const digest=await this.hash.digest(canonical({sequence,at:at.toISOString(),actor,action,subject,payload,previousHash}));const record:AuditRecord={sequence,at,actor,action,subject,payload,previousHash,hash:digest};await this.repo.append(record);return record;}
 async verify(){let previous="GENESIS";for(const r of await this.repo.chain()){const expected=await this.hash.digest(canonical({sequence:r.sequence,at:r.at.toISOString(),actor:r.actor,action:r.action,subject:r.subject,payload:r.payload,previousHash:r.previousHash}));if(r.previousHash!==previous||r.hash!==expected)return false;previous=r.hash;}return true;}}
