import {createHash,randomUUID} from "node:crypto";
export interface RecoveryStore {
  save(snapshot:{id:string;scope:string;checksum:string;document:unknown;createdBy:string;lkg:boolean}):Promise<void>;
  lastKnownGood(scope:string):Promise<{id:string;document:unknown;checksum:string}|undefined>;
}
export interface OobChannel {
  healthy():Promise<boolean>;
  push(scope:string,document:unknown):Promise<void>;
  verify(scope:string,checksum:string):Promise<boolean>;
}
export class OobController {
  constructor(private store:RecoveryStore,private channel:OobChannel){}
  async checkpoint(scope:string,document:unknown,actor:string){
    if(!(await this.channel.healthy()))throw new Error("OOB channel unhealthy; checkpoint refused");
    const checksum=createHash("sha256").update(JSON.stringify(document)).digest("hex");
    await this.channel.push(scope,document);
    if(!(await this.channel.verify(scope,checksum)))throw new Error("OOB verification failed");
    const snapshot={id:randomUUID(),scope,checksum,document,createdBy:actor,lkg:true};
    await this.store.save(snapshot);return snapshot;
  }
  async rollback(scope:string){
    const lkg=await this.store.lastKnownGood(scope);
    if(!lkg)throw new Error("no last-known-good recovery snapshot");
    if(!(await this.channel.healthy()))throw new Error("OOB channel unavailable");
    await this.channel.push(scope,lkg.document);
    if(!(await this.channel.verify(scope,lkg.checksum)))throw new Error("rollback verification failed");
    return {restored:lkg.id,checksum:lkg.checksum};
  }
}
