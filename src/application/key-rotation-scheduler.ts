export interface OverdueRotationSource {
  nodesOverdueForRotation(maxAgeDays:number,now:Date):Promise<string[]>;
}
export interface RotationCommandQueue {
  enqueue(nodeId:string,type:string,payload:unknown,priority?:number):Promise<void>;
  hasPending(nodeId:string,type:string):Promise<boolean>;
}

// KEY_ROTATION_DAYS (config.ts's keyRotationDays) had no consumer anywhere —
// nothing ever compared a node's key-rotation history against it. This is
// that periodic check: any node whose most recent rotation is older than
// the configured window gets the same ROTATE_IDENTITY_REQUIRED command
// ThreatEngine's emergency-tier response uses (PgThreatActionPort
// .rotateMeshIdentity) — never a server-side rotation, since the server
// never holds a node's private key; the node generates its own replacement
// key and signs the rotation itself (agents/shared/production-agent.ts).
export class KeyRotationSchedulerService {
  constructor(private source:OverdueRotationSource,private queue:RotationCommandQueue,private maxAgeDays:number){}
  async run(now=new Date()){
    const overdue=await this.source.nodesOverdueForRotation(this.maxAgeDays,now);
    for(const nodeId of overdue){
      // A node overdue today is still overdue tomorrow's run if it hasn't
      // rotated yet — skip it if it already has an unacknowledged
      // ROTATE_IDENTITY_REQUIRED outstanding instead of piling up another.
      if(await this.queue.hasPending(nodeId,"ROTATE_IDENTITY_REQUIRED"))continue;
      await this.queue.enqueue(nodeId,"ROTATE_IDENTITY_REQUIRED",{},200);
    }
    return {checked:overdue.length,nodeIds:overdue};
  }
}
