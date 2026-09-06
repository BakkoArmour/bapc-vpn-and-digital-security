import type {ThreatActionPort} from "./engine.js";
import type {NodeRepository, JitRepository} from "../../src/ports/repositories.js";
import type {EventBus} from "../../src/ports/infrastructure.js";
import type {PolicyEnforcer} from "../../src/ports/infrastructure.js";
import type {PgCertificateStore} from "../trust-core/pg-certificate-store.js";
import type {PgCommandQueue} from "../mesh-controller/pg-command-queue.js";

// Real implementation of ThreatEngine's action port — ThreatEngine existed
// fully built and tested with no caller anywhere, so this never had
// anything to be real against before now.
//
// rotateMeshIdentity deliberately never rotates anything itself: the server
// has never held and must never hold a node's private key (see
// src/api/grpc/server.ts's verifyRotationSignature — rotation requests are
// verified against the node's own enrolled identity key). It enqueues
// ROTATE_IDENTITY_REQUIRED, the command agents/shared/production-agent.ts
// answers by generating its own replacement key, signing the rotation
// itself, and only then switching its local interface over — the same
// signature-verified RotatePeerKey flow a voluntary rotation uses.
export class PgThreatActionPort implements ThreatActionPort {
  constructor(
    private nodes:NodeRepository,private jit:JitRepository,
    private enforcer:PolicyEnforcer,private certificates:PgCertificateStore,
    private queue:PgCommandQueue,private bus:EventBus
  ){}

  async reauthenticate(nodeId:string):Promise<void>{
    await this.bus.publish("security.challenge.required",{nodeId});
  }

  async terminateJit(nodeId:string):Promise<void>{
    const node=await this.nodes.get(nodeId);
    if(!node)return;
    const now=new Date();
    for(const grant of await this.jit.listActive(now)){
      if(grant.targetZone===node.zone&&!grant.terminated){
        await this.jit.save({...grant,terminated:true,terminationReason:"threat correlation"});
      }
    }
  }

  async isolate(nodeId:string,_reason:string):Promise<void>{
    await this.enforcer.isolateNode(nodeId);
  }

  async revokeNodeCertificates(nodeId:string,reason:string):Promise<void>{
    const cert=await this.certificates.activeCertificateFor(nodeId);
    if(cert)await this.certificates.revoke(cert.serial,reason,new Date());
  }

  async rotateMeshIdentity(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"ROTATE_IDENTITY_REQUIRED",{},200);
  }

  async restore(nodeId:string):Promise<void>{
    await this.enforcer.restoreNode(nodeId);
  }
}
