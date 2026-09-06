import type {PeerDistributor} from "../../src/ports/infrastructure.js";
import type {MeshNode} from "../../src/domain/types.js";
import type {MeshController} from "./controller.js";

// Replaces NoopPeerDistributor in production. EnrollmentService.register
// calls peers.configure(newNode, existingActivePeers) right after a node
// enrolls (src/application/enrollment.ts) — the new node's own peer list is
// already returned synchronously in registerNode's gRPC response, so the
// only thing left for this to do is tell every node that was ALREADY
// active before the new one joined. With NoopPeerDistributor that never
// happened: an existing node's peer list only ever reflected the peers
// that existed at ITS OWN enrollment time, since nothing else ever
// triggered a reconcile for it again. This runs the same zone-aware
// MeshController.reconcile every other topology change already uses, once
// per existing peer, against the now-complete active set.
export class MeshControllerPeerDistributor implements PeerDistributor {
  constructor(private controller:MeshController){}

  async configure(node:MeshNode,existingPeers:MeshNode[]):Promise<void>{
    const all=[...existingPeers,node];
    for(const peer of existingPeers){
      await this.controller.reconcile(peer,all);
    }
  }

  async remove(_nodeId:string):Promise<void>{
    /* No caller anywhere passes through PeerDistributor.remove today — node
       removal/quarantine already reaches the removed node itself via
       MeshController.quarantine -> sink.sever. Telling every OTHER node to
       drop it from their own peer list would need the same per-peer
       reconcile as configure() above, once a real caller for node removal
       (distinct from quarantine) exists to drive it. */
  }
}
