import type {MeshCommandSink, MeshPeerPlan} from "./controller.js";
import type {MeshNode} from "../../src/domain/types.js";
import type {PgCommandQueue} from "./pg-command-queue.js";

// Replaces LoggingMeshCommandSink in production. `sever` (MeshController's
// quarantine path) enqueues into the same durable command queue
// (controller_commands, db/004_security_hardening.sql) the REST endpoint
// agent's heartbeat drains (agents/shared/production-agent.ts) and the
// mesh-grpc streamHeartbeat now drains too (src/api/grpc/server.ts) — using
// "QUARANTINE", the command type ProductionAgent.execute actually implements
// (PlatformAdapter.isolate(reason), no secret material involved), not the
// mesh.proto ControllerCommand.Action name.
//
// `configure` (peer-topology reconciliation) deliberately stays a no-op here.
// The only real handler for a full peer-list push, APPLY_WIREGUARD, requires
// `privateKeyReference` (native/shared/platform-adapter.ts) — the node's own
// WireGuard private key material, which correctly never reaches this server.
// Building that command here would mean either fabricating that field
// (corrupting the node's real WireGuard identity) or omitting it (silently
// wiping it). Delivering peer-only updates safely needs a platform-adapter
// contract change (a peers-only reconcile command, or the node supplying its
// own key reference back), which is out of scope for wiring the queue.
export class PgMeshCommandSink implements MeshCommandSink {
  constructor(private queue:PgCommandQueue){}

  async configure(_node:MeshNode,_peers:MeshPeerPlan[]):Promise<void>{
    /* see class comment: not safely deliverable through this queue yet */
  }

  async sever(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"QUARANTINE",{reason:"mesh topology quarantine"},200);
  }
}
