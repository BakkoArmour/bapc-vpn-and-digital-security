import type {MeshCommandSink, MeshPeerPlan} from "./controller.js";
import type {MeshNode} from "../../src/domain/types.js";
import type {PgCommandQueue} from "./pg-command-queue.js";

// Replaces LoggingMeshCommandSink in production. Both methods enqueue into
// the same durable command queue (controller_commands,
// db/004_security_hardening.sql) the REST endpoint agent's heartbeat drains
// (agents/shared/production-agent.ts) and the mesh-grpc streamHeartbeat now
// drains too (src/api/grpc/server.ts) — using the command types
// ProductionAgent.execute actually implements, not the mesh.proto
// ControllerCommand.Action names.
//
// `configure` uses "APPLY_PEERS" (PlatformAdapter.applyPeers), not
// "APPLY_WIREGUARD": the full-config command requires `privateKeyReference`
// — the node's own WireGuard private key material, which correctly never
// reaches this server. applyPeers replaces the entire peer set on an
// interface that's already up (via `wg syncconf`/`wg.exe syncconf` — see
// native/linux/adapter.ts and native/windows/adapter.ts), so peers dropped
// from `peers` here are actually removed on the node, not just left stale,
// and no key material needs to be fabricated or touched to do it.
export class PgMeshCommandSink implements MeshCommandSink {
  constructor(private queue:PgCommandQueue){}

  async configure(node:MeshNode,peers:MeshPeerPlan[]):Promise<void>{
    await this.queue.enqueue(node.id,"APPLY_PEERS",{
      peers:peers.map(p=>({
        publicKey:p.publicKey,allowedIps:p.allowedIps,keepaliveSeconds:p.keepaliveSeconds,
        ...(p.endpoint?{endpoint:p.endpoint}:{})
      }))
    });
  }

  async sever(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"QUARANTINE",{reason:"mesh topology quarantine"},200);
  }
}
