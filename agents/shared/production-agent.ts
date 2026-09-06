import {createHash} from "node:crypto";
import type {PlatformAdapter} from "../../native/shared/platform-adapter.js";
import {generateWireGuardKeyPair} from "../../native/shared/wireguard-keys.js";
import {canonicalJson} from "../../src/infrastructure/canonical-json.js";
import type {AgentReconciler} from "../../src/agent/reconciler.js";
import type {MeshRotationClient} from "../../services/mesh-controller/grpc-rotation-client.js";
import type {IdentitySigner} from "./identity-signer.js";

export interface AgentController {
  heartbeat(input:{
    nodeId:string;at:string;posture:unknown;postureHash:string;
    agentVersion:string;bytesTransmitted:number;bytesReceived:number;
  }):Promise<{commands:Array<{id:string;type:string;payload:any}>}>;
  acknowledge(id:string,result:unknown):Promise<void>;
}
export class ProductionAgent {
  private stopped=false;
  constructor(
    private nodeId:string,private version:string,private platform:PlatformAdapter,
    private controller:AgentController,private intervalMs=30_000,
    // Optional: only set when `platform` also implements AgentPlatform (the
    // concrete Linux/Windows adapters do). Handles a "RECONCILE" command —
    // route-integrity monitoring/restoration, feature catalog items #56-60.
    private reconciler?:AgentReconciler,
    // Optional: only set when the control plane might ever send
    // ROTATE_IDENTITY_REQUIRED (ThreatEngine's emergency-tier response to a
    // correlated threat). Deliberately never a server-side rotation: the
    // server has never held and must never hold this node's private key
    // (see src/api/grpc/server.ts's verifyRotationSignature) — the node
    // generates its own replacement key and signs the rotation request
    // itself, through the exact same RotatePeerKey flow a voluntary
    // rotation uses.
    private rotationClient?:MeshRotationClient,
    private identitySigner?:IdentitySigner
  ){}
  stop(){this.stopped=true;}
  async run(){
    while(!this.stopped){
      const posture=await this.platform.collectPosture();
      const postureHash=createHash("sha256").update(JSON.stringify(posture)).digest("hex");
      const reply=await this.controller.heartbeat({
        nodeId:this.nodeId,at:new Date().toISOString(),posture,postureHash,
        agentVersion:this.version,bytesTransmitted:0,bytesReceived:0
      });
      for(const c of reply.commands)await this.execute(c);
      await new Promise(r=>setTimeout(r,this.intervalMs));
    }
  }
  private async execute(c:{id:string;type:string;payload:any}){
    try{
      switch(c.type){
        // SET_KILL_SWITCH/SET_DNS echo the value they just applied back in
        // the acknowledgement (not just ok:true) so NodeReconciliationService
        // can tell whether a node's actual kill-switch/DNS state still
        // matches its desired state, instead of only knowing a command was
        // received at some point in the past.
        case "SET_KILL_SWITCH": {
          const enabled=Boolean(c.payload.enabled);
          await this.platform.setKillSwitch(enabled);
          await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString(),enabled});
          return;
        }
        case "SET_DNS": {
          await this.platform.setDns(c.payload.servers);
          await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString(),servers:c.payload.servers});
          return;
        }
        case "APPLY_WIREGUARD": await this.platform.applyWireGuard(c.payload);break;
        case "APPLY_PEERS": {
          await this.platform.applyPeers(c.payload.peers);
          // Echoes back the hash of exactly the peer list just applied, in
          // the same canonical serialization MeshController.planFor hashes
          // (see applyPeersPayload, services/mesh-controller/controller.ts)
          // — canonicalJson, not JSON.stringify, because c.payload came from
          // controller_commands.payload (jsonb), which does not preserve
          // object key order, so a plain JSON.stringify hash here would
          // never match the one computed fresh in memory on the control
          // plane even when nothing has drifted. NodeReconciliationService
          // compares this against what the topology should currently be.
          const topologyHash=createHash("sha256").update(canonicalJson(c.payload.peers)).digest("hex");
          await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString(),topologyHash});
          return;
        }
        case "APPLY_FIREWALL": {
          await this.platform.applyFirewall(c.payload);
          // Echoes the hash of the exact rule set just applied — mirrors
          // APPLY_PEERS's topologyHash echo above (canonicalJson for the same
          // jsonb-key-order reason), so NodeReconciliationService can detect
          // "this node's firewall rules are stale relative to the currently
          // active policy set" (policy-version drift) instead of only
          // knowing some APPLY_FIREWALL command succeeded at some point.
          const firewallHash=createHash("sha256").update(canonicalJson(c.payload.rules??[])).digest("hex");
          await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString(),commitId:c.payload.commitId,firewallHash});
          return;
        }
        case "ROLLBACK_FIREWALL": await this.platform.rollbackFirewall(c.payload.commitId);break;
        case "QUARANTINE": await this.platform.isolate(c.payload.reason??"controller quarantine");break;
        case "RESTORE": await this.platform.restore();break;
        case "ROTATE_IDENTITY_REQUIRED": {
          if(!this.rotationClient||!this.identitySigner){
            throw new Error("ROTATE_IDENTITY_REQUIRED received but no MeshRotationClient/IdentitySigner is configured");
          }
          const wg=generateWireGuardKeyPair();
          const signature=this.identitySigner.sign(this.nodeId,wg.publicKey);
          const result=await this.rotationClient.rotatePeerKey(this.nodeId,wg.publicKey,signature);
          if(!result.acknowledged)throw new Error("mesh rejected the identity rotation");
          await this.platform.rotatePrivateKey(wg.privateKey);
          await this.controller.acknowledge(c.id,{
            ok:true,at:new Date().toISOString(),newPublicKey:wg.publicKey,effectiveEpoch:result.effectiveEpoch
          });
          return;
        }
        case "RECONCILE": {
          if(!this.reconciler)throw new Error("RECONCILE command received but no AgentReconciler is configured");
          const result=await this.reconciler.reconcile(c.payload);
          await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString(),...result});
          return;
        }
        default: throw new Error(`unsupported controller command ${c.type}`);
      }
      await this.controller.acknowledge(c.id,{ok:true,at:new Date().toISOString()});
    }catch(error){
      await this.controller.acknowledge(c.id,{ok:false,error:error instanceof Error?error.message:String(error)});
    }
  }
}
