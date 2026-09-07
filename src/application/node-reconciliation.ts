import {createHash} from "node:crypto";
import type {MeshNode,NetworkPolicy} from "../domain/types.js";
import type {NodeRepository,PolicyRepository} from "../ports/repositories.js";
import type {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import type {PgDesiredStateStore,NodeDesiredState} from "../../services/mesh-controller/pg-desired-state-store.js";
import type {MeshController} from "../../services/mesh-controller/controller.js";
import {firewallRulesFor} from "../infrastructure/pg-policy-enforcer.js";
import {canonicalJson} from "../infrastructure/canonical-json.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

export type DriftDimension="ROUTES_AND_INTEGRITY"|"DNS"|"KILL_SWITCH"|"PEER_TOPOLOGY"|"POLICY_VERSION";
export interface DriftFinding {dimension:DriftDimension;drifted:boolean;correctedBy?:string;}
export interface NodeReconciliationResult {nodeId:string;checked:DriftFinding[];}

const firewallPlanFor=(policies:NetworkPolicy[])=>({defaultAction:"DENY" as const,rules:firewallRulesFor(policies)});
// canonicalJson, not JSON.stringify: compared against a hash
// ProductionAgent computed after reading its payload back out of jsonb,
// which doesn't preserve key order — see canonical-json.ts.
const hashOf=(value:unknown)=>createHash("sha256").update(canonicalJson(value)).digest("hex");

// RECONCILE (src/agent/reconciler.ts) and its four siblings (SET_DNS,
// SET_KILL_SWITCH, APPLY_PEERS, APPLY_FIREWALL) all had real consumers on the
// node side with nothing on the control-plane side that ever compared "what
// should this node look like" against "what did this node last report" and
// issued a correction when they disagreed — node_desired_state
// (db/016_node_desired_state.sql) is the first half of that; this is the
// second. Every comparison below is against a real signal a node actually
// reported (an echoed value in a command_acknowledgements row, or its
// absence) — never a guess about state this architecture has no way to
// observe.
export class NodeReconciliationService {
  constructor(
    private nodes:NodeRepository,private policies:PolicyRepository,
    private desiredState:PgDesiredStateStore,private queue:PgCommandQueue,
    private meshController:MeshController,private db:PgQueryable
  ){}

  async checkAll():Promise<NodeReconciliationResult[]>{
    const states=await this.desiredState.all();
    const results:NodeReconciliationResult[]=[];
    for(const state of states)results.push(await this.checkNode(state.nodeId));
    return results;
  }

  async checkNode(nodeId:string):Promise<NodeReconciliationResult>{
    const node=await this.nodes.get(nodeId);
    // Message must say "not found" — src/api/rest/errors.ts classifies
    // unrecognized errors by keyword, and this exact wording ("unknown node
    // X") fell through every pattern to a generic 500 instead of the 404 a
    // caller hitting POST /api/v1/nodes/:id/reconcile for a real but
    // nonexistent node should get. Found live against the running REST API,
    // not by any unit test (which asserts on the thrown message directly,
    // never on how the HTTP layer classifies it).
    if(!node)throw new Error(`node not found: ${nodeId}`);
    const desired=await this.desiredState.get(nodeId);
    if(!desired)return {nodeId,checked:[]};
    const allNodes=await this.nodes.list();
    const activePolicies=await this.policies.listActive();

    const checked:DriftFinding[]=[];
    checked.push(await this.checkRoutesAndIntegrity(node,desired,activePolicies));
    checked.push(await this.checkDns(node,desired));
    checked.push(await this.checkKillSwitch(node,desired));
    checked.push(await this.checkPeerTopology(node,allNodes));
    checked.push(await this.checkPolicyVersion(node,activePolicies));
    return {nodeId,checked};
  }

  // Routes and integrity-file hashes are anchored on node_desired_state's
  // own revision counter, matching AgentReconciler.reconcile()'s exact
  // staleness contract: it reports back the revision it actually reached,
  // and refuses (STALE) a payload whose revision is lower than one it's
  // already applied. Only a SUCCEEDED, non-STALE acknowledgement at or past
  // the current desired revision counts as "in sync".
  private async checkRoutesAndIntegrity(node:MeshNode,desired:NodeDesiredState,activePolicies:NetworkPolicy[]):Promise<DriftFinding>{
    const ack=await this.queue.latestAcknowledgement(node.id,"RECONCILE");
    const inSync=Boolean(ack&&ack.details?.status==="APPLIED"&&Number(ack.details?.revision)>=desired.revision);
    if(inSync)return {dimension:"ROUTES_AND_INTEGRITY",drifted:false};
    await this.queue.enqueue(node.id,"RECONCILE",{
      revision:desired.revision,routes:desired.routes,
      firewallPlan:firewallPlanFor(activePolicies),integrityFiles:desired.integrityFiles
    },150);
    return {dimension:"ROUTES_AND_INTEGRITY",drifted:true,correctedBy:"RECONCILE"};
  }

  // SET_DNS's acknowledgement echoes back the server list it actually
  // applied (agents/shared/production-agent.ts) — compared directly against
  // desired state's own list rather than merely checking recency, so a node
  // that silently reverted to a different DNS config is still caught even if
  // it separately acknowledged some other, unrelated SET_DNS command since.
  private async checkDns(node:MeshNode,desired:NodeDesiredState):Promise<DriftFinding>{
    const ack=await this.queue.latestAcknowledgement(node.id,"SET_DNS");
    const applied:string[]|undefined=ack?.details?.servers;
    const inSync=Boolean(applied&&JSON.stringify(applied)===JSON.stringify(desired.dnsServers));
    if(inSync)return {dimension:"DNS",drifted:false};
    await this.queue.enqueue(node.id,"SET_DNS",{servers:desired.dnsServers},150);
    return {dimension:"DNS",drifted:true,correctedBy:"SET_DNS"};
  }

  private async checkKillSwitch(node:MeshNode,desired:NodeDesiredState):Promise<DriftFinding>{
    const ack=await this.queue.latestAcknowledgement(node.id,"SET_KILL_SWITCH");
    const applied:boolean|undefined=ack?.details?.enabled;
    const inSync=applied===desired.killSwitchEnabled;
    if(inSync)return {dimension:"KILL_SWITCH",drifted:false};
    await this.queue.enqueue(node.id,"SET_KILL_SWITCH",{enabled:desired.killSwitchEnabled},150);
    return {dimension:"KILL_SWITCH",drifted:true,correctedBy:"SET_KILL_SWITCH"};
  }

  // Compares the topology hash MeshController would compute for this node
  // right now (planFor — pure, doesn't resend anything) against the hash the
  // node actually echoed back from its last successfully-applied APPLY_PEERS
  // command. Only calls meshController.reconcile (which does resend) when
  // they disagree, so a healthy, in-sync node isn't re-sent its own peer
  // list on every check.
  private async checkPeerTopology(node:MeshNode,allNodes:MeshNode[]):Promise<DriftFinding>{
    const {topologyHash}=await this.meshController.planFor(node,allNodes);
    const ack=await this.queue.latestAcknowledgement(node.id,"APPLY_PEERS");
    if(ack?.details?.topologyHash===topologyHash)return {dimension:"PEER_TOPOLOGY",drifted:false};
    await this.meshController.reconcile(node,allNodes);
    return {dimension:"PEER_TOPOLOGY",drifted:true,correctedBy:"APPLY_PEERS"};
  }

  // Compares the firewall-rule hash APPLY_FIREWALL's acknowledgement echoed
  // back (agents/shared/production-agent.ts) against the hash of the rules
  // compiled from the currently active policy set — the same compilation
  // PgPolicyEnforcer.stage uses to push a policy change in the first place.
  // Catches a node that missed (or expired before receiving) the original
  // push, without waiting for the next unrelated policy change to resend it.
  private async checkPolicyVersion(node:MeshNode,activePolicies:NetworkPolicy[]):Promise<DriftFinding>{
    const plan=firewallPlanFor(activePolicies);
    const desiredHash=hashOf(plan.rules);
    const ack=await this.queue.latestAcknowledgement(node.id,"APPLY_FIREWALL");
    if(ack?.details?.firewallHash===desiredHash)return {dimension:"POLICY_VERSION",drifted:false};
    const commitId=await this.latestCommittedCommitId();
    await this.queue.enqueue(node.id,"APPLY_FIREWALL",{commitId,defaultAction:plan.defaultAction,rules:plan.rules},150);
    return {dimension:"POLICY_VERSION",drifted:true,correctedBy:"APPLY_FIREWALL"};
  }

  private async latestCommittedCommitId():Promise<string|null>{
    const r=await this.db.query(
      `SELECT commit_id FROM bapc_security_core.policy_commits
       WHERE status='COMMITTED' ORDER BY finalized_at DESC LIMIT 1`
    );
    return r.rows[0]?.commit_id??null;
  }
}
