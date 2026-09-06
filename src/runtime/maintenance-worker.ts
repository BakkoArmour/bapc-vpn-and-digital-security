import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {OutboxDispatcher} from "../infrastructure/postgres/outbox.js";
import {RetentionService} from "../infrastructure/postgres/maintenance.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import {PgDesiredStateStore} from "../../services/mesh-controller/pg-desired-state-store.js";
import {MeshController} from "../../services/mesh-controller/controller.js";
import {PgMeshCommandSink} from "../../services/mesh-controller/pg-mesh-command-sink.js";
import {PgRelayStore} from "../../services/relay-fleet/pg-relay-store.js";
import {NodeReconciliationService} from "../application/node-reconciliation.js";
import {KeyRotationSchedulerService} from "../application/key-rotation-scheduler.js";
import {PgKeyRotationLedger} from "../../services/mesh-controller/pg-key-rotation-ledger.js";
import {AuditService} from "../application/audit.js";
import {SystemClock,Sha256} from "../infrastructure/memory.js";

/**
 * Runs the two background jobs that TransactionalOutbox/db/005-006 were
 * built for but that nothing ever actually invoked: draining the
 * transactional outbox, and partition/row retention. Without this process
 * running, TransactionalOutbox.publish() writes rows that accumulate in
 * event_outbox forever and are never delivered anywhere — the "reliable
 * ecosystem/security event delivery" this repo's own docs describe was only
 * half-built (write path only) until this was wired up.
 *
 * The delivery sink here is a structured stdout log — real and useful (feed
 * it to your log aggregator/SIEM) but not a live call to BAPC Diagnostics/
 * Headquarters/etc., which don't exist to receive one in this environment.
 * Point `send` at a real webhook/broker client for your deployment.
 */
await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);

const dispatcher=new OutboxDispatcher(db,async(topic,event)=>{
  console.log(JSON.stringify({event:"outbox.delivered",topic,payload:event}));
});
const retention=new RetentionService(db);

// RECONCILE and its siblings (SET_DNS, SET_KILL_SWITCH, APPLY_PEERS,
// APPLY_FIREWALL) had real node-side consumers with nothing that ever
// periodically checked a node against its desired state and corrected drift
// on its own — an operator could trigger POST /api/v1/nodes/:id/reconcile
// manually (src/runtime/production-server.ts), but nothing did it
// automatically. See src/application/node-reconciliation.ts for exactly what
// each dimension checks.
const repo=new PgRepositories(db);
const commandQueue=new PgCommandQueue(db);
const desiredStateStore=new PgDesiredStateStore(db);
const relayStore=new PgRelayStore(db);
const meshController=new MeshController(new PgMeshCommandSink(commandQueue),relayStore);
const nodeReconciliation=new NodeReconciliationService(repo,repo,desiredStateStore,commandQueue,meshController,db);
const audit=new AuditService(repo,new Sha256(),new SystemClock());
const keyRotationScheduler=new KeyRotationSchedulerService(new PgKeyRotationLedger(db),commandQueue,config.keyRotationDays);

const outboxIntervalMs=Number(process.env.OUTBOX_FLUSH_INTERVAL_MS??5_000);
const retentionIntervalMs=Number(process.env.RETENTION_INTERVAL_MS??3_600_000);
const retentionMonths=Number(process.env.EVENT_RETENTION_MONTHS??13);
const reconciliationIntervalMs=Number(process.env.RECONCILIATION_INTERVAL_MS??60_000);
const keyRotationIntervalMs=Number(process.env.KEY_ROTATION_CHECK_INTERVAL_MS??86_400_000);
const RECONCILIATION_ACTOR="system:maintenance-worker";

let stopped=false;

const runOutboxLoop=async()=>{
  while(!stopped){
    try{
      const flushed=await dispatcher.flush();
      if(flushed>0)console.log(JSON.stringify({event:"outbox.flush",flushed}));
    }catch(error){
      console.error(JSON.stringify({event:"outbox.flush_failed",error:error instanceof Error?error.message:String(error)}));
    }
    await new Promise(r=>setTimeout(r,outboxIntervalMs));
  }
};

const runRetentionLoop=async()=>{
  while(!stopped){
    try{
      const partitions=await retention.ensureUpcomingPartitions(1);
      const dropped=await retention.dropExpiredPartitions(retentionMonths);
      const purged=await retention.purgeExpiredRows();
      console.log(JSON.stringify({event:"retention.cycle",partitionsEnsured:partitions,partitionsDropped:dropped,purged}));
    }catch(error){
      console.error(JSON.stringify({event:"retention.cycle_failed",error:error instanceof Error?error.message:String(error)}));
    }
    await new Promise(r=>setTimeout(r,retentionIntervalMs));
  }
};

const runReconciliationLoop=async()=>{
  while(!stopped){
    try{
      const results=await nodeReconciliation.checkAll();
      for(const result of results){
        const drifted=result.checked.filter(c=>c.drifted);
        if(drifted.length===0)continue;
        console.log(JSON.stringify({event:"reconciliation.drift_corrected",nodeId:result.nodeId,
          corrected:drifted.map(d=>({dimension:d.dimension,correctedBy:d.correctedBy}))}));
        await audit.record(RECONCILIATION_ACTOR,"NODE_RECONCILED",result.nodeId,{
          corrected:drifted.map(d=>({dimension:d.dimension,correctedBy:d.correctedBy}))
        });
      }
    }catch(error){
      console.error(JSON.stringify({event:"reconciliation.cycle_failed",error:error instanceof Error?error.message:String(error)}));
    }
    await new Promise(r=>setTimeout(r,reconciliationIntervalMs));
  }
};

const runKeyRotationLoop=async()=>{
  while(!stopped){
    try{
      const result=await keyRotationScheduler.run();
      if(result.checked>0){
        console.log(JSON.stringify({event:"key_rotation.requested",nodeIds:result.nodeIds}));
        for(const nodeId of result.nodeIds){
          await audit.record(RECONCILIATION_ACTOR,"KEY_ROTATION_REQUESTED",nodeId,{reason:`key not rotated within ${config.keyRotationDays} days`});
        }
      }
    }catch(error){
      console.error(JSON.stringify({event:"key_rotation.cycle_failed",error:error instanceof Error?error.message:String(error)}));
    }
    await new Promise(r=>setTimeout(r,keyRotationIntervalMs));
  }
};

console.log(JSON.stringify({event:"ready",service:"bapc-maintenance-worker",outboxIntervalMs,retentionIntervalMs,retentionMonths,reconciliationIntervalMs,keyRotationIntervalMs}));
const loops=Promise.all([runOutboxLoop(),runRetentionLoop(),runReconciliationLoop(),runKeyRotationLoop()]);

const shutdown=async()=>{stopped=true;await loops;await db.close();process.exit(0);};
process.on("SIGTERM",()=>void shutdown());
process.on("SIGINT",()=>void shutdown());
