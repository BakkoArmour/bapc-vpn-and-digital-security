import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {OutboxDispatcher} from "../infrastructure/postgres/outbox.js";
import {RetentionService} from "../infrastructure/postgres/maintenance.js";

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

const outboxIntervalMs=Number(process.env.OUTBOX_FLUSH_INTERVAL_MS??5_000);
const retentionIntervalMs=Number(process.env.RETENTION_INTERVAL_MS??3_600_000);
const retentionMonths=Number(process.env.EVENT_RETENTION_MONTHS??13);

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

console.log(JSON.stringify({event:"ready",service:"bapc-maintenance-worker",outboxIntervalMs,retentionIntervalMs,retentionMonths}));
const loops=Promise.all([runOutboxLoop(),runRetentionLoop()]);

const shutdown=async()=>{stopped=true;await loops;await db.close();process.exit(0);};
process.on("SIGTERM",()=>void shutdown());
process.on("SIGINT",()=>void shutdown());
