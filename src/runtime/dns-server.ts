import {randomUUID} from "node:crypto";
import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {PgRepositories} from "../infrastructure/postgres/repositories.js";
import {DnsProtectionService} from "../application/dns-protection.js";
import {DohUpstream} from "../../services/dns/doh-upstream.js";
import {SecureDnsResolver, type DnsAudit} from "../../services/dns/resolver.js";
import {BapcDnsServer} from "../../services/dns/dns-server.js";
import {StaticListThreatFeed} from "../../services/dns/threat-feed.js";

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const repo=new PgRepositories(db);

const feeds=process.env.DNS_THREAT_FEED_PATH
  ? [StaticListThreatFeed.fromFile(process.env.DNS_THREAT_FEED_PATH)]
  : [];

const protection=new DnsProtectionService(feeds);
const audit:DnsAudit={
  async record(event){
    await repo.append({
      id:randomUUID(),at:event.at,severity:"INFO",engine:"secure-dns",
      type:event.action==="SINKHOLE"?"DNS_SINKHOLE":"DNS_ALLOW",
      description:event.reason,metadata:{nameHash:event.nameHash}
    });
  }
};
const resolver=new SecureDnsResolver(protection,[new DohUpstream()],audit);
const server=new BapcDnsServer(resolver);

const port=Number(process.env.DNS_PORT??53);
const host=process.env.DNS_BIND_HOST??"127.0.0.1";
await server.start(port,host);
console.log(JSON.stringify({event:"ready",service:"bapc-secure-dns",host,port}));

const shutdown=async()=>{await server.stop();await db.close();process.exit(0);};
process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
