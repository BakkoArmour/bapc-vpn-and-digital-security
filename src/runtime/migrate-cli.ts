import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {loadMigrations, MigrationRunner} from "../infrastructure/postgres/migrate.js";

const dir=process.argv[2] ?? "db";
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
const runner=new MigrationRunner(db);
const migrations=loadMigrations(dir);

const command=process.argv[3] ?? "up";
if(command==="status"){
  const rows=await runner.status(migrations);
  for(const r of rows){
    if(!r.applied) console.log(`PENDING  ${r.name}`);
    else console.log(`${r.drifted?"DRIFTED ":"APPLIED "} ${r.name} (${r.appliedAt.toISOString()})`);
  }
}else{
  const result=await runner.apply(migrations);
  console.log(JSON.stringify({event:"migrations.applied",...result}));
}
await db.close();
