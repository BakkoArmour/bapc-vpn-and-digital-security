import {hydrateSecretsFromAws} from "../infrastructure/aws-secrets.js";
import {loadConfig} from "../config.js";
import {Postgres} from "../infrastructure/postgres/client.js";
import {SystemClock} from "../infrastructure/memory.js";
import {PgEnrollmentInviteStore} from "../infrastructure/pg-enrollment-invites.js";
import {mintInvite} from "../application/device-join.js";

// Owner-side CLI for minting a one-time device invite directly against the
// database, for use on the control-plane host itself:
//   docker compose exec control-api node dist/src/runtime/mint-invite.js --hours 24 --label "Owner laptop"
// POST /api/v1/devices/invites (security-owner) does the same over HTTPS.

const argOf=(name:string):string|undefined=>{
  const i=process.argv.indexOf(`--${name}`);
  return i!==-1?process.argv[i+1]:undefined;
};

await hydrateSecretsFromAws();
const config=loadConfig();
const db=new Postgres(config.databaseUrl);
try{
  const hours=argOf("hours");
  const invite=await mintInvite(new PgEnrollmentInviteStore(db),new SystemClock(),"owner-cli",{
    ...(hours!==undefined?{hours:Number(hours)}:{}),label:argOf("label")??""
  });
  console.log(JSON.stringify({event:"invite.minted",inviteId:invite.inviteId,code:invite.code,expiresAt:invite.expiresAt.toISOString()}));
}catch(error){
  console.error(JSON.stringify({event:"fatal",error:error instanceof Error?error.message:String(error)}));
  process.exitCode=1;
}finally{
  await db.close();
}
