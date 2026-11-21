import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID, createHash} from "node:crypto";
import {fileURLToPath} from "node:url";
import {Postgres} from "../../../src/infrastructure/postgres/client.js";
import {MigrationRunner, loadMigrations} from "../../../src/infrastructure/postgres/migrate.js";
import {PgRepositories} from "../../../src/infrastructure/postgres/repositories.js";
import {PgCustomerStore} from "../../../src/infrastructure/pg-customer-store.js";
import {PgAccountData} from "../../../src/infrastructure/pg-account-data.js";

// The portal's audit trail, export and erasure against real Postgres (db/021, db/022): the SQL is only
// proven here, since the HTTP tests use in-memory stores.
const liveDatabaseUrl=process.env.DATABASE_URL;
test("live: audit, export and erasure of a portal account against real Postgres",{skip:!liveDatabaseUrl},async()=>{
  const db=new Postgres(liveDatabaseUrl!);
  await new MigrationRunner(db).apply(loadMigrations(fileURLToPath(new URL("../../../../db",import.meta.url))));
  const account=`acct-${randomUUID()}`,other=`acct-${randomUUID()}`;
  const deviceId=randomUUID(),nodeId=randomUUID(),inviteId=randomUUID();
  try{
    const repo=new PgRepositories(db),now=new Date();
    await repo.save({id:deviceId,hostname:"h",hardwareId:`hw-${deviceId}`,platform:"linux" as const,osVersion:"1",compromised:false,revoked:false,
      posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:now},createdAt:now,updatedAt:now});
    const octet=()=>Math.floor(Math.random()*250)+2;
    await repo.save({id:nodeId,deviceId,wireGuardPublicKey:`pk-${nodeId}`.slice(0,60),internalIpv4:`10.199.${octet()}.${octet()}`,internalIpv6:`fd99::${randomUUID().slice(0,4)}`,
      listenPort:51820,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true});
    const customers=new PgCustomerStore(db),data=new PgAccountData(db);
    await customers.record(nodeId,{accountId:account,email:"pat@example.com",deviceName:"Pat's phone"},"android");
    await db.query(`INSERT INTO bapc_security_core.enrollment_invites(invite_id,code_hash,label,created_by,expires_at,account_id,account_email,device_name)
      VALUES($1,$2,'customer portal',$3,now()+interval '1 day',$4,'pat@example.com','PC')`,[inviteId,createHash("sha256").update(inviteId).digest("hex"),`customer:${account}`,account]);
    await customers.createSession(createHash("sha256").update(account).digest("hex"),{accountId:account,email:"pat@example.com",name:"Pat",csrfToken:"c"},new Date(Date.now()+3600_000));
    assert.equal(await data.hasSignedInBefore(account),false);
    await data.audit(account,"customer","auth.signed_in",{},"203.0.113.9");
    assert.equal(await data.hasSignedInBefore(account),true);
    await data.audit(account,"customer","device.added",{node_id:nodeId,kind:"android"},"203.0.113.9");
    await data.audit(other,"customer","auth.signed_in",{},"198.51.100.1");

    const exp=await data.exportAccount(account);
    assert.deepEqual(exp.devices.map(d=>[d.name,d.kind]),[["Pat's phone","android"]]);
    assert.equal(exp.invites.length,1);
    assert.deepEqual(exp.activity.map(a=>a.action).sort(),["auth.signed_in","device.added"]);
    assert.ok(exp.activity.every(a=>a.ip==="203.0.113.9"),"another account's activity isn't included");

    const erased=await data.eraseAccount(account);
    assert.deepEqual(erased,{devices:1,invites:1,sessions:1,auditRows:2});
    const leftover=await db.query(`SELECT
      (SELECT count(*) FROM bapc_security_core.customer_devices WHERE account_id=$1 OR email='pat@example.com')::int devices,
      (SELECT count(*) FROM bapc_security_core.enrollment_invites WHERE account_id=$1 OR created_by=$2)::int invites,
      (SELECT count(*) FROM bapc_security_core.portal_sessions WHERE account_id=$1)::int sessions,
      (SELECT count(*) FROM bapc_security_core.portal_audit WHERE account_id=$1 OR ip='203.0.113.9')::int audit`,[account,`customer:${account}`]);
    assert.deepEqual(leftover.rows[0],{devices:0,invites:0,sessions:0,audit:0},"nothing identifies the person any more");
    assert.ok((await customers.suspendedNodeIds()).has(nodeId),"the erased device stays blocked at the gateway");
    assert.equal((await data.exportAccount(other)).activity.length,1,"other accounts are untouched");
  }finally{
    await db.query(`DELETE FROM bapc_security_core.portal_audit WHERE account_id=$1 OR account_id LIKE 'erased:%' AND at>now()-interval '1 hour'`,[other]);
    await db.query(`DELETE FROM bapc_security_core.customer_devices WHERE node_id=$1`,[nodeId]);
    await db.query(`DELETE FROM bapc_security_core.enrollment_invites WHERE invite_id=$1`,[inviteId]);
    await db.query(`DELETE FROM bapc_security_core.mesh_nodes WHERE node_id=$1`,[nodeId]);
    await db.query(`DELETE FROM bapc_security_core.devices WHERE device_id=$1`,[deviceId]);
    await db.close();
  }
});

test("live: staff admin store lists, searches and opens accounts; sessions keep their bapc.app role; staff actions audit",{skip:!liveDatabaseUrl},async()=>{
  const {PgAdminStore}=await import("../../../src/infrastructure/pg-account-data.js");
  const db=new Postgres(liveDatabaseUrl!);
  await new MigrationRunner(db).apply(loadMigrations(fileURLToPath(new URL("../../../../db",import.meta.url))));
  const acct=`acct-${randomUUID()}`,tok=createHash("sha256").update(acct).digest("hex"),staffTok=createHash("sha256").update(`s-${acct}`).digest("hex");
  try{
    const customers=new PgCustomerStore(db),data=new PgAccountData(db),admin=new PgAdminStore(db);
    await customers.createSession(tok,{accountId:acct,email:`${acct}@example.com`,name:"Pat",csrfToken:"c"},new Date(Date.now()+3600_000));
    await customers.createSession(staffTok,{accountId:`staff-${acct}`,email:"boss@bapc.app",name:"Boss",csrfToken:"c",role:"admin"},new Date(Date.now()+3600_000));
    assert.equal((await customers.session(tok))!.role,"user");
    assert.equal((await customers.session(staffTok))!.role,"admin");
    await data.audit(acct,"customer","auth.signed_in",{},"203.0.113.7");
    await data.audit(acct,"staff","staff.payment_rechecked",{staff:"boss@bapc.app"},"198.51.100.2");
    const found=await admin.listAccounts({search:acct.slice(0,20).toUpperCase(),page:1,pageSize:50});
    assert.ok(found.rows.some(r=>r.accountId===acct&&r.email===`${acct}@example.com`&&r.lastSignIn instanceof Date),"case-insensitive email search");
    assert.ok((await admin.listAccounts({search:acct,page:1,pageSize:50})).total>=1,"exact account id search");
    assert.equal((await admin.listAccounts({search:"no-such-person-xyz",page:1,pageSize:50})).total,0);
    const detail=await admin.accountDetail(acct);
    assert.equal(detail!.email,`${acct}@example.com`);
    assert.deepEqual(detail!.activity.map(a=>`${a.actor}:${a.action}`),["staff:staff.payment_rechecked","customer:auth.signed_in"]);
    assert.equal(await admin.accountDetail("never-seen"),null);
    await assert.rejects(db.query(`INSERT INTO bapc_security_core.portal_audit(account_id,actor,action) VALUES($1,'robot','x')`,[acct]),/portal_audit_actor_check/,"only customer, system or staff");
  }finally{
    await db.query(`DELETE FROM bapc_security_core.portal_audit WHERE account_id=$1`,[acct]);
    await db.query(`DELETE FROM bapc_security_core.portal_sessions WHERE token_hash IN ($1,$2)`,[tok,staffTok]);
    await db.close();
  }
});
