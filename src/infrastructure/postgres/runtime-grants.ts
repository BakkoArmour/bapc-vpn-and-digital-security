// What the running services may do, when they sign in as a separate runtime role (BAPC Cheisgos: migrations run as
// the migrator acting as the schema owner, the services as e.g. bapc_vpn_rw). Applied after every migration run,
// so tables a new migration adds are covered at once; the default privileges cover tables made later by the owner
// (the monthly event partitions, created by a SECURITY DEFINER function). Rows only: no schema changes.

export const APP_SCHEMA="bapc_security_core";
const IDENT=/^[a-z_][a-z0-9_]{0,62}$/;

export function runtimeGrantStatements(role:string,schema:string=APP_SCHEMA):string[]{
  if(!IDENT.test(role)) throw new Error(`PG_RUNTIME_ROLE must be a plain role name, not ${JSON.stringify(role)}`);
  if(!IDENT.test(schema)) throw new Error("schema must be a plain name");
  const r=`"${role}"`,s=`"${schema}"`;
  return [
    `GRANT USAGE ON SCHEMA ${s} TO ${r}`,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${s} TO ${r}`,
    `GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA ${s} TO ${r}`,
    `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ${s} TO ${r}`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${r}`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ${r}`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} GRANT EXECUTE ON FUNCTIONS TO ${r}`,
  ];
}
