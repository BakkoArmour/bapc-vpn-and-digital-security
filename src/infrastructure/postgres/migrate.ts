import {createHash} from "node:crypto";
import {readFileSync, readdirSync} from "node:fs";
import {join} from "node:path";

// checksum is taken over the file with LF line endings, so a checkout's
// line-ending style (core.autocrlf on Windows vs Linux CI) can't make an
// unchanged migration look edited. acceptedChecksums also carries the CRLF
// variant: databases migrated before this normalisation (the live server was
// deployed from a CRLF Windows checkout) stored that one.
export interface MigrationFile {name:string; sql:string; checksum:string; acceptedChecksums?:string[];}
export interface MigrationResult {applied:string[]; skipped:string[];}
export interface PgRow {[column:string]:any;}
export interface PgQueryable {
  query<T extends PgRow=PgRow>(text:string, values?:unknown[]):Promise<{rows:T[]}>;
}
export interface PgLike extends PgQueryable {
  transaction<T>(work:(client:PgQueryable)=>Promise<T>):Promise<T>;
}

const sha256=(s:string)=>createHash("sha256").update(s).digest("hex");
export const migrationFile=(name:string,raw:string):MigrationFile=>{
  const lf=raw.replace(/\r\n/g,"\n");
  const checksum=sha256(lf);
  return {name,sql:raw,checksum,acceptedChecksums:[checksum,sha256(lf.replace(/\n/g,"\r\n"))]};
};
const matches=(m:MigrationFile,stored:string)=>stored===m.checksum||(m.acceptedChecksums??[]).includes(stored);

const LOCK_KEY = 0x4241_5043_5645; // arbitrary constant advisory-lock key ("BAPCVE")

export const loadMigrations = (dir:string):MigrationFile[] =>
  readdirSync(dir)
    .filter(f=>f.endsWith(".sql"))
    .sort()
    .map(name=>migrationFile(name,readFileSync(join(dir,name),"utf8")));

export class MigrationRunner {
  constructor(private db:PgLike){}

  private async ensureTable(){
    await this.db.query(`CREATE TABLE IF NOT EXISTS public.schema_migrations(
      name text PRIMARY KEY,
      checksum char(64) NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
  }

  async apply(migrations:MigrationFile[]):Promise<MigrationResult>{
    await this.ensureTable();
    return this.db.transaction(async client=>{
      await client.query("SELECT pg_advisory_xact_lock($1)",[LOCK_KEY]);
      const applied:string[]=[], skipped:string[]=[];
      const existing=await client.query<{name:string;checksum:string}>(
        "SELECT name,checksum FROM public.schema_migrations"
      );
      const byName=new Map(existing.rows.map(r=>[r.name,r.checksum]));
      for(const m of migrations){
        const priorChecksum=byName.get(m.name);
        if(priorChecksum){
          if(!matches(m,priorChecksum)){
            throw new Error(`migration ${m.name} has changed since it was applied (checksum mismatch)`);
          }
          skipped.push(m.name);
          continue;
        }
        await client.query(m.sql);
        await client.query(
          "INSERT INTO public.schema_migrations(name,checksum) VALUES($1,$2)",
          [m.name,m.checksum]
        );
        applied.push(m.name);
      }
      return {applied,skipped};
    });
  }

  async status(migrations:MigrationFile[]){
    await this.ensureTable();
    const existing=await this.db.query<{name:string;checksum:string;applied_at:Date}>(
      "SELECT name,checksum,applied_at FROM public.schema_migrations ORDER BY applied_at"
    );
    const byName=new Map(existing.rows.map(r=>[r.name,r]));
    return migrations.map(m=>{
      const row=byName.get(m.name);
      if(!row)return {name:m.name,applied:false as const};
      return {name:m.name,applied:true as const,appliedAt:row.applied_at,drifted:!matches(m,row.checksum)};
    });
  }
}
