import {createHash} from "node:crypto";
import {readFileSync, readdirSync} from "node:fs";
import {join} from "node:path";

export interface MigrationFile {name:string; sql:string; checksum:string;}
export interface MigrationResult {applied:string[]; skipped:string[];}
export interface PgRow {[column:string]:any;}
export interface PgQueryable {
  query<T extends PgRow=PgRow>(text:string, values?:unknown[]):Promise<{rows:T[]}>;
}
export interface PgLike extends PgQueryable {
  transaction<T>(work:(client:PgQueryable)=>Promise<T>):Promise<T>;
}

const LOCK_KEY = 0x4241_5043_5645; // arbitrary constant advisory-lock key ("BAPCVE")

export const loadMigrations = (dir:string):MigrationFile[] =>
  readdirSync(dir)
    .filter(f=>f.endsWith(".sql"))
    .sort()
    .map(name=>{
      const sql=readFileSync(join(dir,name),"utf8");
      return {name,sql,checksum:createHash("sha256").update(sql).digest("hex")};
    });

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
          if(priorChecksum!==m.checksum){
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
      return {name:m.name,applied:true as const,appliedAt:row.applied_at,drifted:row.checksum!==m.checksum};
    });
  }
}
