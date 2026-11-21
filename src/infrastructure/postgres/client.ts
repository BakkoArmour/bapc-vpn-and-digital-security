import pg from "pg";
const {Pool}=pg;

export class Postgres {
  readonly pool:pg.Pool;
  /** An empty connection string means: use the PG* environment variables (PGHOST, PGPASSWORD, PGSSLMODE, ...). */
  constructor(connectionString:string){
    this.pool=new Pool({
      connectionString:connectionString||undefined,
      max:20,
      idleTimeoutMillis:30_000,
      connectionTimeoutMillis:5_000,
      application_name:"bapc-vpn-digital-security"
    });
  }
  async query<T extends pg.QueryResultRow=pg.QueryResultRow>(
    text:string, values:unknown[]=[]
  ):Promise<pg.QueryResult<T>>{return this.pool.query<T>(text,values);}
  async transaction<T>(work:(client:pg.PoolClient)=>Promise<T>):Promise<T>{
    const client=await this.pool.connect();
    try{
      await client.query("BEGIN");
      const value=await work(client);
      await client.query("COMMIT");
      return value;
    }catch(error){
      await client.query("ROLLBACK");
      throw error;
    }finally{client.release();}
  }
  async health(){await this.query("SELECT 1");return true;}
  async close(){await this.pool.end();}
}
