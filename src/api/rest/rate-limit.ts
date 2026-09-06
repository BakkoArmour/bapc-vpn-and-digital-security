export interface RateLimitRule {limit:number; windowMs:number;}
export interface RateLimitResult {allowed:boolean; remaining:number; resetAt:number;}

// In-memory sliding-window counter, keyed by an arbitrary string (typically
// `${subject}:${route}`). Adequate for a single control-plane instance; a
// multi-instance deployment must back this with a shared store (Redis or the
// Postgres-backed variant below) so limits are enforced cluster-wide.
export class MemoryRateLimiter {
  private hits=new Map<string,number[]>();
  check(key:string,rule:RateLimitRule,now=Date.now()):RateLimitResult{
    const windowStart=now-rule.windowMs;
    const existing=(this.hits.get(key)??[]).filter(t=>t>windowStart);
    if(existing.length>=rule.limit){
      this.hits.set(key,existing);
      return {allowed:false,remaining:0,resetAt:existing[0]!+rule.windowMs};
    }
    existing.push(now);
    this.hits.set(key,existing);
    return {allowed:true,remaining:rule.limit-existing.length,resetAt:now+rule.windowMs};
  }
  sweep(now=Date.now()){
    for(const [key,hits] of this.hits){
      const kept=hits.filter(t=>t>now-3_600_000);
      if(kept.length)this.hits.set(key,kept); else this.hits.delete(key);
    }
  }
}
