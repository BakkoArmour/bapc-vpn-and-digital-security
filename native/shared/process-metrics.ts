// Real CPU load sampling via Node's own process.cpuUsage() — no external
// monitoring agent needed. Call sample() once per heartbeat interval; it
// returns the percentage of wall-clock time since the PREVIOUS call that
// this process spent on CPU (user+system), which is exactly what
// "process/resource load" should mean for a single-purpose relay/egress
// process. Previously relay-server.ts/egress-server.ts hardcoded
// loadPercent:0 rather than measuring anything.
export class CpuLoadSampler {
  private lastUsage=process.cpuUsage();
  private lastTime=process.hrtime.bigint();

  sample():number{
    const usage=process.cpuUsage(this.lastUsage);
    const now=process.hrtime.bigint();
    const elapsedMicros=Number(now-this.lastTime)/1000;
    this.lastUsage=process.cpuUsage();
    this.lastTime=now;
    if(elapsedMicros<=0)return 0;
    const cpuMicros=usage.user+usage.system;
    return Math.min(100,Math.max(0,(cpuMicros/elapsedMicros)*100));
  }
}

// Bytes-per-second throughput from a monotonically-increasing cumulative
// counter (e.g. BlindRelayServer.totalBytesRelayed), sampled the same way.
export class ThroughputSampler {
  private lastTotal=0;
  private lastTime=process.hrtime.bigint();

  sample(cumulativeBytes:number):number{
    const now=process.hrtime.bigint();
    const elapsedSeconds=Number(now-this.lastTime)/1e9;
    const delta=Math.max(0,cumulativeBytes-this.lastTotal);
    this.lastTotal=cumulativeBytes;
    this.lastTime=now;
    if(elapsedSeconds<=0)return 0;
    return Math.round(delta/elapsedSeconds);
  }
}
