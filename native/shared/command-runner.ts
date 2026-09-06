import {execFile} from "node:child_process";
import {promisify} from "node:util";

export type CommandRunner=(cmd:string,args:string[])=>Promise<{stdout:string;stderr:string}>;

const execFileAsync=promisify(execFile);

// Real process execution. Always called with an argv ARRAY (never a shell
// string), so caller-supplied values (public keys, IPs, hostnames) cannot be
// interpreted as shell metacharacters — this is the injection-safety
// boundary every native adapter below is built on.
export const systemCommandRunner:CommandRunner=async(cmd,args)=>{
  const {stdout,stderr}=await execFileAsync(cmd,args,{timeout:15_000,maxBuffer:4*1024*1024});
  return {stdout,stderr};
};
