import type { PolicyAction, SecurityZone } from "./types.js";
export interface PolicyIrRule { id:string; source:SecurityZone[]; destination:SecurityZone[]; protocols:Array<"TCP"|"UDP"|"ICMP"|"ANY">; ports:number[]; action:PolicyAction; log:boolean; expiresAt?:Date; }
export interface PolicyIrDocument { version:1; generatedAt:Date; checksum:string; rules:PolicyIrRule[]; }
export interface LinuxEnforcementPlan { ebpfMapEntries:Array<{key:string;value:string}>; nftablesFallback:string[]; }
export interface WindowsEnforcementPlan { wfpFilters:Array<{name:string;layer:string;action:"PERMIT"|"BLOCK";conditions:Record<string,string>}>; }
export interface AppleEnforcementPlan { networkExtensionRules:Array<{matchDomains:string[];matchNetworks:string[];action:"allow"|"drop"}>; }
