export interface PlatformAdapter {
  platform:"linux"|"windows"|"macos"|"ios"|"ipados";
  applyWireGuard(input:{
    privateKeyReference:string;addresses:string[];listenPort?:number;
    peers:Array<{publicKey:string;endpoint?:string;allowedIps:string[];keepaliveSeconds:number}>;
  }):Promise<void>;
  // Updates only the peer set on an interface `applyWireGuard` already
  // brought up — never touches the local private key/address/listen-port, so
  // the control plane (which never holds this node's private key) can safely
  // push topology changes (peer joined, peer's key rotated) without a full
  // re-initialization.
  applyPeers(peers:Array<{publicKey:string;endpoint?:string;allowedIps:string[];keepaliveSeconds:number}>):Promise<void>;
  // Rotates ONLY this node's own private key on an interface that's already
  // up — never touches peers, addresses, or listen-port, so a threat-
  // triggered identity rotation doesn't need to know or resupply any of
  // that. Complements applyPeers exactly the way `wg set` supports setting
  // private-key and peers independently.
  rotatePrivateKey(privateKeyReference:string):Promise<void>;
  applyFirewall(input:{
    commitId:string;defaultAction:"DENY";rules:Array<{
      id:string;action:"ALLOW"|"DENY";protocols:string[];ports:number[];
      sourceZones:string[];destinationZones:string[];
    }>;
  }):Promise<void>;
  rollbackFirewall(commitId:string):Promise<void>;
  setKillSwitch(enabled:boolean):Promise<void>;
  setDns(servers:string[]):Promise<void>;
  isolate(reason:string):Promise<void>;
  restore():Promise<void>;
  collectPosture():Promise<{
    osCurrent:boolean;diskEncrypted:boolean;secureBoot:boolean;
    firewallEnabled:boolean;agentHealthy:boolean;bannedProcessFound:boolean;
  }>;
}
