import type {PlatformAdapter} from "../shared/platform-adapter.js";

const NOT_IMPLEMENTED=
  "macOS/iOS/iPadOS network control requires a native Swift NetworkExtension "+
  "(NEPacketTunnelProvider / NEFilterDataProvider) or System Extension running "+
  "under an Apple Developer Program entitlement — this cannot be implemented "+
  "in a Node/TypeScript process. This class documents the required interface "+
  "so a native Swift extension (communicating with this control plane over "+
  "the gRPC mesh or REST API) can be built against the same PlatformAdapter "+
  "contract as the Linux/Windows adapters. See docs/PRODUCTION-ADAPTERS.md.";

/**
 * Throws on every call by design — see NOT_IMPLEMENTED above. Do not stub
 * this out to silently succeed; iOS/iPadOS is the one platform where the OS
 * itself refuses to grant the equivalent of the Linux/Windows privileges,
 * so pretending this adapter "works" would misrepresent what is actually
 * enforced on the device.
 */
export class ApplePlatformAdapter implements PlatformAdapter {
  readonly platform:"macos"|"ios"|"ipados";
  constructor(platform:"macos"|"ios"|"ipados"){this.platform=platform;}
  async applyWireGuard():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async applyPeers():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async rotatePrivateKey():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async applyFirewall():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async rollbackFirewall():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async setKillSwitch():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async setDns():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async isolate():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async restore():Promise<void>{throw new Error(NOT_IMPLEMENTED);}
  async collectPosture():Promise<{
    osCurrent:boolean;diskEncrypted:boolean;secureBoot:boolean;
    firewallEnabled:boolean;agentHealthy:boolean;bannedProcessFound:boolean;
  }>{throw new Error(NOT_IMPLEMENTED);}
}
