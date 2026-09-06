import {generateKeyPairSync} from "node:crypto";

// Real X25519 keypair generation via Node's own crypto module — WireGuard
// keys ARE raw 32-byte X25519 keys, base64-encoded, so this needs no `wg`
// binary and no hand-rolled crypto: generateKeyPairSync('x25519') already
// produces a spec-compliant keypair, exported here as JWK purely to reach
// the raw key bytes without hand-parsing DER offsets. Shared by the
// enrollment bootstrap flow (src/runtime/enroll-node.ts) and the agent's
// threat-triggered identity rotation (agents/shared/production-agent.ts).
export const generateWireGuardKeyPair=():{privateKey:string;publicKey:string}=>{
  const {publicKey,privateKey}=generateKeyPairSync("x25519");
  const pub=publicKey.export({format:"jwk"}) as {x:string};
  const priv=privateKey.export({format:"jwk"}) as {x:string;d:string};
  return {
    publicKey:Buffer.from(pub.x,"base64url").toString("base64"),
    privateKey:Buffer.from(priv.d,"base64url").toString("base64")
  };
};
