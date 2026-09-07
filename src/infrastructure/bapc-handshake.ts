import {createHmac, timingSafeEqual} from "node:crypto";

// Verifies BAPC Headquarters' own integration-handshake signature scheme
// (bapc-headquarters' src/services/integrations/handshake.ts fetchHandshake):
// HMAC-SHA256 over "${appId}:${nonce}" using the secret both sides configure
// as HEADQUARTERS_SHARED_SECRET. HQ sends this as x-bapc-nonce/x-bapc-signature
// headers on every scheduled or manual integration health check from its
// admin console — not the same signature scheme EcosystemIntegrationService
// uses for signed ecosystem event payloads (src/application/integrations.ts),
// which is a different, heavier contract for actual event delivery.
export const verifyBapcHandshakeSignature=(
  appId:string,secret:string,nonce:string|undefined,signature:string|undefined
):boolean=>{
  if(!nonce||!signature)return false;
  const expected=Buffer.from(createHmac("sha256",secret).update(`${appId}:${nonce}`).digest("hex"),"hex");
  let actual:Buffer;
  try{actual=Buffer.from(signature,"hex");}
  catch{return false;}
  return expected.length===actual.length&&timingSafeEqual(expected,actual);
};
