import test from "node:test";
import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {verifyBapcHandshakeSignature} from "../../../src/infrastructure/bapc-handshake.js";

// Mirrors bapc-headquarters' own fetchHandshake() signature scheme exactly:
// HMAC-SHA256 over "${appId}:${nonce}" using the shared secret.
const sign=(appId:string,secret:string,nonce:string)=>
  createHmac("sha256",secret).update(`${appId}:${nonce}`).digest("hex");

test("accepts a signature genuinely produced with the shared secret",()=>{
  const nonce="abc123";
  const signature=sign("bapc-vpn-and-digital-security","shared-secret",nonce);
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret",nonce,signature),true);
});

test("rejects a signature produced with the wrong secret",()=>{
  const nonce="abc123";
  const signature=sign("bapc-vpn-and-digital-security","attacker-secret",nonce);
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret",nonce,signature),false);
});

test("rejects a signature computed for a different appId",()=>{
  const nonce="abc123";
  const signature=sign("some-other-app","shared-secret",nonce);
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret",nonce,signature),false);
});

test("rejects a replayed signature paired with a different nonce",()=>{
  const signature=sign("bapc-vpn-and-digital-security","shared-secret","original-nonce");
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret","different-nonce",signature),false);
});

test("rejects when the nonce or signature header is missing",()=>{
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret",undefined,"deadbeef"),false);
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret","abc123",undefined),false);
});

test("rejects a malformed (non-hex) signature instead of throwing",()=>{
  assert.equal(verifyBapcHandshakeSignature("bapc-vpn-and-digital-security","shared-secret","abc123","not-hex-!!"),false);
});
