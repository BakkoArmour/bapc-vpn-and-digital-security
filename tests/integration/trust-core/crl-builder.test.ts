import test from "node:test";
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, writeFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {ForgeCrlBuilder} from "../../../services/trust-core/crl-builder.js";
import {createSelfSignedDevCa} from "../../../services/trust-core/dev-self-signed.js";

const hasOpenssl=(()=>{
  try{execFileSync("openssl",["version"],{stdio:"ignore"});return true;}catch{return false;}
})();

test("ForgeCrlBuilder produces a spec-valid, openssl-parseable CRL listing the right serials",{skip:!hasOpenssl?"openssl not available":false},async()=>{
  const ca=await createSelfSignedDevCa("BAPC Test CRL Issuer","crl-test-issuer");
  const builder=new ForgeCrlBuilder();
  const now=new Date();
  const der=await builder.build({
    issuerCertificatePem:ca.certificatePem,
    thisUpdate:now,nextUpdate:new Date(now.getTime()+86_400_000),
    revoked:[
      {serialHex:"02",revokedAt:now},
      {serialHex:"ff03",revokedAt:now} // high bit set: exercises the two's-complement padding path
    ],
    sign:tbs=>ca.keys.sign(ca.keyReference,"RS256",tbs)
  });

  const dir=mkdtempSync(join(tmpdir(),"bapc-crl-"));
  const crlPath=join(dir,"test.crl");
  writeFileSync(crlPath,der);
  try{
    const text=execFileSync("openssl",["crl","-inform","DER","-in",crlPath,"-noout","-text"],{encoding:"utf8"});
    assert.match(text,/Certificate Revocation List/);
    assert.match(text,/Serial Number:\s*02/);
    assert.match(text,/Serial Number:\s*FF03/i);
    assert.match(text,/sha256WithRSAEncryption/);
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
});

test("an empty revocation list still produces a valid CRL",{skip:!hasOpenssl?"openssl not available":false},async()=>{
  const ca=await createSelfSignedDevCa("BAPC Test CRL Issuer 2","crl-test-issuer-2");
  const builder=new ForgeCrlBuilder();
  const now=new Date();
  const der=await builder.build({
    issuerCertificatePem:ca.certificatePem,thisUpdate:now,nextUpdate:new Date(now.getTime()+86_400_000),
    revoked:[],sign:tbs=>ca.keys.sign(ca.keyReference,"RS256",tbs)
  });
  const dir=mkdtempSync(join(tmpdir(),"bapc-crl-"));
  const crlPath=join(dir,"empty.crl");
  writeFileSync(crlPath,der);
  try{
    const text=execFileSync("openssl",["crl","-inform","DER","-in",crlPath,"-noout","-text"],{encoding:"utf8"});
    assert.match(text,/Certificate Revocation List/);
    assert.doesNotMatch(text,/Serial Number/);
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
});
