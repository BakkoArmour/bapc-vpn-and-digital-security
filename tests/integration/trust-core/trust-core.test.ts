import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import forge from "node-forge";
import {DevKeyProvider} from "../../../services/trust-core/dev-key-provider.js";
import {ForgeX509Builder} from "../../../services/trust-core/x509-forge.js";
import {TrustCoreIssuer, type CertificateRecordStore} from "../../../services/trust-core/issuer.js";
import {runDevCeremony} from "../../../services/trust-core/ceremony.js";
import {PgCertificateStore} from "../../../services/trust-core/pg-certificate-store.js";

class MemoryRecordStore implements CertificateRecordStore {
  saved:any[]=[]; revoked:Array<{serial:string;reason:string}>=[];
  async save(record:any){this.saved.push(record);}
  async revoke(serial:string,reason:string){this.revoked.push({serial,reason});}
}

test("dev ceremony produces a root and intermediate that chain-verify",async()=>{
  const dir=mkdtempSync(join(tmpdir(),"bapc-ca-"));
  try{
    const manifest=await runDevCeremony(dir);
    assert.equal(manifest.root.subject,"CN=BAPC Root CA");
    const rootPem=readFileSync(join(dir,"root-ca.crt.pem"),"utf8");
    const intermediatePem=readFileSync(join(dir,"intermediate-ca.crt.pem"),"utf8");
    const root=forge.pki.certificateFromPem(rootPem);
    const intermediate=forge.pki.certificateFromPem(intermediatePem);
    assert.equal(root.verify(intermediate),true);
    assert.equal(root.verify(root),true);
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
});

test("TrustCoreIssuer issues a node certificate that verifies against its issuer",async()=>{
  const keys=new DevKeyProvider();
  const issuerPublicKeyPem=keys.generate("issuer-1");
  const x509=new ForgeX509Builder();
  // Build a self-signed "issuer" certificate to act as the signing CA for this test.
  const issuerSelfPem=await x509.create({
    serial:"10",subject:"CN=BAPC Test Issuer",publicKeyPem:issuerPublicKeyPem,
    issuerCertificatePem:(()=>{
      const placeholder=forge.pki.createCertificate();
      placeholder.publicKey=forge.pki.publicKeyFromPem(issuerPublicKeyPem);
      placeholder.setSubject([{name:"commonName",value:"CN=BAPC Test Issuer"}]);
      placeholder.validity.notBefore=new Date();
      placeholder.validity.notAfter=new Date(Date.now()+86_400_000);
      placeholder.signatureOid=placeholder.siginfo.algorithmOid=forge.pki.oids["sha256WithRSAEncryption"]!;
      placeholder.signature="";
      return forge.pki.certificateToPem(placeholder);
    })(),
    notBefore:new Date(),notAfter:new Date(Date.now()+365*86_400_000),
    extensions:{basicConstraints:"CA:TRUE",keyUsage:"keyCertSign,cRLSign"},
    sign:tbs=>keys.sign("issuer-1","RS256",tbs)
  });

  const records=new MemoryRecordStore();
  const trustCore=new TrustCoreIssuer(keys,records,x509,{
    id:"issuer-1",certificatePem:issuerSelfPem,keyReference:"issuer-1",algorithm:"RS256"
  });

  const nodeKeys=new DevKeyProvider();
  const nodePublicKeyPem=nodeKeys.generate("node-key");
  const result=await trustCore.issueNode("node-abc",nodePublicKeyPem,60);

  assert.equal(records.saved.length,1);
  assert.equal(records.saved[0].nodeId,"node-abc");
  const issuerCert=forge.pki.certificateFromPem(issuerSelfPem);
  const nodeCert=forge.pki.certificateFromPem(result.certificatePem);
  assert.equal(issuerCert.verify(nodeCert),true);
  assert.equal(nodeCert.subject.getField("CN")?.value.includes("node-abc"),true);
});

test("TrustCoreIssuer rejects a TTL outside the allowed range",async()=>{
  const keys=new DevKeyProvider();
  const x509=new ForgeX509Builder();
  const records=new MemoryRecordStore();
  const trustCore=new TrustCoreIssuer(keys,records,x509,{
    id:"issuer-1",certificatePem:"unused",keyReference:"issuer-1",algorithm:"RS256"
  });
  await assert.rejects(()=>trustCore.issueNode("n1","pem",1),/TTL outside allowed range/);
  await assert.rejects(()=>trustCore.issueNode("n1","pem",99999),/TTL outside allowed range/);
});

test("TrustCoreIssuer requires a meaningful revocation reason",async()=>{
  const keys=new DevKeyProvider();
  const x509=new ForgeX509Builder();
  const records=new MemoryRecordStore();
  const trustCore=new TrustCoreIssuer(keys,records,x509,{
    id:"issuer-1",certificatePem:"unused",keyReference:"issuer-1",algorithm:"RS256"
  });
  await assert.rejects(()=>trustCore.revoke("serial-1","bad"),/revocation reason required/);
  await trustCore.revoke("serial-1","key material was compromised in incident INC-42");
  assert.equal(records.revoked.length,1);
});

test("PgCertificateStore issues the expected SQL for save and revoke",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgCertificateStore({
    query:async(text:string,values:unknown[]=[])=>{queries.push({text,values});return {rows:[]};}
  });
  await store.save({
    id:"c1",nodeId:"n1",issuerId:"i1",serial:"01",subject:"CN=x",
    issuedAt:new Date(),expiresAt:new Date(),revoked:false,keyReference:"k1"
  });
  await store.revoke("01","rotated",new Date());
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.certificates/);
  assert.match(queries[1]!.text,/UPDATE bapc_security_core\.certificates/);
});
