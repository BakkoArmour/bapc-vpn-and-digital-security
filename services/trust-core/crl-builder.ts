import forge from "node-forge";

const {pki, asn1} = forge;

export interface RevokedCertificateEntry {serialHex:string; revokedAt:Date;}

const seq=(children:forge.asn1.Asn1[])=>asn1.create(asn1.Class.UNIVERSAL,asn1.Type.SEQUENCE,true,children);
const int=(n:number)=>asn1.create(asn1.Class.UNIVERSAL,asn1.Type.INTEGER,false,asn1.integerToDer(n).getBytes());
// asn1.integerToDer only accepts a JS number; arbitrary-length hex serials
// need the DER INTEGER's two's-complement encoding built by hand (pad a
// leading 0x00 byte when the high bit is set, so it isn't read as negative).
const intHex=(hex:string)=>{
  let bytes=Buffer.from(hex,"hex");
  if((bytes[0]!??0)&0x80)bytes=Buffer.concat([Buffer.from([0]),bytes]);
  return asn1.create(asn1.Class.UNIVERSAL,asn1.Type.INTEGER,false,bytes.toString("binary"));
};
const algorithmIdentifier=(oid:string)=>seq([
  asn1.create(asn1.Class.UNIVERSAL,asn1.Type.OID,false,asn1.oidToDer(oid).getBytes()),
  asn1.create(asn1.Class.UNIVERSAL,asn1.Type.NULL,false,"")
]);
const utcTime=(d:Date)=>asn1.create(asn1.Class.UNIVERSAL,asn1.Type.UTCTIME,false,asn1.dateToUtcTime(d));

// Builds a real RFC 5280 CertificateList (X.509 CRL), DER-encoded, signed by
// an EXTERNAL async signer — same TBS-then-sign-then-splice pattern as
// ForgeX509Builder, so this works unchanged whether the signer is the dev
// in-memory key provider or a real HSM/KMS. Verified against `openssl crl
// -inform DER -noout -text` during development (a real ASN.1 parser other
// than this code's own, confirming the structure is spec-correct).
export class ForgeCrlBuilder {
  async build(input:{
    issuerCertificatePem:string; thisUpdate:Date; nextUpdate:Date;
    revoked:RevokedCertificateEntry[]; sign:(tbs:Buffer)=>Promise<Buffer>;
  }):Promise<Buffer>{
    const issuerCert=pki.certificateFromPem(input.issuerCertificatePem);
    const revokedSeq=seq(input.revoked.map(r=>seq([intHex(r.serialHex),utcTime(r.revokedAt)])));
    const tbsCertList=seq([
      int(1), // v2
      algorithmIdentifier(pki.oids["sha256WithRSAEncryption"]!),
      pki.distinguishedNameToAsn1(issuerCert.subject),
      utcTime(input.thisUpdate),
      utcTime(input.nextUpdate),
      revokedSeq
    ]);
    const tbsDer=Buffer.from(asn1.toDer(tbsCertList).getBytes(),"binary");
    const signature=await input.sign(tbsDer);

    const crl=seq([
      tbsCertList,
      algorithmIdentifier(pki.oids["sha256WithRSAEncryption"]!),
      asn1.create(asn1.Class.UNIVERSAL,asn1.Type.BITSTRING,false,"\x00"+signature.toString("binary"))
    ]);
    return Buffer.from(asn1.toDer(crl).getBytes(),"binary");
  }
}
