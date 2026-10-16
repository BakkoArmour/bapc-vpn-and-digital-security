import forge from "node-forge";

// Extracts and verifies a node's proof-of-possession CSR: node-forge's
// csr.verify() checks the CSR's self-signature against its own embedded
// public key, confirming the node holds the matching private key without
// that key ever leaving the node. See mesh.proto's csr_der field comment for
// why this can't just reuse the WireGuard public key. Shared by the gRPC
// registerNode path (src/api/grpc/server.ts) and the HTTPS device-join path
// (src/application/device-join.ts).
export const publicKeyPemFromCsrDer=(csrDer:Uint8Array):string=>{
  if(csrDer.length===0)throw new Error("csr_der is required: submit a self-signed PKCS#10 CSR to obtain a certificate");
  let csr:forge.pki.CertificateSigningRequest;
  try{
    const asn1=forge.asn1.fromDer(forge.util.createBuffer(Buffer.from(csrDer).toString("binary")));
    csr=forge.pki.certificationRequestFromAsn1(asn1);
  }catch{
    throw new Error("csr_der could not be parsed as a PKCS#10 CertificationRequest");
  }
  if(!csr.verify())throw new Error("CSR signature does not verify against its own embedded public key");
  return forge.pki.publicKeyToPem(csr.publicKey!);
};
