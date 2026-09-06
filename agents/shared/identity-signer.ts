import {readFileSync} from "node:fs";
import {sign as cryptoSign} from "node:crypto";

// Signs a rotation request the same way src/runtime/enroll-node.ts's caller
// persists the identity key and src/api/grpc/server.ts's
// verifyRotationSignature expects it: RSA-SHA256 over "nodeId:newPublicKey".
// This is what proves a rotation request came from the node that originally
// enrolled — see the RotatePeerKey signature-verification work earlier this
// session. The private key never leaves this process; it's read from local
// disk (written once, at enrollment, by enroll.ts) purely to produce a
// signature.
export interface IdentitySigner {sign(nodeId:string,newPublicKey:string):Buffer;}

export class FileIdentitySigner implements IdentitySigner {
  constructor(private privateKeyPemPath:string){}
  sign(nodeId:string,newPublicKey:string):Buffer{
    const pem=readFileSync(this.privateKeyPemPath,"utf8");
    return cryptoSign("RSA-SHA256",Buffer.from(`${nodeId}:${newPublicKey}`),pem);
  }
}
