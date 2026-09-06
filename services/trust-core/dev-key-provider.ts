import forge from "node-forge";
import type {ProtectedKeyProvider} from "./issuer.js";

const {pki, md} = forge;

/**
 * DEVELOPMENT ONLY. Holds RSA private keys in process memory and signs with
 * them directly. This is what "ProtectedKeyProvider" looks like when there is
 * no HSM/KMS behind it yet — it satisfies the interface so the rest of Trust
 * Core (ForgeX509Builder, TrustCoreIssuer) never needs to change when a real
 * PKCS#11/KMS-backed provider is substituted in production. NEVER deploy this
 * class with production traffic: see runbooks/root-ca-ceremony.md.
 */
export class DevKeyProvider implements ProtectedKeyProvider {
  private keys=new Map<string,forge.pki.rsa.KeyPair>();

  generate(keyReference:string,bits:2048|3072|4096=3072):string{
    const pair=pki.rsa.generateKeyPair({bits});
    this.keys.set(keyReference,pair);
    return pki.publicKeyToPem(pair.publicKey);
  }

  // Reconstructs a previously-generated dev key from its exported PEM (see
  // exportPrivateKeyPemForDevOnly) so a multi-process deployment (one
  // ephemeral CA shared by the control-api and mesh-grpc containers, say)
  // doesn't mint a different, mutually-unverifiable CA per process. Dev-only,
  // same as the rest of this class — a real deployment loads keys from an
  // HSM/KMS instead, never from a stored PEM.
  importPrivateKeyPem(keyReference:string,privateKeyPem:string):string{
    const privateKey=pki.privateKeyFromPem(privateKeyPem);
    const publicKey=pki.setRsaPublicKey(privateKey.n,privateKey.e);
    this.keys.set(keyReference,{privateKey,publicKey});
    return pki.publicKeyToPem(publicKey);
  }

  async sign(keyReference:string,algorithm:"ES256"|"RS256",payload:Buffer):Promise<Buffer>{
    if(algorithm!=="RS256")throw new Error(`DevKeyProvider only supports RS256 (got ${algorithm})`);
    const pair=this.keys.get(keyReference);
    if(!pair)throw new Error(`unknown key reference ${keyReference}`);
    const digest=md.sha256.create();
    digest.update(payload.toString("binary"));
    const signature=pair.privateKey.sign(digest);
    return Buffer.from(signature,"binary");
  }

  async publicKey(keyReference:string):Promise<string>{
    const pair=this.keys.get(keyReference);
    if(!pair)throw new Error(`unknown key reference ${keyReference}`);
    return pki.publicKeyToPem(pair.publicKey);
  }

  exportPrivateKeyPemForDevOnly(keyReference:string):string{
    const pair=this.keys.get(keyReference);
    if(!pair)throw new Error(`unknown key reference ${keyReference}`);
    return pki.privateKeyToPem(pair.privateKey);
  }
}
