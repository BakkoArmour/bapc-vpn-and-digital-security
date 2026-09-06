import type {KMSClient} from "@aws-sdk/client-kms";
import {GetPublicKeyCommand, SignCommand} from "@aws-sdk/client-kms";
import type {ProtectedKeyProvider} from "./issuer.js";

const pem=(der:Buffer,label:string)=>{
  const base64=der.toString("base64");
  const lines=base64.match(/.{1,64}/g)??[];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
};

// Real HSM-backed signing via AWS KMS asymmetric keys. The private key never
// leaves KMS — this only ever sends the already-built TBS bytes for KMS to
// sign and hands the resulting signature bytes back, mirroring exactly the
// external-signer contract ForgeX509Builder/ForgeCrlBuilder already expect
// (see dev-key-provider.ts for the in-memory equivalent used until an AWS
// account/KMS key is actually provisioned).
//
// Only RS256 is supported: ForgeX509Builder always writes the
// sha256WithRSAEncryption signature OID into the certificate regardless of
// signer algorithm, so an EC-backed KMS key would produce a structurally
// inconsistent certificate (RSA OID, ECDSA signature bytes). Use an RSA_3072
// or RSA_4096 asymmetric KMS key. ES256 support would need
// ForgeX509Builder/ForgeCrlBuilder fixed to select the signature OID from the
// signer's algorithm first.
export class AwsKmsKeyProvider implements ProtectedKeyProvider {
  constructor(private client:KMSClient,private keyIdsByReference:Map<string,string>){}

  private keyId(keyReference:string):string{
    const keyId=this.keyIdsByReference.get(keyReference);
    if(!keyId)throw new Error(`no AWS KMS key configured for reference "${keyReference}"`);
    return keyId;
  }

  async sign(keyReference:string,algorithm:"ES256"|"RS256",payload:Buffer):Promise<Buffer>{
    if(algorithm!=="RS256")throw new Error(`AwsKmsKeyProvider only supports RS256 (got ${algorithm})`);
    const result=await this.client.send(new SignCommand({
      KeyId:this.keyId(keyReference),
      Message:payload,
      MessageType:"RAW",
      SigningAlgorithm:"RSASSA_PKCS1_V1_5_SHA_256"
    }));
    if(!result.Signature)throw new Error(`AWS KMS returned no signature for key reference "${keyReference}"`);
    return Buffer.from(result.Signature);
  }

  async publicKey(keyReference:string):Promise<string>{
    const result=await this.client.send(new GetPublicKeyCommand({KeyId:this.keyId(keyReference)}));
    if(!result.PublicKey)throw new Error(`AWS KMS returned no public key for key reference "${keyReference}"`);
    return pem(Buffer.from(result.PublicKey),"PUBLIC KEY");
  }
}
