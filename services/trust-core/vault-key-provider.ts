import {createPrivateKey,createPublicKey,sign,type KeyObject} from "node:crypto";
import type {ProtectedKeyProvider} from "./issuer.js";

/**
 * The device CA's private key as kept in BAPC Secrets & Key Management (#11) and handed to the container as a secret
 * at start. It lives only in this process's memory: never written to disk or the database, never exported, and
 * only the three services that sign (control API, customer portal, mesh gRPC) receive it.
 */
export class VaultKeyProvider implements ProtectedKeyProvider {
  private readonly keys=new Map<string,KeyObject>();
  constructor(entries:Record<string,string>){
    for(const [reference,pem] of Object.entries(entries)){
      let key:KeyObject;
      try{key=createPrivateKey(pem);}catch{throw new Error(`${reference}: not a readable private key`);}
      if(key.asymmetricKeyType!=="rsa")throw new Error(`${reference}: the CA key must be RSA`);
      if((key.asymmetricKeyDetails?.modulusLength??0)<3072)throw new Error(`${reference}: the CA key must be at least 3072 bits`);
      this.keys.set(reference,key);
    }
  }
  private key(reference:string):KeyObject{
    const key=this.keys.get(reference);
    if(!key)throw new Error(`unknown key reference ${reference}`);
    return key;
  }
  async sign(reference:string,algorithm:"ES256"|"RS256",payload:Buffer):Promise<Buffer>{
    if(algorithm!=="RS256")throw new Error(`the device CA signs RS256 only (got ${algorithm})`);
    return sign("sha256",payload,this.key(reference));
  }
  async publicKey(reference:string):Promise<string>{
    return createPublicKey(this.key(reference)).export({type:"spki",format:"pem"}).toString();
  }
}
