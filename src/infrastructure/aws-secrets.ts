import {SecretsManagerClient, GetSecretValueCommand} from "@aws-sdk/client-secrets-manager";

export interface SecretsClient {send(command:GetSecretValueCommand):Promise<{SecretString?:string}>;}

// Real, wired AWS Secrets Manager integration — not a stub — gated purely on
// whether AWS_SECRETS_MANAGER_SECRET_ID is set. Every runtime entrypoint
// calls this before loadConfig() so production secrets (CONTROL_API_TOKEN_SECRET,
// EVENT_SIGNING_SECRET, OOB_SHARED_SECRET, the ecosystem HMAC secrets) can
// come from a real secret store instead of .env.example defaults, the moment
// an AWS account exists to hold them. Until then this is a no-op and
// loadConfig falls back to environment variables exactly as before — see
// [[user-build-everything-coming-soon]].
//
// An env var that's already set always wins over the secret store, so local
// overrides (docker-compose's own environment blocks, a developer's shell)
// still work even with AWS_SECRETS_MANAGER_SECRET_ID configured.
export const hydrateSecretsFromAws=async(env:NodeJS.ProcessEnv=process.env,client?:SecretsClient):Promise<void>=>{
  const secretId=env.AWS_SECRETS_MANAGER_SECRET_ID;
  if(!secretId){
    console.log(JSON.stringify({
      event:"secrets.mode",mode:"environment-variables",
      reason:"AWS_SECRETS_MANAGER_SECRET_ID not set — coming soon: set it (plus AWS_REGION and IAM credentials) to load production secrets from AWS Secrets Manager instead"
    }));
    return;
  }
  const secretsClient=client??new SecretsManagerClient(env.AWS_REGION?{region:env.AWS_REGION}:{});
  const result=await secretsClient.send(new GetSecretValueCommand({SecretId:secretId}));
  if(!result.SecretString)throw new Error(`AWS Secrets Manager secret "${secretId}" has no SecretString`);
  let secrets:Record<string,unknown>;
  try{secrets=JSON.parse(result.SecretString);}
  catch{throw new Error(`AWS Secrets Manager secret "${secretId}" is not a JSON object of key/value secrets`);}
  let applied=0;
  for(const [key,value] of Object.entries(secrets)){
    if(typeof value==="string"&&!env[key]){env[key]=value;applied++;}
  }
  console.log(JSON.stringify({event:"secrets.mode",mode:"aws-secrets-manager",secretId,region:env.AWS_REGION,keysApplied:applied}));
};
