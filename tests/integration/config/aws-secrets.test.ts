import test from "node:test";
import assert from "node:assert/strict";
import {hydrateSecretsFromAws} from "../../../src/infrastructure/aws-secrets.js";

test("is a no-op and never touches env when AWS_SECRETS_MANAGER_SECRET_ID is unset",async()=>{
  const env={CONTROL_API_TOKEN_SECRET:"unchanged"};
  await hydrateSecretsFromAws(env,{send:async()=>{throw new Error("should never be called");}});
  assert.equal(env.CONTROL_API_TOKEN_SECRET,"unchanged");
});

test("applies secret-store values for keys not already set in env",async()=>{
  const env:Record<string,string|undefined>={
    AWS_SECRETS_MANAGER_SECRET_ID:"bapc/prod/control-plane",
    CONTROL_API_TOKEN_SECRET:"already-set-locally" // must not be overwritten
  };
  const fakeClient={
    send:async()=>({SecretString:JSON.stringify({
      CONTROL_API_TOKEN_SECRET:"from-secrets-manager",
      EVENT_SIGNING_SECRET:"also-from-secrets-manager"
    })})
  };
  await hydrateSecretsFromAws(env,fakeClient);
  assert.equal(env.CONTROL_API_TOKEN_SECRET,"already-set-locally");
  assert.equal(env.EVENT_SIGNING_SECRET,"also-from-secrets-manager");
});

test("rejects a secret value that isn't a JSON object",async()=>{
  const env={AWS_SECRETS_MANAGER_SECRET_ID:"bad-secret"};
  const fakeClient={send:async()=>({SecretString:"not json"})};
  await assert.rejects(()=>hydrateSecretsFromAws(env,fakeClient),/not a JSON object/);
});

test("rejects a secret with no SecretString at all",async()=>{
  const env={AWS_SECRETS_MANAGER_SECRET_ID:"binary-secret"};
  const fakeClient={send:async()=>({})};
  await assert.rejects(()=>hydrateSecretsFromAws(env,fakeClient),/has no SecretString/);
});
