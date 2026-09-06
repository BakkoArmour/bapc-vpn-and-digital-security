import test from "node:test";
import assert from "node:assert/strict";
import {loadConfig} from "../../../src/config.js";

// loadConfig had no dedicated test at all before this — added alongside
// wiring OobController into production-server.ts, which needed two new
// fields (oobControllerUrl, oobSharedSecret) and a production-strictness
// check mirroring the existing control/event secret validation.

test("defaults oobControllerUrl and oobSharedSecret when unset",()=>{
  const config=loadConfig({});
  assert.equal(config.oobControllerUrl,"http://127.0.0.1:8181");
  assert.equal(config.oobSharedSecret,"development-oob-shared-secret-change-me");
});

// SAFE_APPLY_NODE_FAILURE_THRESHOLD had no wiring at all before
// SafeApplyService started verifying per-node acknowledgements — this pins
// down both the strict-by-default value and that it rejects an out-of-range
// override rather than silently clamping it.
test("defaults safeApplyNodeFailureThreshold to 0 (strictest) and accepts a real override",()=>{
  assert.equal(loadConfig({}).safeApplyNodeFailureThreshold,0);
  assert.equal(loadConfig({SAFE_APPLY_NODE_FAILURE_THRESHOLD:"0.25"}).safeApplyNodeFailureThreshold,0.25);
});

test("rejects a safeApplyNodeFailureThreshold outside 0-1",()=>{
  assert.throws(()=>loadConfig({SAFE_APPLY_NODE_FAILURE_THRESHOLD:"1.5"}),/between 0 and 1/);
});

test("production rejects a short or missing OOB_SHARED_SECRET even if the other secrets are fine",()=>{
  assert.throws(()=>loadConfig({
    NODE_ENV:"production",
    CONTROL_API_TOKEN_SECRET:"x".repeat(32),
    EVENT_SIGNING_SECRET:"y".repeat(32),
    OOB_SHARED_SECRET:"too-short"
  }),/at least 32 characters/);
});

test("production accepts a config with all three secrets long enough",()=>{
  const config=loadConfig({
    NODE_ENV:"production",
    CONTROL_API_TOKEN_SECRET:"x".repeat(32),
    EVENT_SIGNING_SECRET:"y".repeat(32),
    OOB_SHARED_SECRET:"z".repeat(32),
    OOB_CONTROLLER_URL:"http://oob-controller:8181",
    DIAGNOSTICS_SHARED_SECRET:"a".repeat(32),
    HEADQUARTERS_SHARED_SECRET:"b".repeat(32),
    CLOUD_DEPLOYMENT_SHARED_SECRET:"c".repeat(32),
    INTEGRATION_SHARED_SECRET:"d".repeat(32)
  });
  assert.equal(config.oobSharedSecret,"z".repeat(32));
  assert.equal(config.oobControllerUrl,"http://oob-controller:8181");
});
