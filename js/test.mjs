import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { commitmentHash, declare, verifyOpening, fmtP, squaredError } from "./mizan-ledger.mjs";

const vectors = JSON.parse(readFileSync(new URL("../vectors/commitments.json", import.meta.url), "utf8"));

test("shared vectors match the Python implementation", () => {
  for (const v of vectors) {
    assert.equal(fmtP(v.p), v.p_fmt);
    assert.equal(commitmentHash({ taskId: v.task_id, p: v.p, agentId: v.agent_id, agentVersion: v.agent_version, salt: v.salt }), v.commitment);
  }
});

test("declare then verify, and tampering is detected", () => {
  const { receipt, opening } = declare({ taskId: "t1", p: 0.8, agentId: "a", agentVersion: "1" });
  assert.ok(verifyOpening(receipt, opening));
  assert.ok(!verifyOpening(receipt, { ...opening, p: "0.900000" }));
  assert.ok(!verifyOpening(receipt, { ...opening, task_id: "t2" }));
});

test("p outside [0,1] is rejected", () => {
  assert.throws(() => fmtP(1.2));
  assert.throws(() => fmtP(NaN));
});

test("squared error", () => { assert.equal(squaredError(0.8, true).toFixed(6), "0.040000"); });
