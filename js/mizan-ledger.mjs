// Tiny JS shim: commitment hashing + offline opening verification. Uses node:crypto only.
// Mirrors the Python implementation byte for byte (shared vectors in ../vectors/commitments.json).
import { createHash, randomBytes } from "node:crypto";

export const SCHEMA = "mizan-ledger/1";

export function fmtP(p) {
  const x = Number(p);
  if (!Number.isFinite(x) || x < 0 || x > 1) throw new Error("p_success must be a number in [0, 1]");
  return x.toFixed(6);
}

// Strings only, flat object: sorted keys, no whitespace.
export function canonicalJson(obj) {
  const out = {};
  for (const k of Object.keys(obj).sort()) out[k] = obj[k];
  return JSON.stringify(out);
}

export const sha256Hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

export function commitmentHash({ taskId, p, agentId, agentVersion = "unspecified", salt }) {
  return sha256Hex(canonicalJson({
    agent_id: agentId, agent_version: agentVersion, p: fmtP(p), salt, schema: SCHEMA, task_id: taskId,
  }));
}

// Create a commitment. Keep the returned `opening` private until the outcome is known.
export function declare({ taskId, p, agentId, agentVersion = "unspecified" }) {
  const salt = randomBytes(16).toString("hex");
  const commitment = commitmentHash({ taskId, p, agentId, agentVersion, salt });
  return {
    receipt: { schema: SCHEMA, agent_id: agentId, agent_version: agentVersion, commitment, declared_at: new Date().toISOString() },
    opening: { task_id: taskId, p: fmtP(p), salt },
  };
}

export function verifyOpening(receipt, opening) {
  try {
    return commitmentHash({ taskId: opening.task_id, p: Number(opening.p), agentId: receipt.agent_id,
      agentVersion: receipt.agent_version, salt: opening.salt }) === receipt.commitment;
  } catch { return false; }
}

export const squaredError = (p, outcome) => (Number(p) - (outcome ? 1 : 0)) ** 2;
