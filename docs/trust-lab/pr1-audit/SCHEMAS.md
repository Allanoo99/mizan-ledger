# PR 1: Proposed schemas (draft for review, nothing implemented)

Design rule: **extend, do not replace.** No second database. Existing records (`mizan-ledger/1` receipts and resolutions in `seed_runs/`, `mizan-pal/0.1` events, options-lab v1 lines) are never rewritten or re-hashed. v1.1 is an additive layer.

Canonical JSON for all new records: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` (same as `core.canonical_json`). Hash = SHA-256, lowercase hex. Time = UTC ISO-8601 with milliseconds and `Z`.

---

## 1. Mizan Event v1.1 (`schema: "mizan-event/1.1"`)

### 1.1 Fields
| Field | Type | Required in v1.1 | Meaning |
|---|---|---|---|
| `schema` | string | yes | `"mizan-event/1.1"` |
| `seq` | int | yes | 1..n, contiguous per log |
| `prev` | hex64 | yes | `event_hash` of seq-1, genesis = 64 zeros (same as core/PAL) |
| `event_id` | string | yes | `"<log_id>:<seq>"`. Deterministic, so it cannot be chosen to collide |
| `agent_id` | string | yes | must exist in Agent Identity registry |
| `agent_version` | string | yes | must equal a registered version of that agent |
| `event_type` | enum | yes | `identity, approve, grant, revoke, attempt, deny, warning, violation, claim, resolve, anchor` (PAL set, unchanged) |
| `event_timestamp` | ts | yes | when the agent says it happened (agent-claimed) |
| `received_timestamp` | ts | yes | when the ledger accepted it (ledger clock). Must be ≥ previous event's `received_timestamp`. Ordering and the backdating check use this field, never `event_timestamp` |
| `payload_hash` | hex64 | yes | SHA-256 of canonical JSON of `body` |
| `body` | object | yes | type-specific payload (PAL bodies, unchanged) |
| `policy_hash` | hex64 | yes | PAL `POLICY_HASH` in force |
| `permission_snapshot` | object | **optional in v1.1, required in v2** | `{state_hash, evaluated_at, effective: {perm: {grant_seq, approval_seq, tools?}}}`. `state_hash` uses the PAL formula `SHA-256(canonical_json({agent_id, effective, policy_hash, schema}))` |
| `approval_reference` | string \| null | optional in v1.1 | `event_id` of the `approve` event that authorizes this action, or null for event types that need no approval (`identity`, `anchor`) |
| `evidence_reference` | object \| null | optional in v1.1 | see 1.3. Evidence for the claim's **outcome** or for the **timestamp**, never mixed in one object |
| `verification_status` | enum | yes (default `UNVERIFIED`) | see 1.4 |
| `legacy_ref` | object \| null | optional | for wrapped legacy records: `{schema, file, seq, hash_field, hash}` |
| `event_hash` | hex64 | yes | SHA-256 of canonical JSON of the event without `event_hash` |

Rules:
- An event is rejected before append (not written as valid) if: agent not registered, version mismatch, `payload_hash` wrong, or the required permission is revoked/expired/not granted at `received_timestamp`. A refused request is still logged as `deny` + `warning` (note required) or `deny` + critical `violation` (closed permission), as PAL does today.
- `verification_status` and `evidence_reference` may only become stronger by **appending a new event** (e.g. an `anchor` or `resolve` event referencing the earlier `event_id`). The original event is never edited.

### 1.2 Backward compatibility
| Legacy record | How v1.1 reads it | Re-hashed? |
|---|---|---|
| `mizan-ledger/1` receipt (`seed_runs/*/receipts.jsonl`) | Projected as `event_type: claim`, `event_timestamp = received_timestamp = declared_at`, `payload_hash = commitment`, `verification_status = HASH_ONLY`, `legacy_ref = {schema:"mizan-ledger/1", file:"receipts.jsonl", seq, hash_field:"receipt_hash", hash}` | No |
| `mizan-ledger/1` resolution | `event_type: resolve`, `verification_status = OUTCOME_RECORDED` (opening verified by `verify_opening`) | No |
| `mizan-pal/0.1` event | Fields map 1:1: `type→event_type`, `ts→event_timestamp` and `received_timestamp`, claim `permission_state_hash→permission_snapshot.state_hash` | No |
| options lab v1 line | Read-only projection: `declaration→claim`, `outcome→resolve`, `legacy_ref.hash_field="line_hash"`. Its canonical form uses `ensure_ascii=True`; the verifier must use that dialect for these lines | No |

Projection is a **view** computed by the verifier. The legacy file stays the source of truth and keeps its own verifier.

### 1.3 `evidence_reference`
```json
{"kind": "timestamp", "method": "opentimestamps", "target_hash": "<hex64>", "proof_uri": "...ots", "state": "OTS_SUBMITTED", "checked_at": "...", "bitcoin_block": null}
{"kind": "timestamp", "method": "ethereum-sepolia-calldata", "target_hash": "<hex64>", "tx": "0x...", "block": 12132674, "network": "sepolia (testnet)"}
{"kind": "outcome", "method": "test_result | public_api | manual_resolver", "uri": "...", "resolver": "...", "sha256": "<hex64 of the evidence file>"}
```
Proof-engine states (founder's list, used only when `kind = timestamp`):
`HASH_CREATED → OTS_SUBMITTED → BITCOIN_PENDING → BITCOIN_CONFIRMED`, or `VERIFICATION_FAILED` from any state.
Mapping from PAL anchor status: `pending` = `OTS_SUBMITTED` or `BITCOIN_PENDING`, `verified` = `BITCOIN_CONFIRMED`, `failed` = `VERIFICATION_FAILED`.
A Sepolia anchor is a separate method, labelled testnet, and never reported as a Bitcoin state.

### 1.4 `verification_status` (claim vs proof kept apart)
| Value | Means | Does NOT mean |
|---|---|---|
| `UNVERIFIED` | recorded, chain not yet checked | anything |
| `HASH_ONLY` | chain + payload hash recompute | content is true, agent was authorized, action happened |
| `AUTHZ_REPLAYED` | permission snapshot replays to the same decision | the action was performed or was harmless |
| `OUTCOME_RECORDED` | an outcome was recorded by a named resolver with evidence | the resolver is independent (check `evidence_reference.method`) |
| `TIMESTAMP_ANCHORED` | a later anchor event covers this event with `BITCOIN_CONFIRMED` (or testnet anchor, labelled) | the claim is true |
| `FAILED` | any check failed | n/a |
A record can hold several facts at once, so the verifier output is a **set of booleans** (`integrity`, `authorization_replayed`, `outcome_evidenced`, `timestamp_state`), and `verification_status` is only the summary label. The four trust indicators are never folded into it.

---

## 2. Agent Identity v1 (`schema: "qants-agent-identity/1"`)
| Field | Type | Notes |
|---|---|---|
| `agent_id` | string | regex `^[A-Za-z0-9][A-Za-z0-9._:@-]{2,79}$` (same as `AGENT_RE` in `W/src/mizan-core.js`) |
| `operator_type` | `internal` \| `external` | **`internal` iff** the id is in the QANTS-operated list or starts with a reserved prefix. Reserved prefixes: `qants-`, `mztest-`. External registration of a reserved prefix is refused (HTTP 400 `reserved_agent_id`) |
| `owner` | object | `{display_name, contact_hash}`; contact stored as a hash for external owners, never public plaintext |
| `agent_version` | string | immutable once registered; a new version is a new identity record |
| `model` | string \| null | e.g. "rule-based" for seeds (seed page says they are rule-based programs) |
| `model_version` | string \| null | |
| `data_sources` | string[] | declared, not verified |
| `code_fingerprint` | hex64 \| null | SHA-256 of a declared source artefact (wheel, git tree hash, container digest). Self-declared unless reproduced |
| `fingerprint_method` | string \| null | how it was computed |
| `registered_at` | ts | ledger clock |
| `identity_hash` | hex64 | SHA-256 of the record without this field |
| `external_credentials` | object[] | optional links, e.g. APIR Trust Passport URL. Recorded as a reference, not verified by QANTS |

Rules: internal agents never appear in community/external statistics. Every aggregate returns `internal` and `external` counts separately.

---

## 3. Permission Registry v1 (`schema: "qants-permission/1"`)
A registry row is a **view** derived by replaying PAL `approve`/`grant`/`revoke` events. It is not a second table of truth.

| Field | Source in PAL | Notes |
|---|---|---|
| `agent_id` | event `agent_id` | |
| `permission_id` | `"<log_id>:grant:<grant_seq>"` | stable, deterministic |
| `scope` | grant `permission` (+ level) | dotted name, see 3.1 |
| `level` | `analysis` \| `signal` \| `execution` | |
| `granted_by` | grant `granted_by` | |
| `approval_reference` | `approve` event_id (`approval_seq`) | |
| `approval_type` | approve `approval_type` | `human_explicit`, `human_standing`, `delegated` |
| `granted_at` | grant event ts | |
| `expires_at` | approve `expires_at` | required for execution-level grants |
| `status` | derived: `active`, `revoked`, `expired` | never stored as a mutable flag |
| `allowlist` | grant `tools` | required for `use_allowed_tools`, `modify_files`, `exec_commands` |
| `policy_version` | `policy_id` + `POLICY_HASH` | |

### 3.1 Founder's decisions encoded (hybrid model C)
- Mizan sets hard bounds; users grant inside them. Default deny.
- Levels Analysis / Signal / Execution are separate. Approving one never implies another.
- **Permanently closed** (cannot be approved, granted or performed by anyone): `execution.external_action`, `execution.financial_order`. Requesting them = `deny` + critical `violation` naming the actor.
- **Grantable with explicit human approval + allowlist:** `execution.modify_files`, `execution.exec_commands` (`human_explicit` only, expiry required).
- **Signals** (`signal.commit_reveal`, `signal.issue_signal`, `signal.paper_trade` in testnet tQNT only) may use a standing human approval (`human_standing`).
- **Not-granted attempt** = `deny` + `warning` with a required non-empty note.
- **Four trust metrics stay separate** (Prediction Accuracy, Permission Compliance, Transparency, Historical Reliability). No combined score, anywhere.

### 3.2 Scope names for MVP 0.1
| Founder's MVP scope | Status in MVP 0.1 | Maps to PAL permission(s) |
|---|---|---|
| `analysis.readonly` | **the only grantable scope** | `read_data`, `analysis`, `predict` |
| `trading.execute` | rejected at API level (`403 scope_closed`) | `financial_order` (closed) |
| `money.transfer` | rejected at API level | `financial_order` (closed) |
| `production.deploy` | rejected at API level | `external_action` (closed) |
| any other scope | rejected in MVP 0.1 (`403 scope_not_in_mvp`) | Signal and local Execution scopes exist in PAL but stay off in MVP 0.1 |

Rejection happens in the request handler and in the ledger writer (two layers), not only in the UI.
