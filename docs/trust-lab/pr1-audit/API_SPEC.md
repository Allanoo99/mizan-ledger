# PR 1: API and CLI specification, MVP 0.1 (draft, not implemented)

Scope: analysis/test only. No trading, no money movement, no production deploy. Testnet only where chains appear.

**Route placement (open decision D3).** The production worker already serves `/v1/status, /v1/keys, /v1/check, /v1/questions, /v1/passport/*, /v1/pool*, /v1/weekly*, /v1/compass, /v1/certificate*` (`/workspace/qants_site_worker/src/mizan-api.js`). The routes below are free today (no match in `src/`), but they live in the same namespace. Recommended: build MVP 0.1 **offline-first** (SDK + CLI + local ledger) and add the HTTP routes in a later PR, only with the founder's deploy approval.

Common rules
- JSON in and out, `content-type: application/json`. Errors: `{"error":{"code","message"}}`.
- Auth for writes: per-agent API key (hashed at rest, as `api_keys` in the existing Durable Object). Keys never appear in logs or responses after issuance.
- Every write response includes `received_timestamp` (server clock) and `event_hash`.
- Rate limits reuse the existing per-key / per-IP-hash pattern.

---

## POST /v1/agents/register
Request:
```json
{"agent_id":"my-agent","agent_version":"1.0.0","owner":{"display_name":"Example Lab","contact":"ops@example.com"},
 "model":"gpt-x or rule-based","model_version":"…","data_sources":["…"],
 "code_fingerprint":"<hex64>","fingerprint_method":"sha256(wheel)"}
```
Response `201`:
```json
{"agent_id":"my-agent","agent_version":"1.0.0","operator_type":"external","code_fingerprint":"<hex64>",
 "identity_hash":"<hex64>","event_id":"<log>:1","received_timestamp":"…Z","api_key":"(shown once)"}
```
Errors: `400 invalid_agent_id`, `400 reserved_agent_id` (`qants-`, `mztest-` for external callers), `409 agent_version_exists` (versions are immutable), `409 agent_id_taken` (other owner), `429 rate_limited`.
Contact is stored hashed; only `display_name` is public.

## POST /v1/events/submit
Request:
```json
{"agent_id":"my-agent","agent_version":"1.0.0","event_type":"claim","event_timestamp":"…Z",
 "body":{"prediction":"…","p":0.72,"data_sources":["…"],"method_version":"m1","task_id":"t-1","commitment":"<hex64|null>"},
 "payload_hash":"<sha256(canonical_json(body))>","nonce":"<128-bit hex>"}
```
Accepted only if **all** hold:
1. agent registered and key matches agent;
2. `agent_version` equals a registered version;
3. `payload_hash` recomputes;
4. the scope needed for `event_type` (`claim` needs `analysis.readonly`) is active at `received_timestamp` (not revoked, not expired);
5. `nonce` not seen before for this agent (replay guard);
6. `event_timestamp` ≤ `received_timestamp` + 5 min skew, and not older than a configured window (default 24 h, open decision D6).

Response `201`: `{"event_id","event_hash","prev","received_timestamp","permission_snapshot":{"state_hash",…},"approval_reference","verification_status":"HASH_ONLY"}`.
Refusals (event not written as valid; a `deny` is logged):
- `403 permission_not_granted` / `permission_revoked` / `permission_expired` + a `warning` with note.
- `403 scope_closed` for anything mapping to `trading.execute`, `money.transfer`, `production.deploy` (+ critical `violation`).
- `403 scope_not_in_mvp`, `400 payload_hash_mismatch`, `400 version_mismatch`, `409 replay`, `400 timestamp_out_of_window`.

## GET /v1/agents/{agent_id}
Returns identity (all versions), `operator_type`, active permissions (registry view), and the **four indicators separately**, each with `n`, `threshold`, `insufficient_data`. No combined score.

## GET /v1/agents/{agent_id}/events?after_seq=&limit=
Returns the agent's events in order with `seq, prev, event_hash, payload_hash` and public bodies. Claim text that is private is returned as hash only. Enough to re-verify the chain offline.

## GET /v1/verify/{event_id}
```json
{"event_id":"…","payload_hash":"…","prev_hash":"…","event_hash":"…",
 "checks":{"integrity":true,"chain_recomputed":true,"authorization_replayed":true,"outcome_evidenced":false,"timestamp_state":"OTS_SUBMITTED"},
 "verification_status":"AUTHZ_REPLAYED",
 "evidence_reference":{"kind":"timestamp","method":"opentimestamps","proof_uri":"…","state":"OTS_SUBMITTED"} ,
 "limits":["A hash proves integrity, not that the claim is true.","Authorization replay does not prove the action was performed."]}
```
`evidence_reference` is `null` when no anchor covers the event. The server answer is a convenience; `qants verify` must reach the same result offline.

---

## CLI (`qants`, Python, ships inside the SDK package)
| Command | Does | Network |
|---|---|---|
| `qants init [dir]` | creates `qants.toml`, `ledger/`, `private/` (mode 700), `.gitignore` entry for `private/` | none |
| `qants agent register --id --version [--fingerprint auto]` | writes an `identity` event locally; with `--remote` calls `POST /v1/agents/register` | optional |
| `qants agent inspect <id>` | prints identity, active permissions, four indicators | local; `--remote` optional |
| `qants test <suite>` | runs a benchmark suite in the sandbox (no production URLs, no keys, no money) and writes claims + resolutions | sandbox only |
| `qants submit <event.json>` | validates locally (schema, payload hash, permission) then appends or posts | optional |
| `qants verify <dir|file>` | **offline**: detects dialect (mizan-ledger/1, mizan-pal/0.1, mizan-event/1.1, options lab v1), recomputes chains, replays permissions, checks openings, re-scores, checks `.ots` with the local `ots` client if present (otherwise reports `timestamp_state: not_checked`) | none required |
Exit codes: 0 ok, 1 verification failed, 2 usage error. `verify` never contacts QANTS servers.
