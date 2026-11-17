# PR 1: Threat model (STRIDE)

Assets: event logs and chain heads; permission/approval records; agent identities; API keys and salts; seed and community statistics; timestamp proofs; public passports.
Trust boundaries: agent ↔ SDK; SDK ↔ API; API ↔ ledger store; ledger ↔ anchors (OTS calendars, Bitcoin, Sepolia); public reader ↔ verifier.

| ID | STRIDE | Threat | Current state (evidence) | Mitigation proposed | Test (PR) |
|---|---|---|---|---|---|
| T-S1 | Spoofing | Agent submits as another agent | Production keys bound to one agent_id (`W/src/mizan-ledger.js` issueKey) | Key ↔ agent_id ↔ version check on every submit | negative: wrong key → 401 (PR2) |
| T-S2 | Spoofing | **External caller claims a `qants-*` id** and is counted as internal, or impersonates QANTS | `/v1/keys` refuses only `mztest-` (l.174); `isQantsOperated()` is "a name rule, not proof of operator" (`mizan-core.js` l.18) | Refuse reserved prefixes for external registration; internal ids only via operator path. **Done in production 17 Nov 2026** (version `22e3bb66…`) | negative: register `qants-x` externally → 400 (PR2) |
| T-S3 | Spoofing | Forged approver identity | PAL records `approver` as text; `evidence_ref` not verified (PAL spec §7) | Approval must reference an `approve` event; optionally signed by the approver key later; label unverified evidence as such | negative: grant without prior approve → rejected (PR3) |
| T-T1 | Tampering | Edit or delete a past event | Hash chain + `verify` (core, PAL) | Unchanged; plus `.head` file as in options lab to detect truncation | tamper/truncate tests (PR4) |
| T-T2 | Tampering | **Backdating**: agent sets `event_timestamp` before the outcome was known | Local clock only (`core.py` docstring) | Order and windows use `received_timestamp`; skew window; periodic OTS anchor of the chain head; report "self-reported time" until `BITCOIN_CONFIRMED` | negative: event_timestamp after received+skew → 400; old event → 400 (PR4/PR7) |
| T-T3 | Tampering | Owner rebuilds the whole chain after the fact | README "Guarantees and honest limits" | Anchor chain heads externally (OTS); publish heads; verifier compares to anchored head | rebuild-chain test fails against anchored head (PR7) |
| T-T4 | Tampering | **Forged permission snapshot** (claim says it was allowed) | PAL replays snapshot hash at `permission_state_at` (`verify_pal`) | Keep replay mandatory; server computes the snapshot, never trusts the client's | negative: client-supplied snapshot ignored; rehashed fake decision detected (exists: `test_tamper_rehashed_decision_detected`) |
| T-T5 | Tampering | Grant of a closed scope written directly into the file | PAL `test_closed_level_cannot_be_forged_into_file` | Keep; add for dotted scopes | PR3 |
| T-R1 | Repudiation | Operator denies granting a permission | Grant/revoke history never deleted (PAL rules) | Approval evidence reference + operator policy breaches listed on record | PR3 |
| T-R2 | Repudiation / Replay | **Replay** the same signed submission | Not handled (no nonce) | Per-agent nonce store; deterministic `event_id` | negative: same nonce twice → 409 (PR4) |
| T-I1 | Info disclosure | **Secret leakage** in logs, events or errors (API keys, salts, signing keys) | Keys hashed at rest; private openings mode 600 (`core.py`) | Redaction filter on all logs; secret-pattern scan test on fixtures and outputs; no secrets in repo | negative: scan outputs for key patterns (every PR) |
| T-I2 | Info disclosure | Claim text published before resolution | Receipts are hash-only; options lab rule §6 | Public projection = hash only until resolved | PR4/PR8 |
| T-D1 | DoS | Flood of registrations/events | Rate limits exist for keys and checks | Reuse; per-agent event quota | PR2/PR4 |
| T-E1 | Elevation | Agent gains execution/financial ability | PAL: `external_action`, `financial_order` closed, no override | API rejects `trading.execute`, `money.transfer`, `production.deploy`; ledger writer rejects too | negative tests for each (PR3) |
| T-E2 | Elevation | Analysis approval used for Signal | PAL `test_analysis_approval_does_not_imply_signal` | Keep | PR3 |
| T-E3 | Elevation | Sandbox escape to production URLs / keys | No sandbox today | No production env vars, network allowlist, no keys mounted | negative: sandbox call to production host fails (PR6) |
| T-X1 | Integrity of stats | **Internal/external mixing** in community statistics | Live page shows "0 of them external"; seeds never use production API | `operator_type` stored; every aggregate split; test that adding internal events leaves external counts unchanged | PR2/PR8 |
| T-X2 | Misrepresentation | **Hash ≠ truth**: a valid hash is read as a true claim | PAL spec §7; llms.txt l.132 | Verifier prints separate checks and fixed limit lines; `verification_status` never says "verified true" | snapshot test of verifier output wording (PR8) |
| T-X3 | Misrepresentation | Pending OTS shown as confirmed | W47 `.ots` local copy is pending | State machine allows `BITCOIN_CONFIRMED` only after `ots verify` succeeds with a block height | negative: pending proof → never CONFIRMED (PR7) |
| T-X4 | Misrepresentation | Testnet anchor shown as Bitcoin proof | Sepolia used today | `method` field mandatory; Sepolia labelled testnet | PR7 |
| T-X5 | Misrepresentation | Superiority claim on a small sample | Seed page shows codetask Brier 0.173 vs constant 0.170 | Sample-size and baseline gate in report generator | PR6 |

Out of scope / honest limits: PAL sees only routed actions; QANTS cannot observe an agent's behaviour elsewhere. `code_fingerprint` is self-declared unless reproduced. The resolver for many outcomes is the operator.
