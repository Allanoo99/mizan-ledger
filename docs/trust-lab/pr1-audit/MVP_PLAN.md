# PR 1: MVP 0.1 plan, PR-sized sequence

Ground rules (the founder's rules, unchanged):
- Work on a dedicated feature branch in `github.com/qants-labs/mizan-ledger` (proposed name `feature/trust-lab`). **No direct merge into `main`.** Merge only after the founder's explicit approval.
- **No GitHub Actions changes.** The repo has no `.github/` today; this plan does not add one. "Complete CI suite" = the local suites (`python3 -m pytest -q`, `node --test js/test.mjs`), run before every PR, results pasted into the PR body.
- Never bypass a failing test. Every PR lists changed files and remaining limits.
- The site worker is not on GitHub. Any worker change (HTTP routes, pages) is a separate step that needs the founder's deploy approval, a backup and a rollback file.
- No PyPI release without the founder's approval (PAL would be 0.2.0).
- Analysis/test only. No trading, money movement or production deploy permissions, ever.

| PR | Content | Tests (incl. negative security tests) | Depends on |
|---|---|---|---|
| **PR 1** | This audit: architecture map, gap analysis, schemas, API spec, threat model, plan. Docs only, under `docs/trust-lab/`. | none (docs) | — |
| **PR 2** | Identity + registration: `qants-agent-identity/1`, `operator_type`, reserved prefixes, `code_fingerprint`, local `qants init`, `qants agent register/inspect`. | register ok; duplicate version → refused; external `qants-x` / `mztest-x` → refused; internal agent never in external aggregates; fingerprint recompute | PR 1 review |
| **PR 3** | Permission registry: bring PAL `pal.py` (already 40 tests incl. inherited) into the branch; add dotted scopes and the registry view; MVP gate = `analysis.readonly` only. | expired grant does not authorize; revoked grant does not authorize; `trading.execute`, `money.transfer`, `production.deploy` → `scope_closed` + critical violation; not-granted → deny + warning with non-empty note; analysis approval does not imply signal; forged closed grant in file → verify fails | PR 2 |
| **PR 4** | Event ledger v1.1: `mizan-event/1.1` writer, `received_timestamp`, `payload_hash`, nonce, `evidence_reference`, `verification_status`, `.head` truncation guard; read-only projection of legacy records. | all `seed_runs/` still verify byte-for-byte unchanged; PAL demo log still verifies; tamper / truncate / reorder detected; replay nonce → refused; backdated `event_timestamp` → refused; payload hash mismatch → refused | PR 3 |
| **PR 5** | SDK + CLI: `qants submit`, `qants verify` (offline, multi-dialect). Python first. JS/TS SDK in a separate later PR. | verify passes on seeds, PAL demo, options-lab fixture; verify fails on each tamper fixture; verify makes zero network calls (socket blocked in test); no secrets in outputs (pattern scan) | PR 4 |
| **PR 6** | Sandbox + benchmark + scoring: `qants test`, dataset manifest hash, fixed seeds, baseline comparison, version-to-version paired comparison, sample-size gate. | same seed → same result; sandbox cannot reach production host or read keys; report refuses a superiority claim below the minimum n or without beating the constant baseline | PR 5 |
| **PR 7** | Proof engine: chain-head anchoring via OpenTimestamps; states `HASH_CREATED → OTS_SUBMITTED → BITCOIN_PENDING → BITCOIN_CONFIRMED` / `VERIFICATION_FAILED`; Sepolia kept as a separate, labelled testnet method. Timestamp evidence stored apart from performance evidence. | pending proof never reported as CONFIRMED; corrupted `.ots` → VERIFICATION_FAILED; hash of different bytes → FAILED; rebuilt chain fails against anchored head; network-free unit tests with recorded fixtures | PR 4 (founder decision D1) |
| **PR 8** | Independent verifier + Trust Passport: one report per agent (identity, permissions, four separate indicators, evidence states, limits). Static/JSON first; site page only after deploy approval. | internal/external split shown and counted separately; output wording never says "verified true"; four indicators never combined (adding violations leaves accuracy unchanged) | PR 5–7 |

### Bitcoin mainnet note
OpenTimestamps is free (public calendars; no fee paid by us) and anchors to **Bitcoin mainnet**. Today, QANTS anchors are on **Ethereum Sepolia testnet** (`public/cc/2026-W47/anchor_receipt.json`). One file (the W47 commitments) was also submitted to OTS, and the local `.ots` copy is still pending (4 calendar attestations, no Bitcoin attestation). Making OTS-on-mainnet the default for Trust Lab ledgers costs nothing but is a **founder decision** (D1), because it moves proofs from testnet-only to a mainnet chain.

### Success condition (from the directive)
A third-party developer can register an agent, connect with the SDK, submit a prediction, prove its authorization context, and independently verify the record. With the offline-first route this is reachable at the end of PR 5 (local), with timestamp proof at PR 7 and a public passport at PR 8.
