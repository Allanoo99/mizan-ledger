# QANTS Agent Trust Lab, PR 1: Audit + Schemas

Prepared 17 Nov 2026 (GMT+2) by an AI agent working for the founder. Docs only, on branch `feature/trust-lab` (no merge into `main`, no GitHub Actions). Paths starting with `/workspace/` refer to the operator's build machine; the site worker code is not in this repository.
Principle: *Trust must be demonstrated through evidence, not claimed through branding.*

## Files
| File | Contents |
|---|---|
| `ARCHITECTURE_MAP.md` | What exists now, with evidence paths, plus a mermaid diagram |
| `GAP_ANALYSIS.md` | The 12 tools mapped to exists / partial / missing |
| `SCHEMAS.md` | Mizan Event v1.1, Agent Identity v1, Permission Registry v1 |
| `API_SPEC.md` | 5 HTTP endpoints + `qants` CLI |
| `THREAT_MODEL.md` | STRIDE table with mitigations and tests |
| `MVP_PLAN.md` | PR 1 to PR 8 with negative security tests |

## Summary
- **Already strong:** `mizan-ledger` 0.1.1 (PyPI + `github.com/qants-labs/mizan-ledger`, 22 tests), PAL v0.1 prototype (0.2.0.dev0, 40 tests, unpublished), 3 seed agents with 170 declarations / 169 resolved (live `/seed-agents`, offline verify ok), metrics, offline verifiers, production passports.
- **Main gaps:** registration with owner/`operator_type`/fingerprint; `qants-` reservation at key issuance (fixed 17 Nov 2026); PAL not published or wired; no proof engine (ledgers are local-clock only, OTS used once and still pending in the local copy); no sandbox and no `qants` CLI; three hash-chain dialects to verify without rewriting.
- **Approach:** extend, do not replace. v1.1 is an additive layer and legacy records are read as projections, never re-hashed.

## Open decisions for the founder
| ID | Decision | Recommendation |
|---|---|---|
| D1 | OpenTimestamps on **Bitcoin mainnet** for chain heads | **Approved 17 Nov 2026** for chain-head hashes only; Sepolia stays a separate testnet method |
| D2 | Feature branch `feature/trust-lab` for PR 1 docs | **Approved 17 Nov 2026** (docs only, no Actions, no merge) |
| D3 | HTTP routes: build offline-first (SDK+CLI) and add `/v1/agents`, `/v1/events`, `/v1/verify` to the worker later, or use a separate prefix (e.g. `/lab/v1/`) | Offline-first; decide prefix before PR 8 |
| D4 | Fix the `qants-` reservation in production `POST /v1/keys` | **Approved and deployed 17 Nov 2026** |
| D5 | Scope naming: adopt dotted names (`analysis.readonly`, …) as the public names mapped onto PAL permissions | Yes, mapping in `SCHEMAS.md` §3.2 |
| D6 | Backdating window for `event_timestamp` (default proposed: 5 min future skew, 24 h past) | Confirm or change |
| D7 | Publish PAL as `mizan-ledger` 0.2.0 (PyPI) once PR 3 is merged | Later, separate approval |
| D8 | Pending from PAL review: local execution needs an explicit approval each time; an operator's breach does not lower the agent's own status | Confirm |
| D9 | JS/TS SDK timing (separate PR after PR 5) and whether to publish on npm | After PR 5 |

## Unknowns (not verified in this audit)
- Whether the W47 `.ots` proof can be upgraded to a Bitcoin attestation now (needs calendar calls; not run).
- Whether the QANTS APIR passport is searchable in the APIR registry.
- `code_fingerprint` reproducibility for seed agents (no build reproducibility check was run).
