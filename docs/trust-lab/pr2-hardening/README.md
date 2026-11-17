# Trust Lab: scoring additions and hardening

Written by an AI agent (QANTS bot). Approved in scope by the founder; review before merge.

Some ideas here came from an external AI-written draft ("qants_trust_lab" MVP 0.1). Its code was
not copied. The useful ideas were re-implemented inside this package, and the holes found when
probing that draft were turned into tests against this codebase. There is still one package and
one records format (`receipts.jsonl` / `resolutions.jsonl` for the calibration ledger and
`events.jsonl` for PAL).

## Scoring (`metrics.py`, `core.py`)

| Item | Where | Note |
|---|---|---|
| ECE, 10 equal-width bins | `metrics.ece` (already present) | now has known-value tests; ECE is biased upward for small n |
| Bootstrap 95% CI for Brier | `metrics.brier_interval(pairs, reps, seed)` (already present) | deterministic per seed; test proves same seed gives the same interval |
| Rating rule | `metrics.rating(n_resolved, min_n=50)`, `summary()["rating"]` | `unrated` / `insufficient_data` below 50 resolved answers; PAL `prediction_accuracy` threshold is now 50 |
| Honest counts | `n_declared`, `n_resolved`, `n_pending` in `Ledger.summary()` and `verify_ledger_dir()` | old keys `declared/resolved/pending` kept |
| Fair baseline | `metrics.brier_prior_baseline` | rolling base rate of strictly earlier resolved items (0.5 for the first). The in-sample best constant is kept only as `brier_base_rate_hindsight`, labelled as hindsight. `beats_prior_baseline` is `None` until the agent is rated |

## Hardening

| Hole (found in the external draft) | Status here | Test |
|---|---|---|
| Reserved prefix bypass by case or spaces; `mztest-` not reserved | `identity.py`: trim + casefold, reserve `qants-`, `mztest-` and exact QANTS ids for external agents (same rule as the hosted API). PAL `identity(..., operator_type=)` enforces it; `verify_pal` flags a forged external identity | `test_reserved_*`, `test_pal_identity_refuses_reserved_for_external` |
| One agent using another agent's permission | PAL already scoped grants per agent. New: an attempt may cite `grant_seq`; a foreign grant is refused as `foreign_permission` (deny + warning with note) | `test_agent_cannot_use_another_agents_permission`, `test_verify_rejects_forged_cross_agent_attempt` |
| Event accepted without a permission | PAL already denied it (deny + warning with a note, per the founder's rule); regression tests added | `test_action_without_permission_*`, `test_verify_rejects_claim_injected_without_permission` |
| Revoke erased history | Revoke is a new event. New: as-of queries (`permissions_as_of`, `permission_history`); grants and revocations only count from their own event time | `test_revoke_appends_and_history_is_queryable_as_of` |
| Plain word "secret" flagged | `safety.find_secrets` matches real credential shapes only. PAL refuses to write them; `Ledger.declare` refuses them in the public agent_id/version | `test_secret_word_is_not_a_false_positive`, `test_real_token_patterns_are_caught` |
| Verifier trusted a self-submitted permission snapshot | `verify_pal(events, authority=...)` replays decisions and claims against an independent permission ledger and reports self-issued or omitted permission events | `test_verifier_uses_independent_permission_ledger_not_self_submitted`, `test_verifier_flags_revocation_omitted_by_submitter` |
| Mutable verification status inside the hashed body | PAL anchor events are immutable observations; the current status is derived by `proof_status()`; no `verification_status` field is hashed | `test_proof_status_is_appended_not_mutated` |
| Timestamps compared as strings | All comparisons use parsed, offset-aware datetimes; a timestamp without an offset is refused | `test_parse_compares_instants_not_strings`, `test_expiry_with_mixed_offsets` |

## Limits (unchanged)

- Truncating the tail of `events.jsonl` still verifies on its own; publishing or anchoring the head is what proves length (planned `.head` guard, PR 4).
- The secret filter is a pattern list; it cannot catch every credential format.
- Reserved names are a name rule, not proof of who runs an agent.
- PAL only sees actions routed through it.
