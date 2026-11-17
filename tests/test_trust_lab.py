"""Trust Lab hardening: ported scoring ideas + regression tests for holes found in an external draft."""
import copy
import json
import random

import pytest

from mizan_ledger import Ledger, metrics
from mizan_ledger.core import GENESIS, LedgerError, _chain_hash, _parse, canonical_json, verify_ledger_dir
from mizan_ledger.identity import check_agent_id, is_reserved_agent_id, normalize_agent_id, ReservedAgentIdError
from mizan_ledger.pal import (PALError, PermissionLedger, permission_history, permissions_as_of, proof_status,
                              verify_pal)
from mizan_ledger.safety import find_secrets


def clock(start="2026-11-17T10:00:00"):
    state = {"i": 0}
    def f():
        state["i"] += 1
        m, s = divmod(state["i"], 60)
        return f"2026-11-17T10:{m:02d}:{s:02d}.000Z"
    return f


def new_pal(tmp_path, name="pal"):
    return PermissionLedger(tmp_path / name, clock=clock())


def grant_analysis(led, agent, perms=("read_data", "analysis", "predict")):
    ap = led.approve(agent, "operator", "human_explicit", ["analysis"], list(perms))
    return ap, {p: led.grant(agent, p, ap["seq"], "operator") for p in perms}


def rechain(events):
    """Re-hash a tampered event list so the chain itself is internally consistent (a forger's best effort)."""
    prev = GENESIS
    out = []
    for e in events:
        e = dict(e); e["prev"] = prev
        e["event_hash"] = _chain_hash(e, "event_hash")
        prev = e["event_hash"]; out.append(e)
    return out


# ------------------------------------------------------------------ scoring (ported ideas)
def test_ece_known_values():
    assert metrics.ece([(0.8, 1)] * 8 + [(0.8, 0)] * 2) == pytest.approx(0.0)
    assert metrics.ece([(0.9, 0)] * 10) == pytest.approx(0.9)
    # two bins: 0.2 (freq 0.5) and 0.7 (freq 1.0) -> 0.5*0.3 + 0.5*0.3
    assert metrics.ece([(0.2, 1), (0.2, 0), (0.7, 1), (0.7, 1)]) == pytest.approx(0.3)
    assert metrics.ece([(1.0, 1)]) == pytest.approx(0.0)   # p == 1.0 lands in the last bin


def test_brier_bootstrap_ci_is_deterministic_and_seeded():
    rng = random.Random(1)
    pairs = [(round(rng.random(), 3), rng.random() < 0.6) for _ in range(80)]
    a = metrics.brier_interval(pairs, seed=42)
    b = metrics.brier_interval(pairs, seed=42)
    c = metrics.brier_interval(pairs, seed=43)
    assert a == b
    assert a["ci95"] != c["ci95"]
    lo, hi = a["ci95"]
    assert lo <= a["brier"] <= hi and "seed 42" in a["method"]
    assert metrics.brier_interval([(0.5, 1)])["ci95"] == [None, None]


@pytest.mark.parametrize("n,status", [(0, "unrated"), (49, "unrated"), (50, "rated"), (51, "rated")])
def test_rating_rule_50(n, status):
    r = metrics.rating(n)
    assert r["status"] == status and r["rated"] is (status == "rated") and r["min_n"] == 50
    assert (r["reason"] == "insufficient_data") is (status == "unrated")


def test_summary_unrated_below_50_and_no_baseline_claim():
    s = metrics.summarize([(0.9, 1)] * 49)
    assert s["rating"]["status"] == "unrated" and s["beats_prior_baseline"] is None
    s = metrics.summarize([(0.9, 1), (0.1, 0)] * 25)
    assert s["rating"]["status"] == "rated" and s["beats_prior_baseline"] is True
    s = metrics.summarize([(0.1, 1), (0.9, 0)] * 25)
    assert s["beats_prior_baseline"] is False


def test_prior_baseline_uses_only_strictly_earlier_items():
    pairs = [(0.5, 1), (0.5, 1), (0.5, 0), (0.5, 1)]
    # forecasts: prior 0.5, then 1/1, 2/2, 2/3
    want = ((0.5 - 1) ** 2 + (1 - 1) ** 2 + (1 - 0) ** 2 + (2 / 3 - 1) ** 2) / 4
    assert metrics.brier_prior_baseline(pairs)["brier"] == pytest.approx(want)
    # changing a LATER outcome never changes the baseline forecast for an EARLIER item
    first3 = metrics.brier_prior_baseline(pairs[:3])["brier"] * 3
    alt = metrics.brier_prior_baseline(pairs[:3] + [(0.5, 0)])["brier"] * 4
    assert alt - first3 == pytest.approx((2 / 3) ** 2)
    s = metrics.summarize(pairs)
    assert s["brier_prior_baseline"] == pytest.approx(want)
    assert "hindsight" in s["brier_base_rate_hindsight_note"]


def test_pending_is_reported_never_hidden(tmp_path):
    led = Ledger(tmp_path / "l", clock=clock())
    for i in range(5): led.declare(f"t{i}", 0.7, "a1")
    led.resolve("t0", True); led.resolve("t1", False)
    s = led.summary()
    assert (s["n_declared"], s["n_resolved"], s["n_pending"]) == (5, 2, 3)
    assert (s["declared"], s["resolved"], s["pending"]) == (5, 2, 3)   # old keys kept for compatibility
    assert s["coverage"] == pytest.approx(0.4) and s["rating"]["status"] == "unrated"
    v = verify_ledger_dir(tmp_path / "l")["summary"]
    assert (v["n_declared"], v["n_resolved"], v["n_pending"]) == (5, 2, 3)
    empty = Ledger(tmp_path / "e").summary()
    assert empty["n"] == 0 and empty["n_pending"] == 0 and empty["rating"]["status"] == "unrated"


def test_pal_indicator_reports_pending_and_rating(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    grant_analysis(led, "a1")
    cs = [led.claim("a1", f"q{i}", 0.6)["claim"] for i in range(4)]
    led.resolve(cs[0]["seq"], 1)
    acc = led.record("a1")["accountability"]["indicators"]["prediction_accuracy"]
    assert (acc["n_declared"], acc["n_resolved"], acc["n_pending"]) == (4, 1, 3)
    assert acc["threshold"] == 50 and acc["rating"]["status"] == "unrated"


# ------------------------------------------------------------------ reserved prefixes
@pytest.mark.parametrize("aid", ["qants-x", "QANTS-x", "  qants-x", "Qants-Bot ", "mztest-1", "MZTEST-1", " mztest-a",
                                 "qants-hybrid", "QANTS-HYBRID"])
def test_reserved_prefixes_trim_and_casefold(aid):
    assert is_reserved_agent_id(aid)
    with pytest.raises(ReservedAgentIdError):
        check_agent_id(aid, "external")
    assert check_agent_id(aid, "internal") == aid


@pytest.mark.parametrize("aid", ["my-agent", "qants", "qantsx", "acme-qants-1", "mztest", "test-mztest-1"])
def test_unreserved_names_allowed(aid):
    assert not is_reserved_agent_id(aid)
    assert check_agent_id(aid, "external") == aid


def test_normalize():
    assert normalize_agent_id("  QaNtS-A ") == "qants-a"


def test_pal_identity_refuses_reserved_for_external(tmp_path):
    led = new_pal(tmp_path)
    with pytest.raises(PALError): led.identity(" QANTS-evil", "m", "1", "sdk", "s")
    with pytest.raises(PALError): led.identity("MzTest-x", "m", "1", "sdk", "s", operator_type="external")
    assert led.events() == []    # nothing written
    led.identity("qants-opt-a", "m", "1", "sdk", "s", operator_type="internal")
    with pytest.raises(PALError): led.identity("a1", "m", "1", "sdk", "s", operator_type="robot")
    assert verify_pal(led.events())["ok"]


def test_verify_flags_forged_external_identity_with_reserved_name(tmp_path):
    led = new_pal(tmp_path)
    led.identity("qants-opt-a", "m", "1", "sdk", "s", operator_type="internal")
    evs = copy.deepcopy(led.events())
    evs[0]["body"]["operator_type"] = "external"
    rep = verify_pal(rechain(evs))
    assert not rep["ok"] and any("reserved" in e for e in rep["errors"])


# ------------------------------------------------------------------ cross-agent permission use
def test_agent_cannot_use_another_agents_permission(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s"); led.identity("b2", "m", "1", "sdk", "s")
    _, ga = grant_analysis(led, "a1")
    r = led.attempt("b2", "predict", grant_seq=ga["predict"]["seq"])
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "foreign_permission" and r["warning"]["body"]["note"]
    r = led.attempt("b2", "predict")                       # no grant of its own either
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "not_granted"
    assert led.claim("b2", "x", 0.6)["claim"] is None
    with pytest.raises(PALError): led.revoke("b2", ga["predict"]["seq"], "operator")
    with pytest.raises(PALError): led.grant("b2", "predict", ga["predict"]["body"]["approval_seq"], "operator")
    assert led.attempt("a1", "predict", grant_seq=ga["predict"]["seq"])["allowed"]
    r = led.attempt("a1", "analysis", grant_seq=ga["predict"]["seq"])   # wrong permission for the action
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "permission_mismatch"
    assert verify_pal(led.events())["ok"]


def test_verify_rejects_forged_cross_agent_attempt(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s"); led.identity("b2", "m", "1", "sdk", "s")
    _, ga = grant_analysis(led, "a1")
    led.attempt("b2", "predict", grant_seq=ga["predict"]["seq"])
    evs = [e for e in copy.deepcopy(led.events()) if not (e["type"] in ("deny", "warning") and e["body"].get("attempt_seq"))]
    att = next(e for e in evs if e["type"] == "attempt")
    att["body"]["decision"] = "allowed"
    att["body"]["permission_state_hash"] = led.permissions_as_of("a1", att["body"]["evaluated_at"])["state_hash"]
    rep = verify_pal(rechain([dict(e, seq=i + 1) for i, e in enumerate(evs)]))
    assert not rep["ok"] and any("decision does not match replay" in e for e in rep["errors"])


# ------------------------------------------------------------------ authorization required
def test_action_without_permission_is_denied_with_warning_and_note(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    r = led.attempt("a1", "read_data")
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "not_granted"
    assert r["warning"]["body"]["note"].strip() and r["violation"] is None
    c = led.claim("a1", "x", 0.6)
    assert c["allowed"] is False and c["claim"] is None
    assert not any(e["type"] == "claim" for e in led.events())
    assert led.record("a1")["accountability"]["compliance"] == "COMPLIANT_WITH_WARNINGS"
    assert verify_pal(led.events())["ok"]


def test_verify_rejects_claim_injected_without_permission(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    evs = copy.deepcopy(led.events())
    fake = {"schema": evs[0]["schema"], "seq": 2, "prev": None, "ts": "2026-11-17T10:00:05.000Z", "type": "claim",
            "agent_id": "a1", "policy_hash": evs[0]["policy_hash"],
            "body": {"prediction": "x", "p": 0.6, "data_sources": [], "method_version": None, "model_version": None,
                     "task_id": None, "commitment": None, "permission_state_at": "2026-11-17T10:00:05.000Z",
                     "permission_state_hash": led.permissions_as_of("a1", "2026-11-17T10:00:05.000Z")["state_hash"],
                     "effective_permissions": ["predict"]}}
    rep = verify_pal(rechain(evs + [fake]))
    assert not rep["ok"] and any("without predict permission" in e for e in rep["errors"])


# ------------------------------------------------------------------ revocation is append-only, history as-of
def test_revoke_appends_and_history_is_queryable_as_of(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    _, g = grant_analysis(led, "a1")
    t_before = led.events()[-1]["ts"]
    before_bytes = (tmp_path / "pal" / "events.jsonl").read_text()
    rv = led.revoke("a1", g["predict"]["seq"], "operator", "test")
    after_bytes = (tmp_path / "pal" / "events.jsonl").read_text()
    assert after_bytes.startswith(before_bytes)                # nothing rewritten, only appended
    assert led.events()[g["predict"]["seq"] - 1] == g["predict"]   # the grant is still there, unchanged
    hist = led.permission_history("a1")
    assert [h["type"] for h in hist].count("grant") == 3 and [h["type"] for h in hist].count("revoke") == 1
    assert "predict" in led.permissions_as_of("a1", t_before)["effective"]
    assert "predict" not in led.permissions_as_of("a1", rv["ts"])["effective"]
    assert "predict" in permissions_as_of(led.events(), "a1", t_before)["effective"]
    with pytest.raises(PALError): led.revoke("a1", g["predict"]["seq"], "operator")   # no double revoke
    assert led.attempt("a1", "predict")["deny"]["body"]["reason"] == "revoked"
    assert verify_pal(led.events())["ok"]


def test_deleting_a_grant_breaks_verification(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    _, g = grant_analysis(led, "a1")
    evs = [e for e in led.events() if e["seq"] != g["read_data"]["seq"]]   # a grant in the middle of the chain
    assert not verify_pal(evs)["ok"]


# ------------------------------------------------------------------ secret filter
@pytest.mark.parametrize("text", ["The secret to good calibration is honesty.", "secret", "my secret plan",
                                  "token economy", "password reset flow", "Secret sauce: base rates"])
def test_secret_word_is_not_a_false_positive(text):
    assert find_secrets(text) == []


@pytest.mark.parametrize("text", ["ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
                                  "pypi-" + "AgEIcHlwaS5vcmcCJGZh" * 3,
                                  "sk-proj-" + "abcDEF123456ghiJKL789012",
                                  "AKIA" + "ABCDEFGHIJ123456",
                                  "-----BEGIN RSA PRIVATE KEY-----",
                                  "api_key=" + "f3a9c1d2e4b5a6978877",
                                  '{"client_secret": "' + "Zx9Yw8Vu7Ts6Rq5Po4" + '"}',
                                  "Authorization: Bearer " + "abcdef0123456789ABCDEF.xyz"])
def test_real_token_patterns_are_caught(text):
    assert find_secrets(text)


def test_pal_and_ledger_refuse_secrets_but_accept_the_word(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    grant_analysis(led, "a1")
    assert led.claim("a1", "The secret to good calibration is honesty", 0.6)["claim"]
    n = len(led.events())
    with pytest.raises(PALError):
        led.claim("a1", {"note": "token=" + "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}, 0.6)
    # the predict attempt was logged, but no claim containing the token was written
    assert not any("ghp_" in json.dumps(e) for e in led.events()) and len(led.events()) == n + 1
    l = Ledger(tmp_path / "l", clock=clock())
    l.declare("t", 0.5, "a1", version="secret-sauce-1")
    with pytest.raises(LedgerError): l.declare("t2", 0.5, "a1", version="sk-live-" + "abcdefghijklmnopqrstuv1234")


# ------------------------------------------------------------------ verifier: independent permission ledger
def _two_logs(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    _, g = grant_analysis(led, "a1", perms=("predict",))
    authority = copy.deepcopy(led.events())
    return led, g, authority


def test_verifier_uses_independent_permission_ledger_not_self_submitted(tmp_path):
    led, g, authority = _two_logs(tmp_path)
    # submitter forges an extra approve+grant for 'issue_signal' inside its own log and then uses it
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "events.jsonl").write_text("".join(canonical_json(e) + "\n" for e in authority))
    sub = PermissionLedger(tmp_path / "sub", clock=lambda: "2026-11-17T11:00:00.000Z")
    ap = sub.approve("a1", "operator", "human_explicit", ["analysis"], ["read_data"])   # self-issued, not in authority
    sub.grant("a1", "read_data", ap["seq"], "operator")
    assert sub.attempt("a1", "read_data")["allowed"]
    assert verify_pal(sub.events())["ok"]                           # self-consistent on its own ...
    rep = verify_pal(sub.events(), authority=authority)             # ... but not against the authority
    assert not rep["ok"]
    assert any("not found in the independent permission ledger" in e for e in rep["errors"])
    assert any("decision does not match replay" in e for e in rep["errors"])


def test_verifier_flags_revocation_omitted_by_submitter(tmp_path):
    led, g, _ = _two_logs(tmp_path)
    sub_events = copy.deepcopy(led.events())                         # submitter's copy stops here
    led.revoke("a1", g["predict"]["seq"], "operator", "operator revoked")
    authority = led.events()
    # submitter keeps acting as if predict were still granted, on a fork with later timestamps
    fork = new_pal(tmp_path, "fork")
    fork._events = sub_events; [fork._state.apply(e) for e in sub_events]
    fork._clock = lambda: "2026-11-17T11:00:00.000Z"
    assert fork.claim("a1", "x", 0.6)["claim"]
    rep = verify_pal(fork.events(), authority=authority)
    assert not rep["ok"]
    assert any("revoke missing from the submitted log" in e for e in rep["errors"])
    assert any("decision does not match replay" in e or "claim recorded without predict permission" in e for e in rep["errors"])


def test_verifier_with_authority_passes_on_honest_log(tmp_path):
    led, _, _ = _two_logs(tmp_path)
    led.claim("a1", "x", 0.6)
    assert verify_pal(led.events(), authority=led.events())["ok"]


# ------------------------------------------------------------------ mutable proof status outside the hash
def test_proof_status_is_appended_not_mutated(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    first = led.anchor(proof_ref="proofs/head1.ots")
    head = first["body"]["head_hash"]
    snapshot = copy.deepcopy(led.events())
    # verification of the SAME head is a new observation event; the old event is untouched
    led._append("anchor", None, {"head_hash": head, "head_seq": first["body"]["head_seq"], "method": "opentimestamps",
                                 "proof_ref": "proofs/head1.ots", "status": "verified"})
    assert led.events()[: len(snapshot)] == snapshot
    assert proof_status(led.events())[head]["status"] == "verified"
    assert led.record("a1")["accountability"]["timestamp_proof"]["by_head"][head]["status"] == "verified"
    assert verify_pal(led.events())["ok"]
    for e in led.events():
        assert "verification_status" not in e and "verification_status" not in e["body"]


def test_editing_status_inside_a_hashed_event_is_detected(tmp_path):
    led = new_pal(tmp_path)
    led.identity("a1", "m", "1", "sdk", "s")
    led.anchor()
    evs = copy.deepcopy(led.events())
    evs[-1]["body"]["status"] = "verified"
    assert not verify_pal(evs)["ok"]


# ------------------------------------------------------------------ timestamps compared as datetimes
def test_parse_compares_instants_not_strings():
    a, b = "2026-11-17T10:00:00+02:00", "2026-11-17T09:00:00Z"
    assert a > b                      # string order says a is later ...
    assert _parse(a) < _parse(b)      # ... but a is 08:00Z, earlier
    with pytest.raises(LedgerError): _parse("2026-11-17T10:00:00")      # no offset -> refused
    with pytest.raises(LedgerError): _parse("not a time")


def test_expiry_with_mixed_offsets(tmp_path):
    led = new_pal(tmp_path)               # clock is 10:00:xxZ
    led.identity("a1", "m", "1", "sdk", "s")
    # expires 11:30+02:00 == 09:30Z: already expired, although as a string "11:30+02:00" > "10:00Z"
    ap = led.approve("a1", "operator", "human_explicit", ["analysis"], ["predict"],
                     issued_at="2026-11-17T09:00:00.000Z", expires_at="2026-11-17T11:30:00+02:00")
    led.grant("a1", "predict", ap["seq"], "operator")
    r = led.attempt("a1", "predict")
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "expired"
    ap2 = led.approve("a1", "operator", "human_explicit", ["analysis"], ["analysis"],
                      issued_at="2026-11-17T09:00:00.000Z", expires_at="2026-11-17T13:00:00+02:00")   # 11:00Z
    led.grant("a1", "analysis", ap2["seq"], "operator")
    assert led.attempt("a1", "analysis")["allowed"]
    with pytest.raises(PALError):
        led.approve("a1", "operator", "human_explicit", ["analysis"], ["read_data"], expires_at="2026-12-01T00:00:00")
    assert verify_pal(led.events())["ok"]


def test_ledger_resolution_order_uses_parsed_times(tmp_path):
    times = iter(["2026-11-17T10:00:00+02:00", "2026-11-17T08:30:00Z"])   # 08:00Z then 08:30Z: valid order
    l = Ledger(tmp_path / "l", clock=lambda: next(times))
    l.declare("t", 0.5, "a1")
    l.resolve("t", True)
    assert verify_ledger_dir(tmp_path / "l")["ok"]


# ------------------------------------------------------------------ seed ledgers still verify
def test_seed_ledgers_still_verify():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "seed_runs"
    dirs = [d for d in root.iterdir() if (d / "receipts.jsonl").exists()] if root.exists() else []
    if not dirs: pytest.skip("no seed ledgers in this checkout")
    for d in dirs:
        rep = verify_ledger_dir(d)
        assert rep["ok"], (d.name, rep["errors"][:3])
        s = rep["summary"]
        assert s["n_pending"] == s["n_declared"] - s["n_resolved"]
