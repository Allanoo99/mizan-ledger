import json
import pytest
from mizan_ledger import pal
from mizan_ledger.pal import PermissionLedger, PolicyError, PALError, verify_pal, trust_indicators, permission_state_hash
from mizan_ledger.cli import main


def clock(start_min=0):
    state = {"i": 0}
    def f():
        state["i"] += 1
        m, s = divmod(start_min * 60 + state["i"], 60)
        h, m = divmod(m, 60)
        return f"2026-11-17T{10 + h:02d}:{m:02d}:{s:02d}.000Z"
    return f


def setup(tmp_path, levels=("analysis", "signal"), perms=("read_data", "analysis", "predict", "commit_reveal"), expires=None):
    led = PermissionLedger(tmp_path / "pal", clock=clock())
    led.identity("a1", "model-x", "1.0", "sdk", "sess-1")
    ap = led.approve("a1", "operator", "human_explicit", levels, perms, expires_at=expires, evidence_ref="chat:t1")
    grants = {p: led.grant("a1", p, ap["seq"], "operator") for p in perms}
    return led, ap, grants


@pytest.mark.parametrize("perm", ["external_action", "financial_order"])
def test_external_and_financial_always_denied(tmp_path, perm):
    led, ap, _ = setup(tmp_path)
    with pytest.raises(PolicyError):
        led.approve("a1", "operator", "human_explicit", ["execution"], [perm])
    with pytest.raises(PolicyError):
        led.grant("a1", perm, ap["seq"], "operator")
    # trying to grant/approve a closed permission is itself a critical violation
    ops = [e for e in led.events() if e["type"] == "violation" and e["body"]["request"] in ("grant", "approve")]
    assert len(ops) == 2 and all(e["body"]["severity"] == "critical" and e["body"]["actor"] == "operator" for e in ops)
    r = led.attempt("a1", perm)
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "policy_bound"
    assert r["violation"]["body"]["severity"] == "critical" and r["warning"] is None
    assert all(not (e["type"] == "grant" and e["body"]["permission"] == perm) for e in led.events())
    rec = led.record("a1")
    assert rec["accountability"]["compliance"] == "VIOLATIONS_RECORDED"
    assert len(rec["accountability"]["operator_policy_breaches"]) == 2
    assert verify_pal(led.dir)["ok"]


@pytest.mark.parametrize("perm", ["modify_files", "exec_commands"])
def test_local_execution_default_deny_but_grantable(tmp_path, perm):
    led, _, _ = setup(tmp_path)
    r = led.attempt("a1", perm, tool="./out", note="agent tried to write before any grant")
    assert not r["allowed"] and r["warning"]["body"]["kind"] == "not_granted" and r["violation"] is None
    assert r["warning"]["body"]["note"] == "agent tried to write before any grant"
    with pytest.raises(PALError):   # standing approval is not enough for execution-level permissions
        led.approve("a1", "operator", "human_standing", ["execution"], [perm])
    ap = led.approve("a1", "operator", "human_explicit", ["execution"], [perm], evidence_ref="chat:t459")
    with pytest.raises(PALError):   # needs an explicit allowlist
        led.grant("a1", perm, ap["seq"], "operator")
    led.grant("a1", perm, ap["seq"], "operator", tools=["./out"])
    assert led.attempt("a1", perm, tool="./out")["allowed"]
    w = led.attempt("a1", perm, tool="/etc")
    assert w["warning"]["body"]["kind"] == "tool_not_allowed"
    assert led.record("a1")["accountability"]["compliance"] == "COMPLIANT_WITH_WARNINGS"
    assert verify_pal(led.dir)["ok"]


def test_signal_and_paper_trade_with_standing_approval(tmp_path):
    led = PermissionLedger(tmp_path / "pal", clock=clock())
    ap = led.approve("a1", "operator", "human_standing", ["signal"], ["issue_signal", "paper_trade"])
    led.grant("a1", "issue_signal", ap["seq"], "operator")
    led.grant("a1", "paper_trade", ap["seq"], "operator")
    assert led.attempt("a1", "issue_signal")["allowed"] and led.attempt("a1", "paper_trade", detail={"unit": "tQNT"})["allowed"]
    with pytest.raises(PALError):
        led.approve("a1", "bot", "delegated", ["signal"], ["issue_signal"])
    assert verify_pal(led.dir)["ok"]


def test_warning_cannot_downgrade_breach_or_lack_note(tmp_path):
    led, _, _ = setup(tmp_path)
    led.attempt("a1", "financial_order")
    led.attempt("a1", "issue_signal")
    evs = json.loads(json.dumps(led.events()))
    for e in evs:
        if e["type"] == "violation": e["type"] = "warning"; e["body"]["note"] = "x"
        elif e["type"] == "warning": e["body"]["note"] = " "
    prev = pal.GENESIS
    for e in evs:
        e["prev"] = prev; e.pop("event_hash"); e["event_hash"] = pal._chain_hash(e, "event_hash"); prev = e["event_hash"]
    errs = verify_pal(evs)["errors"]
    assert any("downgrade" in x for x in errs) and sum("warning must have a note" in x for x in errs) == 2


def test_closed_level_cannot_be_forged_into_file(tmp_path):
    led, ap, _ = setup(tmp_path)
    evs = led.events()
    forged = dict(evs[-1]); forged.update(seq=len(evs) + 1, prev=evs[-1]["event_hash"], type="grant",
                                          body={"permission": "financial_order", "level": "execution", "approval_seq": ap["seq"], "granted_by": "x"})
    forged.pop("event_hash"); forged["event_hash"] = pal._chain_hash(forged, "event_hash")
    rep = verify_pal(evs + [forged])
    assert not rep["ok"] and any("closed permission" in e for e in rep["errors"])


def test_analysis_approval_does_not_imply_signal(tmp_path):
    led, ap, _ = setup(tmp_path, levels=("analysis",), perms=("read_data", "analysis", "predict"))
    with pytest.raises(PALError):
        led.grant("a1", "commit_reveal", ap["seq"], "operator")
    with pytest.raises(PALError):
        led.approve("a1", "operator", "human_explicit", ["analysis"], ["commit_reveal"])
    assert not led.attempt("a1", "commit_reveal")["allowed"]
    assert led.claim("a1", "x", 0.6, commitment="ab" * 32)["allowed"] is False


def test_revoke_then_attempt_is_warning(tmp_path):
    led, _, g = setup(tmp_path)
    assert led.attempt("a1", "commit_reveal")["allowed"]
    led.revoke("a1", g["commit_reveal"]["seq"], "operator", "test")
    r = led.attempt("a1", "commit_reveal")
    assert not r["allowed"]
    assert r["deny"]["body"]["reason"] == "revoked" and r["warning"]["body"]["kind"] == "revoked" and r["violation"] is None
    assert r["warning"]["body"]["note"]
    assert led.record("a1")["accountability"]["compliance"] == "COMPLIANT_WITH_WARNINGS"
    # history kept: the grant event is still there, unchanged
    assert any(e["seq"] == g["commit_reveal"]["seq"] and e["type"] == "grant" for e in led.events())
    assert verify_pal(led.dir)["ok"]


def test_tamper_detection(tmp_path):
    led, _, _ = setup(tmp_path)
    led.claim("a1", "BTC>95k", 0.7, ["feed"], "m1")
    lines = led.path.read_text().splitlines()
    ev = json.loads(lines[-1]); ev["body"]["p"] = 0.99
    lines[-1] = json.dumps(ev)
    led.path.write_text("\n".join(lines) + "\n")
    rep = verify_pal(led.dir)
    assert not rep["ok"] and any("hash mismatch" in e for e in rep["errors"])
    with pytest.raises(PALError):
        PermissionLedger(led.dir)


def test_tamper_rehashed_decision_detected(tmp_path):
    led, _, g = setup(tmp_path)
    led.revoke("a1", g["predict"]["seq"], "operator")
    led.attempt("a1", "predict")
    evs = led.events()
    # rewrite the denied attempt as "allowed", drop its deny/violation, and rehash the whole chain
    out, prev = [], pal.GENESIS
    for e in evs:
        if e["type"] in ("deny", "violation"): continue
        e = json.loads(json.dumps(e)); e["seq"] = len(out) + 1; e["prev"] = prev
        if e["type"] == "attempt": e["body"]["decision"] = "allowed"
        e.pop("event_hash"); e["event_hash"] = pal._chain_hash(e, "event_hash"); prev = e["event_hash"]; out.append(e)
    rep = verify_pal(out)
    assert not rep["ok"] and any("does not match replay" in x for x in rep["errors"])


def test_claim_embeds_permission_state_hash(tmp_path):
    led, _, g = setup(tmp_path)
    c1 = led.claim("a1", "up", 0.6, ["feed"], "m1")["claim"]
    eff = led._state.effective("a1", c1["body"]["permission_state_at"])
    assert c1["body"]["permission_state_hash"] == permission_state_hash("a1", eff)
    led.revoke("a1", g["read_data"]["seq"], "operator")
    c2 = led.claim("a1", "down", 0.4, ["feed"], "m1")["claim"]
    assert c2["body"]["permission_state_hash"] != c1["body"]["permission_state_hash"]
    assert "read_data" in c1["body"]["effective_permissions"] and "read_data" not in c2["body"]["effective_permissions"]
    assert verify_pal(led.dir)["ok"]


def test_claim_without_predict_is_denied(tmp_path):
    led, _, g = setup(tmp_path)
    led.revoke("a1", g["predict"]["seq"], "operator")
    r = led.claim("a1", "up", 0.6, ["feed"], "m1")
    assert r["allowed"] is False and r["claim"] is None and r["warning"] and r["violation"] is None
    assert not any(e["type"] == "claim" for e in led.events())


def test_authorization_expiry(tmp_path):
    led, _, _ = setup(tmp_path, expires="2026-11-17T10:00:20.000Z")
    assert led.attempt("a1", "predict")["allowed"]
    for _ in range(25): led._clock()          # advance the test clock past expiry
    r = led.attempt("a1", "predict")
    assert not r["allowed"] and r["deny"]["body"]["reason"] == "expired"
    assert verify_pal(led.dir)["ok"]


def test_tool_allowlist(tmp_path):
    led = PermissionLedger(tmp_path / "pal", clock=clock())
    ap = led.approve("a1", "op", "human_explicit", ["analysis"], ["use_allowed_tools"])
    with pytest.raises(PALError):
        led.grant("a1", "use_allowed_tools", ap["seq"], "op")
    led.grant("a1", "use_allowed_tools", ap["seq"], "op", tools=["price_feed"])
    assert led.attempt("a1", "use_allowed_tools", tool="price_feed")["allowed"]
    assert led.attempt("a1", "use_allowed_tools", tool="shell")["deny"]["body"]["reason"] == "tool_not_allowed"


def test_metrics_are_separate(tmp_path):
    led, _, _ = setup(tmp_path)
    for i in range(24):
        c = led.claim("a1", f"q{i}", 0.8, ["feed"] if i % 2 else [], "m1")["claim"]
        led.resolve(c["seq"], 1 if i % 4 else 0, resolver="test")
    before = trust_indicators(led.events(), "a1", min_n={"prediction_accuracy": 10})
    for _ in range(3): led.attempt("a1", "financial_order")
    led.attempt("a1", "issue_signal", note="not granted in this test")
    after = trust_indicators(led.events(), "a1", min_n={"prediction_accuracy": 10})
    assert set(before) == {"prediction_accuracy", "permission_compliance", "transparency", "historical_reliability", "note"}
    assert not any(k in before for k in ("trust_score", "score", "overall"))
    assert after["prediction_accuracy"] == before["prediction_accuracy"]     # violations don't move accuracy
    assert after["transparency"] == before["transparency"]
    pc = after["permission_compliance"]
    assert pc["critical_violations"] == 3 and before["permission_compliance"]["critical_violations"] == 0
    assert pc["warnings"] == 1 and pc["warnings_by_kind"] == {"not_granted": 1}
    assert pc["compliance_rate"] == pytest.approx(1 - 3 / pc["n"]) and pc["warning_rate"] == pytest.approx(1 / pc["n"])
    assert before["transparency"]["share_with_sources_and_method"] == pytest.approx(0.5)
    assert before["prediction_accuracy"]["brier"] == pytest.approx((18 * 0.04 + 6 * 0.64) / 24)
    assert before["prediction_accuracy"]["insufficient_data"] is False
    assert before["historical_reliability"]["n"] == 4 and len(before["historical_reliability"]["window_brier"]) == 4
    small = trust_indicators(led.events(), "a1")
    assert small["prediction_accuracy"]["insufficient_data"] is True and small["prediction_accuracy"]["n"] == 24


def test_record_layers_and_cli(tmp_path, capsys):
    led, _, _ = setup(tmp_path)
    c = led.claim("a1", "up", 0.7, ["feed"], "m1")["claim"]
    led.resolve(c["seq"], 1, actual="93500")
    led.anchor()
    rec = led.record("a1")
    for k in ("identity", "permissions", "authorization", "claims", "accountability"): assert rec[k]
    assert rec["accountability"]["compliance"] == "COMPLIANT"
    assert rec["accountability"]["timestamp_proof"]["anchor"] == "pending"
    assert "financial_order" in rec["permissions"]["closed_by_policy"]
    assert main(["pal", "verify", str(led.dir)]) == 0
    assert main(["pal", "record", str(led.dir), "--agent", "a1"]) == 0
    assert json.loads(capsys.readouterr().out.split("\n}\n", 1)[1])["agent_id"] == "a1"


def test_resolve_and_clock_guards(tmp_path):
    led, _, _ = setup(tmp_path)
    c = led.claim("a1", "up", 0.7, ["feed"], "m1")["claim"]
    led.resolve(c["seq"], 0)
    with pytest.raises(PALError): led.resolve(c["seq"], 1)
    led._clock = lambda: "2026-11-17T09:00:00.000Z"
    with pytest.raises(PALError): led.attempt("a1", "predict")
