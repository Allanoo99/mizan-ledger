import json, math, pathlib
import pytest
from mizan_ledger import Ledger, LedgerError, commitment_hash, verify_opening, verify_ledger_dir, fmt_p, metrics

VEC = json.loads((pathlib.Path(__file__).resolve().parents[1] / "vectors" / "commitments.json").read_text("utf8"))


def make(tmp_path, times=None):
    it = iter(times or [f"2026-11-16T10:00:{i:02d}.000Z" for i in range(60)])
    return Ledger(tmp_path / "pub", tmp_path / "priv", clock=lambda: next(it))


def test_shared_vectors():
    for v in VEC:
        assert fmt_p(v["p"]) == v["p_fmt"]
        assert commitment_hash(v["task_id"], v["p"], v["agent_id"], v["agent_version"], v["salt"]) == v["commitment"]


def test_declare_is_hash_only(tmp_path):
    led = make(tmp_path)
    r = led.declare("secret-task-name", 0.8123, "agent-a", "1")
    pub = (tmp_path / "pub" / "receipts.jsonl").read_text()
    assert "secret-task-name" not in pub and "0.8123" not in pub and "0.812300" not in pub
    assert len(r["commitment"]) == 64 and r["declared_at"].endswith("Z")
    assert oct((tmp_path / "priv" / "openings.jsonl").stat().st_mode & 0o777) == "0o600"


def test_salt_makes_same_input_differ(tmp_path):
    led = make(tmp_path)
    a = led.declare("t1", 0.5, "a", "1")
    b = led.declare("t1", 0.5, "a", "2")
    assert a["commitment"] != b["commitment"]


def test_resolve_scores_and_reveals(tmp_path):
    led = make(tmp_path)
    led.declare("t1", 0.8, "a", "1")
    rec = led.resolve("t1", True)
    assert rec["score"]["squared_error"] == pytest.approx(0.04)
    assert rec["score"]["log_loss"] == pytest.approx(-math.log(0.8))
    rc = led.receipts()[0]
    assert verify_opening(rc, rec["opening"])


def test_cannot_redeclare_or_re_resolve(tmp_path):
    led = make(tmp_path)
    led.declare("t1", 0.8, "a", "1")
    with pytest.raises(LedgerError): led.declare("t1", 0.2, "a", "1")
    led.resolve("t1", False)
    with pytest.raises(LedgerError): led.resolve("t1", True)


def test_resolve_unknown_and_bad_p(tmp_path):
    led = make(tmp_path)
    with pytest.raises(LedgerError): led.resolve("nope", True)
    for bad in (-0.1, 1.1, float("nan")):
        with pytest.raises(LedgerError): led.declare("x", bad, "a")


def test_clock_backwards_rejected(tmp_path):
    led = make(tmp_path, ["2026-11-16T10:00:10.000Z", "2026-11-16T10:00:05.000Z"])
    led.declare("t1", 0.5, "a", "1")
    with pytest.raises(LedgerError): led.resolve("t1", True)


def test_verify_ok_and_tamper_detection(tmp_path):
    led = make(tmp_path)
    for i, (p, y) in enumerate([(0.9, 1), (0.7, 1), (0.2, 0), (0.6, 0)]):
        led.declare(f"t{i}", p, "a", "1"); led.resolve(f"t{i}", bool(y))
    led.declare("pending", 0.5, "a", "1")
    rep = verify_ledger_dir(tmp_path / "pub")
    assert rep["ok"], rep["errors"]
    assert rep["summary"]["declared"] == 5 and rep["summary"]["pending"] == 1 and rep["summary"]["n"] == 4
    # 1) change an outcome in resolutions
    rp = tmp_path / "pub" / "resolutions.jsonl"
    orig = rp.read_text()
    rp.write_text(orig.replace('"outcome":1', '"outcome":0', 1))
    assert not verify_ledger_dir(tmp_path / "pub")["ok"]
    rp.write_text(orig)
    # 2) delete a receipt in the middle
    cp = tmp_path / "pub" / "receipts.jsonl"
    lines = cp.read_text().splitlines(True)
    cp.write_text("".join(lines[:1] + lines[2:]))
    assert not verify_ledger_dir(tmp_path / "pub")["ok"]


def test_verify_detects_opening_swap(tmp_path):
    led = make(tmp_path)
    led.declare("t1", 0.9, "a", "1"); led.resolve("t1", False)
    rp = tmp_path / "pub" / "resolutions.jsonl"
    d = json.loads(rp.read_text()); d["opening"]["p"] = "0.100000"
    # recompute record hash so only the opening check can catch it
    from mizan_ledger.core import _chain_hash, canonical_json
    d["record_hash"] = _chain_hash(d, "record_hash")
    rp.write_text(canonical_json(d) + "\n")
    rep = verify_ledger_dir(tmp_path / "pub")
    assert not rep["ok"] and any("opening" in e for e in rep["errors"])


def test_summary_reports_coverage(tmp_path):
    led = make(tmp_path)
    led.declare("a", 0.9, "x", "1"); led.declare("b", 0.9, "x", "1"); led.resolve("a", True)
    s = led.summary("x")
    assert s["declared"] == 2 and s["resolved"] == 1 and s["coverage"] == 0.5


def test_private_dir_not_needed_for_verification(tmp_path):
    led = make(tmp_path)
    led.declare("t1", 0.9, "a", "1"); led.resolve("t1", True)
    import shutil; shutil.rmtree(tmp_path / "priv")
    assert verify_ledger_dir(tmp_path / "pub")["ok"]


# --- metrics ---------------------------------------------------------------
def test_brier_ece_known_values():
    pairs = [(1.0, 1), (0.0, 0), (0.5, 1), (0.5, 0)]
    assert metrics.brier(pairs) == pytest.approx(0.125)
    assert metrics.ece([(0.7, 1)] * 7 + [(0.7, 0)] * 3) == pytest.approx(0.0)
    assert metrics.ece([(0.9, 0)] * 10) == pytest.approx(0.9)


def test_log_loss_clipped():
    assert math.isfinite(metrics.log_loss([(0.0, 1), (1.0, 0)]))


def test_wilson_matches_reference():
    r = metrics.accuracy_wilson([(0.9, 1)] * 8 + [(0.9, 0)] * 2)  # 8/10 correct
    assert r["accuracy"] == 0.8
    assert r["ci95"][0] == pytest.approx(0.4902, abs=1e-3) and r["ci95"][1] == pytest.approx(0.9433, abs=1e-3)


def test_bootstrap_deterministic_and_brackets_mean():
    pairs = [(0.8, 1), (0.6, 0), (0.9, 1), (0.3, 0), (0.7, 1), (0.4, 1)] * 5
    a = metrics.brier_interval(pairs); b = metrics.brier_interval(pairs)
    assert a == b and a["ci95"][0] <= a["brier"] <= a["ci95"][1]


def test_empty_raises():
    with pytest.raises(ValueError): metrics.brier([])
