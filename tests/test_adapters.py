import pytest
from mizan_ledger import Ledger, LedgerError, verify_ledger_dir
from mizan_ledger.adapters import trace_eval as te


def test_trace_adapter_roundtrip(tmp_path):
    led = Ledger(tmp_path / "pub", tmp_path / "priv")
    te.declare_from_trace(led, {"id": "run-1", "confidence": 0.9}, "agent-t", "1")
    rec = te.resolve_from_trace(led, {"id": "run-1", "score": 1.0}, "agent-t", "1")
    assert rec["outcome"] == 1
    te.declare_from_trace(led, {"id": "run-2", "confidence": 0.9}, "agent-t", "1")
    assert te.resolve_from_trace(led, {"id": "run-2", "score": 0.2}, "agent-t", "1")["outcome"] == 0
    assert verify_ledger_dir(tmp_path / "pub")["ok"]


def test_trace_adapter_refuses_to_guess(tmp_path):
    led = Ledger(tmp_path / "pub", tmp_path / "priv")
    with pytest.raises(LedgerError): te.declare_from_trace(led, {"id": "r"}, "a")
    led.declare("r", 0.5, "a")
    with pytest.raises(LedgerError): te.resolve_from_trace(led, {"id": "r"}, "a")


def test_evaluator_callable(tmp_path):
    led = Ledger(tmp_path / "pub", tmp_path / "priv")
    led.declare("r", 0.8, "a", "1")
    out = te.make_evaluator(led, "a", "1")({"id": "r", "score": 1})
    assert out["score"] == pytest.approx(0.04)



def _plugin_args():
    """Load the plugin explicitly only when it is not already auto-loaded via the pytest11 entry point."""
    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        group = eps.select(group="pytest11") if hasattr(eps, "select") else eps.get("pytest11", [])
        if any(ep.name == "mizan_ledger" for ep in group):
            return []
    except Exception:
        pass
    return ["-p", "mizan_ledger.pytest_plugin"]

# --- pytest plugin, tested through pytester ---------------------------------
def test_pytest_plugin(pytester, tmp_path):
    pytester.makepyfile("""
        import pytest
        @pytest.mark.confidence(0.9)
        def test_pass(): assert True
        @pytest.mark.confidence(0.8)
        def test_fail(): assert False
        @pytest.mark.confidence(0.5)
        @pytest.mark.skip(reason="x")
        def test_skip(): pass
        def test_unmarked(): assert True
    """)
    ld = tmp_path / "ledger"
    r = pytester.runpytest(*_plugin_args(), "--mizan-ledger-dir", str(ld),
                           "--mizan-agent-id", "plug-agent", "--mizan-agent-version", "9", "--mizan-run-id", "r1")
    r.assert_outcomes(passed=2, failed=1, skipped=1)
    led = Ledger(ld)
    s = led.summary("plug-agent", "9")
    assert s["declared"] == 2 and s["resolved"] == 2 and s["pending"] == 0   # skipped test is never declared
    assert s["brier"] == pytest.approx(((0.9 - 1) ** 2 + (0.8 - 0) ** 2) / 2)
    assert verify_ledger_dir(ld)["ok"]


def test_xfail_stays_pending(pytester, tmp_path):
    pytester.makepyfile("""
        import pytest
        @pytest.mark.confidence(0.7)
        @pytest.mark.xfail
        def test_x(): assert False
    """)
    ld = tmp_path / "ledger"
    pytester.runpytest(*_plugin_args(), "--mizan-ledger-dir", str(ld), "--mizan-agent-id", "x", "--mizan-run-id", "r")
    s = Ledger(ld).summary("x")
    assert s["declared"] == 1 and s["pending"] == 1


def test_cli_verify(tmp_path, capsys):
    from mizan_ledger.cli import main
    led = Ledger(tmp_path / "pub", tmp_path / "priv")
    led.declare("t", 0.5, "a"); led.resolve("t", True)
    assert main(["verify", str(tmp_path / "pub")]) == 0
    assert not (tmp_path / "pub" / ".noprivate").exists()
    main(["summary", str(tmp_path / "pub")])
    (tmp_path / "pub" / "resolutions.jsonl").write_text("")
    assert main(["verify", str(tmp_path / "pub")]) == 0
