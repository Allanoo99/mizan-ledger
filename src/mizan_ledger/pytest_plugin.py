"""pytest plugin: declare confidence before a test runs, resolve with its pass/fail.

    @pytest.mark.confidence(0.9)
    def test_parser(): ...

    pytest --mizan-ledger-dir .mizan --mizan-agent-id my-agent --mizan-agent-version 1.2.0

Only tests carrying the marker are recorded. The declaration is committed after skip marks and fixture setup, right
before the test body. A test that is declared but then xfails stays "pending" (counted in coverage, never silently
dropped). Skipped tests and fixture errors are never declared.
"""
from __future__ import annotations
import datetime as _dt
import pytest
from .core import Ledger, LedgerError


def pytest_addoption(parser):
    g = parser.getgroup("mizan-ledger")
    g.addoption("--mizan-ledger-dir", default=None, help="enable mizan-ledger and store the ledger in this directory")
    g.addoption("--mizan-private-dir", default=None, help="directory for private openings (default <ledger>/private)")
    g.addoption("--mizan-agent-id", default="pytest-agent")
    g.addoption("--mizan-agent-version", default="unspecified")
    g.addoption("--mizan-run-id", default=None, help="suffix that makes task ids unique per run (default: UTC start time)")


def pytest_configure(config):
    config.addinivalue_line("markers", "confidence(p): declared probability (0..1) that this test passes, committed before it runs")
    d = config.getoption("--mizan-ledger-dir")
    if d:
        config._mizan = {
            "ledger": Ledger(d, private_path=config.getoption("--mizan-private-dir")),
            "agent": config.getoption("--mizan-agent-id"),
            "version": config.getoption("--mizan-agent-version"),
            "run": config.getoption("--mizan-run-id") or _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        }


def _task_id(cfg, item):
    return f"{item.nodeid}@{cfg['run']}"


@pytest.hookimpl(trylast=True)  # after skip marks and fixture setup: declared right before the test body
def pytest_runtest_setup(item):
    cfg = getattr(item.config, "_mizan", None)
    m = item.get_closest_marker("confidence")
    if not cfg or m is None:
        return
    if not m.args:
        raise pytest.UsageError("@pytest.mark.confidence needs a probability, e.g. @pytest.mark.confidence(0.9)")
    try:
        rec = cfg["ledger"].declare(_task_id(cfg, item), float(m.args[0]), cfg["agent"], cfg["version"])
    except LedgerError as e:
        raise pytest.UsageError(str(e))
    item._mizan_declared = rec["commitment"]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    out = yield
    rep = out.get_result()
    cfg = getattr(item.config, "_mizan", None)
    if not cfg or not hasattr(item, "_mizan_declared") or call.when != "call":
        return
    if hasattr(rep, "wasxfail") or rep.skipped:
        return  # not a real outcome: stays pending
    cfg["ledger"].resolve(_task_id(cfg, item), rep.passed, cfg["agent"], cfg["version"])


def pytest_terminal_summary(terminalreporter, config):
    cfg = getattr(config, "_mizan", None)
    if not cfg:
        return
    s = cfg["ledger"].summary(cfg["agent"], cfg["version"])
    tr = terminalreporter
    tr.section("mizan-ledger")
    if s.get("resolved"):
        tr.line(f"agent {cfg['agent']}@{cfg['version']}: declared {s['declared']}, resolved {s['resolved']}, pending {s['pending']}; "
                f"Brier {s['brier']:.4f} (always-0.5 = 0.25), ECE {s['ece']:.4f}, n={s['n']}")
    else:
        tr.line("no resolved confidence declarations in this ledger yet")
