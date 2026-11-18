"""CLI subcommand `mizan-ledger mcp`. Does not require the [mcp] extra."""
import sys
import types

import pytest

from mizan_ledger.cli import main


def test_mcp_listed_in_help(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "mcp" in out
    assert "verify" in out


def test_mcp_help_does_not_start_server(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["mcp", "--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out + capsys.readouterr().err
    assert "mcp" in out.lower()
    assert "stdio" in out.lower() or "MCP" in out or "[mcp]" in out


def test_mcp_dispatches_to_server_entry_point(monkeypatch):
    called = {}

    def fake_main():
        called["yes"] = True

    fake = types.ModuleType("mizan_ledger.mcp_server")
    fake.main = fake_main
    monkeypatch.setitem(sys.modules, "mizan_ledger.mcp_server", fake)
    assert main(["mcp"]) == 0
    assert called.get("yes") is True


def test_mcp_missing_extra_message(monkeypatch, capsys):
    # Force the same import failure path as a core-only install.
    monkeypatch.setitem(sys.modules, "mcp", None)
    for key in [k for k in list(sys.modules) if k.startswith("mcp.")]:
        monkeypatch.setitem(sys.modules, key, None)
    sys.modules.pop("mizan_ledger.mcp_server", None)
    assert main(["mcp"]) == 1
    err = capsys.readouterr().err
    assert 'pip install "mizan-ledger[mcp]"' in err
