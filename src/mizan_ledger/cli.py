"""Command line: mizan-ledger verify <dir> | summary <dir> [--agent ID] | mcp"""
import argparse, json, sys
from .core import Ledger, verify_ledger_dir

_MCP_HINT = 'The MCP extra is not installed. Run: pip install "mizan-ledger[mcp]"'


def _run_mcp() -> int:
    try:
        from .mcp_server import main as mcp_main
    except SystemExit as exc:
        # mcp_server raises SystemExit(msg) on import when the extra is missing.
        msg = exc.code if isinstance(getattr(exc, "code", None), str) else _MCP_HINT
        print(msg, file=sys.stderr)
        return 1
    except ImportError:
        print(_MCP_HINT, file=sys.stderr)
        return 1
    mcp_main()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mizan-ledger", description="Offline verification and scoring of a local confidence ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify hash chains, openings and scores (no network, no private files)"); v.add_argument("dir")
    s = sub.add_parser("summary", help="print scores for a ledger directory"); s.add_argument("dir"); s.add_argument("--agent"); s.add_argument("--version")
    sub.add_parser(
        "mcp",
        help="run the optional local stdio MCP server (requires the [mcp] extra)",
        description="Run the optional local stdio MCP server. Requires pip install \"mizan-ledger[mcp]\". Same entry point as the mizan-ledger-mcp script.",
    )
    a = ap.parse_args(argv)
    if a.cmd == "verify":
        rep = verify_ledger_dir(a.dir)
        print(json.dumps(rep, indent=2, sort_keys=True))
        return 0 if rep["ok"] else 1
    if a.cmd == "mcp":
        return _run_mcp()
    led = Ledger(a.dir, private_path=a.dir + "/.noprivate")
    print(json.dumps(led.summary(a.agent, a.version), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
