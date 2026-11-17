"""Command line: mizan-ledger verify <dir> | summary <dir> [--agent ID] | pal verify <dir> | pal record <dir> --agent ID"""
import argparse, json, sys
from .core import Ledger, verify_ledger_dir


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mizan-ledger", description="Offline verification and scoring of a local confidence ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify hash chains, openings and scores (no network, no private files)"); v.add_argument("dir")
    s = sub.add_parser("summary", help="print scores for a ledger directory"); s.add_argument("dir"); s.add_argument("--agent"); s.add_argument("--version")
    pl = sub.add_parser("pal", help="Permission & Accountability Ledger (v0.1)")
    pl.add_argument("action", choices=["verify", "record"]); pl.add_argument("dir"); pl.add_argument("--agent")
    a = ap.parse_args(argv)
    if a.cmd == "pal":
        from .pal import verify_pal, agent_record
        from .core import _read_jsonl
        from pathlib import Path
        if a.action == "verify":
            rep = verify_pal(a.dir)
            print(json.dumps(rep, indent=2, sort_keys=True))
            return 0 if rep["ok"] else 1
        if not a.agent: ap.error("pal record needs --agent")
        print(json.dumps(agent_record(_read_jsonl(Path(a.dir) / "events.jsonl"), a.agent), indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    if a.cmd == "verify":
        rep = verify_ledger_dir(a.dir)
        print(json.dumps(rep, indent=2, sort_keys=True))
        return 0 if rep["ok"] else 1
    led = Ledger(a.dir, private_path=a.dir + "/.noprivate")
    print(json.dumps(led.summary(a.agent, a.version), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
