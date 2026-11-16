"""Shared plumbing for the QANTS-operated seed agents.

All three agents are QANTS-operated demonstrators. Their ids start with the reserved prefix `qants-`,
so the Mizan API and the site count them as internal, never as external agents.
They never call the production Mizan API: records live in local ledgers only.
"""
import hashlib, json, os, sys, datetime as dt
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mizan_ledger import Ledger  # noqa: E402

SECRET_ROOT = Path("/workspace/.secrets_mizan_seeds")      # private openings (mode 700/600). Never printed.
RUNS = ROOT / "seed_runs"
VERSION = "0.1.0"
UA = "qants-seed-agents/0.1 (QANTS-operated demo agents; https://qants-site.qants.workers.dev)"


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def open_ledger(agent_id: str) -> Ledger:
    assert agent_id.startswith("qants-"), "seed agents must use the reserved qants- prefix"
    SECRET_ROOT.mkdir(mode=0o700, exist_ok=True)
    priv = SECRET_ROOT / agent_id
    priv.mkdir(mode=0o700, exist_ok=True)
    pub = RUNS / agent_id
    pub.mkdir(parents=True, exist_ok=True)
    return Ledger(pub, priv)


class EventLog:
    """Append-only log of data fetches with response hashes, to show the order: declare -> fetch outcome."""
    def __init__(self, agent_id):
        self.path = RUNS / agent_id / "events.jsonl"
    def add(self, **kw):
        kw["t"] = now()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(kw, sort_keys=True) + "\n")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
