"""Generic trace-evaluator adapter (STUB, UNTESTED against real vendors).

Purpose: let an observability/eval tool (Arize Phoenix, Braintrust, LangSmith or similar) feed a confidence
ledger from traces it already holds. The adapter works on plain dicts only and imports no vendor SDK.

    declare_from_trace(ledger, trace, agent_id, version)   # at the start of a run: reads confidence
    resolve_from_trace(ledger, trace, agent_id, version)   # after evaluation: reads pass/score

Status: unit-tested with synthetic dict traces in this repository ONLY. It has NOT been run inside Phoenix,
Braintrust or LangSmith, and their evaluator signatures were not verified. A vendor wrapper is expected to be
a few lines that map their run/example objects to the dict shape below.

Expected dict shape (keys are configurable):
    {"id": "run-123", "confidence": 0.8}                      # at declaration
    {"id": "run-123", "score": 1.0}                           # at resolution; score >= threshold means success
"""
from __future__ import annotations
from typing import Callable, Optional
from ..core import Ledger, LedgerError


def declare_from_trace(ledger: Ledger, trace: dict, agent_id: str, version: str = "unspecified",
                       id_key: str = "id", confidence_key: str = "confidence") -> dict:
    if confidence_key not in trace or trace[confidence_key] is None:
        raise LedgerError(f"trace has no {confidence_key!r}; nothing to declare")
    return ledger.declare(str(trace[id_key]), float(trace[confidence_key]), agent_id, version)


def resolve_from_trace(ledger: Ledger, trace: dict, agent_id: str, version: str = "unspecified",
                       id_key: str = "id", score_key: str = "score", threshold: float = 0.5) -> dict:
    if score_key not in trace or trace[score_key] is None:
        raise LedgerError(f"trace has no {score_key!r}; leave it pending instead of guessing")
    return ledger.resolve(str(trace[id_key]), float(trace[score_key]) >= threshold, agent_id, version)


def make_evaluator(ledger: Ledger, agent_id: str, version: str = "unspecified", threshold: float = 0.5) -> Callable[[dict], Optional[dict]]:
    """Return fn(trace) -> {'brier_term': ...} usable as a custom evaluator body once wrapped for a vendor."""
    def evaluator(trace: dict):
        rec = resolve_from_trace(ledger, trace, agent_id, version, threshold=threshold)
        return {"key": "mizan_squared_error", "score": rec["score"]["squared_error"]}
    return evaluator
