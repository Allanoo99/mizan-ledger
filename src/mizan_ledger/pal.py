"""Agent Permission & Accountability Ledger (PAL) v0.1.

One append-only, hash-chained event log (events.jsonl) that records, per agent:
IDENTITY -> PERMISSIONS -> AUTHORIZATION -> CLAIMS -> ACCOUNTABILITY.

Policy model ("hybrid", option C)
  * Mizan sets hard bounds (POLICY). Nobody can grant above them.
  * external_action and financial_order are CLOSED permanently. Nobody can approve, grant or perform them.
  * modify_files and exec_commands (local execution) are denied by default. A user may grant them
    only under an explicit human approval and with an explicit target allowlist.
  * Paper trading in testnet units (tQNT) is Signal level (paper_trade), not Execution.
  * Inside the bounds, a user approves a scope (levels + permissions) and grants permissions
    under that approval. Approving one level never implies another.

Honest limits
  * PAL only sees actions routed through Mizan. It cannot observe what an agent does elsewhere.
  * Timestamps come from the local clock unless the chain head is anchored and verified.
  * Single-writer: no cross-process locking in v0.1.
"""
from __future__ import annotations
import datetime as _dt
import os
from pathlib import Path
from typing import Callable, Iterable, Optional

from . import metrics
from .core import GENESIS, LedgerError, canonical_json, sha256_hex, _chain_hash, _now, _parse, _read_jsonl, verify_chain
from .identity import ReservedAgentIdError, check_agent_id, OPERATOR_TYPES
from .safety import find_secrets

PAL_SCHEMA = "mizan-pal/0.1"

# ---------------------------------------------------------------- policy bounds (Mizan-set)
LEVELS = ("analysis", "signal", "execution")
PERMISSION_LEVEL = {
    "read_data": "analysis",
    "analysis": "analysis",
    "predict": "analysis",
    "use_allowed_tools": "analysis",   # only for tools named in the grant's allowlist
    "commit_reveal": "signal",
    "issue_signal": "signal",
    "paper_trade": "signal",           # testnet/paper only (tQNT, no cash value); never a real order
    "modify_files": "execution",
    "exec_commands": "execution",
    "external_action": "execution",
    "financial_order": "execution",
}
PERMISSIONS = tuple(PERMISSION_LEVEL)
POLICY = {
    "policy_id": "mizan-pal-policy/0.1.1",
    "closed_permissions": ["external_action", "financial_order"],   # hard-denied for everyone, no override
    "default_deny": sorted(PERMISSIONS),                              # nothing is allowed until granted
    "requires_allowlist": ["use_allowed_tools", "modify_files", "exec_commands"],
    "approval_types": ["human_explicit", "human_standing", "delegated"],
    "approval_types_by_level": {                                      # who may approve each level
        "analysis": ["human_explicit", "human_standing", "delegated"],
        "signal": ["human_explicit", "human_standing"],
        "execution": ["human_explicit"],
    },
}
CLOSED = frozenset(POLICY["closed_permissions"])
POLICY_HASH = sha256_hex(canonical_json({"policy": POLICY, "permission_level": PERMISSION_LEVEL}))

EVENT_TYPES = ("identity", "approve", "grant", "revoke", "attempt", "deny", "warning", "violation", "claim", "resolve", "anchor")
DENY_REASONS = ("policy_bound", "not_granted", "revoked", "expired", "tool_not_allowed", "outside_approval_scope",
                "foreign_permission", "permission_mismatch")
PERMISSION_EVENT_TYPES = ("identity", "approve", "grant", "revoke")
STATUS_LABELS = ("COMPLIANT", "COMPLIANT_WITH_WARNINGS", "VIOLATIONS_RECORDED")


class PALError(Exception):
    pass


class PolicyError(PALError):
    """Raised when a request exceeds Mizan's hard bounds (the request is still logged as a deny event)."""


def _ts(s: str) -> _dt.datetime:
    """Timestamps are always compared as parsed, offset-aware datetimes, never as strings."""
    try:
        return _parse(s)
    except LedgerError as e:
        raise PALError(str(e))


# ---------------------------------------------------------------- state replay
class _State:
    """Replays events to derive approvals, grants and the effective permission set at a time."""

    def __init__(self):
        self.approvals = {}   # seq -> event
        self.grants = {}      # seq -> event
        self.revoked = {}     # grant seq -> revoke seq
        self.revoke_events = {}  # grant seq -> revoke event (a revoke is a new event; the grant is never erased)
        self.identity = {}    # agent -> latest identity event

    def apply(self, ev: dict) -> None:
        t = ev["type"]
        if t == "identity": self.identity[ev["agent_id"]] = ev
        elif t == "approve": self.approvals[ev["seq"]] = ev
        elif t == "grant": self.grants[ev["seq"]] = ev
        elif t == "revoke":
            self.revoked[ev["body"]["grant_seq"]] = ev["seq"]
            self.revoke_events[ev["body"]["grant_seq"]] = ev

    def _approval_live(self, a: dict, at: str) -> bool:
        b = a["body"]
        t = _ts(at)
        if t < _ts(a["ts"]) or t < _ts(b["issued_at"]): return False   # a later-recorded approval cannot authorize the past
        return not (b.get("expires_at") and t >= _ts(b["expires_at"]))

    def _revoked_at(self, grant_seq: int, at: str) -> bool:
        r = self.revoke_events.get(grant_seq)
        return bool(r) and _ts(r["ts"]) <= _ts(at)

    def effective(self, agent_id: str, at: str) -> dict:
        """{permission: {"grant_seq", "approval_seq", "tools"}} in force for agent at time `at` (as-of query:
        grants recorded after `at` and revocations recorded after `at` are ignored)."""
        out = {}
        for gs, g in sorted(self.grants.items()):
            if g["agent_id"] != agent_id or _ts(g["ts"]) > _ts(at) or self._revoked_at(gs, at): continue
            a = self.approvals.get(g["body"]["approval_seq"])
            if not a or a["agent_id"] != agent_id or not self._approval_live(a, at): continue
            p = g["body"]["permission"]
            out[p] = {"grant_seq": gs, "approval_seq": a["seq"], "tools": sorted(g["body"].get("tools") or [])}
        return out

    def why_not(self, agent_id: str, permission: str, at: str) -> str:
        if permission in CLOSED or permission not in PERMISSION_LEVEL:
            return "policy_bound"
        mine = [(s, g) for s, g in self.grants.items() if g["agent_id"] == agent_id and g["body"]["permission"] == permission
                and _ts(g["ts"]) <= _ts(at)]
        if not mine: return "not_granted"
        if all(self._revoked_at(s, at) for s, _ in mine): return "revoked"
        return "expired"

    def state_hash(self, agent_id: str, at: str) -> str:
        return permission_state_hash(agent_id, self.effective(agent_id, at))


def permission_state_hash(agent_id: str, effective: dict) -> str:
    """Hash of what an agent was allowed to do at a moment, bound to the policy version."""
    return sha256_hex(canonical_json({"agent_id": agent_id, "effective": effective,
                                      "policy_hash": POLICY_HASH, "schema": PAL_SCHEMA}))


def decide(state: _State, agent_id: str, action: str, at: str, tool: Optional[str] = None,
           grant_seq: Optional[int] = None) -> tuple:
    """Returns (allowed: bool, reason: str|None, effective: dict).

    If the caller cites a specific grant (grant_seq), it must be a grant of this same agent for this
    same action; citing another agent's permission is refused ("foreign_permission").
    """
    eff = state.effective(agent_id, at)
    if action not in PERMISSION_LEVEL or action in CLOSED:
        return False, "policy_bound", eff
    if grant_seq is not None:
        g = state.grants.get(grant_seq)
        if g is not None and g["agent_id"] != agent_id:
            return False, "foreign_permission", eff
        if g is None or g["body"]["permission"] != action:
            return False, "permission_mismatch", eff
        if eff.get(action, {}).get("grant_seq") != grant_seq:   # the cited grant itself is not in force
            return False, ("revoked" if state._revoked_at(grant_seq, at) else
                           "not_granted" if _ts(state.grants[grant_seq]["ts"]) > _ts(at) else "expired"), eff
    if action not in eff:
        return False, state.why_not(agent_id, action, at), eff
    if action in POLICY["requires_allowlist"] and (not tool or tool not in eff[action]["tools"]):
        return False, "tool_not_allowed", eff
    return True, None, eff


# ---------------------------------------------------------------- ledger
class PermissionLedger:
    """Append-only, hash-chained PAL event log in <dir>/events.jsonl.

    label: optional tag stamped on every event (e.g. "DEMO - simulated data") so demo runs
    can never be mistaken for real ledgers.
    """

    def __init__(self, path, clock: Optional[Callable[[], str]] = None, label: Optional[str] = None):
        self.dir = Path(path)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "events.jsonl"
        self._clock = clock or _now
        self.label = label
        self._events = _read_jsonl(self.path)
        errs = verify_chain(self._events, "event_hash")
        if errs: raise PALError("refusing to append to a broken chain: " + "; ".join(errs[:3]))
        self._state = _State()
        for e in self._events: self._state.apply(e)

    # -- low level
    def events(self) -> list: return list(self._events)

    def _append(self, type_: str, agent_id: Optional[str], body: dict) -> dict:
        assert type_ in EVENT_TYPES
        leaked = find_secrets({"agent_id": agent_id, "body": body})
        if leaked: raise PALError(f"refusing to write a credential-shaped value into the public chain ({', '.join(leaked)})")
        ts = self._clock()
        if self._events and _ts(ts) < _ts(self._events[-1]["ts"]):
            raise PALError("clock went backwards; refusing to append")
        ev = {"schema": PAL_SCHEMA, "seq": len(self._events) + 1, "prev": self._events[-1]["event_hash"] if self._events else GENESIS,
              "ts": ts, "type": type_, "agent_id": agent_id, "policy_hash": POLICY_HASH, "body": body}
        if self.label: ev["label"] = self.label
        ev["event_hash"] = _chain_hash(ev, "event_hash")
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(ev) + "\n"); f.flush(); os.fsync(f.fileno())
        self._events.append(ev); self._state.apply(ev)
        return ev

    def _get(self, seq: int, type_: str) -> dict:
        if not (1 <= seq <= len(self._events)) or self._events[seq - 1]["type"] != type_:
            raise PALError(f"seq {seq} is not a {type_} event")
        return self._events[seq - 1]

    def head(self) -> str:
        return self._events[-1]["event_hash"] if self._events else GENESIS

    # -- IDENTITY
    def identity(self, agent_id: str, model: str, model_version: str, source: str, session_id: str,
                 operator_type: str = "external", **extra) -> dict:
        """Register an agent. External agents may not use reserved names (qants-, mztest-; trimmed and
        case-insensitive, same rule as the hosted API). Internal (operator-run) agents may."""
        try:
            check_agent_id(agent_id, operator_type)
        except ReservedAgentIdError as e:
            raise PALError(str(e))
        except ValueError as e:
            raise PALError(str(e))
        return self._append("identity", agent_id, {"model": model, "model_version": model_version, "operator_type": operator_type,
                                                   "connection_source": source, "session_id": session_id, **extra})

    # -- AUTHORIZATION
    def approve(self, agent_id: str, approver: str, approval_type: str, levels: Iterable[str], permissions: Iterable[str],
                expires_at: Optional[str] = None, evidence_ref: Optional[str] = None, issued_at: Optional[str] = None) -> dict:
        levels, permissions = sorted(set(levels)), sorted(set(permissions))
        if approval_type not in POLICY["approval_types"]: raise PALError(f"unknown approval type {approval_type}")
        bad = [l for l in levels if l not in LEVELS] + [p for p in permissions if p not in PERMISSION_LEVEL]
        if bad: raise PALError(f"unknown levels/permissions {bad}")
        over = [p for p in permissions if p in CLOSED]
        if over:
            self._policy_breach(agent_id, "approve", over, approver)
            raise PolicyError(f"Mizan policy closes {over}; approval refused and logged as a critical violation")
        weak = [l for l in levels if approval_type not in POLICY["approval_types_by_level"][l]]
        if weak: raise PALError(f"level(s) {weak} cannot be approved with '{approval_type}'")
        stray = [p for p in permissions if PERMISSION_LEVEL[p] not in levels]
        if stray: raise PALError(f"permissions {stray} are outside the approved levels {levels} (no implied levels)")
        issued_at = issued_at or self._clock()
        _ts(issued_at)
        if expires_at is not None and _ts(expires_at) <= _ts(issued_at): raise PALError("expires_at must be after issued_at")
        body = {"approver": approver, "approval_type": approval_type, "scope": {"levels": levels, "permissions": permissions},
                "issued_at": issued_at, "expires_at": expires_at, "evidence_ref": evidence_ref}
        return self._append("approve", agent_id, body)

    # -- PERMISSIONS
    def grant(self, agent_id: str, permission: str, approval_seq: int, granted_by: str, tools: Optional[Iterable[str]] = None) -> dict:
        if permission not in PERMISSION_LEVEL or permission in CLOSED:
            self._policy_breach(agent_id, "grant", [permission], granted_by)
            raise PolicyError(f"{permission} is closed by Mizan policy; grant refused and logged as a critical violation")
        a = self._get(approval_seq, "approve")
        if a["agent_id"] != agent_id: raise PALError("approval belongs to another agent")
        if permission not in a["body"]["scope"]["permissions"]:
            self._append("deny", agent_id, {"reason": "outside_approval_scope", "request": "grant", "requested": [permission],
                                            "approval_seq": approval_seq, "by": granted_by})
            raise PALError(f"{permission} is outside approval seq {approval_seq}; refused and logged")
        if permission in POLICY["requires_allowlist"] and not tools:
            raise PALError(f"{permission} needs an explicit allowlist (tools, paths or commands)")
        body = {"permission": permission, "level": PERMISSION_LEVEL[permission], "approval_seq": approval_seq, "granted_by": granted_by}
        if tools: body["tools"] = sorted(set(tools))
        return self._append("grant", agent_id, body)

    def revoke(self, agent_id: str, grant_seq: int, revoked_by: str, reason: str = "") -> dict:
        g = self._get(grant_seq, "grant")
        if g["agent_id"] != agent_id: raise PALError("grant belongs to another agent")
        if grant_seq in self._state.revoked: raise PALError("grant already revoked")
        return self._append("revoke", agent_id, {"grant_seq": grant_seq, "permission": g["body"]["permission"],
                                                 "revoked_by": revoked_by, "reason": reason})

    def _policy_breach(self, agent_id, request, requested, actor):
        d = self._append("deny", agent_id, {"reason": "policy_bound", "request": request, "requested": requested, "by": actor})
        self._append("violation", agent_id, {"kind": "policy_bound", "request": request, "deny_seq": d["seq"], "requested": requested,
                                             "actor": actor, "severity": "critical"})

    # -- attempts (every action routed through Mizan)
    def attempt(self, agent_id: str, action: str, tool: Optional[str] = None, detail: Optional[dict] = None,
                note: Optional[str] = None, grant_seq: Optional[int] = None) -> dict:
        """Log an attempted action. Returns {"allowed", "attempt", "deny", "warning", "violation"}.

        Policy breach (closed permission) -> deny + critical violation.
        Anything else not granted (not_granted, revoked, expired, tool_not_allowed, foreign_permission,
        permission_mismatch) -> deny + warning with a note. No attempt is allowed without a live grant.
        """
        at = self._clock()
        ok, reason, eff = decide(self._state, agent_id, action, at, tool, grant_seq)
        body = {"action": action, "level": PERMISSION_LEVEL.get(action, "unknown"), "decision": "allowed" if ok else "denied",
                "evaluated_at": at, "permission_state_hash": permission_state_hash(agent_id, eff)}
        if grant_seq is not None: body["grant_seq"] = grant_seq
        if tool: body["tool"] = tool
        if detail: body["detail"] = detail
        a = self._append("attempt", agent_id, body)
        out = {"allowed": ok, "attempt": a, "deny": None, "warning": None, "violation": None}
        if not ok:
            out["deny"] = self._append("deny", agent_id, {"reason": reason, "request": "attempt", "attempt_seq": a["seq"]})
            if reason == "policy_bound":
                out["violation"] = self._append("violation", agent_id, {"kind": reason, "request": "attempt", "attempt_seq": a["seq"],
                                                                       "action": action, "actor": agent_id, "severity": "critical"})
            else:
                out["warning"] = self._append("warning", agent_id, {"kind": reason, "attempt_seq": a["seq"], "action": action,
                                                                   "note": (note or "").strip() or f"{action} attempted while {reason.replace('_', ' ')}"})
        return out

    # -- CLAIMS
    def claim(self, agent_id: str, prediction, p: float, data_sources: Optional[list] = None, method_version: Optional[str] = None,
              model_version: Optional[str] = None, commitment: Optional[str] = None, task_id: Optional[str] = None) -> dict:
        """A claim is an attempt to `predict` (and `commit_reveal` if a commitment is attached).

        The claim embeds the hash of the permission state in force at that moment. If the agent
        lacked the permission, no claim is recorded; deny + warning are logged instead.
        """
        p = float(p)
        if not 0.0 <= p <= 1.0: raise PALError("p must be in [0, 1]")
        for need in (["predict"] + (["commit_reveal"] if commitment else [])):
            r = self.attempt(agent_id, need, detail={"for": "claim"})
            if not r["allowed"]: return {"allowed": False, **{k: r[k] for k in ("attempt", "deny", "warning", "violation")}, "claim": None}
        at = self._events[-1]["ts"]
        eff = self._state.effective(agent_id, at)
        body = {"prediction": prediction, "p": round(p, 6), "data_sources": list(data_sources or []),
                "method_version": method_version, "model_version": model_version, "task_id": task_id,
                "commitment": commitment, "permission_state_hash": permission_state_hash(agent_id, eff),
                "permission_state_at": at, "effective_permissions": sorted(eff)}
        return {"allowed": True, "claim": self._append("claim", agent_id, body)}

    # -- ACCOUNTABILITY
    def resolve(self, claim_seq: int, outcome: int, actual=None, resolver: str = "unspecified", evidence_ref: Optional[str] = None) -> dict:
        c = self._get(claim_seq, "claim")
        if outcome not in (0, 1): raise PALError("outcome must be 0 or 1 (did the claim come true?)")
        if any(e["type"] == "resolve" and e["body"]["claim_seq"] == claim_seq for e in self._events): raise PALError("claim already resolved")
        p = c["body"]["p"]
        return self._append("resolve", c["agent_id"], {"claim_seq": claim_seq, "outcome": outcome, "actual": actual, "resolver": resolver,
                                                       "evidence_ref": evidence_ref, "squared_error": round((p - outcome) ** 2, 12)})

    def anchor(self, method: str = "opentimestamps", proof_ref: Optional[str] = None, status: str = "pending") -> dict:
        """Record an observation about external timestamping of the current head.

        Each anchor event is immutable. The *current* proof status is never stored by editing a hashed
        body: a later verification appends a new anchor event, and `proof_status()` derives the latest
        status per anchored head. Bulky proof bytes (.ots) live outside the chain, referenced by proof_ref."""
        if status not in ("pending", "verified", "failed"): raise PALError("bad anchor status")
        return self._append("anchor", None, {"head_hash": self.head(), "head_seq": len(self._events), "method": method,
                                             "proof_ref": proof_ref, "status": status})

    # -- views
    def record(self, agent_id: str, min_n: Optional[dict] = None) -> dict:
        return agent_record(self._events, agent_id, min_n)

    def permissions_as_of(self, agent_id: str, at: str) -> dict:
        """What the agent was allowed to do at time `at`, replayed from the append-only history."""
        return permissions_as_of(self._events, agent_id, at)

    def permission_history(self, agent_id: str) -> list:
        return permission_history(self._events, agent_id)


def permissions_as_of(events: list, agent_id: str, at: str) -> dict:
    st = _State()
    for e in events:
        if e["type"] in PERMISSION_EVENT_TYPES: st.apply(e)
    eff = st.effective(agent_id, at)
    return {"agent_id": agent_id, "as_of": at, "effective": eff, "state_hash": permission_state_hash(agent_id, eff)}


def permission_history(events: list, agent_id: str) -> list:
    """Every approve/grant/revoke for the agent, in order. Revocations are added events; grants stay."""
    return [{"seq": e["seq"], "ts": e["ts"], "type": e["type"], **e["body"]} for e in events
            if e.get("agent_id") == agent_id and e["type"] in ("approve", "grant", "revoke")]


def proof_status(events: list) -> dict:
    """Latest timestamp-proof status per anchored head hash, derived from anchor events (never stored mutably)."""
    out = {}
    for e in events:
        if e["type"] == "anchor":
            b = e["body"]
            out[b["head_hash"]] = {"head_seq": b["head_seq"], "status": b["status"], "method": b["method"],
                                   "proof_ref": b.get("proof_ref"), "observed_seq": e["seq"], "observed_at": e["ts"]}
    return out


# ---------------------------------------------------------------- verification
def _load_events(events_or_dir) -> list:
    if isinstance(events_or_dir, (str, Path)):
        p = Path(events_or_dir); p = p / "events.jsonl" if p.is_dir() else p
        return _read_jsonl(p)
    return list(events_or_dir)


def verify_pal(events_or_dir, authority=None) -> dict:
    """Offline verification: hash chain + replay of every decision and every claim's state hash.

    authority: optional independent permission ledger (events list or dir) kept by the operator.
    When given, every decision and claim is checked against the permissions in *that* ledger,
    not against whatever approve/grant/revoke events the submitter put in its own log (a claim is
    not proof). Any approve/grant/revoke in the submitted log that is absent from the authority
    is reported, and so is an authority revocation the submitted log omits.
    """
    events = _load_events(events_or_dir)
    errs = verify_chain(events, "event_hash")
    auth_state = None
    if authority is not None:
        auth_events = _load_events(authority)
        errs += [f"authority: {x}" for x in verify_chain(auth_events, "event_hash")]
        auth_state = _State()
        for a in auth_events:
            if a.get("type") in PERMISSION_EVENT_TYPES: auth_state.apply(a)
        auth_hashes = {a.get("event_hash") for a in auth_events if a.get("type") in PERMISSION_EVENT_TYPES}
        for e in events:
            if e.get("type") in ("approve", "grant", "revoke") and e.get("event_hash") not in auth_hashes:
                errs.append(f"seq {e.get('seq')}: {e.get('type')} not found in the independent permission ledger")
        sub_hashes = {e.get("event_hash") for e in events}
        last_ts = events[-1]["ts"] if events else None
        for a in auth_events:
            if a.get("type") == "revoke" and a.get("event_hash") not in sub_hashes and last_ts and _ts(a["ts"]) <= _ts(last_ts):
                errs.append(f"authority seq {a.get('seq')}: revoke missing from the submitted log")
    st, last, denied = _State(), None, {}
    for e in events:
        s, t, b = e.get("seq"), e.get("type"), e.get("body", {})
        try:
            if t not in EVENT_TYPES: errs.append(f"seq {s}: unknown type {t}"); continue
            if e.get("policy_hash") != POLICY_HASH: errs.append(f"seq {s}: policy hash differs from this verifier's policy")
            if last and _ts(e["ts"]) < _ts(last): errs.append(f"seq {s}: timestamp goes backwards")
            last = e["ts"]
            leaked = find_secrets({"agent_id": e.get("agent_id"), "body": b})
            if leaked: errs.append(f"seq {s}: credential-shaped value in a public event ({', '.join(leaked)})")
            if t == "identity":
                if b.get("operator_type", "external") not in OPERATOR_TYPES: errs.append(f"seq {s}: unknown operator_type")
                elif "operator_type" in b:
                    try: check_agent_id(e["agent_id"], b["operator_type"])
                    except ValueError: errs.append(f"seq {s}: external identity uses a reserved agent_id")
            elif t == "grant":
                if b["permission"] in CLOSED: errs.append(f"seq {s}: grant of closed permission")
                if b["permission"] in POLICY["requires_allowlist"] and not b.get("tools"): errs.append(f"seq {s}: grant without allowlist")
                a = st.approvals.get(b["approval_seq"])
                if not a or a["agent_id"] != e["agent_id"] or b["permission"] not in a["body"]["scope"]["permissions"]:
                    errs.append(f"seq {s}: grant not covered by its approval")
            elif t == "approve":
                sc = b["scope"]
                if any(p in CLOSED for p in sc["permissions"]): errs.append(f"seq {s}: approval of closed permission")
                if any(b["approval_type"] not in POLICY["approval_types_by_level"].get(l, []) for l in sc["levels"]): errs.append(f"seq {s}: approval type too weak for its levels")
                if any(PERMISSION_LEVEL.get(p) not in sc["levels"] for p in sc["permissions"]): errs.append(f"seq {s}: approval permission outside its levels")
            elif t == "revoke":
                if b["grant_seq"] not in st.grants: errs.append(f"seq {s}: revoke of unknown grant")
            elif t == "attempt":
                ok, reason, eff = decide(auth_state or st, e["agent_id"], b["action"], b["evaluated_at"], b.get("tool"), b.get("grant_seq"))
                if ("allowed" if ok else "denied") != b["decision"]: errs.append(f"seq {s}: recorded decision does not match replay")
                if permission_state_hash(e["agent_id"], eff) != b["permission_state_hash"]: errs.append(f"seq {s}: permission state hash mismatch")
                if not ok: denied[s] = reason
            elif t in ("deny", "violation", "warning") and "attempt_seq" in b:
                if b["attempt_seq"] not in denied: errs.append(f"seq {s}: {t} references an attempt that was not denied")
                elif t == "violation" and denied[b["attempt_seq"]] != "policy_bound": errs.append(f"seq {s}: violation for a non-policy denial (must be a warning)")
                elif t == "warning" and (denied[b["attempt_seq"]] == "policy_bound" or not str(b.get("note", "")).strip()):
                    errs.append(f"seq {s}: warning must have a note and must not downgrade a policy breach")
            elif t == "claim":
                eff = (auth_state or st).effective(e["agent_id"], b["permission_state_at"])
                if permission_state_hash(e["agent_id"], eff) != b["permission_state_hash"]: errs.append(f"seq {s}: claim permission state hash mismatch")
                if "predict" not in eff: errs.append(f"seq {s}: claim recorded without predict permission")
                if b.get("commitment") and "commit_reveal" not in eff: errs.append(f"seq {s}: commitment without commit_reveal permission")
            elif t == "resolve":
                c = events[b["claim_seq"] - 1] if 1 <= b["claim_seq"] <= len(events) else None
                if not c or c["type"] != "claim" or c["seq"] >= s: errs.append(f"seq {s}: resolve of unknown/later claim")
                elif abs(b["squared_error"] - (c["body"]["p"] - b["outcome"]) ** 2) > 1e-9: errs.append(f"seq {s}: score mismatch")
        except (KeyError, TypeError, ValueError) as ex:
            errs.append(f"seq {s}: malformed event ({ex.__class__.__name__}: {ex})")
        st.apply(e)
    for a_seq, reason in denied.items():
        kinds = {e["type"] for e in events if e.get("body", {}).get("attempt_seq") == a_seq}
        need = {"deny", "violation" if reason == "policy_bound" else "warning"}
        if not need <= kinds: errs.append(f"attempt seq {a_seq}: denied without {'+'.join(sorted(need))} events")
    return {"ok": not errs, "errors": errs, "events": len(events), "head": events[-1]["event_hash"] if events else GENESIS}


# ---------------------------------------------------------------- trust indicators (never collapsed)
DEFAULT_MIN_N = {"prediction_accuracy": metrics.MIN_RATED_N, "permission_compliance": 20, "transparency": 20, "historical_reliability": 3}


def _flag(n: int, threshold: int) -> dict:
    return {"n": n, "threshold": threshold, "insufficient_data": n < threshold}


def trust_indicators(events: list, agent_id: str, min_n: Optional[dict] = None, windows: int = 4, min_per_window: int = 5) -> dict:
    """Four separate indicators. There is deliberately no combined score."""
    th = {**DEFAULT_MIN_N, **(min_n or {})}
    mine = [e for e in events if e.get("agent_id") == agent_id]
    claims = {e["seq"]: e for e in mine if e["type"] == "claim"}
    res = sorted([e for e in mine if e["type"] == "resolve" and e["body"]["claim_seq"] in claims], key=lambda e: claims[e["body"]["claim_seq"]]["ts"])
    pairs = [(claims[r["body"]["claim_seq"]]["body"]["p"], r["body"]["outcome"]) for r in res]

    acc = _flag(len(pairs), th["prediction_accuracy"])
    acc.update({"brier": metrics.brier(pairs), "ece": metrics.ece(pairs)} if pairs else {"brier": None, "ece": None})
    acc.update({"n_declared": len(claims), "n_resolved": len(pairs), "n_pending": len(claims) - len(pairs),
                "rating": metrics.rating(len(pairs), th["prediction_accuracy"])})

    attempts = [e for e in mine if e["type"] == "attempt"]
    viol = [e for e in mine if e["type"] == "violation" and e["body"].get("request") == "attempt"]
    warn = [e for e in mine if e["type"] == "warning"]
    ops = [e for e in mine if e["type"] == "violation" and e["body"].get("request") in ("grant", "approve")]
    comp = _flag(len(attempts), th["permission_compliance"])
    comp.update({"compliance_rate": (1 - len(viol) / len(attempts)) if attempts else None,
                 "warning_rate": (len(warn) / len(attempts)) if attempts else None,
                 "critical_violations": len(viol), "warnings": len(warn),
                 "warnings_by_kind": {k: sum(1 for v in warn if v["body"]["kind"] == k) for k in sorted({v["body"]["kind"] for v in warn})},
                 "operator_policy_breaches": len(ops),
                 "definition": "compliance_rate = 1 - critical violations / attempts; warnings (not granted, not a policy breach) are reported separately",
                 "scope": "actions routed through Mizan only"})

    transparent = [c for c in claims.values() if c["body"]["data_sources"] and c["body"]["method_version"]]
    tr = _flag(len(claims), th["transparency"])
    tr["share_with_sources_and_method"] = (len(transparent) / len(claims)) if claims else None

    chunks = []
    if len(pairs) >= windows * min_per_window:
        size = len(pairs) // windows
        chunks = [pairs[i * size:(i + 1) * size] if i < windows - 1 else pairs[i * size:] for i in range(windows)]
    hist = _flag(len(chunks), th["historical_reliability"])
    if chunks:
        bs = [metrics.brier(c) for c in chunks]
        m = sum(bs) / len(bs)
        hist.update({"window_brier": bs, "brier_spread": max(bs) - min(bs), "brier_std": (sum((b - m) ** 2 for b in bs) / len(bs)) ** 0.5,
                     "method": f"{windows} equal-count windows of resolved claims in time order"})
    else:
        hist.update({"window_brier": [], "brier_spread": None, "brier_std": None,
                     "method": f"needs >= {windows * min_per_window} resolved claims for {windows} windows"})
    return {"prediction_accuracy": acc, "permission_compliance": comp, "transparency": tr, "historical_reliability": hist,
            "note": "Four separate indicators; PAL never combines them into one number."}


def agent_record(events: list, agent_id: str, min_n: Optional[dict] = None) -> dict:
    """The five-layer accountability record for one agent, derived from the event log."""
    st = _State()
    for e in events: st.apply(e)
    mine = [e for e in events if e.get("agent_id") == agent_id]
    at = events[-1]["ts"] if events else _now()
    eff = st.effective(agent_id, at)
    agent_viol = [e for e in mine if e["type"] == "violation" and e["body"].get("request") == "attempt"]
    warns = [e for e in mine if e["type"] == "warning"]
    status = "VIOLATIONS_RECORDED" if agent_viol else ("COMPLIANT_WITH_WARNINGS" if warns else "COMPLIANT")
    resolved = {e["body"]["claim_seq"]: e for e in mine if e["type"] == "resolve"}
    anchors = [e for e in events if e["type"] == "anchor"]
    ver = verify_pal(events)
    return {
        "schema": PAL_SCHEMA, "agent_id": agent_id, "as_of": at,
        "identity": (st.identity.get(agent_id) or {}).get("body"),
        "permissions": {"effective": eff, "state_hash": permission_state_hash(agent_id, eff),
                        "closed_by_policy": sorted(CLOSED),
                        "history": [{"seq": e["seq"], "ts": e["ts"], "type": e["type"], **e["body"]} for e in mine if e["type"] in ("grant", "revoke")]},
        "authorization": [{"seq": e["seq"], **e["body"]} for e in mine if e["type"] == "approve"],
        "claims": [{"seq": c["seq"], "ts": c["ts"], **c["body"], "resolution": (resolved.get(c["seq"]) or {}).get("body")} for c in mine if c["type"] == "claim"],
        "accountability": {
            "compliance": status,
            "violations": [{"seq": e["seq"], "ts": e["ts"], **e["body"]} for e in agent_viol],
            "warnings": [{"seq": e["seq"], "ts": e["ts"], **e["body"]} for e in warns],
            "operator_policy_breaches": [{"seq": e["seq"], "ts": e["ts"], **e["body"]} for e in mine
                                         if e["type"] == "violation" and e["body"].get("request") in ("grant", "approve")],
            "indicators": trust_indicators(events, agent_id, min_n),
            "chain": {"ok": ver["ok"], "head_sha256": ver["head"], "events": ver["events"]},
            "timestamp_proof": {"clock": "local (self-reported)", "anchor": anchors[-1]["body"]["status"] if anchors else "none",
                                "by_head": proof_status(events)},
            "observability": "Only actions routed through Mizan are visible to PAL.",
        },
    }
