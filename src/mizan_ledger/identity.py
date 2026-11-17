"""Agent id rules shared by the ledger, PAL and the hosted API.

Reserved names match the live hosted rule (POST /v1/keys, 17 Nov 2026): an id is normalised
with trim + casefold before the check, and the prefixes ``qants-`` and ``mztest-`` plus the exact
QANTS-operated ids are reserved. A public (external) caller may not claim them. This is a name
rule, not proof of who operates an agent.
"""
from __future__ import annotations

RESERVED_PREFIXES = ("qants-", "mztest-")
QANTS_OPERATED_IDS = ("qants-hybrid", "qants-blockchain-first-principles")
OPERATOR_TYPES = ("internal", "external")


class ReservedAgentIdError(ValueError):
    """An external agent tried to use a name reserved for QANTS-operated or test agents."""


def normalize_agent_id(agent_id) -> str:
    """Trim surrounding whitespace and casefold (so ' QANTS-x' and 'Qants-x' compare equal to 'qants-x')."""
    return str(agent_id or "").strip().casefold()


def is_reserved_agent_id(agent_id) -> bool:
    n = normalize_agent_id(agent_id)
    return n in QANTS_OPERATED_IDS or any(n.startswith(p) for p in RESERVED_PREFIXES)


def is_qants_operated(agent_id) -> bool:
    """Name rule used to keep internal agents out of external counts (same as the hosted API)."""
    return is_reserved_agent_id(agent_id)


def check_agent_id(agent_id, operator_type: str = "external") -> str:
    """Return the id unchanged if allowed for this operator type, else raise.

    External agents may not use a reserved name. Internal agents (the operator path) may.
    """
    if operator_type not in OPERATOR_TYPES:
        raise ValueError(f"operator_type must be one of {OPERATOR_TYPES}")
    if not normalize_agent_id(agent_id):
        raise ValueError("agent_id is required")
    if operator_type == "external" and is_reserved_agent_id(agent_id):
        raise ReservedAgentIdError(
            f"agent_id {agent_id!r} is reserved: names starting with {' or '.join(RESERVED_PREFIXES)} "
            "(case-insensitive, surrounding spaces ignored) are for QANTS-operated and test agents")
    return agent_id
