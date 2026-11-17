"""mizan-ledger: confidence commitments and honesty scoring. Hash-only, local-first, offline-verifiable."""
from .core import (
    SCHEMA, Ledger, LedgerError, canonical_json, commitment_hash, fmt_p,
    verify_opening, verify_chain, verify_ledger_dir,
)
from .metrics import brier, log_loss, ece, accuracy_wilson, brier_interval, summarize, rating, brier_prior_baseline, MIN_RATED_N
from .identity import is_reserved_agent_id, check_agent_id, normalize_agent_id, ReservedAgentIdError
from .safety import find_secrets
from . import pal
from .pal import PermissionLedger, PolicyError, PALError, verify_pal, trust_indicators, agent_record

__version__ = "0.1.2"
__all__ = [
    "SCHEMA", "Ledger", "LedgerError", "canonical_json", "commitment_hash", "fmt_p",
    "verify_opening", "verify_chain", "verify_ledger_dir",
    "brier", "log_loss", "ece", "accuracy_wilson", "brier_interval", "summarize", "rating", "brier_prior_baseline", "MIN_RATED_N",
    "is_reserved_agent_id", "check_agent_id", "normalize_agent_id", "ReservedAgentIdError", "find_secrets",
    "pal", "PermissionLedger", "PolicyError", "PALError", "verify_pal", "trust_indicators", "agent_record",
]
