"""Secret detection for anything written to a public, hash-chained record.

Matches real credential shapes (key prefixes, PEM blocks, JWTs, key=value assignments with a
long opaque value). The plain English word "secret" is NOT a match: "The secret to good
calibration is honesty" is fine. No pattern list is complete; this is a guard, not a guarantee.
"""
from __future__ import annotations
import json
import re

_PATTERNS = (
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b")),
    ("openai_style_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b")),
    ("stripe_key", re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("discord_webhook", re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*")),
    # key = value / "key": "value" where the key names a credential and the value is a long opaque string
    ("credential_assignment", re.compile(
        r"(?i)\b[\w-]*(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|"
        r"private[_-]?key|token|secret)\b[\"']?\s*[:=]\s*[\"']?(?=[A-Za-z0-9_\-+/=.]{16,})(?=[^\s\"']*\d)[A-Za-z0-9_\-+/=.]{16,}")),
)


def find_secrets(value) -> list:
    """Return the names of credential patterns found in a string or JSON-serialisable value."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)
    return sorted({name for name, rx in _PATTERNS if rx.search(text)})


def contains_secret(value) -> bool:
    return bool(find_secrets(value))
