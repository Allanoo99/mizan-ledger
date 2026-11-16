"""Scoring helpers. Pure functions on lists of (p, outcome) with outcome in {0, 1}.

Conventions match the Mizan API: log loss clips p to [0.01, 0.99], ECE uses 10 equal-width bins.
"""
from __future__ import annotations
import math, random
from typing import Iterable, Sequence

LOG_LOSS_CLIP = (0.01, 0.99)


def _pairs(pairs: Iterable) -> list:
    out = []
    for p, y in pairs:
        p = float(p); y = 1 if y else 0
        if not (0.0 <= p <= 1.0):
            raise ValueError("p must be in [0, 1]")
        out.append((p, y))
    return out


def brier(pairs) -> float:
    xs = _pairs(pairs)
    if not xs: raise ValueError("no data")
    return sum((p - y) ** 2 for p, y in xs) / len(xs)


def log_loss(pairs) -> float:
    xs = _pairs(pairs)
    if not xs: raise ValueError("no data")
    lo, hi = LOG_LOSS_CLIP
    tot = 0.0
    for p, y in xs:
        q = min(hi, max(lo, p))
        tot += -(math.log(q) if y else math.log(1 - q))
    return tot / len(xs)


def ece(pairs, bins: int = 10) -> float:
    """Expected calibration error with equal-width bins; p == 1.0 falls in the last bin."""
    xs = _pairs(pairs)
    if not xs: raise ValueError("no data")
    buckets = [[] for _ in range(bins)]
    for p, y in xs:
        buckets[min(bins - 1, int(p * bins))].append((p, y))
    n = len(xs)
    return sum(len(b) / n * abs(sum(p for p, _ in b) / len(b) - sum(y for _, y in b) / len(b)) for b in buckets if b)


def reliability_table(pairs, bins: int = 10) -> list:
    xs = _pairs(pairs)
    buckets = [[] for _ in range(bins)]
    for p, y in xs:
        buckets[min(bins - 1, int(p * bins))].append((p, y))
    rows = []
    for i, b in enumerate(buckets):
        if b:
            rows.append({"bin": f"{i/bins:.1f}-{(i+1)/bins:.1f}", "n": len(b),
                         "mean_p": round(sum(p for p, _ in b) / len(b), 4),
                         "freq": round(sum(y for _, y in b) / len(b), 4)})
    return rows


def accuracy_wilson(pairs, z: float = 1.959964) -> dict:
    """Accuracy of thresholded predictions (p >= 0.5 -> 1) with a Wilson 95% interval."""
    xs = _pairs(pairs)
    n = len(xs)
    if not n: raise ValueError("no data")
    k = sum(1 for p, y in xs if (p >= 0.5) == bool(y))
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return {"accuracy": ph, "ci95": [max(0.0, c - h), min(1.0, c + h)], "n": n}


def brier_interval(pairs, reps: int = 2000, seed: int = 20261116) -> dict:
    """Percentile bootstrap 95% interval for the mean Brier score (deterministic seed)."""
    xs = _pairs(pairs)
    n = len(xs)
    if not n: raise ValueError("no data")
    sq = [(p - y) ** 2 for p, y in xs]
    mean = sum(sq) / n
    if n < 2:
        return {"brier": mean, "ci95": [None, None], "method": "bootstrap", "n": n}
    rng = random.Random(seed)
    means = sorted(sum(sq[rng.randrange(n)] for _ in range(n)) / n for _ in range(reps))
    return {"brier": mean, "ci95": [means[int(0.025 * reps)], means[int(0.975 * reps) - 1]], "method": f"percentile bootstrap, {reps} reps, seed {seed}", "n": n}


def summarize(pairs) -> dict:
    xs = _pairs(pairs)
    n = len(xs)
    if not n:
        return {"n": 0}
    base = sum(y for _, y in xs) / n
    bi = brier_interval(xs)
    return {
        "n": n,
        "base_rate": base,
        "brier": bi["brier"],
        "brier_ci95": bi["ci95"],
        "brier_ci_method": bi["method"],
        "brier_always_0.5": 0.25,
        "brier_base_rate_hindsight": base * (1 - base),  # in-sample best constant; a ceiling for "no skill" claims
        "log_loss": log_loss(xs),
        "ece": ece(xs),
        "accuracy": accuracy_wilson(xs),
        "reliability": reliability_table(xs),
        "note": "With small n the intervals are wide; ECE is biased upward for small n.",
    }
