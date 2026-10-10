"""Statistical anomaly detectors. Pure functions over normalized events; deterministic for a given input."""
from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime
from typing import Iterable

BUCKET_SECONDS = 300
MIN_BUCKETS = 6          # baseline needs at least this many buckets of history
MIN_BASELINE_EVENTS = 5  # per-user events needed before "new IP" means anything
Z_THRESHOLD = 4.0        # robust z-score (median/MAD)
MIN_BURST = 4            # ignore spikes smaller than this many events
FAIL_TYPES = {"login_failed", "authz_denied"}


def _ts(e: dict) -> float:
    return datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()


def rate_spikes(events: Iterable[dict]) -> list[dict]:
    """Per-user failure counts in 5-minute buckets; flag buckets far above the user's own median (robust z-score).

    The baseline is the user's bucket counts *including zeros* between their first and last activity, so a
    quiet account that suddenly produces a burst scores high, while a chronically noisy one does not.
    """
    by_user: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("user") and e["type"] in FAIL_TYPES:
            by_user[e["user"]].append(e)
    out = []
    for user, evs in sorted(by_user.items()):
        buckets: dict[int, list[dict]] = defaultdict(list)
        for e in evs:
            buckets[int(_ts(e) // BUCKET_SECONDS)].append(e)
        lo, hi = min(buckets), max(buckets)
        # include the user's login activity span so quiet time counts as zeros
        span = range(lo, hi + 1)
        if len(span) < MIN_BUCKETS:
            span = range(lo, lo + MIN_BUCKETS)
        counts = [len(buckets.get(b, [])) for b in span]
        med = statistics.median(counts)
        mad = statistics.median([abs(c - med) for c in counts]) or 0.5   # floor avoids division by zero on flat baselines
        for b in sorted(buckets):
            n = len(buckets[b])
            z = 0.6745 * (n - med) / mad
            if n >= MIN_BURST and z >= Z_THRESHOLD:
                evs_b = sorted(buckets[b], key=lambda e: (e["timestamp"], e["id"]))
                out.append({
                    "kind": "rate_spike", "subject": f"user:{user}", "score": round(z, 2),
                    "eventIds": [e["id"] for e in evs_b],
                    "explanation": f"{n} failures for {user} in one {BUCKET_SECONDS // 60}-minute bucket vs a median of {med:g} "
                                   f"(robust z={z:.1f}, threshold {Z_THRESHOLD:g}).",
                })
    return out


def new_source_ip(events: Iterable[dict]) -> list[dict]:
    """Flag a user's login activity from an IP never seen before once they have an established baseline."""
    evs = sorted((e for e in events if e.get("user") and e.get("ip") and e["type"].startswith("login")),
                 key=lambda e: (e["timestamp"], e["id"]))
    seen: dict[str, dict[str, int]] = defaultdict(dict)
    count: dict[str, int] = defaultdict(int)
    out = []
    for e in evs:
        u, ip = e["user"], e["ip"]
        if count[u] >= MIN_BASELINE_EVENTS and ip not in seen[u] and e["type"] == "login_success":
            known = ", ".join(sorted(seen[u])[:3])
            out.append({
                "kind": "new_source_ip", "subject": f"user:{u}", "score": 1.0, "eventIds": [e["id"]],
                "explanation": f"Successful login for {u} from {ip}, never seen in {count[u]} earlier login events (known: {known}).",
            })
        seen[u][ip] = seen[u].get(ip, 0) + 1
        count[u] += 1
    return out


def detect(events: list[dict]) -> list[dict]:
    return rate_spikes(events) + new_source_ip(events)
