"""Evaluate the statistical detectors against the labeled synthetic datasets (run from analytics/: python evaluate.py)."""
import json
import subprocess
from pathlib import Path

from app.detectors import detect

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "synthetic"

for name, ev, lb in [("dev", "events.json", "labels.json"), ("holdout", "holdout-events.json", "holdout-labels.json")]:
    labels = json.loads((DATA / lb).read_text())
    norm = json.loads(subprocess.check_output(["npx", "tsx", "scripts/dump-normalized.ts", str(DATA / ev)], cwd=ROOT / "api"))
    anomalies = detect([{k: e.get(k) for k in ("id", "timestamp", "type", "user", "ip")} for e in norm])
    mal_total = {k for k, v in labels["scenarios"].items() if v["malicious"]}
    for kind in ("rate_spike", "new_source_ip"):
        xs = [a for a in anomalies if a["kind"] == kind]
        tp = [a for a in xs if sum(labels["scenarios"][labels["events"][i]]["malicious"] for i in a["eventIds"]) > len(a["eventIds"]) / 2]
        hit = {labels["events"][i] for a in tp for i in a["eventIds"]} & mal_total
        print(f"{name:8} {kind:14} flagged={len(xs):3} on_malicious={len(tp):3} precision={len(tp) / len(xs) if xs else 0:.2f} "
              f"malicious_scenarios_touched={len(hit)}/{len(mal_total)}")
