"""
Apply a batch of `Gxxxx=severity` decisions to a labels file.

Same output shape triage.py writes, so compare_labels.py and build_train.py
consume either without caring which produced it. Decisions are tagged
`decided_by: model` so provenance always records that a human did not read
this group -- the training set can be filtered on it later, and the eval set
must never contain it.

    python3 apply_batch.py --labels labels_auto.json < decisions.txt
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

VALID = {"none", "low", "medium", "high", "critical", "drop"}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious", "drop": "drop"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="labels_auto.json")
    ap.add_argument("--index", default="group_index.json")
    ap.add_argument("--queue", default="triage_queue.jsonl")
    args = ap.parse_args()

    index = json.loads(Path(args.index).read_text())
    counts = Counter()
    for line in open(args.queue):
        counts[json.loads(line)["signature"]] += 1

    out = Path(args.labels)
    labels = json.loads(out.read_text()) if out.exists() else {}

    n, bad = 0, []
    for raw in sys.stdin:
        raw = raw.split("#")[0].strip()
        if not raw:
            continue
        for tok in raw.split():
            if "=" not in tok:
                continue
            gid, sev = tok.split("=", 1)
            gid, sev = gid.strip(), sev.strip().lower()
            if gid not in index or sev not in VALID:
                bad.append(tok)
                continue
            sig = index[gid]
            labels[sig] = {"severity": None if sev == "drop" else sev,
                           "gold": BUCKET[sev], "decided_by": "model",
                           "gid": gid, "n": counts.get(sig, 0)}
            n += 1

    out.write_text(json.dumps(labels, indent=2))
    print(f"applied {n} decisions -> {out} ({len(labels)} total)")
    if bad:
        print(f"INVALID, ignored: {bad[:10]}")
    c = Counter(v["severity"] or "drop" for v in labels.values())
    print("severity:", dict(c))
    ev = Counter()
    for v in labels.values():
        ev[v["gold"]] += v["n"]
    print("events covered:", dict(ev))


if __name__ == "__main__":
    main()
