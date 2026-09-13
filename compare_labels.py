"""
Measure automated labels against a human baseline.

Reads two decision files over the same groups and reports agreement -- overall,
per class, and specifically on the direction of disagreement. The last of those
is the one that matters: this project's primary metric is under-call rate, so
automation that errs toward `none` is a different and worse problem than
automation that errs toward `critical`.

    python3 compare_labels.py --human blind_labels.json --auto labels_attack.json
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

ORDER = ["drop", "none", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(ORDER)}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious", "drop": "drop"}


def key(v):
    return v["severity"] or "drop"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--human", default="blind_labels.json")
    ap.add_argument("--auto", default="labels_attack.json")
    ap.add_argument("--queue", default="triage_queue.jsonl")
    ap.add_argument("--show", type=int, default=12,
                    help="how many disagreements to print")
    args = ap.parse_args()

    human = json.loads(Path(args.human).read_text())
    auto = json.loads(Path(args.auto).read_text())
    shared = [s for s in human if s in auto]
    if not shared:
        print("no overlapping groups -- nothing to compare")
        return

    reps = {}
    for line in open(args.queue):
        r = json.loads(line)
        if r["signature"] in human and r["signature"] not in reps:
            reps[r["signature"]] = r

    exact = sum(1 for s in shared if key(human[s]) == key(auto[s]))
    bexact = sum(1 for s in shared
                 if BUCKET[key(human[s])] == BUCKET[key(auto[s])])
    print(f"compared {len(shared)} groups\n")
    print(f"exact severity agreement: {exact}/{len(shared)} = {exact/len(shared):.0%}")
    print(f"3-class agreement:        {bexact}/{len(shared)} = {bexact/len(shared):.0%}")

    under = [s for s in shared if RANK[key(auto[s])] < RANK[key(human[s])]]
    over = [s for s in shared if RANK[key(auto[s])] > RANK[key(human[s])]]
    print(f"\nautomation under-called (softer than you): {len(under)}"
          f"  <-- the costly direction")
    print(f"automation over-called  (harsher than you): {len(over)}")

    print("\nconfusion (rows = your label, cols = automation):")
    conf = defaultdict(Counter)
    for s in shared:
        conf[key(human[s])][key(auto[s])] += 1
    present = [c for c in ORDER if any(conf[r][c] for r in ORDER) or conf[c]]
    print(f"{'':<10}" + "".join(f"{c:<10}" for c in present))
    for r in present:
        print(f"{r:<10}" + "".join(f"{conf[r][c]:<10}" for c in present))

    if under or over:
        print(f"\ndisagreements (showing up to {args.show}):")
        for s in (under + over)[:args.show]:
            rep = reps.get(s)
            print(f"\n  you={key(human[s]):<9} auto={key(auto[s]):<9} "
                  f"rule={auto[s].get('rule')}")
            if rep:
                print(f"  {rep['src']}")
                for line in rep["event"].splitlines()[:5]:
                    print(f"    {line[:110]}")


if __name__ == "__main__":
    main()
