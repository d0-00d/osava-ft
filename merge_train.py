"""
Assemble the final training set: real captures + the synthetic classes.

The real attack corpus supplies malicious and a lot of genuine benign, but it
has no `suspicious` at all -- nobody publishes captures of ambiguous admin
activity -- and its benign side is whatever happened to be running on the
sample author's VM. The generators fill both gaps.

Everything is filtered on behaviour signature against the eval set and against
what the real portion already contributes, so no behaviour is duplicated
across the split or within it.

    python3 merge_train.py --out train_final.jsonl
"""

import argparse
import collections
import json
from pathlib import Path

from build_train import load_eval_signatures
from signature import signature


def fields(body):
    return {k.strip(): v.strip() for k, v in
            (l.split(":", 1) for l in body.splitlines())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", default="train_real.jsonl")
    ap.add_argument("--synthetic", nargs="*",
                    default=["train_benign", "train_susp"])
    ap.add_argument("--eval-sets", nargs="*",
                    default=["eval_set_v2.jsonl", "eval_synthetic.jsonl"])
    ap.add_argument("--out", default="train_final.jsonl")
    ap.add_argument("--collapse-critical", action="store_true",
                    help="fold `critical` into `high`, producing a 4-way ordinal. "
                         "Two blind samples put the maintainer's use of `critical` "
                         "at 6/160 groups against the model's 22.7%%, and folding "
                         "the level lifts exact agreement from 48%% to 69%% -- the "
                         "level is not shared, so a classifier cannot learn it. "
                         "Train both and score them on the identical harness.")
    args = ap.parse_args()

    held = load_eval_signatures(args.eval_sets)
    rows = [json.loads(l) for l in open(args.real)]
    n_real = len(rows)
    seen = {r["provenance"]["signature"] for r in rows}

    added = skipped = 0
    for d in args.synthetic:
        p = Path(d)
        labels = json.loads((p / "labels.json").read_text())
        for eid, (name, gold, sev, why) in sorted(labels.items()):
            body = (p / f"{eid}.txt").read_text().strip()
            sig = signature(fields(body))
            if sig in held or sig in seen:
                skipped += 1
                continue
            seen.add(sig)
            rows.append({"id": eid, "name": name, "gold": gold, "severity": sev,
                         "event": body,
                         "provenance": {"source": f"synthetic:{d}",
                                        "signature": sig, "attck": "-",
                                        "rationale": why}})
            added += 1

    if args.collapse_critical:
        for r in rows:
            if r["severity"] == "critical":
                r["severity"] = "high"

    Path(args.out).write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    print(f"{args.out}: {n_real} real + {added} synthetic "
          f"(skipped {skipped} as eval-reserved or duplicate) = {len(rows)}")
    print("class:   ", dict(collections.Counter(r["gold"] for r in rows)))
    print("severity:", dict(collections.Counter(r["severity"] for r in rows)))
    leak = [r["id"] for r in rows if r["provenance"]["signature"] in held]
    print(f"eval overlap: {len(leak)}" + ("  LEAK" if leak else "  (clean)"))


if __name__ == "__main__":
    main()
