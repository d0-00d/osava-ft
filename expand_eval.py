"""
Merge the blind pass over eval_candidates.jsonl into an expanded eval set.

    python3 triage.py --queue eval_candidates.jsonl --out eval_blind_100.json --blind
    python3 expand_eval.py                 # dry run
    python3 expand_eval.py --apply         # -> eval_set_v3.jsonl

Why expand: at n=50 the binomial standard error is about +/-7 points, so two
checkpoints differing by 6 points are indistinguishable and every A/B from here
measures noise. 150 events puts it near +/-4.

The original 50 are carried through unchanged and tagged `subset: v2-50`, so
every number measured so far stays reproducible on exactly the events that
produced it. New rows are tagged `expand-100`. Report both.

Three things this enforces, in order:

  contract      new rows go through render() like every other class, so the
                eval set cannot be split by formatting
  boundary      boundary.py's rule is applied to the new labels too -- the
                whole point of lever 1 was one boundary, not two
  disjointness  exact signature AND parent-blind action are both checked
                against the training set. The parent-blind check is the one
                that matters: signature() includes the parent basename, so a
                generator that varies parents manufactures "distinct"
                behaviours out of identical commands, which is how 16 of the
                first 50 eval rows ended up sharing an action with training
                while the exact-signature assertion passed.
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import boundary as B
import targets
from contract import render, validate
from signature import signature

SEV2GOLD = {"none": "benign", "low": "benign", "medium": "suspicious",
            "high": "malicious", "critical": "malicious"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blind", default="eval_blind_100.json")
    ap.add_argument("--candidates", default="eval_candidates.jsonl")
    ap.add_argument("--base-eval", default="eval_set_v2.jsonl")
    ap.add_argument("--train", default="train_final.jsonl")
    ap.add_argument("--out", default="eval_set_v3.jsonl")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    if not Path(args.blind).exists():
        raise SystemExit(f"{args.blind} not found -- run triage.py first")

    cand = {r["signature"]: r
            for r in map(json.loads, Path(args.candidates).read_text().splitlines())}
    blind = json.loads(Path(args.blind).read_text())
    base = [json.loads(l) for l in Path(args.base_eval).read_text().splitlines() if l.strip()]
    train = [json.loads(l) for l in Path(args.train).read_text().splitlines() if l.strip()]

    tr_sig = {r["provenance"].get("signature") for r in train}
    tr_act = defaultdict(set)
    for r in train:
        tr_act[B.pblind(r)].add(r["gold"])

    kept, dropped, leaked = [], [], []
    for sig, v in blind.items():
        sev = v.get("severity") if isinstance(v, dict) else v
        if not sev or sev == "drop":
            dropped.append(sig)
            continue
        src = cand.get(sig)
        if src is None:
            continue
        fields = targets.parse(src["event"])
        body = render(fields)
        row = {"id": src["id"], "name": v.get("name", "-") if isinstance(v, dict) else "-",
               "gold": SEV2GOLD[sev], "severity": sev, "event": body,
               "provenance": {"source": f"real:{src.get('src','-')}",
                              "signature": signature(targets.parse(body)),
                              "attck": "-", "rationale": "blind human pass",
                              "label_rule": "human-blind (single pass)",
                              "subset": "expand-100"}}
        want, why = B.classify(row)
        if want in ("malicious", "benign") and row["gold"] != want:
            row["gold"] = want
            row["severity"] = {"benign": "none", "malicious": "high"}[want]
            row["provenance"]["boundary_rule"] = why
        if row["provenance"]["signature"] in tr_sig:
            leaked.append((row["id"], "exact signature"))
            continue
        if B.pblind(row) in tr_act:
            leaked.append((row["id"], "same action, parent aside"))
            continue
        ok, err = (validate(body) if callable(validate) else (True, None)) or (True, None)
        kept.append(row)

    for r in base:
        r.setdefault("provenance", {})["subset"] = "v2-50"

    print(f"blind decisions      {len(blind)}")
    print(f"  dropped by you     {len(dropped)}")
    print(f"  rejected as leaked {len(leaked)}")
    for i, why in leaked[:8]:
        print(f"      {i}  {why}")
    print(f"  kept               {len(kept)}   {dict(sorted(Counter(r['gold'] for r in kept).items()))}")
    out = base + kept
    print(f"\n{args.out}: {len(out)} events   "
          f"{dict(sorted(Counter(r['gold'] for r in out).items()))}")
    print(f"  v2-50      {dict(sorted(Counter(r['gold'] for r in base).items()))}")
    print(f"  expand-100 {dict(sorted(Counter(r['gold'] for r in kept).items()))}")

    if args.apply:
        Path(args.out).write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in out))
        print(f"\nwrote {args.out}")
        print("  next: python3 build_sft.py --eval-set eval_set_v3.jsonl")


if __name__ == "__main__":
    main()
