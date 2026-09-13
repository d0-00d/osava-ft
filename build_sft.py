"""
train_final.jsonl -> prompt/completion pairs for QLoRA.

Three things this does that a plain format-and-dump would not:

  target regeneration   `provenance.rationale` is a note about the corpus
                        ("unique to this capture"), not about the event. See
                        targets.py. Everything in the completion except
                        `severity` is recomputed from the event text.
  signature-disjoint val
                        The validation split is held out by behaviour
                        signature, not by row. Splitting by row puts near
                        duplicates on both sides and the val loss then measures
                        memorisation, which is the same mistake the eval set
                        was built to avoid.
  eval quarantine       Hard assert that no training signature appears in the
                        eval set. build_train.py enforces this for the real
                        captures; nothing enforced it for the synthetic ones
                        after merge_train.py, so it is enforced here for all.

    python3 build_sft.py --val-frac 0.08
"""

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from transformers import AutoTokenizer

import prompt as P
import targets
from signature import coarse_signature, signature


def sig_of(row):
    s = row.get("provenance", {}).get("signature")
    return s if s else signature(targets.parse(row["event"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="train_final.jsonl")
    ap.add_argument("--eval-set", default="eval_set_v2.jsonl")
    ap.add_argument("--model", default="HuggingFaceTB/SmolLM3-3B")
    ap.add_argument("--variant", choices=list(P.TAIL), default="strict")
    ap.add_argument("--scale", choices=list(P.SCALES), default="4way")
    ap.add_argument("--val-frac", type=float, default=0.08)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out-prefix", default="sft")
    args = ap.parse_args()

    rows = [json.loads(l) for l in Path(args.train).read_text().splitlines() if l.strip()]
    ev = [json.loads(l) for l in Path(args.eval_set).read_text().splitlines() if l.strip()]

    # --- quarantine
    ev_sig = {sig_of(r) for r in ev}
    ev_coarse = {coarse_signature(targets.parse(r["event"])) for r in ev}
    leaked = [r["id"] for r in rows if sig_of(r) in ev_sig]
    if leaked:
        raise SystemExit(f"{len(leaked)} training rows share an eval behaviour "
                         f"signature: {leaked[:10]}")
    coarse_hits = sum(1 for r in rows
                      if coarse_signature(targets.parse(r["event"])) in ev_coarse)
    print(f"eval quarantine: exact 0/{len(rows)} | "
          f"coarse (image+parent only) {coarse_hits}/{len(rows)} "
          f"= {coarse_hits/len(rows):.1%}")

    # --- split by signature, stratified by class
    rng = random.Random(args.seed)
    by_sig = defaultdict(list)
    for r in rows:
        by_sig[sig_of(r)].append(r)
    sigs_by_class = defaultdict(list)
    for s, rs in by_sig.items():
        sigs_by_class[Counter(r["gold"] for r in rs).most_common(1)[0][0]].append(s)
    val_sigs = set()
    for cls, ss in sigs_by_class.items():
        ss = sorted(ss)
        rng.shuffle(ss)
        want = max(1, round(len(ss) * args.val_frac))
        val_sigs.update(ss[:want])

    tok = AutoTokenizer.from_pretrained(args.model)
    split = {"train": [], "val": []}
    lens, bad = [], 0
    for r in rows:
        tgt = targets.build(r)
        if tgt["severity"] not in P.SCALES[args.scale]:
            bad += 1
            continue
        pr = P.build_prompt(tok, r["event"], args.variant, args.scale)
        comp = json.dumps(tgt, ensure_ascii=False)
        assert comp.startswith(P.PREFIX), comp[:40]      # R4: severity first
        lens.append(len(tok(pr + comp).input_ids))
        split["val" if sig_of(r) in val_sigs else "train"].append(
            {"prompt": pr, "completion": comp, "id": r["id"], "gold": r["gold"],
             "severity": tgt["severity"], "signature": sig_of(r)})

    if bad:
        print(f"dropped {bad} rows outside the {args.scale} scale "
              f"(re-run merge_train.py --collapse-critical)")

    for name, rs in split.items():
        p = Path(f"{args.out_prefix}_{name}.jsonl")
        p.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rs))
        c, s = Counter(r["gold"] for r in rs), Counter(r["severity"] for r in rs)
        print(f"{p}  {len(rs):5} rows  "
              f"{dict(sorted(c.items()))}  {dict(sorted(s.items()))}")

    assert not ({r["signature"] for r in split["train"]}
                & {r["signature"] for r in split["val"]}), "train/val signature overlap"
    lens.sort()
    print(f"\nsequence length  p50={lens[len(lens)//2]}  p95={lens[int(len(lens)*.95)]}  "
          f"max={lens[-1]}  (prompt is ~316 of these)")


if __name__ == "__main__":
    main()
