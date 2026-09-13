"""
The PRD success metrics, computed from run_eval.py output.

    python3 run_eval.py --prompt strict --eval-set eval_set_v2.jsonl --out ft_v1.json
    python3 report.py base_v3_strict.json ft_v1.json

Exists so the Monday numbers are reproducible instead of arithmetic done by
hand in a chat window. Targets are the PRD's, not aspirations set after
seeing the results.
"""

import argparse
import json
from pathlib import Path

CLASSES = ["benign", "suspicious", "malicious"]
RANK = {c: i for i, c in enumerate(CLASSES)}
TARGET = {"bucketed accuracy": (0.80, "ge"), "under-call rate": (0.10, "le"),
          "MISSED THREAT rate": (0.05, "le"),
          "over-call rate": (0.20, "le"), "malicious recall": (0.90, "ge"),
          "suspicious recall": (None, None), "benign precision": (None, None),
          "mean margin (correct)": (None, None), "mean margin (wrong)": (None, None)}


def metrics(res):
    res = [r for r in res if r["gold"] in RANK]
    n = len(res) or 1
    m = {}
    m["bucketed accuracy"] = sum(r["pred"] == r["gold"] for r in res) / n
    m["under-call rate"] = sum(RANK[r["pred"]] < RANK[r["gold"]] for r in res) / n
    m["over-call rate"] = sum(RANK[r["pred"]] > RANK[r["gold"]] for r in res) / n
    for c in ("malicious", "suspicious"):
        g = [r for r in res if r["gold"] == c]
        m[f"{c} recall"] = (sum(r["pred"] == c for r in g) / len(g)) if g else float("nan")
    # Not all under-calls cost the same. A malicious event called `suspicious`
    # still escalates under R7 margin routing -- an analyst sees it. A
    # malicious event called `benign` is dismissed silently and nobody ever
    # looks at it. The flat under-call rate scores those identically, which is
    # how a model can cut its dangerous misses by two thirds and show no
    # improvement at all.
    mal = [r for r in res if r["gold"] == "malicious"]
    m["MISSED THREAT rate"] = (sum(r["pred"] == "benign" for r in mal) / len(mal)) \
        if mal else float("nan")

    p = [r for r in res if r["pred"] == "benign"]
    m["benign precision"] = (sum(r["gold"] == "benign" for r in p) / len(p)) if p else float("nan")
    for lbl, ok in (("correct", True), ("wrong", False)):
        s = [r["margin"] for r in res if (r["pred"] == r["gold"]) is ok]
        m[f"mean margin ({lbl})"] = sum(s) / len(s) if s else float("nan")
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+", help="run_eval.py --out JSON files")
    ap.add_argument("--errors", action="store_true", help="list every miss in the last run")
    ap.add_argument("--subset", default=None,
                    help="restrict to one provenance.subset tag (e.g. v2-50). "
                         "Lets numbers measured on the original 50 stay "
                         "comparable after the eval set grew to 138.")
    ap.add_argument("--eval-set", default="eval_set_v3.jsonl",
                    help="source of the subset tags")
    ap.add_argument("--by-subset", action="store_true",
                    help="report every subset separately, then the whole set")
    args = ap.parse_args()

    # `gold` is snapshotted into each results file when the run happens, so a
    # run scored before a label correction keeps the label it saw. Predictions
    # do not change when a gold label does, so the current eval set is the
    # authority and stale golds are refreshed from it rather than silently
    # scoring against yesterday's answer key.
    tags, gold_now = {}, {}
    if Path(args.eval_set).exists():
        for line in Path(args.eval_set).read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                tags[r["id"]] = r.get("provenance", {}).get("subset", "-")
                gold_now[r["id"]] = r["gold"]

    def _refresh(res, label):
        n = 0
        for r in res:
            g = gold_now.get(r["id"])
            if g and g != r["gold"]:
                r["gold"], n = g, n + 1
        if n:
            print(f"  note: refreshed {n} stale gold label(s) in {label}")
        return res

    def load(f):
        res = _refresh(json.loads(Path(f).read_text()), Path(f).stem)
        if args.subset:
            res = [r for r in res if tags.get(r["id"]) == args.subset]
        return res

    if args.by_subset:
        for tag in sorted(set(tags.values())) + ["ALL"]:
            sel = {f: [r for r in _refresh(json.loads(Path(f).read_text()), Path(f).stem)
                       if tag == "ALL" or tags.get(r["id"]) == tag] for f in args.runs}
            n = len(next(iter(sel.values())))
            print(f"\n{'='*30} subset {tag}  (n={n})")
            runs = [(Path(f).stem, metrics(sel[f])) for f in args.runs]
            _table(runs)
        return

    runs = [(Path(f).stem, metrics(load(f))) for f in args.runs]
    if args.subset:
        print(f"\nsubset={args.subset}  n={len(load(args.runs[0]))}")
    _table(runs)

    hit = [k for k, (t, d) in TARGET.items() if t is not None
           and ((runs[-1][1][k] >= t) if d == "ge" else (runs[-1][1][k] <= t))]
    gated = [k for k, (t, _) in TARGET.items() if t is not None]
    print(f"\n{runs[-1][0]}: {len(hit)}/{len(gated)} gated metrics met"
          + (f" ({', '.join(hit)})" if hit else ""))

    if args.errors:
        res = load(args.runs[-1])
        bad = sorted((r for r in res if r["pred"] != r["gold"]),
                     key=lambda r: (RANK[r["pred"]] - RANK[r["gold"]], -r["margin"]))
        print(f"\n{len(bad)} misses in {runs[-1][0]} (worst under-calls first):")
        print(f"  {'id':<6}{'name':<30}{'gold':<11}{'pred':<11}{'sev':<9}{'marg':>7}")
        for r in bad:
            print(f"  {r['id']:<6}{r['name'][:29]:<30}{r['gold']:<11}{r['pred']:<11}"
                  f"{r['severity']:<9}{r['margin']:>7.3f}")


def _table(runs):
    w = max(len(k) for k in TARGET) + 2
    print(f"\n{'metric':<{w}}" + "".join(f"{n[:16]:>18}" for n, _ in runs) + f"{'target':>12}")
    print("-" * (w + 18 * len(runs) + 12))
    for k, (t, dirn) in TARGET.items():
        row = f"{k:<{w}}"
        for _, m in runs:
            v = m[k]
            pct = "margin" not in k
            row += f"{(f'{v:.1%}' if pct else f'{v:+.3f}'):>18}"
        tgt = "-" if t is None else (f"{'>=' if dirn == 'ge' else '<='}{t:.0%}")
        print(row + f"{tgt:>12}")


if __name__ == "__main__":
    main()
