"""
Hand-verify the held-out eval set.

Every number this project reports -- the 48% baseline, the 38% under-call
rate, the >=80% target -- is computed against 50 labels. 32 of those were
assigned by the same generator that wrote the events, which makes the
measuring stick partly circular: it would confirm that the model agrees with
our rules, not that it detects threats.

This shows all 50 events with the label hidden and records your judgement,
then reports where you and the current labels differ and offers to adopt
yours. Ten minutes, and it is the difference between a metric and a mirror.

    python3 verify_eval.py                 # verify (resumable)
    python3 verify_eval.py --report        # compare, change nothing
    python3 verify_eval.py --apply         # adopt your labels

Keys
    1 none    2 low    3 medium    4 high
    s skip    u undo    n/p nav    ? show why it is currently labelled that way
    q save and quit
"""

import argparse
import json
import sys
import termios
import tty
from collections import Counter, defaultdict
from pathlib import Path

SEV = {"1": "none", "2": "low", "3": "medium", "4": "high"}
ORDER = ["none", "low", "medium", "high"]
RANK = {s: i for i, s in enumerate(ORDER)}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious", "high": "malicious"}
C = {"r": "\033[0m", "b": "\033[1m", "d": "\033[2m", "grn": "\033[32m",
     "yel": "\033[33m", "red": "\033[31m", "cyn": "\033[36m", "mag": "\033[35m"}
SEVC = {"none": C["grn"], "low": C["grn"], "medium": C["yel"], "high": C["red"]}


def getkey():
    if not sys.stdin.isatty():
        return (sys.stdin.readline().strip() or "q")[:1]
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if ch == "\x03":
        raise KeyboardInterrupt
    return ch


def load(path):
    return [json.loads(l) for l in open(path) if l.strip()]


def report(rows, mine):
    shared = [r for r in rows if r["id"] in mine]
    if not shared:
        print("nothing verified yet")
        return []
    same = [r for r in shared if mine[r["id"]] == r["severity"]]
    bshift = [r for r in shared
              if BUCKET[mine[r["id"]]] != BUCKET[r["severity"]]]
    print(f"\nverified {len(shared)}/{len(rows)}")
    print(f"  exact severity agrees : {len(same)}/{len(shared)} = {len(same)/len(shared):.0%}")
    print(f"  routing class changes : {len(bshift)}   <- these move the metrics")
    conf = defaultdict(Counter)
    for r in shared:
        conf[r["severity"]][mine[r["id"]]] += 1
    present = [s for s in ORDER if conf[s] or any(conf[x][s] for x in ORDER)]
    if present:
        print(f"\n  {'current':<10}" + "".join(f"{s:<9}" for s in present) + "  (cols = yours)")
        for s in present:
            print(f"  {s:<10}" + "".join(f"{conf[s][t]:<9}" for t in present))
    if bshift:
        print("\n  events whose routing class you changed:")
        for r in bshift:
            img = next((l.split(": ", 1)[1] for l in r["event"].splitlines()
                        if l.startswith("Image:")), r["event"].splitlines()[1])
            print(f"    {r['id']:<7} {r['severity']:<7} -> {mine[r['id']]:<7} "
                  f"{BUCKET[r['severity']]:<10} -> {BUCKET[mine[r['id']]]:<10} {img[:52]}")
    return bshift


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-set", default="eval_set_v2.jsonl")
    ap.add_argument("--out", default="eval_verified.json")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--rule", choices=["human", "max"], default="max",
                    help="how to resolve a disagreement. `human` adopts your "
                         "label outright. `max` (default) takes the higher of "
                         "yours and the existing one -- not a judgement call, "
                         "but a consequence of the PRD setting malicious recall "
                         ">=90%% and under-call <=10%%: when two labellers "
                         "disagree, the cautious label wins.")
    ap.add_argument("--also", nargs="*", default=[],
                    help="other eval files to apply the same per-id labels to")
    ap.add_argument("--review", action="store_true", help="revisit ones you already did")
    args = ap.parse_args()

    rows = load(args.eval_set)
    out = Path(args.out)
    mine = json.loads(out.read_text()) if out.exists() else {}

    if args.report or args.apply:
        shift = report(rows, mine)
        if args.apply:
            if len(mine) < len(rows):
                print(f"\nrefusing: only {len(mine)}/{len(rows)} verified. "
                      f"Finish the pass first, or the set ends up half one "
                      f"judgement and half another.")
                return
            # the 5-way files carry `critical`, which the human pass could not
            # reach; rank it above `high` so `max` still resolves correctly
            FULL = ["none", "low", "medium", "high", "critical"]
            FR = {s: i for i, s in enumerate(FULL)}
            FB = dict(BUCKET, critical="malicious")

            def resolve(cur, human):
                return human if args.rule == "human" else (
                    cur if FR[cur] >= FR[human] else human)

            for path in [args.eval_set] + args.also:
                f = Path(path)
                if not f.exists():
                    print(f"  skip {path} (missing)")
                    continue
                rs = load(path)
                changed = 0
                for r in rs:
                    if r["id"] not in mine:
                        continue
                    new = resolve(r["severity"], mine[r["id"]])
                    if new != r["severity"]:
                        changed += 1
                    r["severity"] = new
                    r["gold"] = FB[new]
                    r["provenance"]["label_rule"] = f"{args.rule}(generator, human-blind)"
                f.write_text("\n".join(json.dumps(r) for r in rs) + "\n")
                print(f"  {path:<28} {changed:>2} changed   "
                      f"{dict(Counter(r['gold'] for r in rs))}")
            print(f"\nrule: {args.rule}")
            print("STALE — re-measure before trusting: base_v2_*.json")
        return

    # deterministic shuffle so class order carries no hint
    work = sorted(rows, key=lambda r: r["id"])
    import random
    random.Random("osava-verify").shuffle(work)
    if not args.review:
        work = [r for r in work if r["id"] not in mine]
    if not work:
        print("all 50 already verified. Run --report to compare, --apply to adopt.")
        return

    print(f"{len(work)} to verify. Labels are hidden. Any key to start.")
    getkey()

    i, hist, why = 0, [], False
    while 0 <= i < len(work):
        r = work[i]
        print("\033[H\033[J", end="")
        print(f"{C['d']}{i+1}/{len(work)}   verified {len(mine)}/{len(rows)}{C['r']}")
        print("-" * 74)
        for line in r["event"].splitlines():
            k, v = line.split(":", 1)
            hl = C["cyn"] if k in ("CommandLine", "ParentCommandLine", "TargetFilename") else ""
            print(f"  {C['d']}{k}:{C['r']} {hl}{v.strip()[:170]}{C['r']}")
        print("-" * 74)
        if why:
            p = r["provenance"]
            print(f"  {C['d']}source: {p['source'][:66]}{C['r']}")
            if p.get("attck", "-") != "-":
                print(f"  {C['d']}att&ck: {p['attck']}{C['r']}")
            if p.get("rationale"):
                print(f"  {C['d']}note:   {p['rationale'][:100]}{C['r']}")
            print(f"  {C['b']}currently labelled: "
                  f"{SEVC[r['severity']]}{r['severity']}{C['r']}")
        prev = mine.get(r["id"])
        if prev:
            print(f"\n  {C['b']}you said: {SEVC[prev]}{prev}{C['r']}")
        print(f"\n  {C['d']}1 none   2 low   3 medium   4 high"
              f"     s skip  u undo  n/p nav  ? why  q quit{C['r']}")

        k = getkey()
        why = False
        if k == "q":
            break
        elif k == "?":
            why = True
            continue
        elif k == "n" or k == "s":
            i += 1
        elif k == "p":
            i = max(0, i - 1)
        elif k == "u":
            if hist:
                eid, old = hist.pop()
                if old is None:
                    mine.pop(eid, None)
                else:
                    mine[eid] = old
                out.write_text(json.dumps(mine, indent=2))
                i = max(0, i - 1)
        elif k in SEV:
            hist.append((r["id"], mine.get(r["id"])))
            mine[r["id"]] = SEV[k]
            out.write_text(json.dumps(mine, indent=2))
            i += 1

    out.write_text(json.dumps(mine, indent=2))
    print("\033[H\033[J", end="")
    print(f"saved {out}: {len(mine)}/{len(rows)} verified")
    if len(mine) == len(rows):
        report(rows, mine)
        print(f"\nAll 50 done. Review the table above, then:")
        print(f"  python3 verify_eval.py --apply")
    else:
        print(f"{len(rows)-len(mine)} left. Re-run to continue.")


if __name__ == "__main__":
    main()
