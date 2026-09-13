"""
Shortcut audit for the assembled sets.

Answers one question: can a class be predicted from something other than
behaviour? Three checks, in increasing order of how badly you want them to
fail to find anything.

  1. field presence      -- is `Signed` present iff benign? (R2)
  2. surface identifiers -- do hostnames / usernames separate the classes?
  3. unigram separability -- is there any single token that is near-perfectly
                            predictive of a class?

Run after any regeneration. A token with support >= 4 and purity >= 0.9 is a
shortcut the model will take instead of learning the technique.

    python3 audit_leak.py benign_events:benign suspicious_events:suspicious \
                          attack_events:malicious

A .jsonl is also accepted directly, which is the form that matters: the
directory-based invocation audits the *inputs* to merge_train.py, and the
capping and merging that happen after it can reintroduce a shortcut the
component sets did not have.

    python3 audit_leak.py train_final.jsonl
"""

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from contract import FIELD_ORDER


def load(spec):
    if spec.endswith(".jsonl"):
        import json
        return [(r["id"], r["gold"], r["event"]) for r in
                (json.loads(l) for l in Path(spec).read_text().splitlines() if l.strip())]
    d, cls = spec.split(":")
    return [(f.stem, cls, f.read_text()) for f in sorted(Path(d).glob("[A-Z]*.txt"))]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    events = [e for s in sys.argv[1:] for e in load(s)]
    classes = sorted({c for _, c, _ in events})
    n_by_cls = Counter(c for _, c, _ in events)
    print(f"{len(events)} events: {dict(n_by_cls)}\n")

    # 1. field presence -------------------------------------------------
    print("=== field presence by class (fraction of events) ===")
    pres = {c: Counter() for c in classes}
    for _, c, body in events:
        for line in body.splitlines():
            k = line.split(":", 1)[0].strip()
            if k in FIELD_ORDER:
                pres[c][k] += 1
    print(f"{'field':<22}" + "".join(f"{c:>13}" for c in classes) + "   spread")
    worst = []
    for f in FIELD_ORDER:
        fr = [pres[c][f] / n_by_cls[c] for c in classes]
        if max(fr) == 0:
            continue
        spread = max(fr) - min(fr)
        flag = "  <-- LEAK" if spread > 0.6 else ""
        if spread > 0.6:
            worst.append(f)
        print(f"{f:<22}" + "".join(f"{v:>13.2f}" for v in fr) + f"   {spread:.2f}{flag}")
    print()

    # 2. surface identifiers --------------------------------------------
    print("=== identifier overlap (hosts / accounts) ===")
    ids = defaultdict(set)
    for _, c, body in events:
        for line in body.splitlines():
            if line.startswith("User:"):
                ids[c].add(line.split(":", 1)[1].strip())
    for c in classes:
        others = set().union(*[ids[o] for o in classes if o != c]) if len(classes) > 1 else set()
        uniq = ids[c] - others
        print(f"  {c:<12} {len(ids[c]):>3} accounts, {len(uniq):>3} unique to class"
              + (f"  <-- {sorted(uniq)[:6]}" if uniq else ""))
    print()

    # 3. unigram separability -------------------------------------------
    print("=== single-token shortcuts (support>=4, purity>=0.90) ===")
    tokcount = defaultdict(Counter)
    doccount = Counter()
    for _, c, body in events:
        toks = set(t.lower() for t in re.findall(r"[A-Za-z0-9_.\-]{3,}", body))
        for t in toks:
            tokcount[t][c] += 1
            doccount[t] += 1
    found = 0
    for t, cnt in sorted(tokcount.items(), key=lambda kv: -sum(kv[1].values())):
        tot = sum(cnt.values())
        if tot < 4:
            continue
        top, k = cnt.most_common(1)[0]
        purity = k / tot
        # a token seen in most of one class and almost none of the others
        if purity >= 0.90 and k >= 4 and k / n_by_cls[top] >= 0.15:
            print(f"  {t:<34} {top:<12} {k}/{tot}  purity={purity:.2f}  "
                  f"covers {k/n_by_cls[top]:.0%} of class")
            found += 1
            if found >= 25:
                print("  ... (truncated)")
                break
    if not found:
        print("  none")
    print()
    # 4. one-sided binaries -------------------------------------------
    print("=== binaries that appear under a single class (support>=6) ===")
    from signature import basename
    img = defaultdict(Counter)
    for _, c, body in events:
        for line in body.splitlines():
            if line.startswith("Image:"):
                img[basename(line.split(":", 1)[1].strip())][c] += 1
    onesided = 0
    for b, c in sorted(img.items(), key=lambda kv: -sum(kv[1].values())):
        tot = sum(c.values())
        top, k = c.most_common(1)[0]
        if tot >= 6 and k / tot >= 0.85:
            print(f"  {b:<28} {dict(c)}")
            onesided += 1
            if onesided >= 12:
                print("  ...")
                break
    if not onesided:
        print("  none")
    print()

    if worst:
        print(f"ACTION: field-presence leak on {worst} -- fix before training.")
    else:
        print("field presence: OK")


if __name__ == "__main__":
    main()
