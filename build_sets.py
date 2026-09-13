"""
Assemble the held-out eval set and the reserved training pool.

Consumes the per-class directories (each with labels.json + manifest.tsv) plus
the nine original synthetic events, and emits:

    eval_set_v2.jsonl    the frozen held-out set, never trained on
    train_pool.jsonl     everything else, the seed for M3
    eval_synthetic.jsonl the original 9, scored separately for continuity with
                         the Round 1 / Round 2 baseline

The split is deterministic and stratified within template family, so both
sides see every family. That is the right choice for measuring in-distribution
accuracy and the wrong one for measuring generalisation to unseen techniques:
two events from the same generator family are not independent samples. Treat
eval numbers on the synthetic classes as an upper bound, and weight the
malicious class -- which comes from real captures -- more heavily when judging
whether the adapter actually learned anything.

    python3 build_sets.py --eval-n 50
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

from contract import validate

SEV_BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
              "high": "malicious", "critical": "malicious"}




def load_dir(d, source):
    p = Path(d)
    labels = json.loads((p / "labels.json").read_text())
    fam = {}
    for line in (p / "manifest.tsv").read_text().splitlines()[1:]:
        c = line.split("\t")
        if len(c) >= 7:
            fam[c[0]] = {"family": c[3], "attck": c[5], "src": c[1]}
    out = []
    for eid, (name, gold, sev, why) in sorted(labels.items()):
        body = (p / f"{eid}.txt").read_text().strip()
        errs = validate(body)
        if errs:
            raise SystemExit(f"{eid}: contract violation {errs}")
        assert SEV_BUCKET[sev] == gold, f"{eid}: severity {sev} != gold {gold}"
        m = fam.get(eid, {})
        out.append({"id": eid, "name": name, "gold": gold, "severity": sev,
                    "event": body,
                    "provenance": {"source": m.get("src", source),
                                   "family": m.get("family", "-"),
                                   "attck": m.get("attck", "-"),
                                   "rationale": why}})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-n", type=int, default=50)
    ap.add_argument("--suffix", default="")
    ap.add_argument("--benign", default="benign_events")
    ap.add_argument("--susp", default="suspicious_events")
    ap.add_argument("--attack", default="attack_events")
    args = ap.parse_args()

    sources = [(args.benign, "synthetic"), (args.susp, "synthetic"),
               (args.attack, "EVTX-ATTACK-SAMPLES")]
    rows = [r for d, s in sources for r in load_dir(d, s)]

    # stratify by (class, family); take every other event into eval so both
    # sides cover every family
    buckets = defaultdict(list)
    for r in rows:
        buckets[(r["gold"], r["provenance"]["family"])].append(r)

    # the malicious class is the scarce, real-capture one: it all goes to eval,
    # and M3 will need its own disjoint attack pull rather than a split of this
    ev, tr = [], []
    for (cls, _fam), items in sorted(buckets.items()):
        if cls == "malicious":
            ev.extend(items)
            continue
        for i, r in enumerate(items):
            (ev if i % 2 == 0 else tr).append(r)

    # trim eval toward the requested size, dropping from the synthetic classes
    # only, never from the real-capture malicious events
    while len(ev) > args.eval_n:
        cand = [r for r in ev if r["gold"] != "malicious"]
        counts = defaultdict(int)
        for r in ev:
            counts[r["gold"]] += 1
        drop = max(cand, key=lambda r: counts[r["gold"]])
        ev.remove(drop)
        tr.append(drop)

    sfx = args.suffix
    for name, data in [(f"eval_set_v2{sfx}.jsonl", ev), (f"train_pool{sfx}.jsonl", tr)]:
        Path(name).write_text("\n".join(json.dumps(r) for r in data) + "\n")

    # the original nine, kept separate for baseline continuity (R12)
    syn = Path("eval_set.jsonl")
    if syn.exists():
        Path(f"eval_synthetic{sfx}.jsonl").write_text(syn.read_text())

    ids_ev = {r["id"] for r in ev}
    ids_tr = {r["id"] for r in tr}
    assert not (ids_ev & ids_tr), "eval/train overlap"
    bodies_ev = {r["event"] for r in ev}
    dupe = [r["id"] for r in tr if r["event"] in bodies_ev]
    if dupe:
        print(f"WARNING identical event bodies across the split: {dupe}")

    def summary(tag, data):
        c = defaultdict(int)
        s = defaultdict(int)
        for r in data:
            c[r["gold"]] += 1
            s[r["severity"]] += 1
        print(f"{tag:<16} n={len(data):<4} {dict(c)}")
        print(f"{'':<16} severity {dict(s)}")

    print()
    summary("eval_set_v2", ev)
    summary("train_pool", tr)
    print(f"\ndisjoint: {len(ids_ev)} eval ids, {len(ids_tr)} train ids, 0 shared")


if __name__ == "__main__":
    main()
