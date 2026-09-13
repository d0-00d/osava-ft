"""
Propagate maliciousness from a known-bad parent to its children.

The blind comparison found this as a systematic bias: 4 of 10 under-calls were
events whose parent binary was independently labelled malicious, but which were
scored on their own content. `cmd.exe /c pause` is nothing on its own; spawned
by a binary that is malicious everywhere else it appears, it is part of an
intrusion. Under-call rate is the project's primary metric, so a bias that
runs in this direction is the expensive kind.

A path counts as known-bad when it is malicious in most of the events where it
appears as the Image, and it does not live in a system directory -- cmd.exe and
powershell.exe appear on both sides of the label and must never qualify. The
threshold is a majority rather than unanimity because the labels themselves are
noisy: com-hijack.exe was malicious in 3 of its 4 events and unanimity excluded it.

    python3 lineage_fix.py --labels labels_auto.json --apply
"""

import argparse
import collections
import json
from pathlib import Path

ORDER = ["drop", "none", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(ORDER)}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious"}
SYSTEM_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64",
               "c:\\windows\\microsoft.net", "c:\\program files")


def path_of(ev, key):
    for l in ev.splitlines():
        if l.startswith(key + ":"):
            return l.split(":", 1)[1].strip().lower()
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="labels_auto.json")
    ap.add_argument("--queue", default="triage_queue.jsonl")
    ap.add_argument("--threshold", type=float, default=0.6)
    ap.add_argument("--floor", default="high", choices=ORDER)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    labels = json.loads(Path(args.labels).read_text())
    rep = {}
    for line in open(args.queue):
        r = json.loads(line)
        rep.setdefault(r["signature"], r)

    cls = collections.defaultdict(collections.Counter)
    for sig, v in labels.items():
        if sig in rep:
            p = path_of(rep[sig]["event"], "Image")
            if p:
                cls[p][v.get("gold", "drop")] += 1

    knownbad = {p for p, c in cls.items()
                if sum(c.values()) and c["malicious"] / sum(c.values()) >= args.threshold
                and not p.startswith(SYSTEM_DIRS)}
    print(f"{len(knownbad)} image paths are malicious in >={args.threshold:.0%} "
          f"of their events and sit outside system directories")

    raised = []
    for sig, v in labels.items():
        if sig not in rep:
            continue
        ev = rep[sig]["event"]
        cur = v.get("severity") or "drop"
        if RANK[cur] >= RANK[args.floor]:
            continue
        par = path_of(ev, "ParentImage")
        if par and par in knownbad:
            raised.append((sig, cur, par))
            continue
        # Image loads were bulk-scored on the shape of the DLL and the path,
        # which ignores what the loading binary actually is. A UAC-bypass tool
        # loading cfgmgr32.dll is not a benign event; the blind sample caught
        # exactly this. Judge the loader, not only the module.
        if ev.startswith("EventID: 7"):
            img = path_of(ev, "Image")
            if img and img in knownbad:
                raised.append((sig, cur, img))

    print(f"{len(raised)} groups scored below '{args.floor}' despite a known-bad parent\n")
    for sig, cur, par in raised[:15]:
        print(f"  {cur:<7} -> {args.floor:<8} "
              f"{path_of(rep[sig]['event'], 'Image')[:48]:<48} <- {par.split(chr(92))[-1]}")
    if len(raised) > 15:
        print(f"  ... and {len(raised)-15} more")

    if args.apply:
        for sig, _, par in raised:
            labels[sig]["severity"] = args.floor
            labels[sig]["gold"] = BUCKET[args.floor]
            labels[sig]["lineage_raised"] = par
        Path(args.labels).write_text(json.dumps(labels, indent=2))
        print(f"\napplied to {args.labels}")
    else:
        print("\n(dry run -- pass --apply to write)")


if __name__ == "__main__":
    main()
