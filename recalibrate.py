"""
Rule-level corrections found by the blind sample.

IMPORTANT: these are deliberately rules, not per-group patches. Tuning 1663
labels to match 100 human ones would fit the sample's noise and inflate the
agreement number without improving the dataset. Each rule below is defensible
from IR practice on its own, independently of which groups happened to be
sampled -- the sample only pointed at where to look.

  R1  known-bad is decided by execution, not by image loads.
      Circularity: Akagi64.exe appears as the Image in 41 image-load events
      (all bulk-scored benign, because a signed System32 DLL is unremarkable)
      and 1 process-create (malicious). Its "malicious ratio" was 2%, so the
      lineage rule could never raise its own image loads. What a binary IS
      shows in how it is executed, so the ratio is now computed over
      EventID 1 / 4688 only.

  R2  autorun-location registry WRITES and DELETES are high.
      Writing a Run key is persistence; deleting one is an intruder cleaning
      up, or an admin removing malware, and neither is low. I scored the
      delete side medium/low throughout. Reads are excluded: `reg query` over
      the same keys is enumeration, which is medium, and the first draft of
      this rule promoted 4 query events by mistake.

  R3  anti-forensic and telemetry-tampering operations are high.
      MRU deletion, trace/log capture manipulation, event-log clearing. Same
      reasoning: I scored these on how mundane the binary looked (regedit,
      netsh) rather than on what the operation does.

    python3 recalibrate.py --apply
"""

import argparse
import collections
import json
import re
from pathlib import Path

ORDER = ["drop", "none", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(ORDER)}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious", "drop": "drop"}
SYSTEM_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64",
               "c:\\windows\\microsoft.net", "c:\\program files")

AUTORUN = re.compile(
    r"(?i)CurrentVersion\\+Run(Once)?(Ex)?\b"
    r"|CurrentVersion\\+Policies\\+Explorer\\+Run"
    r"|Winlogon\\+(Shell|Userinit|Notify)"
    r"|Start ?Menu\\+Programs\\+Startup"
    r"|Image File Execution Options\\+[^\\\s]+\\+Debugger"
    r"|Environment\\+UserInitMprLogonScript")

ANTIFORENSIC = re.compile(
    r"(?i)\bMRU\b|RecentDocs"
    r"|wevtutil\s+(cl|clear-log)"
    r"|netsh\s+trace\s+(start|stop)"
    r"|fltmc(\.exe)?\s+unload"
    r"|Clear-EventLog|/dontLog:true"
    r"|ScriptBlockLogging|EnableScriptBlockLogging")


# a registry read is not a registry write; `reg query ...\\Run` enumerates
# persistence, `reg add` establishes it
REG_READ = re.compile(r"(?i)\breg(\.exe)?\s+query\b|\bGet-ItemProperty\b|/s\s+/f\b")


def path_of(ev, key):
    for l in ev.splitlines():
        if l.startswith(key + ":"):
            return l.split(":", 1)[1].strip().lower()
    return ""


def eid_of(ev):
    return ev.split("\n", 1)[0].split(": ", 1)[1].strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="labels_auto.json")
    ap.add_argument("--queue", default="triage_queue.jsonl")
    ap.add_argument("--threshold", type=float, default=0.6)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    labels = json.loads(Path(args.labels).read_text())
    rep = {}
    for line in open(args.queue):
        r = json.loads(line)
        rep.setdefault(r["signature"], r)

    # R1: known-bad from execution events only
    execs = collections.defaultdict(collections.Counter)
    for sig, v in labels.items():
        if sig in rep and eid_of(rep[sig]["event"]) in ("1", "4688"):
            p = path_of(rep[sig]["event"], "Image")
            if p:
                execs[p][v.get("gold", "drop")] += 1
    knownbad = {p for p, c in execs.items()
                if sum(c.values()) and c["malicious"] / sum(c.values()) >= args.threshold
                and not p.startswith(SYSTEM_DIRS)}

    changes = collections.defaultdict(list)
    for sig, v in labels.items():
        if sig not in rep:
            continue
        ev = rep[sig]["event"]
        cur = v.get("severity") or "drop"
        floor, why = None, None

        par, img = path_of(ev, "ParentImage"), path_of(ev, "Image")
        if par in knownbad or (eid_of(ev) == "7" and img in knownbad):
            floor, why = "high", "R1 known-bad binary (by execution)"
        elif AUTORUN.search(ev) and not REG_READ.search(ev):
            floor, why = "high", "R2 autorun-location registry write or delete"
        elif ANTIFORENSIC.search(ev):
            floor, why = "high", "R3 anti-forensic / telemetry tampering"

        if floor and RANK[cur] < RANK[floor]:
            changes[why].append((sig, cur))
            if args.apply:
                v["severity"] = floor
                v["gold"] = BUCKET[floor]
                v["recalibrated"] = why

    total = sum(len(v) for v in changes.values())
    print(f"{len(knownbad)} binaries are known-bad by execution "
          f"(was computed over all event types before)\n")
    for why, items in sorted(changes.items()):
        print(f"  {why}: {len(items)} groups raised")
        for sig, cur in items[:4]:
            ev = rep[sig]["event"]
            f = dict(l.split(": ", 1) for l in ev.splitlines() if ": " in l)
            d = f.get("TargetFilename") or f.get("CommandLine", "")
            print(f"      {cur:<7} -> high   {f.get('Image','-').split(chr(92))[-1]:<16} {d[:62]}")
        if len(items) > 4:
            print(f"      ... and {len(items)-4} more")
    print(f"\ntotal raised: {total}")
    if args.apply:
        Path(args.labels).write_text(json.dumps(labels, indent=2))
        print(f"applied to {args.labels}")
    else:
        print("(dry run -- pass --apply to write)")


if __name__ == "__main__":
    main()
