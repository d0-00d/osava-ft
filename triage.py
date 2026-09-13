"""
Keyboard triage for the labelling queue.

The throughput idea is to label behaviours, not events. Events are grouped by
the signature from signature.py, so `svchost.exe -k netsvcs` seen 400 times is
one decision, not 400. One representative is shown per group with the group
size and the pre-filter's reasoning; the decision applies to every member.

Decisions are written after every keystroke, so quitting and resuming loses
nothing.

    python3 triage.py --queue triage_queue.jsonl --out labels_attack.json
    python3 triage.py --min-score 2          # only the plausible end
    python3 triage.py --review               # revisit what you already decided

Keys
    1 2 3 4 5   label severity none / low / medium / high / critical
    d           drop the group (noise, lab scaffolding, unusable)
    D           drop every remaining group scoring below this one
    s           skip, decide later
    u           undo the previous decision
    n / p       next / previous group
    ?           explain the pre-filter's score for this group
    q           save and quit
"""

import argparse
import json
import os
import sys
import termios
import tty
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

SEVERITY = {"1": "none", "2": "low", "3": "medium", "4": "high", "5": "critical"}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious"}

C = {"r": "\033[0m", "b": "\033[1m", "dim": "\033[2m", "red": "\033[31m",
     "grn": "\033[32m", "yel": "\033[33m", "blu": "\033[34m", "mag": "\033[35m",
     "cyn": "\033[36m"}
SEV_COLOR = {"none": C["grn"], "low": C["grn"], "medium": C["yel"],
             "high": C["red"], "critical": C["mag"]}

# A suggestion is only as good as what it looked at. Behavioural rules read the
# event itself; tactic rules read the folder the capture was filed under, which
# describes the whole capture and not this event. The distinction is shown so a
# weak suggestion is never accepted as if it were a strong one.
def strength(rule):
    if rule.startswith("tactic:"):
        return ("weak", C["yel"], "from the capture's folder, not this event")
    if rule in ("unclassified",):
        return ("none", C["dim"], "no rule matched -- read it yourself")
    if rule in ("ambient", "low-score"):
        return ("strong", C["grn"], "")
    return ("strong", C["grn"], "")


def getkey():
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()[:1] or "q"
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


def clear():
    print("\033[H\033[J", end="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", default="triage_queue.jsonl")
    ap.add_argument("--out", default="labels_attack.json")
    ap.add_argument("--min-score", type=float, default=None)
    ap.add_argument("--prelabel", default=None,
                    help="only groups the prefilter marked this way")
    ap.add_argument("--review", action="store_true",
                    help="revisit groups already decided")
    ap.add_argument("--auto", default="auto_labels.json",
                    help="rule-decided groups to treat as already done")
    ap.add_argument("--propose", default="proposed_labels.json",
                    help="severity suggestions to confirm or override")
    ap.add_argument("--blind", action="store_true",
                    help="hide every machine opinion -- suggestion, prefilter "
                         "verdict and score. Use with --sample to produce an "
                         "unanchored human baseline the automation can be "
                         "measured against.")
    ap.add_argument("--sample", type=int, default=0,
                    help="label a random subset of this many groups")
    ap.add_argument("--sample-seed", default="osava-blind-1")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.queue)]
    prop = Path(args.propose)
    proposals = json.loads(prop.read_text()) if prop.exists() else {}

    groups = OrderedDict()
    for r in rows:
        g = groups.setdefault(r["signature"], {
            "signature": r["signature"], "members": [], "score": r["score"],
            "prelabel": r["prelabel"], "why": r["why"], "rep": r,
            "srcs": set(), "eventid": r["eventid"]})
        g["members"].append(r["id"])
        g["srcs"].add(r["src"])
        if r["score"] > g["score"]:
            g["score"], g["why"], g["rep"] = r["score"], r["why"], r
    order = sorted(groups.values(), key=lambda g: (-g["score"], -len(g["members"])))

    out = Path(args.out)
    decided = json.loads(out.read_text()) if out.exists() else {}
    auto = Path(args.auto)
    if auto.exists() and not args.blind:
        n0 = len(decided)
        for sig, v in json.loads(auto.read_text()).items():
            decided.setdefault(sig, v)
        print(f"loaded {len(decided)-n0} rule-decided groups from {auto}")

    work = order
    if args.min_score is not None:
        work = [g for g in work if g["score"] >= args.min_score]
    if args.prelabel:
        work = [g for g in work if g["prelabel"] == args.prelabel]
    if not args.review:
        work = [g for g in work if g["signature"] not in decided]

    if args.blind:
        # A blind pass must not see the machine's opinion, and must not inherit
        # its rule-decided groups either: those would appear in both files as
        # free agreement and inflate the measurement it exists to produce.
        proposals = {}
    if args.sample:
        from contract import stable_rng
        r = stable_rng(args.sample_seed)
        work = sorted(work, key=lambda g: g["signature"])
        if len(work) > args.sample:
            work = r.sample(work, args.sample)
        r.shuffle(work)

    if not work:
        print("nothing to triage with these filters")
        return

    total_ev = sum(len(g["members"]) for g in work)
    print(f"{len(work)} groups / {total_ev} events to triage "
          f"({len(decided)} already decided)")
    print("press any key to start")
    getkey()

    i, history, explain = 0, [], False
    while 0 <= i < len(work):
        g = work[i]
        rep = g["rep"]
        done = len(decided)
        ev_done = sum(len(groups[s]["members"]) for s in decided if s in groups)
        clear()
        print(f"{C['dim']}group {i+1}/{len(work)}   decided {done} groups / "
              f"{ev_done} events{C['r']}")
        pl = g["prelabel"]
        plc = {"malicious": C["red"], "review": C["yel"], "drop": C["dim"]}[pl]
        verdict = ("" if args.blind else
                   f"   prefilter: {plc}{pl}{C['r']} "
                   f"{C['dim']}(score {g['score']}){C['r']}")
        print(f"{C['b']}x{len(g['members'])} events{C['r']}  "
              f"{C['dim']}in {len(g['srcs'])} capture(s){C['r']}{verdict}")
        print(f"{C['dim']}{rep['src']}{C['r']}")
        print("-" * 76)
        for line in rep["event"].splitlines():
            k, v = line.split(":", 1)
            hl = C["cyn"] if k in ("CommandLine", "ParentCommandLine",
                                  "TargetFilename") else ""
            print(f"  {C['dim']}{k}:{C['r']} {hl}{v.strip()[:180]}{C['r']}")
        print("-" * 76)
        if not args.blind and (explain or pl != "drop"):
            for w in g["why"]:
                sign = C["red"] + "+" if not any(
                    k in w for k in ("ambient", "unrelated", "captures", "real host")
                ) else C["grn"] + "-"
                print(f"  {sign} {w}{C['r']}")
        if len(g["srcs"]) > 1:
            print(f"  {C['dim']}captures: "
                  f"{', '.join(sorted(g['srcs'])[:3])}{C['r']}")
        sug = None if args.blind else proposals.get(g["signature"])
        if sug:
            sev = sug["severity"]
            st, stc, note = strength(sug["rule"])
            label = sev if sev else "drop"
            col = SEV_COLOR.get(sev, C["dim"])
            print(f"\n  {C['b']}suggest:{C['r']} {col}{label}{C['r']}   "
                  f"{C['dim']}rule {sug['rule']}{C['r']}  {stc}[{st}]{C['r']}")
            print(f"  {C['dim']}{sug['why']}{C['r']}")
            if note:
                print(f"  {stc}^ {note}{C['r']}")

        prev = decided.get(g["signature"])
        if prev:
            print(f"\n  {C['b']}current: {prev['severity']} "
                  f"({prev['gold']}){C['r']}")
        print(f"\n  {C['dim']}a accept suggestion   A accept all remaining with "
              f"the same rule{C['r']}")
        print(f"  {C['dim']}1 none  2 low  3 medium  4 high  5 critical   "
              f"d drop  D drop tail  s skip  u undo  n/p nav  ? why  q quit{C['r']}")

        k = getkey()
        explain = False
        if k == "q":
            break
        elif k == "?":
            explain = True
            continue
        elif k == "n":
            i += 1
        elif k == "p":
            i = max(0, i - 1)
        elif k == "s":
            i += 1
        elif k == "u":
            if history:
                sig, prevval = history.pop()
                if prevval is None:
                    decided.pop(sig, None)
                else:
                    decided[sig] = prevval
                out.write_text(json.dumps(decided, indent=2))
                i = max(0, i - 1)
        elif k in ("a", "A") and sug:
            sev = sug["severity"]
            targets = [g]
            if k == "A":
                targets = [h for h in work[i:]
                           if h["signature"] not in decided
                           and proposals.get(h["signature"], {}).get("rule")
                           == sug["rule"]]
                st, _, _ = strength(sug["rule"])
                clear()
                nev = sum(len(h["members"]) for h in targets)
                print(f"accept '{sev or 'drop'}' for {len(targets)} groups / "
                      f"{nev} events matching rule {sug['rule']}?")
                if st != "strong":
                    print(f"\n{C['yel']}This is a {st} rule: {sug['why']}.\n"
                          f"Bulk-accepting it labels events the rule never "
                          f"actually read.{C['r']}")
                print("\n[y/N]")
                if getkey() != "y":
                    continue
            for h in targets:
                hs = proposals.get(h["signature"], {})
                hsev = hs.get("severity")
                decided[h["signature"]] = {
                    "severity": hsev,
                    "gold": BUCKET[hsev] if hsev else "drop",
                    "decided_by": "human: accepted suggestion"
                                  + (" (bulk)" if k == "A" else ""),
                    "rule": hs.get("rule"), "n": len(h["members"]),
                    "srcs": sorted(h["srcs"])[:5]}
            out.write_text(json.dumps(decided, indent=2))
            if k == "A":
                work = [h for h in work if h["signature"] not in decided]
                i = min(i, max(0, len(work) - 1))
            else:
                i += 1
        elif k == "D":
            tail = [h for h in work[i:] if h["signature"] not in decided
                    and h["score"] <= g["score"]]
            clear()
            nev = sum(len(h["members"]) for h in tail)
            print(f"drop {len(tail)} groups / {nev} events scoring "
                  f"<= {g['score']}?  [y/N]")
            if getkey() == "y":
                for h in tail:
                    decided[h["signature"]] = {
                        "severity": None, "gold": "drop", "n": len(h["members"]),
                        "decided_by": "bulk tail drop",
                        "rule": f"below score {g['score']} at bulk drop",
                        "srcs": sorted(h["srcs"])[:5]}
                out.write_text(json.dumps(decided, indent=2))
                work = [h for h in work if h["signature"] not in decided]
                i = min(i, max(0, len(work) - 1))
        elif k == "d":
            history.append((g["signature"], decided.get(g["signature"])))
            decided[g["signature"]] = {"severity": None, "gold": "drop",
                                       "decided_by": "human",
                                       "n": len(g["members"]),
                                       "srcs": sorted(g["srcs"])[:5]}
            out.write_text(json.dumps(decided, indent=2))
            i += 1
        elif k in SEVERITY:
            sev = SEVERITY[k]
            history.append((g["signature"], decided.get(g["signature"])))
            decided[g["signature"]] = {"severity": sev, "gold": BUCKET[sev],
                                       "decided_by": "human",
                                       "n": len(g["members"]),
                                       "srcs": sorted(g["srcs"])[:5],
                                       "prefilter": g["prelabel"],
                                       "score": g["score"]}
            out.write_text(json.dumps(decided, indent=2))
            i += 1

    out.write_text(json.dumps(decided, indent=2))
    clear()
    lab = [v for v in decided.values() if v["gold"] != "drop"]
    print(f"saved {out}: {len(decided)} groups decided "
          f"({len(lab)} labelled, {len(decided)-len(lab)} dropped)")
    print("events by class:")
    cls = defaultdict(int)
    sev = defaultdict(int)
    for v in decided.values():
        cls[v["gold"]] += v["n"]
        if v["severity"]:
            sev[v["severity"]] += v["n"]
    print(" ", dict(cls))
    print(" ", dict(sev))
    left = sum(1 for g in order if g["signature"] not in decided)
    how = defaultdict(int)
    for v in decided.values():
        how[v.get("decided_by", "human")] += 1
    print("decided by:")
    for k2, n2 in sorted(how.items(), key=lambda kv: -kv[1]):
        print(f"  {k2:<34} {n2:>5} groups")
    print(f"{left} groups remaining")


if __name__ == "__main__":
    main()
