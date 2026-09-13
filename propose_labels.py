"""
Propose a severity for each triage group, from explicit named rules.

triage.py without this is 1317 blank decisions. With it, each group arrives
with a suggested severity and the name of the rule that suggested it, so the
work becomes confirm-or-override at one keystroke.

These are SUGGESTIONS, written to a separate file and never merged into the
decisions. Nothing enters the training set until a human presses a key. That
matters because under-call rate is the metric the whole project is judged on,
and a model proposing its own training labels is a closed loop that would
launder its own leniency bias straight back into the data.

Two inputs feed a proposal:

  tactic   the corpus's top-level directory (Credential Access, Lateral
           Movement, ...). The corpus author's own categorisation, and the
           best coarse prior available.
  behaviour  the heuristics prefilter.py already computed.

Behaviour wins over tactic wherever they disagree, because the tactic
describes the capture and the behaviour describes the event -- and a capture
filed under Credential Access still contains its share of ordinary process
starts.

Like filename_match, the tactic directory is a LABELLING AID ONLY. It is
metadata about the source file, not about the event, and it must never become
a model feature.

    python3 propose_labels.py --out proposed_labels.json
"""

import argparse
import json
from collections import Counter, OrderedDict
from pathlib import Path

# Behavioural rules, highest precedence first. (name, predicate, severity, why)
def _has(w, *needles):
    return any(any(n in x for n in needles) for x in w)


BEHAVIOUR_RULES = [
    ("destruction", lambda w, s: _has(w, "destruction"), "critical",
     "shadow copy or backup deletion -- ransomware precursor, no benign reading"),
    ("credential-access", lambda w, s: _has(w, "credential access"), "critical",
     "LSASS or secret material access"),
    ("encoded-and-hidden", lambda w, s: _has(w, "encoded command")
     and _has(w, "concealment"), "critical",
     "encoded payload plus deliberate concealment -- intent is not ambiguous"),
    ("encoded-command", lambda w, s: _has(w, "encoded command"), "high",
     "base64 / -enc payload"),
    ("drop-and-fetch", lambda w, s: _has(w, "payload in writable path")
     and _has(w, "remote fetch"), "high",
     "remote fetch writing an executable to a user-writable path"),
    ("payload-drop", lambda w, s: _has(w, "payload in writable path"), "high",
     "executable content staged in a writable path"),
    ("anomalous-lineage", lambda w, s: _has(w, "anomalous lineage"), "high",
     "parent-child pair that does not occur in normal operation"),
    ("remote-fetch", lambda w, s: _has(w, "remote fetch"), "high",
     "inline retrieval from an external host"),
    ("concealment", lambda w, s: _has(w, "concealment"), "high",
     "hidden window or execution-policy bypass"),
    ("c2-port", lambda w, s: _has(w, "uncommon C2 port"), "high",
     "outbound to a port associated with implant defaults"),
    ("lolbin", lambda w, s: _has(w, "LOLBin"), "medium",
     "living-off-the-land binary with no other aggravating signal -- dual-use"),
    ("discovery", lambda w, s: _has(w, "discovery"), "medium",
     "enumeration; identical whether run by an admin or an intruder"),
]

# Coarse prior from the corpus's own tactic directory, used only when no
# behavioural rule fires.
TACTIC_SEVERITY = {
    "Credential Access": ("critical", "capture filed under credential access"),
    "Command and Control": ("critical", "capture filed under command and control"),
    "Lateral Movement": ("high", "capture filed under lateral movement"),
    "Privilege Escalation": ("high", "capture filed under privilege escalation"),
    "Persistence": ("high", "capture filed under persistence"),
    "Defense Evasion": ("high", "capture filed under defense evasion"),
    "Execution": ("high", "capture filed under execution"),
    "Discovery": ("medium", "capture filed under discovery"),
}

# Evidence of innocence outranks everything above.
EXCULPATORY = ("ambient in real capture", "unrelated captures",
               "common image/parent pair on a real host")


def propose(group):
    r = group["rep"]
    w = r["why"]
    s = r["score"]
    tactic = r["src"].split("/")[0]

    if _has(w, *EXCULPATORY) and s < 4.0:
        return None, "ambient", ("occurs on a real working machine or across "
                                 "unrelated captures")
    if s < 1.0:
        return None, "low-score", "no attack signal found; expected to be dropped"

    for name, pred, sev, why in BEHAVIOUR_RULES:
        if pred(w, s):
            return sev, name, why

    if tactic in TACTIC_SEVERITY:
        sev, why = TACTIC_SEVERITY[tactic]
        return sev, f"tactic:{tactic}", why + " with no specific behavioural signal"

    return None, "unclassified", "no rule matched; needs a human read"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", default="triage_queue.jsonl")
    ap.add_argument("--auto", default="auto_labels.json")
    ap.add_argument("--out", default="proposed_labels.json")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.queue)]
    auto = json.loads(Path(args.auto).read_text()) if Path(args.auto).exists() else {}

    groups = OrderedDict()
    for r in rows:
        g = groups.setdefault(r["signature"], {"rep": r, "n": 0})
        g["n"] += 1
        if r["score"] > g["rep"]["score"]:
            g["rep"] = r

    out, stats, rules = {}, Counter(), Counter()
    for sig, g in groups.items():
        if sig in auto:
            continue
        sev, rule, why = propose(g)
        out[sig] = {"severity": sev, "rule": rule, "why": why, "n": g["n"]}
        stats[sev or "drop"] += 1
        rules[rule] += 1

    Path(args.out).write_text(json.dumps(out, indent=2))
    print(f"wrote {args.out}: {len(out)} suggestions\n")
    print("suggested severity:")
    for k in ("critical", "high", "medium", "low", "none", "drop"):
        if stats.get(k):
            print(f"  {k:<10} {stats[k]:>5} groups")
    print("\nby rule:")
    for k, n in rules.most_common():
        print(f"  {k:<28} {n:>5}")
    print("\nSuggestions only. Nothing is labelled until you press a key in triage.py.")


if __name__ == "__main__":
    main()
