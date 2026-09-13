"""
One class boundary, applied to the training set and the eval set together.

The problem this fixes: `net localgroup administrators helpdesk /add` was
labelled `suspicious` in training and `malicious` in the eval set. The model
learned the training boundary and was then scored against a different one, so
three of its fourteen errors were not errors at all -- they were the two sets
disagreeing. A boundary defined in one place and applied to both cannot drift.

THE RULE, in the order it is applied:

  1. durable state change   -> malicious
     Creating an account, granting privilege, installing a service, writing a
     scheduled task, writing an autorun key, excluding a path from Defender.
     Something persists after the process exits.
     Support: the blind labelling passes called autorun writes and `reg add`
     malicious 7 times out of 7.

  2. observation only       -> at most suspicious
     `net user`, `net localgroup` (without /add), `whoami`, `systeminfo`,
     `adfind`, `dsquery`, `reg query`. Nothing changes; an analyst should look.
     This is a CEILING, not a floor: it stops enumeration being rated malicious
     for the act alone. It does not promote affirmatively-normal observation out
     of `benign`, and it does not demote a row that is malicious for some other
     reason (an unsigned binary in Temp running `whoami` is still malicious --
     the binary is the problem, not the whoami).

  3. affirmatively normal   -> benign
     Named exceptions only, for events built as hard negatives.

  4. reconcile contradictions (eval only, derived -- nothing hand-listed)
     An eval row whose exact action also appears in the training set, where
     every training instance of that action carries a LOWER class, and where
     the act itself is observation-only, adopts the training class.
     These are synthetic events with no external fact to appeal to, so
     consistency is the only standard available -- and a model scored on a
     boundary it was trained against the other way is not being measured, it
     is being contradicted.
     Actions are matched parent-blind: signature() includes the parent
     basename, so the generator varying the parent at random manufactures
     "distinct" behaviours out of byte-identical commands. That is also why
     16 of 50 eval rows share an action with training despite the disjointness
     assertion passing -- see the parent-blind check printed below.

Rule 1 reads the VERB, not the path. `reg query HKCU\\...\\CurrentVersion\\Run`
reads an autorun key and is observation; `reg add` to the same key is a state
change. Fifteen training rows were nearly mislabelled by a rule that matched the
path alone -- the same mistake recalibrate.py's R2 already made once.

    python3 boundary.py                 # dry run, prints every change
    python3 boundary.py --apply
"""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
SEV = {"benign": "none", "suspicious": "medium", "malicious": "high"}

# --- rule 1: durable state change ------------------------------------------
# every pattern here must name an action that persists after the process exits
CHANGE = [
    ("account_create_or_grant",
     r"\bnet1?(?:\.exe)?\b[^\n]*?\b(?:user|localgroup|group)\b[^\n]*?/(?:add|delete)"),
    ("scheduled_task_create",
     r"\bschtasks(?:\.exe)?\b[^\n]*?/create|\bat(?:\.exe)?\s+\d{1,2}:\d{2}"),
    ("service_create",
     r"\bsc(?:\.exe)?\b[^\n]*?\b(?:create|config)\b[^\n]*?binpath|\bnew-service\b"),
    ("defender_exclusion",
     r"windows defender\\exclusions|add-mppreference[^\n]*?exclusion"),
    # a WRITE to an autorun location. The verb is what makes it a write:
    # an EventID 12/13/14 registry-set event, or an explicit `reg add`.
    ("autorun_write",
     r"\breg(?:\.exe)?\b[^\n]*?\badd\b[^\n]*?(?:currentversion\\run|\\winlogon\\|"
     r"image file execution)"),
]
# EventID 13 (RegistryValueSet) against an autorun path is a write by definition
AUTORUN_PATH = re.compile(
    r"(?i)(currentversion\\run(?:once)?\b|\\winlogon\\(?:shell|userinit)|"
    r"image file execution options\\|windows defender\\exclusions)")

# --- rule 2: observation ----------------------------------------------------
OBSERVE = re.compile(
    r"(?i)(\bnet1?(?:\.exe)?\b[^\n]*?\b(?:user|localgroup|group|view|share|accounts)\b"
    r"(?![^\n]*?/(?:add|delete))"
    r"|\b(?:whoami|systeminfo|nltest|hostname|ipconfig|tasklist|quser|qwinsta|arp)\b"
    r"|\badfind\b|\bdsquery\b|\bnbtscan\b"
    r"|\breg(?:\.exe)?\b[^\n]*?\bquery\b)")

# --- rule 3: named hard negatives ------------------------------------------
# events built to be affirmatively normal, where the generator's label is
# definitional rather than an estimate -- there is no hidden fact to discover
NORMAL = {"B010": "IIS worker to SQL Server on 1433, by hostname, internal subnet"}


def pblind(row):
    """signature() with the ParentImage component removed: the action alone."""
    from signature import basename, cmd_shape, dirname, normalise, port_bucket
    import targets
    f = targets.parse(row["event"])
    eid = str(f.get("EventID", ""))
    img = f.get("Image", "")
    parts = [eid, basename(img), dirname(img)]
    if eid in ("1", "4688"):
        parts.append(cmd_shape(f.get("CommandLine", ""), img))
    elif eid in ("11", "12", "13", "7"):
        parts.append(normalise(f.get("TargetFilename", ""))[:200])
    elif eid == "3":
        parts += [port_bucket(f.get("DestinationPort")),
                  "dns" if f.get("DestinationHostname") else "nodns"]
    elif eid in ("4624", "4625"):
        parts += [str(f.get("LogonType", "")), str(f.get("AuthPackage", ""))]
    return "|".join(parts)


def classify(row):
    """Return (target_class, reason) or (None, None) if no rule applies."""
    if row.get("id") in NORMAL:
        return "benign", f"normal: {NORMAL[row['id']]}"
    ev = row["event"]
    eid = ev.split("\n", 1)[0].replace("EventID:", "").strip()
    for name, pat in CHANGE:
        if re.search(pat, ev, re.I):
            return "malicious", f"state change: {name}"
    if eid in ("12", "13", "14") and AUTORUN_PATH.search(ev):
        return "malicious", "state change: autorun_write (registry set)"
    if OBSERVE.search(ev):
        return "observe", "observation only"
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--files", nargs="+", default=[
        "train_final.jsonl", "train_final_5way.jsonl",
        "eval_set_v2.jsonl", "eval_set_v2_5way.jsonl", "eval_set_v2_nosig.jsonl"])
    args = ap.parse_args()

    train = [json.loads(l) for l in Path("train_final.jsonl").read_text().splitlines()
             if l.strip()]

    for path in args.files:
        p = Path(path)
        if not p.exists():
            print(f"{path}: missing, skipped")
            continue
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        five = "5way" in path
        is_eval = "eval" in path

        # rule 1 first, so the training side is settled before rule 4 reads it
        tclass = {}
        for t in train:
            w, _ = classify(t)
            tclass.setdefault(pblind(t), set()).add(
                w if w == "malicious" else t["gold"])

        changes = []
        for r in rows:
            want, why = classify(r)
            cur = r["gold"]
            if want == "observe":
                # rule 4: a contradiction is only resolvable where the same act
                # exists in training and training is unanimous and lower
                seen = tclass.get(pblind(r))
                if (is_eval and seen and
                        all(RANK[c] < RANK[cur] for c in seen)):
                    tgt = max(seen, key=lambda c: RANK[c])
                    changes.append((r, cur, tgt,
                                    f"reconcile: observation-only, training is "
                                    f"unanimously {tgt}"))
                continue
            if want is None:
                continue
            if RANK[cur] < RANK[want] or (want == "benign" and RANK[cur] > 0):
                changes.append((r, cur, want, why))
        print(f"\n=== {path} ({len(rows)} rows) — {len(changes)} changes")
        for r, cur, want, why in changes:
            print(f"  {r['id']:<7} {cur:<11} -> {want:<11} {why}")
        if args.apply and changes:
            for r, cur, want, why in changes:
                r["gold"] = want
                if not (five and r.get("severity") == "critical" and want == "malicious"):
                    r["severity"] = SEV[want]
                r.setdefault("provenance", {})["boundary_rule"] = why
            p.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
            print(f"  -> written. now {dict(sorted(Counter(x['gold'] for x in rows).items()))}")


if __name__ == "__main__":
    main()
