"""
Assemble eval_set.jsonl from events/<ID>.txt + labels.

Keeps gold labels in one place and event bodies in editable plain-text files.
Reused later for the training set: same layout, different directory.

    python3 build_eval.py                       # events/ -> eval_set.jsonl
    python3 build_eval.py --src train_events --out train_set.jsonl
"""

import argparse
import json
from pathlib import Path

# id -> (display name, gold label, note)
LABELS = {
    "E01": ("Standard UI launch",       "benign",     "signed, System32, normal parent"),
    "E02": ("Web browsing HTTPS",       "benign",     "R2 false-positived this one"),
    "E03": ("Service startup",          "benign",     "LOCAL SERVICE, restricted"),
    "E04": ("Word spawning PowerShell", "malicious",  "T1566/T1059, under-called both rounds"),
    "E05": ("Reverse shell port",       "malicious",  "unsigned Temp binary, raw IP, 4444"),
    "E06": ("Unsigned Temp execution",  "malicious",  "biggest leniency swing R1->R2"),
    "E07": ("Admin discovery tool",     "suspicious", "T1033 whoami /all"),
    "E08": ("PsExec lateral movement",  "malicious",  "FABRICATION CANARY - model invented "
                                                      "'Performance Experience Service' at 0.9 "
                                                      "conf in both rounds"),
    "E09": ("Blank password logon",     "suspicious", "Guest + NTLM, network logon"),
}

VALID = {"benign", "suspicious", "malicious"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="events")
    ap.add_argument("--out", default="eval_set.jsonl")
    args = ap.parse_args()

    src = Path(args.src)
    lines, missing = [], []

    for eid, (name, gold, note) in sorted(LABELS.items()):
        assert gold in VALID, f"{eid}: bad label {gold!r}"
        f = src / f"{eid}.txt"
        if not f.exists():
            missing.append(eid)
            continue
        body = f.read_text().strip()
        if not body:
            missing.append(eid)
            continue
        lines.append(json.dumps({"id": eid, "name": name, "gold": gold,
                                 "notes": note, "event": body}))

    Path(args.out).write_text("\n".join(lines) + "\n")

    print(f"wrote {args.out}: {len(lines)} events")
    if missing:
        print(f"MISSING or empty: {missing}")

    counts = {}
    for line in lines:
        counts[json.loads(line)["gold"]] = counts.get(json.loads(line)["gold"], 0) + 1
    print("class balance:", counts)

    # cheap contract check: flag field names not in the agreed set
    known = {"EventID", "EventType", "Image", "CommandLine", "ParentImage",
             "ParentCommandLine", "User", "Signed", "Signer", "DestinationIp",
             "DestinationPort", "DestinationHostname", "TargetFilename",
             "LogonType", "AuthPackage"}
    seen = set()
    for line in lines:
        for row in json.loads(line)["event"].splitlines():
            if ":" in row:
                seen.add(row.split(":", 1)[0].strip())
    unknown = seen - known
    if unknown:
        print(f"WARNING off-contract fields: {sorted(unknown)}")


if __name__ == "__main__":
    main()
