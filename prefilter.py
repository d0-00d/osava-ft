"""
Separate the technique from the background noise in the attack corpus.

The problem, concretely: EVTX-ATTACK-SAMPLES ships whole captures, not isolated
techniques. A file named `rundll32_hollowing_wermgr_masquerading.evtx` contains
the hollowing -- and also Defender's scheduled scan, svchost talking to the
gateway, and WmiPrvSE starting. Labelling by source filename marks all of it
malicious. That is how A002 (a Defender scan) and A027 (svchost to an internal
IP) ended up in a shortlist of "attack signal".

Four signals, combined into a technique score:

  ambient_real   the event's behaviour signature also occurs in the real Sysmon
                 capture from a working machine. The strongest evidence of
                 innocence available, and the reason the capture was worth
                 taking.
  ubiquity       the signature occurs across many different attack sample
                 files. A behaviour present in 40 unrelated captures is the
                 operating system, not the technique. (Plain IDF.)
  filename_match tokens from the sample's filename appear in the event. The
                 corpus author named the file after the technique, so this
                 points at the events they meant to capture.
  heuristics     encoded commands, execution from writable paths, LOLBins,
                 anomalous lineage, uncommon ports.

`filename_match` is a labelling aid and must never become a model feature --
that is precisely the tool-name leakage the PRD warns about. It selects which
events a human looks at first. It does not appear in the training data.

    python3 prefilter.py --attack attack_raw.jsonl --benign sysmon.jsonl \
                         --out triage_queue.jsonl
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from signature import basename, coarse_signature, normalise, signature

# tokens that appear in nearly every sample filename and carry no technique
STOP = {"sysmon", "evtx", "windows", "microsoft", "attack", "sample", "test",
        "log", "logs", "event", "events", "and", "the", "via", "with", "from",
        "win", "win7", "win10", "x64", "x86", "exe", "dll", "proc", "process",
        "security", "operational", "detected", "detection", "poc", "demo"}

HEURISTICS = [
    (re.compile(r"(?i)-enc(odedcommand)?\s|frombase64string|::frombase64"), 3.0,
     "encoded command"),
    (re.compile(r"(?i)\\(temp|appdata|programdata|users\\public|windows\\tasks)"
                r"\\[^\\\s\"]*\.(exe|dll|scr|ps1|vbs|js|hta|bat|cmd|sct|cpl)"), 2.5,
     "payload in writable path"),
    (re.compile(r"(?i)\b(rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|cscript"
                r"|wscript|installutil|msbuild|odbcconf|hh|control)\.exe"), 1.5,
     "LOLBin"),
    (re.compile(r"(?i)https?://(?!.*\.(icorp|corp|local|internal))"), 2.0,
     "remote fetch"),
    (re.compile(r"(?i)-w\s+hidden|-windowstyle\s+hidden|-nop\b|-noni\b"
                r"|executionpolicy\s+bypass"), 2.0, "concealment / policy bypass"),
    (re.compile(r"(?i)(minidump|lsass|sekurlsa|comsvcs\.dll,\s*minidump)"), 3.5,
     "credential access"),
    (re.compile(r"(?i)(vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled)"),
     3.5, "destruction"),
    (re.compile(r"(?i)\\(winword|excel|powerpnt|outlook)\.exe"), 0.0, ""),
    (re.compile(r"(?i)DestinationPort.: ?(4444|1337|8080|8443|9001|1234|31337|6666)"),
     2.0, "uncommon C2 port"),
    (re.compile(r"(?i)(whoami|net\s+(group|user|localgroup)|nltest|systeminfo"
                r"|net\s+view)\b"), 1.0, "discovery"),
]

# lineage pairs that are anomalous regardless of arguments
BAD_LINEAGE = {
    ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"), ("w3wp.exe", "cmd.exe"),
    ("w3wp.exe", "powershell.exe"), ("services.exe", "cmd.exe"),
    ("services.exe", "powershell.exe"), ("hh.exe", "cmd.exe"),
    ("sqlservr.exe", "cmd.exe"), ("wmiprvse.exe", "rundll32.exe"),
    ("mshta.exe", "powershell.exe"), ("winlogon.exe", "cmd.exe"),
}


def file_tokens(src):
    stem = Path(src).stem
    toks = re.split(r"[^A-Za-z0-9]+", re.sub(r"(?<=[a-z])(?=[A-Z])", " ", stem))
    return {t.lower() for t in toks if len(t) > 3 and t.lower() not in STOP
            and not t.isdigit()}


def normalised_fields(f):
    """Contract-normalised copy. Signatures and rendered bodies MUST both be
    computed from this, never from the raw record: a command line truncated at
    512 characters signs differently from its untruncated original, and a
    signature computed before truncation will not match the one computed after.
    That mismatch silently defeats the eval/train disjointness check, since the
    eval set was built from normalised events."""
    from contract import normalise_cmdline
    g = {k: v for k, v in f.items() if not k.startswith("_")}
    for k in ("CommandLine", "ParentCommandLine"):
        if k in g:
            g[k] = normalise_cmdline(str(g[k]))
    return g


def render_event(g):
    """Render exactly as the training set will, so what a human confirms in
    triage is what the model is shown."""
    from contract import FIELD_ORDER
    return "\n".join(f"{k}: {g[k]}" for k in FIELD_ORDER if k in g)


WRITABLE = re.compile(r"(?i)\\(temp|appdata|programdata|users\\public|"
                      r"windows\\tasks|downloads|perflogs)\\")


def auto_rule(fields, body, amb):
    """Decisions a rule can make correctly every time, so a human never sees
    them. Each returns (label, reason); the reason is stored so the dataset
    records that a rule decided, not a person.

    Conservative by construction: a rule only fires to DROP, never to mark
    something malicious. A wrong drop costs one training example; a wrong
    malicious label teaches the model a falsehood."""
    eid = str(fields.get("EventID", ""))
    if eid == "7":
        tgt = fields.get("TargetFilename", "")
        img = fields.get("Image", "")
        # only ordinary when BOTH ends are ordinary: a System32 DLL is unremarkable,
        # but a binary in Downloads loading one is still worth a human's eye
        if tgt and not WRITABLE.search(tgt) and not WRITABLE.search(img):
            return ("drop", "system module loaded by a system-path binary -- "
                            "image loads carry signal only for sideloading")
    if amb >= 25:
        return ("drop", f"signature occurs {amb}x in the real benign capture")
    return (None, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="attack_raw.jsonl")
    ap.add_argument("--benign", default="sysmon.jsonl")
    ap.add_argument("--out", default="triage_queue.jsonl")
    ap.add_argument("--ambient-min", type=int, default=2,
                    help="occurrences in the real capture before a signature "
                         "counts as ambient")
    args = ap.parse_args()

    # ---- background profile from the real capture -------------------------
    fine, coarse = Counter(), Counter()
    nb = 0
    for line in open(args.benign):
        f = json.loads(line)
        fine[signature(f)] += 1
        coarse[coarse_signature(f)] += 1
        nb += 1
    print(f"benign profile: {nb} events, {len(fine)} signatures, "
          f"{len(coarse)} coarse")

    # ---- attack corpus ----------------------------------------------------
    rows = [json.loads(l) for l in open(args.attack)]
    print(f"attack corpus:  {len(rows)} events from "
          f"{len({r['_src'] for r in rows})} files")

    # normalise once; every downstream use (signature, body, heuristics) reads
    # the normalised form
    norm = {id(r): normalised_fields(r) for r in rows}

    sig_files = defaultdict(set)
    for r in rows:
        sig_files[signature(norm[id(r)])].add(r["_src"])

    out, kept = [], 0
    for r in rows:
        g = norm[id(r)]
        sig = signature(g)
        csig = coarse_signature(g)
        body = render_event(g)
        score, why = 0.0, []

        # 1. ambient in the real capture
        amb = fine.get(sig, 0)
        camb = coarse.get(csig, 0)
        if amb >= args.ambient_min:
            score -= 6.0
            why.append(f"ambient in real capture (x{amb})")
        elif camb >= 20:
            score -= 2.5
            why.append(f"common image/parent pair on a real host (x{camb})")

        # 2. ubiquity across unrelated attack captures
        nfiles = len(sig_files[sig])
        if nfiles >= 8:
            score -= 4.0
            why.append(f"appears in {nfiles} unrelated captures")
        elif nfiles >= 4:
            score -= 1.5
            why.append(f"appears in {nfiles} captures")
        elif nfiles == 1:
            score += 1.5
            why.append("unique to this capture")

        # 3. the corpus author named the file after the technique
        toks = file_tokens(r["_src"])
        low = body.lower()
        hit = {t for t in toks if t in low}
        if hit:
            score += 2.0 + 0.5 * len(hit)
            why.append(f"matches sample name ({', '.join(sorted(hit)[:3])})")

        # 4. behavioural heuristics
        for pat, w, label in HEURISTICS:
            if w and pat.search(body):
                score += w
                why.append(label)
        pair = (basename(g.get("ParentImage", "")), basename(g.get("Image", "")))
        if pair in BAD_LINEAGE:
            score += 3.0
            why.append(f"anomalous lineage {pair[0]} -> {pair[1]}")

        auto, auto_why = auto_rule(g, body, amb)
        pre = ("malicious" if score >= 4.0 else
               "review" if score >= 1.0 else "drop")
        if auto:
            pre = auto
        out.append({"src": r["_src"], "event": body, "signature": sig,
                    "score": round(score, 2), "prelabel": pre, "why": why,
                    "eventid": r["EventID"], "auto": auto, "auto_why": auto_why})
        kept += 1

    out.sort(key=lambda r: -r["score"])
    for i, r in enumerate(out):
        r["id"] = f"T{i+1:05d}"
    Path(args.out).write_text("\n".join(json.dumps(r) for r in out) + "\n")

    # rule-decided groups go straight into a labels file so triage never shows
    # them; they are recorded as machine decisions, distinguishable from human
    # ones in provenance
    auto_out = Path(args.out).with_name("auto_labels.json")
    autos = {}
    for r in out:
        if r["auto"] and r["signature"] not in autos:
            autos[r["signature"]] = {
                "severity": None, "gold": "drop", "decided_by": "rule",
                "rule": r["auto_why"],
                "n": sum(1 for x in out if x["signature"] == r["signature"])}
    auto_out.write_text(json.dumps(autos, indent=2))
    auto_ev = sum(v["n"] for v in autos.values())
    print(f"\nauto-decided by rule: {len(autos)} groups / {auto_ev} events "
          f"-> {auto_out}")

    dist = Counter(r["prelabel"] for r in out)
    print(f"\nwrote {args.out}: {kept} events")
    print("prelabel:", dict(dist))
    print("\nby EventID within 'malicious':")
    print(" ", dict(Counter(r["eventid"] for r in out
                            if r["prelabel"] == "malicious").most_common()))


if __name__ == "__main__":
    main()
