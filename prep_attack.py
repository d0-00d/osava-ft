"""
Attack candidates -> contract-normalised malicious class.

The EVTX corpus cannot be used as-scraped. Four defects, each of which teaches
the model something other than the technique:

  * identity      -- 94x IEWIN7\\IEUser, 75x MSEDGEWIN10\\IEUser. The synthetic
                     classes use different hosts, so hostname alone separates
                     them. Rewritten through the shared pool.
  * signature     -- Signed/Signer appear on EventID 7 only, never on process
                     creates. Applied under the same policy as every other class.
  * escaping      -- rendered EVTX doubles '%'. R3 says normalise.
  * tool names    -- RoguePotato.exe, SpoolFool.exe, UACME.exe. Real operators
                     rename binaries; a model keyed on the filename is defeated
                     by `mv`. RENAME rewrites these to neutral names, keeping
                     the path and the behaviour, which is the actual signal.

    python3 prep_attack.py --sig backfill
"""

import argparse
import json
import re
from pathlib import Path

from attack_labels import ATTACK_LABELS, KEEP, RENAME
from contract import (HOSTS, LOCAL_USERS, normalise_cmdline, pick_account,
                      render, stable_rng, validate)

# lab scaffolding: a python.exe running winpwnage.py never appears in
# production telemetry, and the parent is a giveaway rather than a signal.
LAB_PARENTS = {
    "C:\\Python27\\python.exe": ("C:\\Windows\\System32\\cmd.exe",
                                 '"C:\\Windows\\System32\\cmd.exe"'),
}

# tool-name parents that leak the answer; keep the path, drop the name
PARENT_RENAME = {
    "UACME.exe": "a.exe",
}


def rewrite_identity(body, r):
    """Rewrite hostnames and user names through the shared pool, consistently
    within one event (the account in User: must match the profile path)."""
    m = re.search(r"^User: (.+)$", body, re.M)
    if not m:
        # no account field; still normalise profile paths that appear in paths
        old_user = None
    else:
        val = m.group(1).strip()
        if val.upper().startswith("NT AUTHORITY") or "APPPOOL" in val.upper():
            old_user = None
        else:
            old_user = val.split("\\")[-1]

    new_account = pick_account(r, r.choice(["local", "local", "domain"]))
    new_user = new_account.split("\\")[-1]

    if old_user:
        body = re.sub(r"^User: .+$", lambda _m: f"User: {new_account}", body, flags=re.M)
    # profile paths leak the original account even on SYSTEM-context events
    for stale in set(re.findall(r"[Cc]:\\+[Uu]sers\\+([A-Za-z0-9_.\-]+)", body)):
        if stale.lower() in ("public", "default", "all users"):
            continue
        body = re.sub(rf"([Cc]:\\+[Uu]sers\\+){re.escape(stale)}\b",
                      lambda mm: mm.group(1) + new_user, body)
    # bare hostnames from the corpus
    for stale_host in ("MSEDGEWIN10", "IEWIN7", "PC01", "insecurebank"):
        body = body.replace(stale_host + "\\", new_account.split("\\")[0] + "\\")
    return body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="candidates")
    ap.add_argument("--out", default="attack_events")
    ap.add_argument("--sig", choices=["backfill", "strip"], default="backfill")
    ap.add_argument("--seed", default="osava-attack-v1")
    args = ap.parse_args()

    src, out = Path(args.src), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("M*.txt"):
        old.unlink()

    # provenance from the converter's manifest
    prov = {}
    mf = src / "manifest.tsv"
    if mf.exists():
        for line in mf.read_text().splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 4:
                prov[parts[0].replace(".txt", "")] = (parts[1], parts[3])

    ids = list(KEEP) + [k for k in RENAME if k not in KEEP]
    rows, labels, n = [], {}, 0

    for aid in ids:
        f = src / f"{aid}.txt"
        if not f.exists():
            print(f"  missing {aid}")
            continue
        body = f.read_text().strip()
        meta = ATTACK_LABELS.get(aid)
        if not meta:
            print(f"  no label for {aid}")
            continue
        name, gold, sev, why = meta
        if why.startswith("CUT"):
            continue

        r = stable_rng(f"{args.seed}|{aid}")
        body = rewrite_identity(body, r)

        # tool-name removal
        if aid in RENAME:
            repl = RENAME[aid]
            # replace the leaking basename wherever it appears
            for line in body.splitlines():
                if line.startswith(("Image:", "ParentImage:", "CommandLine:")):
                    pass
            old_base = None
            m = re.search(r"^Image: .*\\([^\\]+)$", body, re.M)
            if m and aid in ("A340", "A496", "A428"):
                old_base = m.group(1)
            if old_base:
                new_full = repl
                # the command line repeats the image path; rewrite it whole so
                # Image and CommandLine do not disagree about the directory
                old_dir = re.search(r"^Image: (.*)\\[^\\]+$", body, re.M)
                if old_dir:
                    body = body.replace(old_dir.group(1) + "\\" + old_base, new_full)
                body = body.replace(old_base, new_full.rsplit("\\", 1)[-1])
                body = re.sub(r"^Image: .*$", lambda _m: f"Image: {new_full}", body,
                              count=1, flags=re.M)
        for leak, safe in PARENT_RENAME.items():
            body = body.replace(leak, safe)

        fields = {}
        for line in body.splitlines():
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
        # lab scaffolding parents
        pi = fields.get("ParentImage")
        if pi in LAB_PARENTS:
            fields["ParentImage"], fields["ParentCommandLine"] = LAB_PARENTS[pi]
        for k in ("CommandLine", "ParentCommandLine"):
            if k in fields:
                fields[k] = normalise_cmdline(fields[k])
        fields.pop("EventType", None)

        rendered = render(fields, sig_mode=args.sig)
        errs = validate(rendered)
        if errs:
            print(f"  {aid}: {errs}")
            continue

        n += 1
        mid = f"M{n:03d}"
        (out / f"{mid}.txt").write_text(rendered + "\n")
        labels[mid] = (name, gold, sev, why)
        srcf, attck = prov.get(aid, ("EVTX-ATTACK-SAMPLES", "-"))
        tech = re.search(r"T\d{4}(?:\.\d{3})?", why)
        # column 3 is the "family" slot consumed by build_sets.py; for real
        # captures the original candidate id plays that role
        rows.append("\t".join([mid, f"EVTX-ATTACK-SAMPLES:{srcf}",
                               fields["EventID"], aid, sev,
                               tech.group(0) if tech else attck, why]))

    (out / "manifest.tsv").write_text(
        "file\tsource\tevent_id\tfamily\tseverity\tattck\trationale\n"
        + "\n".join(rows) + "\n")
    (out / "labels.json").write_text(json.dumps(labels, indent=2))
    print(f"wrote {n} malicious events to {out}/  (sig={args.sig})")
    sev = {}
    for _, _, s_, _ in labels.values():
        sev[s_] = sev.get(s_, 0) + 1
    print("severity:", sev)


if __name__ == "__main__":
    main()
