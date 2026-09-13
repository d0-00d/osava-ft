"""
EVTX -> classifier input contract.

Converts Windows event logs (.evtx) into the frozen `Key: value` contract so
they can be hand-labeled and dropped into an eval or training set.

    pip install python-evtx --quiet
    python3 evtx_to_contract.py --src ~/EVTX-ATTACK-SAMPLES --out candidates/
    python3 evtx_to_contract.py --src /mnt/c/Users/Ayush/benign.evtx --out benign/

Writes one .txt per event plus a manifest.tsv listing source file and event id,
which is your provenance record. Nothing is auto-labeled: you label by hand.
"""

import argparse
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# contract field order - MUST match docs/classifier-input-contract.md
FIELD_ORDER = [
    "EventID", "EventType", "Image", "CommandLine", "ParentImage",
    "ParentCommandLine", "User", "Signed", "Signer", "DestinationIp",
    "DestinationPort", "DestinationHostname", "TargetFilename",
    "LogonType", "AuthPackage",
]

EVENT_TYPES = {
    1: "Process Create", 3: "Network Connection", 7: "Image Load",
    8: "Remote Thread", 10: "Process Access", 11: "File Create",
    12: "Registry Create", 13: "Registry Set", 22: "DNS Query",
    4624: "Logon", 4625: "Failed Logon", 4688: "Process Create",
    4697: "Service Install",
}

# Sysmon EventData name -> contract field
FIELD_MAP = {
    "Image": "Image", "CommandLine": "CommandLine",
    "ParentImage": "ParentImage", "ParentCommandLine": "ParentCommandLine",
    "User": "User", "TargetUserName": "User",
    "Signed": "Signed", "Signature": "Signer", "SignatureStatus": "SignatureStatus",
    "DestinationIp": "DestinationIp", "DestinationPort": "DestinationPort",
    "DestinationHostname": "DestinationHostname", "IpAddress": "DestinationIp",
    "TargetFilename": "TargetFilename", "TargetObject": "TargetFilename",
    # Sysmon EventID 7 names the loaded module `ImageLoaded`, and the
    # Signed/Signature pair on that event describes the LOADED MODULE, not the
    # loading process. Without this mapping the module is dropped and the
    # signature silently re-reads as a claim about the process -- the opposite
    # of what the record says.
    "ImageLoaded": "TargetFilename",
    "LogonType": "LogonType", "AuthenticationPackageName": "AuthPackage",
    "LmPackageName": "AuthPackage",
}

MAX_CMDLINE = 512


def parse_record(xml_str):
    """Return dict of contract fields, or None if the event isn't useful."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    sysblk = root.find(f"{NS}System")
    if sysblk is None:
        return None
    eid_el = sysblk.find(f"{NS}EventID")
    if eid_el is None or not eid_el.text:
        return None
    eid = int(eid_el.text)
    if eid not in EVENT_TYPES:
        return None

    out = {"EventID": str(eid), "EventType": EVENT_TYPES[eid]}

    data = root.find(f"{NS}EventData")
    if data is not None:
        for d in data.findall(f"{NS}Data"):
            name = d.get("Name")
            if name in FIELD_MAP and d.text:
                val = d.text.strip()
                if val and val not in ("-", "N/A", "0x0"):
                    out.setdefault(FIELD_MAP[name], val)

    # normalise signature into Signed/Signer
    status = out.pop("SignatureStatus", None)
    if status:
        out["Signed"] = "true" if status.lower() == "valid" else "false"
    elif "Signer" in out:
        out.setdefault("Signed", "true")

    if "CommandLine" in out and len(out["CommandLine"]) > MAX_CMDLINE:
        out["CommandLine"] = out["CommandLine"][:MAX_CMDLINE] + "..."

    # require at least one substantive field beyond the header
    if not any(k in out for k in ("Image", "TargetFilename", "DestinationIp", "User")):
        return None
    return out


def render(fields):
    return "\n".join(f"{k}: {fields[k]}" for k in FIELD_ORDER if k in fields)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help=".evtx file or directory of them")
    ap.add_argument("--out", default="candidates")
    ap.add_argument("--max-per-file", type=int, default=3,
                    help="cap per source file so one noisy log can't dominate")
    ap.add_argument("--prefix", default="C", help="filename prefix for outputs")
    args = ap.parse_args()

    src = Path(args.src).expanduser()
    files = sorted(src.rglob("*.evtx")) if src.is_dir() else [src]
    if not files:
        print(f"no .evtx found under {src}")
        return

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest, n = [], 0
    seen = set()

    for f in files:
        kept = 0
        try:
            with Evtx(str(f)) as log:
                for rec in log.records():
                    if kept >= args.max_per_file:
                        break
                    fields = parse_record(rec.xml())
                    if not fields:
                        continue
                    body = render(fields)
                    key = body[:300]
                    if key in seen:
                        continue
                    seen.add(key)
                    n += 1
                    kept += 1
                    name = f"{args.prefix}{n:03d}.txt"
                    (out / name).write_text(body + "\n")
                    # technique often encoded in the sample filename
                    tech = re.findall(r"T\d{4}(?:\.\d{3})?", f.name)
                    manifest.append(f"{name}\t{f.relative_to(src) if src.is_dir() else f.name}"
                                    f"\t{fields['EventID']}\t{','.join(tech) or '-'}")
        except Exception as e:
            print(f"  skip {f.name}: {type(e).__name__}: {e}")

    (out / "manifest.tsv").write_text(
        "file\tsource_evtx\tevent_id\tattck\n" + "\n".join(manifest) + "\n")
    print(f"wrote {n} events to {out}/ from {len(files)} evtx file(s)")
    print(f"provenance in {out}/manifest.tsv")
    print("\nNext: read each .txt, delete the useless ones, then add ids+labels "
          "to LABELS in build_eval.py")


if __name__ == "__main__":
    main()
