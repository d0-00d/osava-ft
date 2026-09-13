"""
Bulk EVTX -> JSONL extraction.

evtx_to_contract.py writes one .txt per event, which is right for a 50-event
eval set and wrong for a hundred thousand. Same parser, streaming JSONL out,
no per-file cap by default, and it records the source file on every record so
provenance survives (R13).

    python3 evtx_bulk.py --src sysmon-benign.evtx --out sysmon.jsonl
    python3 evtx_bulk.py --src ~/evtx-samples  --out attack_raw.jsonl
"""

import argparse
import json
import sys
import time
from pathlib import Path

from Evtx.Evtx import Evtx

from evtx_to_contract import parse_record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-per-file", type=int, default=0, help="0 = no cap")
    ap.add_argument("--progress", type=int, default=20000)
    args = ap.parse_args()

    src = Path(args.src).expanduser()
    files = sorted(src.rglob("*.evtx")) if src.is_dir() else [src]
    t0 = time.time()
    n = kept = 0

    with open(args.out, "w") as fh:
        for f in files:
            per = 0
            try:
                with Evtx(str(f)) as log:
                    for rec in log.records():
                        n += 1
                        if args.max_per_file and per >= args.max_per_file:
                            break
                        fields = parse_record(rec.xml())
                        if not fields:
                            continue
                        rel = str(f.relative_to(src)) if src.is_dir() else f.name
                        fields["_src"] = rel
                        fh.write(json.dumps(fields) + "\n")
                        kept += 1
                        per += 1
                        if args.progress and kept % args.progress == 0:
                            el = time.time() - t0
                            print(f"  {kept} kept / {n} read  {el:.0f}s "
                                  f"({n/el:.0f} rec/s)", flush=True)
            except Exception as e:
                print(f"  skip {f.name}: {type(e).__name__}: {e}", file=sys.stderr)

    el = time.time() - t0
    print(f"done: {kept} events kept from {n} records, {len(files)} file(s), {el:.0f}s")


if __name__ == "__main__":
    main()
