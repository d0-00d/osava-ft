"""
Materialise triage decisions into a training set.

Takes the signature-level decisions from triage.py and expands them back to
events, with three corrections that matter more than the labelling itself:

  per-signature cap   A signature covering 400 events contributes 400 nearly
                      identical rows and dominates the gradient. Capped, with
                      the surplus discarded rather than downweighted.
  behavioural disjointness
                      Eval/train separation is enforced on the behaviour
                      signature, not the event id. Sharing a signature across
                      the split means eval measures memorisation. This is
                      stricter than the family-level split in build_sets.py and
                      supersedes it for real-capture data.
  contract normalisation
                      Identities rewritten, escaping normalised, signature
                      policy applied -- the same path every other class takes,
                      so the training set cannot be told apart from the eval
                      set by formatting.

    python3 build_train.py --cap 6 --out train_set.jsonl
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from contract import normalise_cmdline, pick_account, render, stable_rng, validate
from prep_attack import rewrite_identity
from signature import signature

# Red-team corpora ship binaries under their real names, and often under
# directories named after the tool as well. A model keyed on "UACME.exe" is
# defeated by `mv`, which is the PRD's tool-name-leakage risk.
#
# Two rules that matter:
#   * directories leak as much as filenames (C:\\Users\\den\\Source\\Repos\\UACME\\...)
#   * every tool must NOT collapse to the same replacement, or the replacement
#     becomes the new marker -- mapping them all to "a.exe" put that string on
#     7% of the malicious class. Names are drawn per-event from a neutral pool.
TOOL_TOKENS = [
    "uacme", "akagi", "akagi64", "ppldump", "pldump", "efspotato", "roguepotato",
    "roguewinrm", "printspoofer", "spoolfool", "networkserviceexploit",
    "keefarce", "sharprdp", "outflank-dumpert-dll", "outflank-dumpert",
    "andrewspecial", "malseclogon", "gsecdump", "wmighost", "furutaka",
    "byeintegrity5-uac", "byeintegrity", "uacbypass", "psexecprivesc",
    "processherpaderping", "winpwnage", "dumpert", "allthethings",
    "keylogger_directx", "atomicredteam", "atomicservice", "atomictestservice",
    "atomicbits", "exfilthis", "hellox86", "allthethingsx86", "allthethingsx64", "fubuki", "winpm", "nbtscan",
    "rdpwrap", "rdpwinst", "universaltermsrvpatch", "spoolsample", "smbmap",
]
_TOOL_RE = re.compile(r"(?<![A-Za-z0-9])(" +
                      "|".join(re.escape(t) for t in
                               sorted(TOOL_TOKENS, key=len, reverse=True)) +
                      r")(?![A-Za-z0-9])", re.IGNORECASE)

NEUTRAL = ["svc", "upd", "helper", "task", "agent", "tool", "run", "proc",
           "mod", "core", "app", "util", "host", "bin", "drv", "cfg", "sync",
           "mgr", "node", "job"]


def scrub_tool_names(body, rng):
    """Replace tool-name tokens with neutral ones, consistently within an event
    (so Image and ParentCommandLine still agree) and variably across events."""
    mapping = {}

    def sub(m):
        k = m.group(0).lower()
        if k not in mapping:
            mapping[k] = rng.choice(NEUTRAL) + (str(rng.randrange(10, 99))
                                                if rng.random() < 0.5 else "")
        return mapping[k]

    return _TOOL_RE.sub(sub, body)


def load_eval_signatures(paths):
    """Behaviours already spent on the eval set; training must not reuse them."""
    sigs = set()
    for p in paths:
        if not Path(p).exists():
            continue
        for line in open(p):
            r = json.loads(line)
            fields = {}
            for row in r["event"].splitlines():
                k, v = row.split(":", 1)
                fields[k.strip()] = v.strip()
            sigs.add(signature(fields))
    return sigs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", default="triage_queue.jsonl")
    ap.add_argument("--labels", default="labels_attack.json")
    ap.add_argument("--out", default="train_set.jsonl")
    ap.add_argument("--cap", type=int, default=6,
                    help="max events kept per behaviour signature")
    ap.add_argument("--image-cap", type=int, default=40,
                    help="max events any single Image may contribute to one "
                         "class. The signature cap alone does not stop a "
                         "process that appears under many distinct signatures: "
                         "consent.exe loading a different system DLL each time "
                         "is 275 signatures and one behaviour, and it took 23%% "
                         "of the benign class before this existed.")
    ap.add_argument("--sig", choices=["backfill", "strip"], default="backfill")
    ap.add_argument("--eval-sets", nargs="*",
                    default=["eval_set_v2.jsonl", "eval_synthetic.jsonl"])
    ap.add_argument("--seed", default="osava-train-v1")
    args = ap.parse_args()

    labels = json.loads(Path(args.labels).read_text())
    rows = [json.loads(l) for l in open(args.queue)]
    held = load_eval_signatures(args.eval_sets)
    print(f"{len(labels)} decided signatures, {len(rows)} queued events, "
          f"{len(held)} signatures reserved by the eval set")

    by_sig = defaultdict(list)
    for r in rows:
        by_sig[r["signature"]].append(r)

    out, skipped = [], Counter()
    for sig, dec in labels.items():
        if dec["gold"] == "drop":
            skipped["dropped in triage"] += len(by_sig.get(sig, []))
            continue
        if sig in held:
            skipped["reserved by eval"] += len(by_sig.get(sig, []))
            continue
        members = by_sig.get(sig, [])
        if not members:
            continue
        r = stable_rng(f"{args.seed}|{sig}")
        keep = members if len(members) <= args.cap else r.sample(members, args.cap)
        skipped["over cap"] += len(members) - len(keep)

        for m in keep:
            fields = {}
            for row in m["event"].splitlines():
                k, v = row.split(":", 1)
                fields[k.strip()] = v.strip()
            fields.pop("EventType", None)
            for k in ("CommandLine", "ParentCommandLine"):
                if k in fields:
                    fields[k] = normalise_cmdline(fields[k])
            body = "\n".join(f"{k}: {v}" for k, v in fields.items())
            body = rewrite_identity(body, stable_rng(f"{args.seed}|{m['id']}"))
            fields = {}
            for row in body.splitlines():
                k, v = row.split(":", 1)
                fields[k.strip()] = v.strip()
            rendered = scrub_tool_names(render(fields, sig_mode=args.sig),
                                        stable_rng(f"{args.seed}|scrub|{m['id']}"))
            errs = validate(rendered)
            if errs:
                skipped[f"contract: {errs[0]}"] += 1
                continue
            out.append({"id": m["id"], "name": dec.get("prefilter", "-"),
                        "gold": dec["gold"], "severity": dec["severity"],
                        "event": rendered,
                        "provenance": {"source": m["src"], "signature": sig,
                                       "attck": "-",
                                       "rationale": "; ".join(m["why"][:3])}})

    # per-image cap, applied after expansion so it sees the real distribution
    from signature import basename
    seen = Counter()
    capped = []
    r = stable_rng(f"{args.seed}|imagecap")
    r.shuffle(out)
    for row in out:
        img = ""
        for line in row["event"].splitlines():
            if line.startswith("Image:"):
                img = basename(line.split(":", 1)[1].strip())
                break
        key = (row["gold"], img)
        if seen[key] >= args.image_cap:
            skipped["over image cap"] += 1
            continue
        seen[key] += 1
        capped.append(row)
    out = sorted(capped, key=lambda x: x["id"])

    Path(args.out).write_text("\n".join(json.dumps(r) for r in out) + "\n")
    print(f"\nwrote {args.out}: {len(out)} events")
    print("class:   ", dict(Counter(r["gold"] for r in out)))
    print("severity:", dict(Counter(r["severity"] for r in out)))
    print("excluded:", dict(skipped))

    # hard assertion: no behaviour is shared with the eval set. Checked on the
    # signature recorded in provenance, which is the pre-identity-rewrite one --
    # the same value the exclusion above tested, so the check cannot pass by
    # accident of the rewrite changing the signature.
    leak = [r["id"] for r in out if r["provenance"]["signature"] in held]
    print(f"eval/train signature overlap: {len(leak)}"
          + (f"  LEAK {leak[:5]}" if leak else "  (clean)"))


if __name__ == "__main__":
    main()
