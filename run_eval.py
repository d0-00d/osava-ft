"""OSAVA classifier eval harness (v3).

Targets the real SENTRI contract. Scores `severity` (5-way ordinal) by
log-likelihood and buckets into the 3 gold classes.

Requires severity to be the FIRST field in the output schema so it can be
scored without forcing the model through earlier fields. This is a deliberate
change to the classifier-tier contract.

  --prompt round2   use the shipped SENTRI prompt (default)
  --prompt strict   same, with the leniency instruction inverted
"""

import argparse, json, math
from pathlib import Path
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

import prompt
from prompt import BUCKET, CLASSES, PREFIX, SCALES, TAIL

# Severity scale.
#
# `critical` was dropped from this tier on evidence, not preference. Two blind
# labelling passes over the corpus put the maintainer's use of `critical` at
# 6/160 groups when judging single events, against 14% (7/50) in
# attack_labels.py where the whole capture was visible. Same person, same
# scale, different context: `critical` describes an incident, not an event, and
# this tier only ever sees one event. Folding it into `high` lifted labeller
# agreement from 48% to 69% exact.
#
# `--scale 5way` restores the original ordinal for comparison; score both on
# this harness before committing the contract change (R5).


def build_prompt(tok, event, variant):
    return prompt.build_prompt(tok, event, variant, SCALE, OVERRIDE)


@torch.no_grad()
def score(model, tok, event, variant, device, norm="mean"):
    base = build_prompt(tok, event, variant) + PREFIX
    base_ids = tok(base, return_tensors="pt", add_special_tokens=False).input_ids
    n = base_ids.shape[1]
    ll = {}
    for s in SEVERITIES:
        comp = tok(s + '"', return_tensors="pt", add_special_tokens=False).input_ids
        full = torch.cat([base_ids, comp], dim=1).to(device)
        lp = torch.log_softmax(model(full).logits[0, :-1].float(), dim=-1)
        tgt = full[0, 1:]
        tl = lp[n - 1:, :].gather(1, tgt[n - 1:].unsqueeze(1)).squeeze(1)
        ll[s] = tl.mean().item() if norm == "mean" else tl.sum().item()
    m = max(ll.values())
    e = {k: math.exp(v - m) for k, v in ll.items()}
    z = sum(e.values())
    sev_p = {k: v / z for k, v in e.items()}
    cls_p = {c: 0.0 for c in CLASSES}
    for s, p in sev_p.items():
        cls_p[BUCKET[s]] += p
    return sev_p, cls_p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="HuggingFaceTB/SmolLM3-3B")
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--eval-set", default="eval_set.jsonl")
    ap.add_argument("--prompt", choices=list(TAIL), default="strict")
    ap.add_argument("--norm", choices=["mean", "sum"], default="mean")
    ap.add_argument("--scale", choices=list(SCALES), default="4way")
    ap.add_argument("--legacy-prompt", action="store_true",
                    help="keep SmolLM3's injected date + /think metadata header "
                         "(reproduces measurements taken before 2026-09-10)")
    ap.add_argument("--no-4bit", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    global SEVERITIES, SCALE, OVERRIDE
    SCALE, OVERRIDE = args.scale, not args.legacy_prompt
    SEVERITIES = SCALES[args.scale]

    tok = AutoTokenizer.from_pretrained(args.model)
    kw = {"dtype": torch.bfloat16, "device_map": "cuda:0", "attn_implementation": "sdpa"}
    if not args.no_4bit:
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(args.model, **kw)
    if args.adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, args.adapter)
    model.eval()

    rows = [json.loads(l) for l in Path(args.eval_set).read_text().splitlines() if l.strip()]
    res, correct = [], 0
    conf = {g: {p: 0 for p in CLASSES} for g in CLASSES}

    print(f"\nprompt={args.prompt}  scale={args.scale}  norm={args.norm}  "
          f"header={'legacy' if args.legacy_prompt else 'override'}  "
          f"adapter={args.adapter}")
    print(f"\n{'id':<5} {'name':<26} {'gold':<11} {'pred':<11} {'sev':<9} {'p':>6} {'marg':>7} ok")
    print("-" * 88)
    for r in rows:
        if r["event"].startswith("PASTE_"):
            continue
        sev_p, cls_p = score(model, tok, r["event"], args.prompt, "cuda:0", args.norm)
        top_sev = max(sev_p, key=sev_p.get)
        rk = sorted(cls_p.items(), key=lambda kv: -kv[1])
        pred, p = rk[0]
        marg = p - rk[1][1]
        ok = pred == r["gold"]
        correct += ok
        conf[r["gold"]][pred] += 1
        res.append({**{k: r[k] for k in ("id", "name", "gold")}, "pred": pred,
                    "severity": top_sev, "sev_probs": sev_p, "class_probs": cls_p,
                    "margin": marg})
        print(f"{r['id']:<5} {r['name']:<26} {r['gold']:<11} {pred:<11} {top_sev:<9} "
              f"{p:>6.3f} {marg:>7.3f} {'Y' if ok else 'N'}")

    n = len(res)
    if n:
        print(f"\naccuracy: {correct}/{n} = {correct/n:.1%}")
        print("\nconfusion (rows=gold, cols=pred):")
        print(f"{'':<12}" + "".join(f"{c:<12}" for c in CLASSES))
        for g in CLASSES:
            print(f"{g:<12}" + "".join(f"{conf[g][p]:<12}" for p in CLASSES))
        sev = {c: i for i, c in enumerate(CLASSES)}
        under = sum(1 for r in res if sev[r["pred"]] < sev[r["gold"]])
        over = sum(1 for r in res if sev[r["pred"]] > sev[r["gold"]])
        print(f"\nunder-called (leniency): {under}   over-called: {over}")
        spread = {c: sum(1 for r in res if r["pred"] == c) for c in CLASSES}
        print(f"prediction spread: {spread}")
        sspread = {s: sum(1 for r in res if r["severity"] == s) for s in SEVERITIES}
        print(f"severity spread:   {sspread}")

    if args.out:
        Path(args.out).write_text(json.dumps(res, indent=2))
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
