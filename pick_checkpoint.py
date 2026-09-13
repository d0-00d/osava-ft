"""
Score every training checkpoint on the held-out eval set and pick one.

    python3 pick_checkpoint.py --adapter-dir adapters/v1

`train_qlora.py` deliberately does not use `load_best_model_at_end`, because
the criterion it selects on -- eval_loss -- is ~99% JSON boilerplate here. This
selects on the thing the PRD actually measures: bucketed accuracy, with the
under-call rate as the tie-break, since R7 and the PRD both treat a missed
threat as the expensive error.

The base model is loaded once and adapters are swapped in place; running
run_eval.py per checkpoint would reload 3B of weights ten times.
"""

import argparse
import json
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

import prompt as P
import run_eval
from report import metrics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="HuggingFaceTB/SmolLM3-3B")
    ap.add_argument("--adapter-dir", default="adapters/v1")
    ap.add_argument("--eval-set", default="eval_set_v2.jsonl")
    ap.add_argument("--variant", choices=list(P.TAIL), default="strict")
    ap.add_argument("--scale", choices=list(P.SCALES), default="4way")
    ap.add_argument("--out-dir", default="logs")
    ap.add_argument("--include-base", action="store_true",
                    help="also score the un-adapted model, as a control")
    args = ap.parse_args()

    run_eval.SCALE, run_eval.OVERRIDE = args.scale, True
    run_eval.SEVERITIES = P.SCALES[args.scale]

    cks = sorted(Path(args.adapter_dir).glob("checkpoint-*"),
                 key=lambda p: int(p.name.split("-")[1]))
    final = Path(args.adapter_dir)
    if (final / "adapter_model.safetensors").exists():
        cks.append(final)
    if not cks:
        raise SystemExit(f"no checkpoints under {args.adapter_dir}")

    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForCausalLM.from_pretrained(
        args.model, dtype=torch.bfloat16, device_map="cuda:0",
        attn_implementation="sdpa",
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16))
    model.eval()

    rows = [json.loads(l) for l in Path(args.eval_set).read_text().splitlines()
            if l.strip()]
    rows = [r for r in rows if not r["event"].startswith("PASTE_")]
    Path(args.out_dir).mkdir(exist_ok=True)

    def score_all(m, tag):
        res = []
        for r in rows:
            sev_p, cls_p = run_eval.score(m, tok, r["event"], args.variant, "cuda:0")
            rk = sorted(cls_p.items(), key=lambda kv: -kv[1])
            res.append({"id": r["id"], "name": r["name"], "gold": r["gold"],
                        "pred": rk[0][0], "severity": max(sev_p, key=sev_p.get),
                        "sev_probs": sev_p, "class_probs": cls_p,
                        "margin": rk[0][1] - rk[1][1]})
        Path(args.out_dir, f"{tag}.json").write_text(json.dumps(res, indent=2))
        return res

    scored = []
    if args.include_base:
        scored.append(("base", metrics(score_all(model, "ckpt_base"))))
        print(f"  base                 acc {scored[-1][1]['bucketed accuracy']:.1%}")

    from peft import PeftModel
    pm = None
    for c in cks:
        name = c.name.replace("checkpoint-", "step")
        if pm is None:
            pm = PeftModel.from_pretrained(model, c, adapter_name=name)
        else:
            pm.load_adapter(c, adapter_name=name)
        pm.set_adapter(name)
        pm.eval()
        m = metrics(score_all(pm, f"ckpt_{name}"))
        scored.append((name, m))
        print(f"  {name:<20} acc {m['bucketed accuracy']:6.1%}   "
              f"under {m['under-call rate']:6.1%}   "
              f"mal-recall {m['malicious recall']:6.1%}   "
              f"susp-recall {m['suspicious recall']:6.1%}")

    best = max(scored, key=lambda kv: (kv[1]["bucketed accuracy"],
                                       -kv[1]["under-call rate"]))
    print(f"\nbest: {best[0]}")
    for k, v in best[1].items():
        print(f"  {k:<24}{v:.1%}" if "margin" not in k else f"  {k:<24}{v:+.3f}")
    print(f"\n  python3 report.py base_v3_strict.json "
          f"{args.out_dir}/ckpt_{best[0]}.json --errors")


if __name__ == "__main__":
    main()
