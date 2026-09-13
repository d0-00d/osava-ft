"""
M4 -- QLoRA fine-tune of SmolLM3-3B on the SENTRI intake contract.

    python3 build_sft.py
    python3 train_qlora.py --out adapters/v1
    python3 run_eval.py --adapter adapters/v1 --eval-set eval_set_v2.jsonl \
        --out ft_v1.json

Sized for 8GB (RTX 4060 Laptop): NF4 weights, LoRA on every linear projection,
gradient checkpointing, paged 8-bit optimiser. Peak is ~7.9GB at max_length 1280.

Interruptible. Checkpoints land every 10% of the run and carry optimiser,
scheduler and RNG state, so `--resume` continues the run rather than restarting
it warm. Killing the process costs at most the steps since the last checkpoint.

Loss is computed on the completion only. The prompt is ~316 of ~470 median
tokens, and it is byte-identical on every row -- training on it would spend
two thirds of the gradient teaching the model to recite its own system prompt.

The completion opens with `{"severity": "`, which is exactly the string
run_eval.py pins before scoring. Field order in the target is load-bearing
(R4), not cosmetic.
"""

import argparse
import json
from pathlib import Path

import torch
import torch.nn.functional as F
from datasets import Dataset
from peft import LoraConfig, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

import prompt as P

# The severity token is one token out of a ~94-token completion -- 1.07% of the
# loss. The other 99% teaches JSON punctuation and the templated reasoning,
# which the model reaches 99.6% accuracy on while still coin-flipping the only
# field that is scored. `--sev-weight` re-allocates the gradient toward it.
#
# The position is fixed and checked at runtime: PREFIX tokenises to exactly 4
# tokens for every severity value, so the value is the 5th completion token.
SEV_OFFSET = 4


class WeightedSFTTrainer(SFTTrainer):
    """SFTTrainer with a per-token loss weight on the severity token."""

    sev_weight = 1.0
    sev_ids = ()

    def compute_loss(self, model, inputs, return_outputs=False,
                     num_items_in_batch=None):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        inputs["labels"] = labels

        logits = outputs.logits[:, :-1, :]
        tgt = labels[:, 1:]
        valid = tgt != -100

        w = torch.ones_like(tgt, dtype=torch.float32)
        for i in range(tgt.size(0)):
            idx = valid[i].nonzero(as_tuple=True)[0]
            if idx.numel() > SEV_OFFSET:
                pos = idx[SEV_OFFSET]
                if int(tgt[i, pos]) in self.sev_ids:      # never guess blind
                    w[i, pos] = self.sev_weight

        ce = F.cross_entropy(logits.reshape(-1, logits.size(-1)).float(),
                             tgt.reshape(-1), reduction="none",
                             ignore_index=-100).view(tgt.shape)
        # weighted MEAN, not sum: re-allocates gradient across tokens without
        # inflating its magnitude, so the effective learning rate is unchanged
        loss = (ce * w)[valid].sum() / w[valid].sum()
        return (loss, outputs) if return_outputs else loss


def load(path):
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    return Dataset.from_list([{"prompt": r["prompt"], "completion": r["completion"]}
                              for r in rows])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="HuggingFaceTB/SmolLM3-3B")
    ap.add_argument("--train", default="sft_train.jsonl")
    ap.add_argument("--val", default="sft_val.jsonl")
    ap.add_argument("--out", default="adapters/v1")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--batch", type=int, default=2)
    ap.add_argument("--accum", type=int, default=8)
    ap.add_argument("--max-length", type=int, default=1280)
    ap.add_argument("--sev-weight", type=float, default=20.0,
                    help="loss weight on the severity token (1.0 disables). "
                         "20 gives it ~18%% of the loss instead of 1.07%%.")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--resume", nargs="?", const=True, default=None,
                    metavar="CHECKPOINT",
                    help="resume training. Bare --resume takes the latest "
                         "checkpoint under --out; pass a path for a specific one. "
                         "Optimiser, scheduler and RNG state are restored, so the "
                         "run continues rather than restarting warm.")
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16),
        dtype=torch.bfloat16, device_map={"": 0}, attn_implementation="sdpa")
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(
        model, use_gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False})

    peft_cfg = LoraConfig(
        r=args.rank, lora_alpha=args.alpha, lora_dropout=args.dropout,
        bias="none", task_type="CAUSAL_LM",
        # every linear projection, not just q/v. The task is a distribution
        # shift over a narrow input format, and the MLP blocks are where the
        # `Key: value` -> severity mapping has room to live.
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"])

    tr, va = load(args.train), load(args.val)
    cfg = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=args.accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        max_grad_norm=0.3,
        weight_decay=0.0,
        optim="paged_adamw_8bit",
        bf16=True,
        max_length=args.max_length,
        packing=False,               # packing would cross the completion boundary
        completion_only_loss=True,   # prompt is masked out of the loss
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        # No length grouping: TRL 0.24 dropped `group_by_length`, and its
        # replacements both cost more than the padding does here. `packing`
        # concatenates rows into fixed blocks, which crosses the
        # prompt/completion boundary that `completion_only_loss` depends on;
        # `padding_free` needs FlashAttention 2, which is not installed.
        logging_steps=5,
        eval_strategy="steps",
        eval_steps=0.1,
        save_strategy="steps",
        save_steps=0.1,
        # Keep every checkpoint and select afterwards on classification
        # accuracy, not on eval_loss.
        #
        # eval_loss is the wrong criterion here: the severity token is 1.07%
        # of a 93-token mean completion, so ~99% of the loss is JSON
        # boilerplate and templated reasoning. It reached 0.066 / 97.9% token
        # accuracy at a third of an epoch while saying nothing about whether
        # the model can classify. The checkpoint that best predicts the
        # boilerplate is not necessarily the one that best predicts the label.
        save_total_limit=None,
        load_best_model_at_end=False,
        seed=args.seed,
        report_to=[],
    )

    Trainer = WeightedSFTTrainer if args.sev_weight != 1.0 else SFTTrainer
    trainer = Trainer(model=model, args=cfg, train_dataset=tr,
                      eval_dataset=va, processing_class=tok,
                      peft_config=peft_cfg)
    if args.sev_weight != 1.0:
        # Trainer skips its own /gradient_accumulation_steps when the model
        # accepts loss kwargs AND num_items_in_batch is passed, because it then
        # expects compute_loss to have returned a token SUM it normalises
        # globally. compute_loss above returns a weighted MEAN, so leaving this
        # True made the gradient 8x too large -- an 8x effective learning rate,
        # reported as train_loss 15.46 against an eval_loss of 1.75. Forcing it
        # False restores the division and puts this run on the same loss scale
        # as v1 and v2.
        trainer.model_accepts_loss_kwargs = False
        trainer.sev_weight = args.sev_weight
        trainer.sev_ids = {tok(s, add_special_tokens=False).input_ids[0]
                           for s in P.SCALES["4way"]}
        assert len(trainer.sev_ids) == 4, "severity values are not single tokens"

    # sanity: the loss must see the completion and nothing before it
    b = trainer.data_collator([trainer.train_dataset[i] for i in range(2)])
    lab = b["labels"][0]
    kept = tok.decode([t for t in b["input_ids"][0][lab != -100]])
    note = (f"masked {int((lab == -100).sum())}/{len(lab)} tokens\n"
            f"loss sees: {kept!r}\n")
    print("\n" + note)
    Path(args.out).mkdir(parents=True, exist_ok=True)
    (Path(args.out) / "mask_check.txt").write_text(note)
    assert kept.lstrip().startswith('{"severity"'), "completion mask is wrong"

    if args.sev_weight != 1.0:
        # prove the weight lands on the severity value, not on punctuation
        lab1 = b["labels"][0]
        idx = (lab1 != -100).nonzero(as_tuple=True)[0]
        hit = tok.decode([b["input_ids"][0][idx[SEV_OFFSET]]])
        print(f"sev-weight {args.sev_weight} applied to token "
              f"{idx[SEV_OFFSET].item()}: {hit!r}\n")
        assert hit.strip() in P.SCALES["4way"], f"weight would land on {hit!r}"

    trainer.train(resume_from_checkpoint=args.resume)
    trainer.model.save_pretrained(args.out)
    tok.save_pretrained(args.out)
    m = trainer.state.log_history
    print(f"\nsaved {args.out}")
    print("best eval_loss:", min((h["eval_loss"] for h in m if "eval_loss" in h),
                                 default=None))


if __name__ == "__main__":
    main()
