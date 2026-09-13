# osava-ft — SENTRI-Classifier training data

Builds the eval and training sets for the SmolLM3-3B intake classifier that
replaces `phi3:mini` in HIRA/OSAVA. See the PRD for goals and metrics.

## Pipeline

    ~/evtx-samples/*.evtx ─┐
    (278 attack captures)  ├→ evtx_bulk.py → attack_raw.jsonl ┐
    sysmon-benign.evtx ────┘                 sysmon.jsonl ────┴→ prefilter.py
    (52k real benign events from a working machine)                   │
                                                                      ↓
                                                            triage_queue.jsonl
                                                                      │
                                                            triage.py │ (label
                                                                      ↓  behaviours,
                                                            labels_auto.json  not events)
                                                                      │
    gen_benign.py    → train_benign/ ┐                    build_train.py
    gen_suspicious.py → train_susp/  ┴→ merge_train.py ←──────────┘
                                              ↓
                                      train_final.jsonl → QLoRA

## Core modules

| File | Role |
|---|---|
| `contract.py`   | The frozen `Key: value` input contract (R1/R3). Field order, 512-char truncation, `%%`→`%`, plus the shared identity/parent pools that stop hostnames and parent processes from predicting the class. |
| `signature.py`  | Behaviour signatures. Collapses *who and where* (usernames, GUIDs, versions, IPs, ports) and keeps *what happened*. Everything downstream groups and de-duplicates on this. |
| `indicators.py` | Closed indicator vocabulary (R6). Consumed by `targets.py`. |
| `prompt.py`     | The system prompt, severity scale and bucketing. **One definition.** `run_eval.py`, `build_sft.py` and `merge_export.py` all import it; a prompt defined twice eventually gets defined differently, which already happened once (`round2` vs `strict`). |
| `targets.py`    | Builds the full output object -- indicators, threatType, reasoning -- from the event text alone. `provenance.rationale` is a note about the corpus, not the event, so it is not used as reasoning. |

## Building the data

| File | Role |
|---|---|
| `evtx_bulk.py`      | Streaming EVTX → JSONL. No per-file cap. |
| `evtx_to_contract.py` | Original per-event extractor. Still used for the `candidates/` set the eval malicious class is built from. |
| `prefilter.py`      | Separates the technique from background noise. Scores each event against the real Sysmon capture (ambient = innocent), corpus ubiquity, sample-filename match, and attack heuristics. |
| `triage.py`         | Keyboard labelling TUI. One decision per behaviour, not per event. |
| `propose_labels.py` | Rule-based severity suggestions shown inside triage. |
| `apply_batch.py`    | Applies `Gxxxx=severity` decisions in bulk. |
| `lineage_fix.py`    | Propagates maliciousness from known-bad parents/loaders. |
| `recalibrate.py`    | Rule-level corrections found by the blind samples. |
| `gen_benign.py`     | Synthetic benign, incl. hard negatives (signed vendor binaries in AppData, LOLBins doing their real job, unsigned in-house tools). |
| `gen_suspicious.py` | Synthetic `suspicious` — the class no public corpus contains. |
| `prep_attack.py`    | Normalises hand-picked attack candidates into the eval malicious class. |
| `build_sets.py`     | Assembles the eval set + synthetic training pool. |
| `build_train.py`    | Expands labels to events; per-signature and per-image caps; tool-name scrub; enforces eval/train disjointness by behaviour. |
| `merge_train.py`    | Merges real + synthetic into the final training set. |

## Checking the data

| File | Role |
|---|---|
| `audit_leak.py`     | Shortcut detector: field presence, identifier overlap, single-token predictors. Run after any regeneration. |
| `compare_labels.py` | Scores one label file against another. Used for the blind human-vs-model comparison. |
| `run_eval.py`       | The eval harness (R14). Scores `severity` by length-normalised log-likelihood. `--prompt shipped\|strict`, `--scale 4way\|5way`. |

## Datasets

| File | What |
|---|---|
| `train_final.jsonl`      | **The training set.** 1993 events, 4-way severity. |
| `sft_train.jsonl`        | 1822 prompt/completion pairs. Built by `build_sft.py`. |
| `sft_val.jsonl`          | 171 pairs, held out **by behaviour signature**, not by row. |
| `train_final_5way.jsonl` | Same events, original 5-way ordinal (PRD open question 2). |
| `eval_set_v2.jsonl`      | **The held-out eval set.** 50 events, never trained on. |
| `eval_set_v2_5way.jsonl` | 5-way variant, for scoring a 5-way model. |
| `eval_set_v2_nosig.jsonl`| `Signed`/`Signer` stripped (PRD open question 1). |
| `eval_synthetic.jsonl`   | The original 9 synthetic events, kept for baseline continuity (R12). |
| `sysmon.jsonl`           | 52,791 real benign events extracted from `sysmon-benign.evtx`. |
| `attack_raw.jsonl`       | 2,929 attack events from 199 EVTX files. |
| `triage_queue.jsonl`     | The scored, ranked labelling queue. |
| `labels_auto.json`       | Every labelling decision, with `decided_by` provenance. |
| `blind_labels*.json`     | Two independent blind human passes, used to measure the automated labels. |

## Regenerating

    ./build_all.sh                                  # eval sets, both signature variants
    python3 build_train.py --labels labels_auto.json --out train_real.jsonl
    python3 merge_train.py --out train_final.jsonl
    python3 audit_leak.py train_final.jsonl         # audits what is actually trained on

## Training (M4/M5)

    python3 build_sft.py                            # -> sft_train.jsonl / sft_val.jsonl
    python3 train_qlora.py --out adapters/v1        # ~90 min on an 8GB 4060
    python3 run_eval.py --adapter adapters/v1 --eval-set eval_set_v2.jsonl --out ft_v1.json
    python3 report.py base_v3_strict.json ft_v1.json
    python3 merge_export.py --adapter adapters/v1 --out dist/sentri-v1

| File | Role |
|---|---|
| `build_sft.py`    | Training rows -> prompt/completion pairs. Regenerates every target field except `severity`; holds out val by signature; hard-asserts no eval signature appears in training. |
| `train_qlora.py`  | QLoRA on SmolLM3-3B. NF4, r=16/alpha=32, all linear projections, loss on the completion only. |
| `merge_export.py` | Merges the adapter, checksums the output, and **generates** the Ollama Modelfile from `prompt.py`. |

## Measured baseline (SmolLM3-3B, no fine-tuning, held-out 50)

Labels are `max(generator, human-blind)` -- two independent passes resolved by
a rule fixed before the results were looked at. Earlier figures on this table
(36.0% / 48.0%) were measured against the generator's labels alone.

| | shipped prompt | M1 fix | target |
|---|---|---|---|
| bucketed accuracy | 34.0% | 54.0% | ≥80% |
| under-call rate   | 66.0% | 38.0% | ≤10% |
| over-call rate    |  0.0% |  8.0% | ≤20% |
| malicious recall  |  4.3% | 56.5% | ≥90% |
| suspicious recall |  0.0% |  0.0% | — |
| benign precision  | 32.7% | 42.4% | — |

Reproduce with `python3 report.py base_v3_shipped.json base_v3_strict.json`.
Both were measured under SmolLM3's date-stamped prompt header; `prompt.py` now
suppresses it with `/system_override`, so re-run before comparing to a
fine-tune (`--legacy-prompt` restores the old behaviour).
