"""
Emit the classifier contract as one machine-readable artefact.

    python3 export_contract.py --out contract.json

The problem this solves: the contract is authored in Python (prompt.py,
contract.py, indicators.py) and consumed in TypeScript (HIRA). Every shared
fact -- the input field order, the severity scale, the bucketing, the
escalation rule, the output schema -- was independently restated on the
TypeScript side, and the restatements had already drifted:

  * HIRA's VALID_SEVERITIES still carried `critical`, dropped from this tier
    on evidence (R5).
  * parseClassification() required `confidence`, removed by R7, so every
    response failed validation and fell back to "benign".
  * promptBuilder's few-shot examples demonstrate the pre-R4 seven-field
    schema with severity fourth, contradicting what the model was trained on.

A contract that is restated is a contract that drifts. This file is the only
place it is written down; HIRA reads the JSON and checks `prompt_sha256`
against the deployed Modelfile at startup, so drift fails loudly instead of
silently degrading classification.
"""

import argparse
import hashlib
import json
from pathlib import Path

import prompt as P
from contract import FIELD_ORDER, MAX_CMDLINE, TRUNC_MARKER
from indicators import INDICATORS

# Input types this model can actually classify. It was trained on Windows
# Sysmon telemetry rendered into FIELD_ORDER and nothing else; on anything
# else it returns "none" with high confidence, which is the worst possible
# failure for an intake tier. Anything outside this set must not be routed
# here -- see HIRA cascadeRouter.
SUPPORTED_INPUT_TYPES = ["log_lines", "process_list", "registry_entry"]

# threatType values that force escalation regardless of severity. Restores the
# rule the pre-R7 Modelfile stated, now evaluated host-side.
ESCALATE_THREAT_TYPES = [
    "lateral_movement", "data_exfiltration", "ransomware",
    "privilege_escalation", "supply_chain", "rce", "zero_day",
]


def build(variant="strict", scale="4way"):
    system = P.system_prompt(variant, scale, override=True)
    return {
        "schema_version": "2.0.0",
        "model": "osava-smollm",
        "base": "HuggingFaceTB/SmolLM3-3B",
        "generated_by": "osava-ft/export_contract.py",

        # R1 -- the frozen input contract. Order is load-bearing: the model
        # was trained on exactly this sequence.
        "input": {
            "field_order": FIELD_ORDER,
            "max_cmdline": MAX_CMDLINE,
            "truncation_marker": TRUNC_MARKER,
            "user_message_template": "Event:\n{body}\n\nClassify.",
            "supported_input_types": SUPPORTED_INPUT_TYPES,
        },

        # R4/R5 -- severity first, four-way. `critical` is accepted on input
        # for backward compatibility and folded into `high`.
        "severity": {
            "scale": P.SCALES[scale],
            "accepted_on_input": P.SCALES["5way"],
            "bucket": P.BUCKET,
            "classes": P.CLASSES,
            "score_prefix": P.PREFIX,
        },

        # R7 -- routing is the host's decision, not the model's.
        "routing": {
            "escalate_severities": ["high", "critical"],
            "escalate_threat_types": ESCALATE_THREAT_TYPES,
            "confidence_reported_by_model": False,
            "confidence_from_severity": {
                "none": 0.05, "low": 0.2, "medium": 0.5,
                "high": 0.85, "critical": 0.95,
            },
        },

        # R6 -- closed indicator vocabulary.
        "indicators": sorted(INDICATORS),

        "output_fields": ["severity", "isThreat", "threatType",
                          "indicators", "reasoning"],

        # Drift detector. HIRA compares this against the SYSTEM block of the
        # Modelfile it deployed; a mismatch means the model is being prompted
        # differently from how it was trained, which is invisible otherwise.
        "prompt_sha256": hashlib.sha256(system.encode()).hexdigest(),
        "prompt_variant": variant,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="contract.json")
    ap.add_argument("--variant", choices=list(P.TAIL), default="strict")
    ap.add_argument("--scale", choices=list(P.SCALES), default="4way")
    ap.add_argument("--also", nargs="*", default=[],
                    help="additional paths to write the same artefact to "
                         "(e.g. HIRA/backend/src/ollama/contract.json)")
    args = ap.parse_args()

    doc = build(args.variant, args.scale)
    text = json.dumps(doc, indent=2) + "\n"
    for p in [args.out, *args.also]:
        Path(p).write_text(text)
        print(f"wrote {p}")
    print(f"\nschema_version   {doc['schema_version']}")
    print(f"prompt_sha256    {doc['prompt_sha256'][:16]}…")
    print(f"input fields     {len(doc['input']['field_order'])}")
    print(f"supported types  {', '.join(doc['input']['supported_input_types'])}")
    print(f"indicators       {len(doc['indicators'])}")


if __name__ == "__main__":
    main()
