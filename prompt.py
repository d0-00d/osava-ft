"""
The prompt, the severity scale, and the bucketing -- in one place.

This module exists because of a bug worth remembering. `run_eval.py` used to
carry two prompt variants named `round2` and `strict` that differed by a
single trailing full stop, so every "shipped vs strict" comparison compared a
prompt against itself and reported the difference as noise. A prompt that is
defined twice will eventually be defined differently.

Training and evaluation MUST agree on this text exactly. A fine-tune learns
P(severity | prompt + event); scoring it under a different prompt measures
something else and there is no warning when it happens.
"""

BASE = """You are SENTRI-Classifier, an intake analysis engine for a cybersecurity incident
response system. You receive raw security data and classify it.

You ONLY output valid JSON. No preamble. No markdown. No explanation outside JSON.

Output schema (always use exactly this structure):
{
  "severity": <SEVERITY_VALUES>,
  "isThreat": boolean,
  "threatType": string or null,
  "indicators": { "key": "value" },
  "reasoning": "one to three sentence explanation"
}

threatType values you may use:
traffic_spike, failed_logins, port_scan, data_exfiltration, lateral_movement,
malware, phishing, ransomware, privilege_escalation, supply_chain, sql_injection,
xss, rce, credential_stuffing, reconnaissance, cryptomining, unknown
"""

TAIL = {
    # verbatim from HIRA/backend/ollama/SENTRIClassifier.Modelfile as it shipped,
    # kept only as the pre-M1 baseline
    "shipped": """
	You are precise. You do not over-flag. A clean nginx config is not a threat.
	A standard cron job is not a threat. Err toward false negative over false positive
	only when genuinely ambiguous. High confidence requires clear indicators.""",
    # M1: written into the Modelfile 2026-09-10
    "strict": """
	You are precise. When an event shows a known attack technique -- unsigned binaries
	executing from temp paths, office applications spawning shells, service binaries
	running as SYSTEM from non-standard paths, encoded or hidden-window commands --
	rate it "high" or "critical" even if benign explanations are conceivable.
	Reserve "none" and "low" for activity that is affirmatively normal: signed
	binaries from system paths with expected parents. Do not under-rate clear
	technique matches.""",
}

SCALES = {
    "4way": ["none", "low", "medium", "high"],
    "5way": ["none", "low", "medium", "high", "critical"],
}
BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious"}
CLASSES = ["benign", "suspicious", "malicious"]

# SmolLM3's chat template injects a `## Metadata` header into every system
# message containing (a) today's date from strftime_now() and (b) a
# `Reasoning Mode: /think` line. Both are wrong here:
#
#   the date makes the prompt non-reproducible -- the exact string fed to the
#   model changes at midnight, so a baseline measured today cannot be compared
#   to a fine-tune measured tomorrow, silently.
#   /think tells the model to emit a <think> block first, but the harness pins
#   `{"severity": "` immediately after the generation prompt, scoring the
#   severity token in the position the model wants to reason in.
#
# `/system_override` is the template's own escape hatch: it drops the metadata
# header entirely and passes the system message through verbatim. Determinism
# is worth more here than the model's default framing, and this tier has no use
# for chain-of-thought it is not allowed to print.
OVERRIDE = "/system_override\n"

# the model is scored on the first field, so the harness pins everything up to
# and including the opening quote of the severity value
PREFIX = '{"severity": "'


def system_prompt(variant="strict", scale="4way", override=True):
    body = BASE.replace("<SEVERITY_VALUES>",
                        " or ".join(f'"{s}"' for s in SCALES[scale])) + TAIL[variant]
    return (OVERRIDE + body) if override else body


def messages(event, variant="strict", scale="4way", override=True):
    return [{"role": "system", "content": system_prompt(variant, scale, override)},
            {"role": "user", "content": f"Event:\n{event}\n\nClassify."}]


def build_prompt(tok, event, variant="strict", scale="4way", override=True):
    return tok.apply_chat_template(messages(event, variant, scale, override),
                                   tokenize=False, add_generation_prompt=True)
