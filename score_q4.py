"""
Score the quantised model's answers against the eval set.

    powershell -File dist/sentri-v1/q4_eval.ps1 osava-smollm
    python3 score_q4.py dist/sentri-v1/q4_results.json

The bf16 numbers do not describe the deployed model. `ollama run` generates
rather than scoring severity by log-likelihood, so this is not strictly
comparable to run_eval.py -- but it IS what production does, which makes it the
number that counts. Divergences are listed per event.
"""
import json, sys, collections
from pathlib import Path

BUCKET = {"none": "benign", "low": "benign", "medium": "suspicious",
          "high": "malicious", "critical": "malicious"}
RANK = {"benign": 0, "suspicious": 1, "malicious": 2}

res = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
ev = {r["id"]: r for r in map(json.loads, open("eval_set_v3.jsonl"))}
bf = {r["id"]: r for r in json.load(open("logs/v3/merged_verify.json"))}

ok = bad = parse_fail = 0
conf = collections.defaultdict(collections.Counter)
flips = []
for i, sev in res.items():
    g = ev[i]["gold"]
    if sev == "PARSE-FAIL":
        parse_fail += 1
        continue
    p = BUCKET[sev]
    conf[g][p] += 1
    ok += p == g
    bad += p != g
    if bf.get(i) and bf[i]["pred"] != p:
        flips.append((i, ev[i]["name"], bf[i]["pred"], p, g))

n = ok + bad
print(f"Q4 accuracy: {ok}/{n} = {ok/n:.1%}   (bf16 was 89.9%)")
if parse_fail:
    print(f"  !! {parse_fail} responses had no parseable severity")
mal = sum(conf['malicious'].values())
print(f"  threats dismissed as benign: {conf['malicious']['benign']}/{mal} "
      f"= {conf['malicious']['benign']/mal:.1%}   (bf16 0.0%)")
print(f"  malicious recall: {conf['malicious']['malicious']/mal:.1%}   (bf16 96.4%)")
under = sum(v for g in conf for p, v in conf[g].items() if RANK[p] < RANK[g])
print(f"  under-call rate: {under/n:.1%}   (bf16 4.3%)")
print("\nconfusion (rows=gold, cols=pred):")
cl = ["benign", "suspicious", "malicious"]
print(f"{'':<12}" + "".join(f"{c:<12}" for c in cl))
for g in cl:
    print(f"{g:<12}" + "".join(f"{conf[g][p]:<12}" for p in cl))
print(f"\n{len(flips)} events where Q4 disagrees with bf16:")
for i, nm, a, b, g in sorted(flips, key=lambda f: f[4]):
    mark = "  <- Q4 worse" if a == g and b != g else ("  <- Q4 better" if b == g and a != g else "")
    print(f"  {i:<6}{nm[:30]:<32} bf16={a:<11} q4={b:<11} gold={g}{mark}")
