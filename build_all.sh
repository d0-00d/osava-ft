#!/usr/bin/env bash
# Regenerate every set from scratch, in both signature variants.
#
# The two variants exist to settle PRD open question 1 empirically: score both
# with run_eval.py and compare. If accuracy is unchanged, Signed/Signer carry
# no weight and should leave the contract; if `strip` is worse, they stay.
set -euo pipefail
cd "$(dirname "$0")"

for SIG in backfill strip; do
  if [ "$SIG" = "backfill" ]; then SFX=""; D=""; else SFX="_nosig"; D="_nosig"; fi
  python3 gen_benign.py      --n 40 --sig "$SIG" --out "benign_events${D}"
  python3 gen_suspicious.py  --n 30 --sig "$SIG" --out "suspicious_events${D}"
  python3 prep_attack.py            --sig "$SIG" --out "attack_events${D}"
  python3 build_sets.py --eval-n 50 --suffix "$SFX" \
      --benign "benign_events${D}" --susp "suspicious_events${D}" \
      --attack "attack_events${D}"
  echo
done

echo "=== leakage audit (backfill) ==="
python3 audit_leak.py benign_events:benign suspicious_events:suspicious attack_events:malicious
echo
echo "=== leakage audit (strip) ==="
python3 audit_leak.py benign_events_nosig:benign suspicious_events_nosig:suspicious attack_events_nosig:malicious
