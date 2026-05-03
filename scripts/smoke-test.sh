#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${REPORT_DIR:-reports}"
REPORT_NAME="${REPORT_NAME:-smoke}"
OUT_PATH="$ROOT_DIR/$REPORT_DIR/$REPORT_NAME.out"
TRIALS_PATH="$ROOT_DIR/$REPORT_DIR/$REPORT_NAME-trials.csv"

mkdir -p "$ROOT_DIR/$REPORT_DIR"

DURATION_MS="${DURATION_MS:-500}" \
WARMUP_MS="${WARMUP_MS:-100}" \
COOLDOWN_MS="${COOLDOWN_MS:-50}" \
REPEATS="${REPEATS:-1}" \
SPEEDUPS="${SPEEDUPS:-0,10}" \
SEED="${SEED:-42}" \
REPORT_DIR="$REPORT_DIR" \
REPORT_NAME="$REPORT_NAME" \
"$ROOT_DIR/scripts/run-demo.sh" | tee "$OUT_PATH"

awk -F, '
    NR == 1 { next }
    $5 + 0 > 0 { progress_seen = 1 }
    $3 + 0 > 0 && $10 + 0 > 0 { target_hits_seen = 1 }
    END {
        if (!progress_seen) {
            print "smoke test failed: no positive progress_count in trials" > "/dev/stderr";
            exit 1;
        }
        if (!target_hits_seen) {
            print "smoke test failed: no target_hits for a non-zero speedup trial" > "/dev/stderr";
            exit 1;
        }
    }
' "$TRIALS_PATH"

summary_count="$(grep -c '^summary,' "$OUT_PATH" || true)"
if [[ "$summary_count" -lt 2 ]]; then
  echo "smoke test failed: expected at least two summary rows, found $summary_count" >&2
  exit 1
fi

echo "smoke test passed: progress, target hits, and summary rows were observed"
