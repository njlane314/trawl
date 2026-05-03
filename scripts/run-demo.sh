#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TRAWL_DOCKER_IMAGE:-trawl-dev}"

SYMBOL="${SYMBOL:-target_work}"
TARGET_BINARY="${TARGET_BINARY:-./examples/demo_server}"
TARGET_COMMAND="${TARGET_COMMAND:-$TARGET_BINARY}"
DURATION_MS="${DURATION_MS:-5000}"
WARMUP_MS="${WARMUP_MS:-1000}"
COOLDOWN_MS="${COOLDOWN_MS:-200}"
REPEATS="${REPEATS:-10}"
SPEEDUPS="${SPEEDUPS:-0,5,10,25,50}"
SAMPLE_NS="${SAMPLE_NS:-100000}"
REPORT_DIR="${REPORT_DIR:-reports}"
REPORT_NAME="${REPORT_NAME:-demo}"
SEED="${SEED:-}"

"$ROOT_DIR/scripts/docker-build.sh"
mkdir -p "$ROOT_DIR/$REPORT_DIR"

docker run --rm --privileged --pid=host \
  -v "$ROOT_DIR":/src \
  -w /src \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    echo -1 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true
    seed_args=()
    if [[ -n "${12}" ]]; then
      seed_args=(--seed "${12}")
    fi
    exec ./build/trawl \
      --shim ./build/libtrawl_shim.so \
      --binary "$1" \
      --symbol "$2" \
      --progress-id 1 \
      --latency \
      --duration-ms "$3" \
      --warmup-ms "$4" \
      --cooldown-ms "$5" \
      --repeats "$6" \
      --speedups "$7" \
      --sample-ns "$8" \
      --json "$9" \
      --trials-csv "${10}" \
      --candidates-csv "${11}" \
      "${seed_args[@]}" \
      -- "${13}"
  ' bash \
    "$TARGET_BINARY" \
    "$SYMBOL" \
    "$DURATION_MS" \
    "$WARMUP_MS" \
    "$COOLDOWN_MS" \
    "$REPEATS" \
    "$SPEEDUPS" \
    "$SAMPLE_NS" \
    "$REPORT_DIR/$REPORT_NAME.json" \
    "$REPORT_DIR/$REPORT_NAME-trials.csv" \
    "$REPORT_DIR/$REPORT_NAME-candidates.csv" \
    "$SEED" \
    "$TARGET_COMMAND"
