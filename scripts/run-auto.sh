#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TRAWL_DOCKER_IMAGE:-trawl-dev}"

TARGET_COMMAND="${TARGET_COMMAND:-./examples/demo_server}"
DURATION_MS="${DURATION_MS:-5000}"
WARMUP_MS="${WARMUP_MS:-1000}"
COOLDOWN_MS="${COOLDOWN_MS:-200}"
DISCOVER_MS="${DISCOVER_MS:-3000}"
REPEATS="${REPEATS:-5}"
SPEEDUPS="${SPEEDUPS:-0,10,25,50}"
SAMPLE_NS="${SAMPLE_NS:-100000}"
TOP_CANDIDATES="${TOP_CANDIDATES:-5}"
REPORT_DIR="${REPORT_DIR:-reports}"
REPORT_NAME="${REPORT_NAME:-auto}"
LATENCY="${LATENCY:-1}"
LATENCY_SAMPLE="${LATENCY_SAMPLE:-}"
LATENCY_BUDGET="${LATENCY_BUDGET:-5000}"
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
    latency_args=()
    case "${14}" in
      0|false|False|FALSE|no|No|NO|off|Off|OFF) ;;
      *)
        latency_args=(--latency)
        if [[ -n "${15}" && "${15}" != "0" ]]; then
          latency_args=(--latency-sample "${15}")
        elif [[ -n "${16}" && "${16}" != "0" ]]; then
          latency_args=(--latency-budget "${16}")
        fi
        ;;
    esac
    exec ./build/trawl \
      --shim ./build/libtrawl_shim.so \
      --auto \
      --top-candidates "$1" \
      --progress-id 1 \
      "${latency_args[@]}" \
      --duration-ms "$2" \
      --warmup-ms "$3" \
      --cooldown-ms "$4" \
      --discover-ms "$5" \
      --repeats "$6" \
      --speedups "$7" \
      --sample-ns "$8" \
      --json "$9" \
      --trials-csv "${10}" \
      --candidates-csv "${11}" \
      "${seed_args[@]}" \
      -- "${13}"
  ' bash \
    "$TOP_CANDIDATES" \
    "$DURATION_MS" \
    "$WARMUP_MS" \
    "$COOLDOWN_MS" \
    "$DISCOVER_MS" \
    "$REPEATS" \
    "$SPEEDUPS" \
    "$SAMPLE_NS" \
    "$REPORT_DIR/$REPORT_NAME.json" \
    "$REPORT_DIR/$REPORT_NAME-trials.csv" \
    "$REPORT_DIR/$REPORT_NAME-candidates.csv" \
    "$SEED" \
    "$TARGET_COMMAND" \
    "$LATENCY" \
    "$LATENCY_SAMPLE" \
    "$LATENCY_BUDGET"
