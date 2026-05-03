#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TRAWL_DOCKER_IMAGE:-trawl-dev}"

DURATION_MS="${DURATION_MS:-5000}"
WARMUP_MS="${WARMUP_MS:-1000}"
COOLDOWN_MS="${COOLDOWN_MS:-200}"
DISCOVER_MS="${DISCOVER_MS:-3000}"
REPEATS="${REPEATS:-5}"
SPEEDUPS="${SPEEDUPS:-0,10,25,50}"
SAMPLE_NS="${SAMPLE_NS:-100000}"
TOP_CANDIDATES="${TOP_CANDIDATES:-5}"
SEED="${SEED:-}"

"$ROOT_DIR/scripts/docker-build.sh"

seed_args=()
if [[ -n "$SEED" ]]; then
  seed_args=(--seed "$SEED")
fi

docker run --rm --privileged --pid=host \
  -v "$ROOT_DIR":/src \
  -w /src \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    echo -1 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true
    exec ./build/trawl \
      --shim ./build/libtrawl_shim.so \
      --auto \
      --top-candidates "$1" \
      --progress-id 1 \
      --latency \
      --duration-ms "$2" \
      --warmup-ms "$3" \
      --cooldown-ms "$4" \
      --discover-ms "$5" \
      --repeats "$6" \
      --speedups "$7" \
      --sample-ns "$8" \
      "${@:9}" \
      -- ./examples/demo_server
  ' bash "$TOP_CANDIDATES" "$DURATION_MS" "$WARMUP_MS" "$COOLDOWN_MS" "$DISCOVER_MS" "$REPEATS" "$SPEEDUPS" "$SAMPLE_NS" "${seed_args[@]}"
