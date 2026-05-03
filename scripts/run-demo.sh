#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TRAWL_DOCKER_IMAGE:-trawl-dev}"

DURATION_MS="${DURATION_MS:-5000}"
WARMUP_MS="${WARMUP_MS:-1000}"
COOLDOWN_MS="${COOLDOWN_MS:-200}"
REPEATS="${REPEATS:-10}"
SPEEDUPS="${SPEEDUPS:-0,5,10,25,50}"
SAMPLE_NS="${SAMPLE_NS:-100000}"
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
      --binary ./examples/demo_server \
      --symbol target_work \
      --progress-id 1 \
      --latency \
      --duration-ms "$1" \
      --warmup-ms "$2" \
      --cooldown-ms "$3" \
      --repeats "$4" \
      --speedups "$5" \
      --sample-ns "$6" \
      "${@:7}" \
      -- ./examples/demo_server
  ' bash "$DURATION_MS" "$WARMUP_MS" "$COOLDOWN_MS" "$REPEATS" "$SPEEDUPS" "$SAMPLE_NS" "${seed_args[@]}"
