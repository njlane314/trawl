#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TRAWL_DOCKER_IMAGE:-trawl-dev}"

docker build --quiet -t "$IMAGE" "$ROOT_DIR" >/dev/null

docker run --rm \
  -v "$ROOT_DIR":/src \
  -w /src \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    case "$(uname -m)" in
      aarch64|arm64) trawl_arch=arm64 ;;
      x86_64|amd64) trawl_arch=x86 ;;
      *) echo "unsupported container architecture: $(uname -m)" >&2; exit 1 ;;
    esac

    make clean
    make ARCH="$trawl_arch"
    make ARCH="$trawl_arch" examples
  '
