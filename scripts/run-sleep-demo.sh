#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export TARGET_BINARY="${TARGET_BINARY:-./examples/sleep_bound_server}"
export TARGET_COMMAND="${TARGET_COMMAND:-$TARGET_BINARY}"
export REPORT_NAME="${REPORT_NAME:-sleep-bound}"

exec "$ROOT_DIR/scripts/run-demo.sh"
