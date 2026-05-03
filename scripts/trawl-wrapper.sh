#!/bin/sh
# Dispatch build/trawl subcommands without making the privileged controller parse UI flags.
set -eu

case "$0" in
    */*) self_dir=${0%/*} ;;
    *) self_dir=$(dirname "$(command -v "$0")") ;;
esac

if [ "${1:-}" = "repl" ]; then
    shift
    exec "$self_dir/trawl-repl" --trawl-core "$self_dir/trawlctl" "$@"
fi

if [ "${1:-}" = "studio" ]; then
    echo "trawl: the studio TUI was removed; use 'trawl repl' instead" >&2
    exit 64
fi

exec "$self_dir/trawlctl" "$@"
