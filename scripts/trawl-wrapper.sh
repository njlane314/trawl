#!/bin/sh
# Dispatch build/trawl subcommands without making the privileged controller parse UI flags.
set -eu

case "$0" in
    */*) self_dir=${0%/*} ;;
    *) self_dir=$(dirname "$(command -v "$0")") ;;
esac

if [ "${1:-}" = "studio" ]; then
    shift
    exec "$self_dir/trawl-studio" --trawl-core "$self_dir/trawlctl" "$@"
fi

exec "$self_dir/trawlctl" "$@"
