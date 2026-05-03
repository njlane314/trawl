# Trawl

This repository is a production-shaped Coz-style causal profiler. eBPF is used for low-overhead observation; a user-space controller runs randomized virtual-speedup experiments; an `LD_PRELOAD` shim implements cooperative pause debt and progress markers.

The current version includes the production upgrades that were missing from the first prototype:

- randomized repeated trials per candidate/speedup;
- 95% confidence intervals for rate and impact estimates;
- latency begin/end tracking with token-correlated request ids and p50/p90/p99 reporting;
- auto-discovery of hot function candidates from the BPF sample histogram;
- DWARF/source attribution through `addr2line` after robust `/proc/<pid>/maps` load-bias translation;
- stronger ELF/PIE/shared-object symbol resolution;
- machine-readable JSON, trial CSV, and candidate CSV outputs;
- a cooperative pause backend plus an invasive `ptrace` backend for uninstrumented CPU-bound code;
- thread registration through a `pthread_create` wrapper and more blocking-boundary polling wrappers.

## Repository layout

```text
bpf/
  trawl.bpf.c          # CO-RE BPF sampler + progress/latency uprobes
  trawl_shared.h       # BPF/userspace ABI
src/
  trawlctl.c           # controller, statistics, discovery, ELF attribution, delay backends
shim/
  trawl_shim.c         # LD_PRELOAD pause-debt shim and progress marker functions
include/
  trawl_marker.h       # app-facing marker macros
  trawl_shm.h          # shared-memory pause-debt table
examples/
  demo_server.c      # toy multithreaded workload with throughput and latency markers
```

## Build requirements

You need a Linux system with eBPF, perf events, uprobes, and BTF at `/sys/kernel/btf/vmlinux`, plus:

```text
clang
bpftool
libbpf headers and library
libelf/gelf headers and library
zlib
addr2line from binutils
root, CAP_BPF/CAP_PERFMON, or equivalent privileges
```

Build:

```sh
make
make examples
```

On macOS, build inside a Linux environment such as Docker or on a Linux host. The Makefile uses kernel BTF from `/sys/kernel/btf/vmlinux` when available and falls back to the minimal bundled header for compile-only environments.

## Throughput markers

Add a progress point after one completed unit of useful work:

```c
#include "trawl_marker.h"

void handle_request(...) {
    ...
    TRAWL_PROGRESS(1);
}
```

The progress id is selected with `--progress-id 1`.

## Latency markers

For synchronous single-threaded request handling, the simple markers are sufficient:

```c
TRAWL_LATENCY_BEGIN(1);
...
TRAWL_LATENCY_END(1);
TRAWL_PROGRESS(1);
```

For production services where requests can overlap, move across threads, or nest, use token-correlated markers:

```c
uint64_t token = request_id;
TRAWL_LATENCY_BEGIN_ID(1, token);
...
TRAWL_LATENCY_END_ID(1, token);
TRAWL_PROGRESS(1);
```

The controller matches begin/end events by `(epoch, progress_id, token)` when a token is supplied; otherwise it falls back to `(epoch, progress_id, tid)`. It reports latency count, mean, p50, p90, p99, max, orphan begin/end counts, and nesting overflow counts.

## Manual function-level causal profiling

```sh
sudo ./build/trawl \
  --shim ./build/libtrawl_shim.so \
  --binary ./examples/demo_server \
  --symbol target_work \
  --progress-id 1 \
  --latency \
  --duration-ms 3000 \
  --warmup-ms 1000 \
  --repeats 5 \
  --speedups 0,5,10,25,50 \
  --json report.json \
  -- ./examples/demo_server
```

The controller prints one CSV row per trial and then a summary table. The summary table contains the mean progress rate, the rate confidence interval, and the estimated impact relative to the baseline trials for the same candidate.

## Auto-discovery mode

Auto mode runs a discovery window, reads `sample_hist`, maps sampled instruction pointers back through `/proc/<pid>/maps`, resolves them to ELF function symbols, attaches source locations with `addr2line`, and selects the hottest functions.

```sh
sudo ./build/trawl \
  --shim ./build/libtrawl_shim.so \
  --auto \
  --top-candidates 5 \
  --discover-ms 5000 \
  --progress-id 1 \
  --latency \
  --repeats 3 \
  --speedups 0,10,25,50 \
  --candidates-csv candidates.csv \
  --json report.json \
  -- ./examples/demo_server
```

Auto mode is intentionally function-level. Line-level attribution is emitted as source file/line metadata for candidates, but the virtual speedup target remains the function address interval. For true line-level causal experiments, narrow the target with `--range LO-HI` using runtime addresses.

## Pause backends

The default backend is cooperative:

```sh
--pause-backend coop
```

It adds pause debt to all registered target threads except the sampled thread. Threads pay debt when they call `TRAWL_POLL()`, `TRAWL_PROGRESS()`, `TRAWL_LATENCY_*()`, or cross wrapped boundaries such as `pthread_mutex_lock`, `pthread_cond_wait`, `read`, `write`, `poll`, `select`, `epoll_wait`, `accept`, `recv`, and `send`.

For CPU-bound code with no polling, use the invasive backend:

```sh
--pause-backend ptrace
```

The `ptrace` backend seizes target threads, interrupts all non-sampled threads on a target hit, sleeps for the virtual-delay quantum, then resumes them. This is much higher overhead and should be used for validation, controlled benchmarks, or uninstrumented programs where cooperative debt cannot be paid promptly.

## Output

Trial rows:

```text
trial,candidate_idx,speedup_pct,epoch,progress_count,begin_count,end_count,elapsed_ms,effective_ms,target_hits,virtual_delay_ms,rate_per_sec,lat_count,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms,lat_max_ms,lat_orphan_begin,lat_orphan_end,lat_stack_overflow
```

Summary rows:

```text
summary_type,candidate_idx,name,speedup_pct,n,rate_mean,rate_ci95_low,rate_ci95_high,impact_pct,impact_ci95_low,impact_ci95_high,lat_count,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms
```

`impact_pct` estimates the application-level throughput effect of virtually speeding up that candidate by the given percentage. The confidence interval is computed on the log rate ratio using the repeated randomized trials.

## Interpretation constraints

Causal profiles are only as good as the progress metric and the workload. Use representative load, stable progress points, and enough repeated trials to reduce noise. The tool deliberately perturbs scheduling to emulate local speedups, so use it in a benchmark rig, staging system, or controlled production canary rather than across all production traffic.

## Known limitations

- The BPF sampler uses instruction-pointer intervals; line-level speedups require manually supplied runtime ranges.
- Latency quantiles are histogram-based approximations, not exact order statistics.
- `addr2line` attribution depends on debug information being available.
- The `ptrace` backend is intentionally invasive and can substantially distort very fine-grained workloads.
- Auto-discovery groups samples by ELF function symbols; heavily inlined code may be attributed to the containing concrete symbol rather than the logical inline frame.
