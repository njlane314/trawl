# Trawl

This repository is a production-shaped Coz-style causal profiler. eBPF is used for low-overhead observation; a user-space controller runs randomised virtual-speedup experiments; an `LD_PRELOAD` shim implements cooperative pause debt and progress markers.

The current version includes the production upgrades that were missing from the first prototype:

- randomised repeated trials per candidate/speedup;
- 95% confidence intervals for rate and impact estimates;
- sampled latency begin/end tracking with token-correlated request ids and p50/p90/p99 reporting;
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
  demo_server.c        # CPU-heavy multithreaded workload with throughput and latency markers
  sleep_bound_server.c # workload where sleeping dominates target_work
scripts/
  docker-build.sh    # build Linux artefacts in the Docker image
  run-demo.sh        # run a targeted target_work causal profile
  run-auto.sh        # run auto-discovery against the demo workload
  run-sleep-demo.sh  # run the sleep-bound comparison workload
  smoke-test.sh      # assert that a short profiled run observes work and target hits
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

## Docker quick start

Build the Linux container image and artefacts:

```sh
./scripts/docker-build.sh
make docker-build
```

Run a targeted demo experiment against `target_work`:

```sh
./scripts/run-demo.sh
make docker-demo
```

Run auto-discovery against the demo workload:

```sh
./scripts/run-auto.sh
make docker-auto
```

Run the smoke test:

```sh
./scripts/smoke-test.sh
make docker-smoke
```

The run scripts use `--privileged --pid=host` and set `kernel.perf_event_paranoid=-1` inside the Docker Linux VM when permitted. This is needed for the perf-event and uprobe paths used by the profiler. On a normal Linux host, you can run the `build/trawl` commands directly with root or equivalent `CAP_BPF`/`CAP_PERFMON` privileges.

Each run writes report files under `reports/` by default:

```text
reports/demo.json
reports/demo-trials.csv
reports/demo-candidates.csv
reports/auto.json
reports/auto-trials.csv
reports/auto-candidates.csv
```

Common run-script overrides:

```sh
DURATION_MS=10000 REPEATS=20 SPEEDUPS=0,5,10,25,50 ./scripts/run-demo.sh
TOP_CANDIDATES=10 DISCOVER_MS=5000 REPEATS=10 ./scripts/run-auto.sh
SEED=42 ./scripts/run-demo.sh
LATENCY=0 DURATION_MS=10000 REPEATS=20 SAMPLE_NS=1000000 ./scripts/run-demo.sh
LATENCY=1 LATENCY_BUDGET=5000 DURATION_MS=10000 REPEATS=20 ./scripts/run-demo.sh
LATENCY=1 LATENCY_SAMPLE=100 DURATION_MS=10000 REPEATS=20 ./scripts/run-demo.sh
```

Use `LATENCY=0` for long throughput-only runs. The default `LATENCY=1` now uses `LATENCY_BUDGET=5000`, so the shim samples latency spans before they hit uprobes and keeps latency traffic bounded on very fast workloads. Set `LATENCY_SAMPLE=N` to record a fixed 1-in-N span sample, or set `LATENCY_BUDGET=0` to record every latency span.

Compare against a workload where sleeping dominates the request:

```sh
./scripts/run-sleep-demo.sh
REPORT_NAME=sleep-long DURATION_MS=10000 REPEATS=20 ./scripts/run-sleep-demo.sh
```

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

The marker macros sample latency spans in the `LD_PRELOAD` shim before calling the noinline uprobe target functions. Unsampled spans still call `trawl_poll()` but do not emit begin/end uprobes. Token-correlated markers use a deterministic hash of `(progress_id, token, seed)`, so begin and end make the same sampling decision. Simple non-token markers keep a thread-local sampling stack.

The controller matches sampled begin/end events by `(epoch, progress_id, token)` when a token is supplied; otherwise it falls back to `(epoch, progress_id, tid)`. It reports latency count, mean, p50, p90, p99, max, orphan begin/end counts, nesting overflow counts, and the sample rate used for each trial.

Latency sampling options:

```sh
--latency                 # exact latency mode; records every span unless paired with sampling
--latency-sample 100      # fixed 1-in-100 span sample
--latency-budget 5000     # adaptive sampling towards 5000 sampled spans/sec
```

## Manual function-level causal profiling

```sh
sudo ./build/trawl \
  --shim ./build/libtrawl_shim.so \
  --binary ./examples/demo_server \
  --symbol target_work \
  --progress-id 1 \
  --latency \
  --latency-budget 5000 \
  --duration-ms 3000 \
  --warmup-ms 1000 \
  --repeats 5 \
  --speedups 0,5,10,25,50 \
  --json report.json \
  -- ./examples/demo_server
```

The controller prints one CSV row per trial and then a summary table. The summary table contains the mean progress rate, the rate confidence interval, and the estimated impact relative to the baseline trials for the same candidate.

The Docker wrapper writes the same trial rows to `reports/demo-trials.csv` and the machine-readable report to `reports/demo.json`.

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
  --latency-budget 5000 \
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
trial,candidate_idx,speedup_pct,epoch,progress_count,begin_count,end_count,elapsed_ms,effective_ms,target_hits,virtual_delay_ms,rate_per_sec,lat_sample_rate,lat_count,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms,lat_max_ms,lat_orphan_begin,lat_orphan_end,lat_stack_overflow
```

Summary rows:

```text
summary_type,candidate_idx,name,speedup_pct,n,rate_mean,rate_ci95_low,rate_ci95_high,impact_pct,impact_ci95_low,impact_ci95_high,lat_sample_rate_mean,lat_count,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms
```

`impact_pct` estimates the application-level throughput effect of virtually speeding up that candidate by the given percentage. The confidence interval is computed on the log rate ratio using the repeated randomised trials.

## How to read results

Start with `progress_count`. If it is zero, the workload did not report completed units of work and the experiment is not meaningful.

Check `target_hits` for non-zero speedup trials. If it is zero, the sampler did not observe execution inside the selected target, so the virtual speedup was not actually exercised.

Use `rate_mean` and `impact_pct` together. `rate_mean` is measured throughput; `impact_pct` is the estimated whole-program throughput change relative to baseline. A hot function is worth optimising only when speeding it up improves the application-level progress rate.

Use `rate_ci95_low`, `rate_ci95_high`, `impact_ci95_low`, and `impact_ci95_high` to judge uncertainty. Wide intervals usually mean the run was too short, had too few repeats, or used an unstable workload.

Use `lat_sample_rate` to see the span sampling denominator for a trial. `lat_sample_rate=1` means every span was recorded; `lat_sample_rate=100` means roughly 1 in 100 spans was recorded. Use `lat_p50_ms`, `lat_p90_ms`, and `lat_p99_ms` to check whether a throughput gain came with better or worse request latency.

Use `virtual_delay_ms` as a sanity check. It should be positive for non-zero speedup trials with target hits. Very large delay values indicate that the experiment heavily perturbed scheduling.

The sleep-bound demo is useful as a negative-control workload. It still calls `TRAWL_PROGRESS()`, but request time is dominated by `usleep(5000)`, so speeding up `target_work` should have a much smaller whole-program effect than in the CPU-heavy demo.

## Continuous integration

The GitHub Actions workflow builds the Docker image, runs ShellCheck over scripts, and compiles the controller, BPF object, shim, and examples inside the container. It does not run privileged eBPF profiling on GitHub-hosted runners; use `./scripts/smoke-test.sh` locally or in a privileged Linux runner for runtime validation.

## Interpretation constraints

Causal profiles are only as good as the progress metric and the workload. Use representative load, stable progress points, and enough repeated trials to reduce noise. The tool deliberately perturbs scheduling to emulate local speedups, so use it in a benchmark rig, staging system, or controlled production canary rather than across all production traffic.

## Known limitations

- The BPF sampler uses instruction-pointer intervals; line-level speedups require manually supplied runtime ranges.
- Latency quantiles are sampled, histogram-based approximations, not exact order statistics.
- `addr2line` attribution depends on debug information being available.
- The `ptrace` backend is intentionally invasive and can substantially distort very fine-grained workloads.
- Auto-discovery groups samples by ELF function symbols; heavily inlined code may be attributed to the containing concrete symbol rather than the logical inline frame.
