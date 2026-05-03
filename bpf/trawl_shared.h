#ifndef TRAWL_SHARED_H
#define TRAWL_SHARED_H

/* Shared ABI between trawl.bpf.c and the user-space controller. */

#define TRAWL_MAX_STACK_DEPTH 64
#define TRAWL_MAX_STACKS      8192
#define TRAWL_HIST_ENTRIES    65536
#define TRAWL_COUNTER_ENTRIES 8192

#define TRAWL_SPEEDUP_PPM_DEN 1000000ULL

#ifndef __u8
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
#endif

enum trawl_progress_kind {
    TRAWL_PROGRESS_STEP  = 1,
    TRAWL_PROGRESS_BEGIN = 2,
    TRAWL_PROGRESS_END   = 3,
};

enum trawl_progress_flags {
    TRAWL_PROGRESS_F_HAS_TOKEN = 1u << 0,
};

struct trawl_config {
    __u32 target_tgid;
    __u32 active;

    __u64 epoch;

    /* Runtime instruction-address interval for the current experiment. */
    __u64 target_lo;
    __u64 target_hi;

    /* 0..1_000_000. 250000 means a 25% virtual speedup. */
    __u32 speedup_ppm;
    __u32 progress_id;

    /* Sampling period expressed in nanoseconds when using CPU_CLOCK. */
    __u64 sample_period_ns;

    __u32 capture_user_stack;
    __u32 emit_all_samples;

    /* Progress events are expensive. Leave off for throughput-only runs. */
    __u32 emit_progress_events;
    __u32 latency_enabled;
};

struct trawl_sample_key {
    __u64 ip;
    __s32 user_stack_id;
    __u32 _pad;
};

struct trawl_count {
    __u64 count;
};

struct trawl_progress_key {
    __u64 epoch;
    __u32 id;
    __u32 kind;
};

struct trawl_progress_value {
    __u64 count;
    __u64 last_ts_ns;
};

enum trawl_event_kind {
    TRAWL_EVENT_TARGET_HIT = 1,
    TRAWL_EVENT_SAMPLE     = 2,
    TRAWL_EVENT_PROGRESS   = 3,
};

struct trawl_event {
    __u32 kind;
    __u32 tgid;
    __u32 tid;
    __u32 progress_kind;

    __u64 epoch;
    __u64 ts_ns;
    __u64 ip;
    __s32 user_stack_id;
    __u32 progress_id;

    __u64 correlation_id;
    __u32 progress_flags;

    __u64 sample_period_ns;
    __u32 speedup_ppm;
    __u32 _pad;
};

#endif /* TRAWL_SHARED_H */
