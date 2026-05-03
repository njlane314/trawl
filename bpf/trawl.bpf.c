#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trawl_shared.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trawl_config);
} trawl_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TRAWL_HIST_ENTRIES);
    __type(key, struct trawl_sample_key);
    __type(value, struct trawl_count);
} sample_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TRAWL_COUNTER_ENTRIES);
    __type(key, struct trawl_progress_key);
    __type(value, struct trawl_progress_value);
} progress_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, TRAWL_MAX_STACKS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, TRAWL_MAX_STACK_DEPTH * sizeof(__u64));
} user_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline struct trawl_config *get_config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&trawl_config_map, &zero);
}

static __always_inline int is_target_tgid(const struct trawl_config *cfg, __u32 tgid)
{
    return cfg && cfg->target_tgid && tgid == cfg->target_tgid;
}

static __always_inline void incr_hist(__u64 ip, __s32 stack_id)
{
    struct trawl_sample_key key = {
        .ip = ip,
        .user_stack_id = stack_id,
        ._pad = 0,
    };

    struct trawl_count *v = bpf_map_lookup_elem(&sample_hist, &key);
    if (v) {
        __sync_fetch_and_add(&v->count, 1);
        return;
    }

    struct trawl_count init = { .count = 1 };
    bpf_map_update_elem(&sample_hist, &key, &init, BPF_ANY);
}

static __always_inline void emit_event(__u32 kind,
                                       const struct trawl_config *cfg,
                                       __u32 tgid,
                                       __u32 tid,
                                       __u64 ip,
                                       __s32 stack_id,
                                       __u32 progress_kind,
                                       __u32 progress_id,
                                       __u64 correlation_id,
                                       __u32 progress_flags)
{
    struct trawl_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->kind = kind;
    ev->tgid = tgid;
    ev->tid = tid;
    ev->progress_kind = progress_kind;
    ev->epoch = cfg ? cfg->epoch : 0;
    ev->ts_ns = bpf_ktime_get_ns();
    ev->ip = ip;
    ev->user_stack_id = stack_id;
    ev->progress_id = progress_id;
    ev->correlation_id = correlation_id;
    ev->progress_flags = progress_flags;
    ev->sample_period_ns = cfg ? cfg->sample_period_ns : 0;
    ev->speedup_ppm = cfg ? cfg->speedup_ppm : 0;
    ev->_pad = 0;

    bpf_ringbuf_submit(ev, 0);
}

SEC("perf_event")
int trawl_on_sample(struct bpf_perf_event_data *ctx)
{
    struct trawl_config *cfg = get_config();
    if (!cfg)
        return 0;

    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pidtgid;
    __u32 tgid = (__u32)(pidtgid >> 32);

    if (!is_target_tgid(cfg, tgid))
        return 0;

    __u64 ip = PT_REGS_IP(&ctx->regs);
    __s32 stack_id = -1;

    if (cfg->capture_user_stack)
        stack_id = bpf_get_stackid(ctx, &user_stacks,
                                   BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

    incr_hist(ip, stack_id);

    if (cfg->emit_all_samples)
        emit_event(TRAWL_EVENT_SAMPLE, cfg, tgid, tid, ip, stack_id, 0, 0, 0, 0);

    if (!cfg->active)
        return 0;

    if (ip >= cfg->target_lo && ip < cfg->target_hi) {
        emit_event(TRAWL_EVENT_TARGET_HIT, cfg, tgid, tid, ip, stack_id, 0, 0, 0, 0);
    }

    return 0;
}

static __always_inline int record_progress(struct pt_regs *ctx, __u32 kind, __u32 has_token)
{
    struct trawl_config *cfg = get_config();
    if (!cfg)
        return 0;

    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pidtgid;
    __u32 tgid = (__u32)(pidtgid >> 32);

    if (!is_target_tgid(cfg, tgid))
        return 0;
    if (!cfg->active)
        return 0;

    __u32 id = (__u32)PT_REGS_PARM1(ctx);
    if (cfg->progress_id && id != cfg->progress_id)
        return 0;

    struct trawl_progress_key key = {
        .epoch = cfg->epoch,
        .id = id,
        .kind = kind,
    };

    struct trawl_progress_value *v = bpf_map_lookup_elem(&progress_counts, &key);
    __u64 now = bpf_ktime_get_ns();
    if (v) {
        __sync_fetch_and_add(&v->count, 1);
        v->last_ts_ns = now;
    } else {
        struct trawl_progress_value init = {
            .count = 1,
            .last_ts_ns = now,
        };
        bpf_map_update_elem(&progress_counts, &key, &init, BPF_ANY);
    }

    if (kind == TRAWL_PROGRESS_STEP && !cfg->emit_progress_events)
        return 0;
    if ((kind == TRAWL_PROGRESS_BEGIN || kind == TRAWL_PROGRESS_END) &&
        !cfg->latency_enabled && !cfg->emit_progress_events)
        return 0;

    __u64 token = 0;
    __u32 flags = 0;
    if (has_token) {
        token = (__u64)PT_REGS_PARM2(ctx);
        flags = TRAWL_PROGRESS_F_HAS_TOKEN;
    }

    emit_event(TRAWL_EVENT_PROGRESS, cfg, tgid, tid, 0, -1, kind, id, token, flags);
    return 0;
}

SEC("uprobe")
int trawl_uprobe_progress(struct pt_regs *ctx)
{
    return record_progress(ctx, TRAWL_PROGRESS_STEP, 0);
}

SEC("uprobe")
int trawl_uprobe_latency_begin(struct pt_regs *ctx)
{
    return record_progress(ctx, TRAWL_PROGRESS_BEGIN, 0);
}

SEC("uprobe")
int trawl_uprobe_latency_end(struct pt_regs *ctx)
{
    return record_progress(ctx, TRAWL_PROGRESS_END, 0);
}

SEC("uprobe")
int trawl_uprobe_latency_begin_id(struct pt_regs *ctx)
{
    return record_progress(ctx, TRAWL_PROGRESS_BEGIN, 1);
}

SEC("uprobe")
int trawl_uprobe_latency_end_id(struct pt_regs *ctx)
{
    return record_progress(ctx, TRAWL_PROGRESS_END, 1);
}
