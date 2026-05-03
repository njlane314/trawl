#ifndef TRAWL_MIN_VMLINUX_H
#define TRAWL_MIN_VMLINUX_H

#ifndef __VMLINUX_H__
#define __VMLINUX_H__
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

struct bpf_perf_event_data {
    struct pt_regs regs;
    __u64 sample_period;
    __u64 addr;
};
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs;

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct bpf_perf_event_data {
    struct user_pt_regs regs;
    __u64 sample_period;
    __u64 addr;
};
#else
#error "trawl_min_vmlinux.h supports __TARGET_ARCH_x86 and __TARGET_ARCH_arm64"
#endif

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_RINGBUF = 27,
};

#define BPF_ANY 0
#define BPF_F_USER_STACK (1ULL << 8)
#define BPF_F_FAST_STACK_CMP (1ULL << 9)

#endif /* TRAWL_MIN_VMLINUX_H */
