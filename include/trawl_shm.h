#ifndef TRAWL_SHM_H
#define TRAWL_SHM_H

#include <stdint.h>

#define TRAWL_SHM_MAGIC   0x545241574c534832ULL /* "TRAWLSH2" */
#define TRAWL_SHM_VERSION 2
#define TRAWL_MAX_THREADS 4096

/* Cache-line-sized slot. The controller writes debt_ns; target threads read it. */
struct trawl_thread_slot {
    volatile uint32_t tid;
    volatile uint32_t flags;
    volatile uint64_t debt_ns;
    volatile uint64_t slept_ns;
    volatile uint64_t polls;
    volatile uint64_t registered_ns;
    volatile uint64_t last_poll_ns;
    volatile uint64_t exited_ns;
    uint8_t _pad[8];
};

struct trawl_shm {
    volatile uint64_t magic;
    volatile uint32_t version;
    volatile uint32_t max_threads;
    volatile uint64_t controller_epoch;
    volatile uint64_t total_virtual_delay_ns;
    volatile uint64_t dropped_debt_events;
    struct trawl_thread_slot slots[TRAWL_MAX_THREADS];
};

#endif /* TRAWL_SHM_H */
