#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "trawl_marker.h"

static volatile uint64_t sink;
static volatile uint64_t request_id;

__attribute__((noinline))
void target_work(void)
{
    for (int i = 0; i < 40000; i++) {
        sink += (uint64_t)i * 11400714819323198485ULL;
        if ((i & 1023) == 0)
            TRAWL_POLL();
    }
}

static void *worker(void *arg)
{
    (void)arg;
    while (1) {
        uint64_t rid = __sync_add_and_fetch(&request_id, 1);
        TRAWL_LATENCY_BEGIN_ID(1, rid);
        target_work();
        usleep(5000);
        TRAWL_LATENCY_END_ID(1, rid);
        TRAWL_PROGRESS(1);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[4];
    for (long i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, (void *)i);
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
    return 0;
}
