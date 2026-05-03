#ifndef TRAWL_MARKER_H
#define TRAWL_MARKER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implemented by libtrawl_shim.so. */
void trawl_progress(uint32_t id);
void trawl_latency_begin(uint32_t id);
void trawl_latency_end(uint32_t id);
void trawl_latency_begin_id(uint32_t id, uint64_t token);
void trawl_latency_end_id(uint32_t id, uint64_t token);
void trawl_latency_begin_sampled(uint32_t id);
void trawl_latency_end_sampled(uint32_t id);
void trawl_latency_begin_id_sampled(uint32_t id, uint64_t token);
void trawl_latency_end_id_sampled(uint32_t id, uint64_t token);
void trawl_poll(void);

#define TRAWL_PROGRESS(id_)             do { trawl_progress((uint32_t)(id_)); } while (0)
#define TRAWL_LATENCY_BEGIN(id_)        do { trawl_latency_begin_sampled((uint32_t)(id_)); } while (0)
#define TRAWL_LATENCY_END(id_)          do { trawl_latency_end_sampled((uint32_t)(id_)); } while (0)
#define TRAWL_LATENCY_BEGIN_ID(id_, t_) do { trawl_latency_begin_id_sampled((uint32_t)(id_), (uint64_t)(t_)); } while (0)
#define TRAWL_LATENCY_END_ID(id_, t_)   do { trawl_latency_end_id_sampled((uint32_t)(id_), (uint64_t)(t_)); } while (0)
#define TRAWL_POLL()                    do { trawl_poll(); } while (0)

#ifdef __cplusplus
}
#endif

#endif /* TRAWL_MARKER_H */
