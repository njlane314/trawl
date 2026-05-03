#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "trawl_shm.h"

static struct trawl_shm *g_shm;
static int g_fd = -1;
static __thread int g_slot = -1;
static __thread uint64_t g_local_debt_ns;
static __thread int g_inside_poll;

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static pid_t gettid_linux(void)
{
    return (pid_t)syscall(SYS_gettid);
}

static void sleep_ns_raw(uint64_t ns)
{
    struct timespec req;
    req.tv_sec = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);

    while (syscall(SYS_nanosleep, &req, &req) < 0 && errno == EINTR) {
        ;
    }
}

static void trawl_init_shm(void)
{
    if (g_shm)
        return;

    const char *path = getenv("TRAWL_SHM_PATH");
    if (!path || !*path)
        return;

    g_fd = open(path, O_RDWR | O_CLOEXEC, 0600);
    if (g_fd < 0)
        return;

    size_t len = sizeof(struct trawl_shm);
    g_shm = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, g_fd, 0);
    if (g_shm == MAP_FAILED) {
        g_shm = NULL;
        close(g_fd);
        g_fd = -1;
        return;
    }

    if (__atomic_load_n(&g_shm->magic, __ATOMIC_ACQUIRE) != TRAWL_SHM_MAGIC) {
        memset(g_shm, 0, len);
        __atomic_store_n(&g_shm->version, TRAWL_SHM_VERSION, __ATOMIC_RELEASE);
        __atomic_store_n(&g_shm->max_threads, TRAWL_MAX_THREADS, __ATOMIC_RELEASE);
        __atomic_store_n(&g_shm->magic, TRAWL_SHM_MAGIC, __ATOMIC_RELEASE);
    }
}

static void trawl_release_slot(void)
{
    if (g_shm && g_slot >= 0) {
        struct trawl_thread_slot *s = &g_shm->slots[g_slot];
        __atomic_store_n(&s->exited_ns, monotonic_ns(), __ATOMIC_RELEASE);
        __atomic_store_n(&s->tid, 0, __ATOMIC_RELEASE);
        g_slot = -1;
    }
}

static int trawl_find_slot(void)
{
    if (g_slot >= 0)
        return g_slot;

    trawl_init_shm();
    if (!g_shm)
        return -1;

    uint32_t tid = (uint32_t)gettid_linux();
    for (int i = 0; i < TRAWL_MAX_THREADS; i++) {
        uint32_t seen = __atomic_load_n(&g_shm->slots[i].tid, __ATOMIC_ACQUIRE);
        if (seen == tid) {
            g_slot = i;
            return i;
        }
        if (seen == 0) {
            if (__sync_bool_compare_and_swap(&g_shm->slots[i].tid, 0, tid)) {
                g_slot = i;
                __atomic_store_n(&g_shm->slots[i].registered_ns, monotonic_ns(), __ATOMIC_RELEASE);
                __atomic_store_n(&g_shm->slots[i].last_poll_ns, monotonic_ns(), __ATOMIC_RELEASE);
                return i;
            }
        }
    }

    return -1;
}

__attribute__((visibility("default")))
void trawl_poll(void)
{
    if (g_inside_poll)
        return;
    g_inside_poll = 1;

    int slot = trawl_find_slot();
    if (slot < 0 || !g_shm) {
        g_inside_poll = 0;
        return;
    }

    struct trawl_thread_slot *s = &g_shm->slots[slot];
    __atomic_fetch_add(&s->polls, 1ULL, __ATOMIC_RELAXED);
    __atomic_store_n(&s->last_poll_ns, monotonic_ns(), __ATOMIC_RELEASE);

    uint64_t debt = __atomic_load_n(&s->debt_ns, __ATOMIC_ACQUIRE);
    if (debt > g_local_debt_ns) {
        uint64_t delta = debt - g_local_debt_ns;
        g_local_debt_ns = debt;
        sleep_ns_raw(delta);
        __atomic_fetch_add(&s->slept_ns, delta, __ATOMIC_RELAXED);
    }

    g_inside_poll = 0;
}

/* Tiny exported functions used as uprobe targets. Keep them non-inline. */
__attribute__((visibility("default"), noinline))
void trawl_progress(uint32_t id)
{
    asm volatile("" ::: "memory");
    trawl_poll();
    (void)id;
}

__attribute__((visibility("default"), noinline))
void trawl_latency_begin(uint32_t id)
{
    asm volatile("" ::: "memory");
    trawl_poll();
    (void)id;
}

__attribute__((visibility("default"), noinline))
void trawl_latency_end(uint32_t id)
{
    asm volatile("" ::: "memory");
    trawl_poll();
    (void)id;
}

__attribute__((visibility("default"), noinline))
void trawl_latency_begin_id(uint32_t id, uint64_t token)
{
    asm volatile("" ::: "memory");
    trawl_poll();
    (void)id;
    (void)token;
}

__attribute__((visibility("default"), noinline))
void trawl_latency_end_id(uint32_t id, uint64_t token)
{
    asm volatile("" ::: "memory");
    trawl_poll();
    (void)id;
    (void)token;
}

struct trawl_start_thunk {
    void *(*fn)(void *);
    void *arg;
};

static void *trawl_thread_start(void *arg)
{
    struct trawl_start_thunk *t = arg;
    void *(*fn)(void *) = t->fn;
    void *fn_arg = t->arg;
    free(t);

    trawl_find_slot();
    void *ret = fn(fn_arg);
    trawl_release_slot();
    return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg)
{
    static int (*real_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "pthread_create");

    struct trawl_start_thunk *t = calloc(1, sizeof(*t));
    if (!t)
        return real_fn(thread, attr, start_routine, arg);
    t->fn = start_routine;
    t->arg = arg;

    int rc = real_fn(thread, attr, trawl_thread_start, t);
    if (rc != 0)
        free(t);
    return rc;
}

/* Cooperative polling at common blocking/synchronization boundaries. */
int pthread_mutex_lock(pthread_mutex_t *m)
{
    static int (*real_fn)(pthread_mutex_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    trawl_poll();
    return real_fn(m);
}

int pthread_mutex_unlock(pthread_mutex_t *m)
{
    static int (*real_fn)(pthread_mutex_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    trawl_poll();
    return real_fn(m);
}

int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{
    static int (*real_fn)(pthread_cond_t *, pthread_mutex_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "pthread_cond_wait");
    trawl_poll();
    int rc = real_fn(c, m);
    trawl_poll();
    return rc;
}

int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, const struct timespec *ts)
{
    static int (*real_fn)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
    trawl_poll();
    int rc = real_fn(c, m, ts);
    trawl_poll();
    return rc;
}

ssize_t read(int fd, void *buf, size_t count)
{
    static ssize_t (*real_fn)(int, void *, size_t);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "read");
    trawl_poll();
    ssize_t rc = real_fn(fd, buf, count);
    trawl_poll();
    return rc;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    static ssize_t (*real_fn)(int, const void *, size_t);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "write");
    trawl_poll();
    ssize_t rc = real_fn(fd, buf, count);
    trawl_poll();
    return rc;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    static int (*real_fn)(struct pollfd *, nfds_t, int);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "poll");
    trawl_poll();
    int rc = real_fn(fds, nfds, timeout);
    trawl_poll();
    return rc;
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
    static int (*real_fn)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "ppoll");
    trawl_poll();
    int rc = real_fn(fds, nfds, timeout, sigmask);
    trawl_poll();
    return rc;
}

int select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout)
{
    static int (*real_fn)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "select");
    trawl_poll();
    int rc = real_fn(nfds, rfds, wfds, efds, timeout);
    trawl_poll();
    return rc;
}

int pselect(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
            const struct timespec *timeout, const sigset_t *sigmask)
{
    static int (*real_fn)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "pselect");
    trawl_poll();
    int rc = real_fn(nfds, rfds, wfds, efds, timeout, sigmask);
    trawl_poll();
    return rc;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    static int (*real_fn)(int, struct epoll_event *, int, int);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "epoll_wait");
    trawl_poll();
    int rc = real_fn(epfd, events, maxevents, timeout);
    trawl_poll();
    return rc;
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask)
{
    static int (*real_fn)(int, struct epoll_event *, int, int, const sigset_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "epoll_pwait");
    trawl_poll();
    int rc = real_fn(epfd, events, maxevents, timeout, sigmask);
    trawl_poll();
    return rc;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    static int (*real_fn)(int, struct sockaddr *, socklen_t *);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "accept");
    trawl_poll();
    int rc = real_fn(sockfd, addr, addrlen);
    trawl_poll();
    return rc;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    static ssize_t (*real_fn)(int, void *, size_t, int);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "recv");
    trawl_poll();
    ssize_t rc = real_fn(sockfd, buf, len, flags);
    trawl_poll();
    return rc;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    static ssize_t (*real_fn)(int, const void *, size_t, int);
    if (!real_fn)
        real_fn = dlsym(RTLD_NEXT, "send");
    trawl_poll();
    ssize_t rc = real_fn(sockfd, buf, len, flags);
    trawl_poll();
    return rc;
}

__attribute__((constructor))
static void trawl_ctor(void)
{
    trawl_init_shm();
    trawl_find_slot();

    /* Let the controller attach eBPF after exec but before workload start. */
    const char *hold = getenv("TRAWL_HOLD");
    if (hold && strcmp(hold, "1") == 0) {
        unsetenv("TRAWL_HOLD");
        raise(SIGSTOP);
    }
}

__attribute__((destructor))
static void trawl_dtor(void)
{
    trawl_release_slot();
    if (g_shm) {
        munmap(g_shm, sizeof(*g_shm));
        g_shm = NULL;
    }
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}
