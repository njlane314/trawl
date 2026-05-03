#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/perf_event.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "trawl.skel.h"
#include "trawl_shared.h"
#include "trawl_shm.h"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define TRAWL_MAX_SPEEDUPS       64
#define TRAWL_MAX_CANDIDATES     64
#define TRAWL_MAX_TRIALS         8192
#define TRAWL_MAX_MAPS           8192
#define TRAWL_MAX_IMAGES         256
#define TRAWL_LAT_BUCKETS        512
#define TRAWL_BEGIN_TABLE_SIZE   65536
#define TRAWL_BEGIN_STACK_DEPTH  8
#define TRAWL_PATH_MAX           PATH_MAX
#define TRAWL_NAME_MAX           256

enum pause_backend_kind {
    PAUSE_COOP = 0,
    PAUSE_PTRACE = 1,
};

struct options {
    const char *shim_path;
    const char *binary_path;
    const char *symbol;
    const char *range;
    const char *json_path;
    const char *trials_csv_path;
    const char *candidates_csv_path;
    uint32_t progress_id;
    uint64_t sample_period_ns;
    int duration_ms;
    int warmup_ms;
    int cooldown_ms;
    int discover_ms;
    int repeats;
    int capture_stacks;
    int leave_running;
    int auto_candidates;
    int top_candidates;
    int latency_enabled;
    int emit_progress_events;
    int randomize;
    uint64_t seed;
    enum pause_backend_kind pause_backend;
    int speedup_count;
    uint32_t speedups_ppm[TRAWL_MAX_SPEEDUPS];
    char **cmd_argv;
};

struct func_sym {
    uint64_t value;
    uint64_t size;
    char name[TRAWL_NAME_MAX];
};

struct elf_image {
    char path[TRAWL_PATH_MAX];
    int loaded;
    int is_dyn;
    struct func_sym *funcs;
    size_t nfuncs;
    size_t capfuncs;
};

struct elf_symbol {
    uint64_t value;
    uint64_t size;
    int is_dyn;
};

struct map_entry {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char perms[8];
    char path[TRAWL_PATH_MAX];
};

struct proc_maps {
    struct map_entry *v;
    size_t n;
};

struct candidate {
    char name[TRAWL_NAME_MAX];
    char path[TRAWL_PATH_MAX];
    char fileline[TRAWL_PATH_MAX];
    uint64_t obj_lo;
    uint64_t obj_hi;
    uint64_t lo;
    uint64_t hi;
    uint64_t samples;
    int from_auto;
};

struct latency_snapshot {
    uint64_t count;
    uint64_t sum_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    double mean_ns;
    double m2_ns;
    uint64_t buckets[TRAWL_LAT_BUCKETS];
    uint64_t orphan_begin;
    uint64_t orphan_end;
    uint64_t stack_overflow;
};

struct begin_record {
    uint8_t used;
    uint32_t id;
    uint64_t epoch;
    uint64_t key;
    uint8_t depth;
    uint64_t ts[TRAWL_BEGIN_STACK_DEPTH];
};

struct latency_tracker {
    uint64_t epoch;
    struct latency_snapshot snap;
    struct begin_record recs[TRAWL_BEGIN_TABLE_SIZE];
};

struct trial_result {
    int trial_no;
    int candidate_idx;
    uint32_t speedup_ppm;
    uint64_t epoch;
    uint64_t progress_count;
    uint64_t begin_count;
    uint64_t end_count;
    uint64_t elapsed_ns;
    uint64_t effective_ns;
    uint64_t virtual_delay_ns;
    uint64_t target_hits;
    double rate_per_sec;
    struct latency_snapshot latency;
};

struct trial_spec {
    int candidate_idx;
    uint32_t speedup_ppm;
};

struct thread_set {
    pid_t tids[TRAWL_MAX_THREADS];
    int traced[TRAWL_MAX_THREADS];
    int n;
};

struct delay_backend {
    enum pause_backend_kind kind;
    pid_t pid;
    struct trawl_shm *shm;
    struct thread_set threads;
    uint64_t refresh_counter;
};

struct run_state {
    const struct options *opt;
    struct trawl_shm *shm;
    struct delay_backend *delay;
    struct latency_tracker latency;
    struct trial_result *current;
    uint64_t epoch;
};

static struct elf_image g_images[TRAWL_MAX_IMAGES];
static size_t g_image_count;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_ns(uint64_t ns)
{
    struct timespec req;
    req.tv_sec = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);
    while (nanosleep(&req, &req) < 0 && errno == EINTR) {
        ;
    }
}

static long perf_event_open_sys(struct perf_event_attr *attr, pid_t pid, int cpu,
                                int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage:\n"
        "  sudo %s --shim ./build/libtrawl_shim.so --symbol FUNC [options] -- PROGRAM [ARGS...]\n"
        "  sudo %s --shim ./build/libtrawl_shim.so --range LO-HI [options] -- PROGRAM [ARGS...]\n"
        "  sudo %s --shim ./build/libtrawl_shim.so --auto --top-candidates N [options] -- PROGRAM [ARGS...]\n\n"
        "required/profiling options:\n"
        "  --shim PATH             LD_PRELOAD shim path\n"
        "  --binary PATH           ELF containing --symbol; default: /proc/<pid>/exe\n"
        "  --symbol FUNC           function to virtually speed up\n"
        "  --range LO-HI           runtime address range to virtually speed up\n"
        "  --auto                  discover hot function candidates from sample_hist\n"
        "  --top-candidates N      number of auto-discovered candidates; default: 1\n"
        "  --progress-id ID        progress marker id; default: 1\n"
        "  --latency               consume BEGIN/END marker events and report latency quantiles\n\n"
        "experiment design:\n"
        "  --duration-ms N         duration per trial; default: 5000\n"
        "  --warmup-ms N           warmup before discovery/trials; default: 1000\n"
        "  --cooldown-ms N         drain pause debt after each trial; default: 200\n"
        "  --discover-ms N         auto-discovery sampling window; default: 3000\n"
        "  --repeats N             repeated randomized trials per candidate/speedup; default: 3\n"
        "  --speedups CSV          percentages, e.g. 0,5,10,25,50; default: 0,10,25,50,75\n"
        "  --seed N                randomization seed; default: monotonic time\n"
        "  --no-randomize          run the trial grid deterministically\n\n"
        "runtime/control:\n"
        "  --sample-ns N           CPU-clock sample period; default: 1000000\n"
        "  --stacks                capture user stack ids in BPF stack map\n"
        "  --pause-backend NAME    coop or ptrace; default: coop\n"
        "  --emit-progress-events  emit STEP events too; expensive\n"
        "  --json PATH             write machine-readable report\n"
        "  --trials-csv PATH       write trial table to file instead of stdout\n"
        "  --candidates-csv PATH   write candidate table\n"
        "  --leave-running         do not terminate PROGRAM after profiling\n",
        argv0, argv0, argv0);
}

static void trim_newline(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = 0;
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int path_matches(const char *map_path, const char *path)
{
    if (!map_path || !*map_path || !path || !*path)
        return 0;
    if (strcmp(map_path, path) == 0)
        return 1;
    const char *a = base_name(map_path);
    const char *b = base_name(path);
    return a && b && strcmp(a, b) == 0;
}

static int parse_u64_hex_range(const char *s, uint64_t *lo, uint64_t *hi)
{
    char *dash = strchr(s, '-');
    if (!dash)
        return -1;
    char a[64], b[64];
    size_t alen = (size_t)(dash - s);
    if (alen >= sizeof(a) || strlen(dash + 1) >= sizeof(b))
        return -1;
    memcpy(a, s, alen);
    a[alen] = 0;
    strcpy(b, dash + 1);
    *lo = strtoull(a, NULL, 0);
    *hi = strtoull(b, NULL, 0);
    return (*lo && *hi && *hi > *lo) ? 0 : -1;
}

static int speedup_present(const struct options *opt, uint32_t ppm)
{
    for (int i = 0; i < opt->speedup_count; i++)
        if (opt->speedups_ppm[i] == ppm)
            return 1;
    return 0;
}

static int parse_speedups(struct options *opt, const char *csv)
{
    char *tmp = strdup(csv);
    if (!tmp)
        return -1;
    char *save = NULL;
    char *tok = strtok_r(tmp, ",", &save);
    int n = 0;
    while (tok && n < (int)ARRAY_LEN(opt->speedups_ppm)) {
        char *end = NULL;
        double pct = strtod(tok, &end);
        while (end && isspace((unsigned char)*end))
            end++;
        if (!end || *end || pct < 0.0 || pct > 100.0) {
            free(tmp);
            return -1;
        }
        uint32_t ppm = (uint32_t)(pct * 10000.0 + 0.5); /* pct -> ppm */
        opt->speedups_ppm[n++] = ppm;
        tok = strtok_r(NULL, ",", &save);
    }
    free(tmp);
    opt->speedup_count = n;
    return n > 0 ? 0 : -1;
}

static int ensure_zero_speedup(struct options *opt)
{
    if (speedup_present(opt, 0))
        return 0;
    if (opt->speedup_count >= (int)ARRAY_LEN(opt->speedups_ppm))
        return -1;
    memmove(&opt->speedups_ppm[1], &opt->speedups_ppm[0],
            (size_t)opt->speedup_count * sizeof(opt->speedups_ppm[0]));
    opt->speedups_ppm[0] = 0;
    opt->speedup_count++;
    return 0;
}

static int parse_pause_backend(const char *s, enum pause_backend_kind *out)
{
    if (strcmp(s, "coop") == 0 || strcmp(s, "cooperative") == 0) {
        *out = PAUSE_COOP;
        return 0;
    }
    if (strcmp(s, "ptrace") == 0) {
        *out = PAUSE_PTRACE;
        return 0;
    }
    return -1;
}

static int parse_args(int argc, char **argv, struct options *opt)
{
    memset(opt, 0, sizeof(*opt));
    opt->duration_ms = 5000;
    opt->warmup_ms = 1000;
    opt->cooldown_ms = 200;
    opt->discover_ms = 3000;
    opt->repeats = 3;
    opt->sample_period_ns = 1000000ULL;
    opt->progress_id = 1;
    opt->top_candidates = 1;
    opt->randomize = 1;
    opt->seed = now_ns() ^ (uint64_t)getpid();
    opt->pause_backend = PAUSE_COOP;
    parse_speedups(opt, "0,10,25,50,75");

    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else if (strcmp(argv[i], "--shim") == 0 && i + 1 < argc) {
            opt->shim_path = argv[++i];
        } else if (strcmp(argv[i], "--binary") == 0 && i + 1 < argc) {
            opt->binary_path = argv[++i];
        } else if (strcmp(argv[i], "--symbol") == 0 && i + 1 < argc) {
            opt->symbol = argv[++i];
        } else if (strcmp(argv[i], "--range") == 0 && i + 1 < argc) {
            opt->range = argv[++i];
        } else if (strcmp(argv[i], "--progress-id") == 0 && i + 1 < argc) {
            opt->progress_id = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--duration-ms") == 0 && i + 1 < argc) {
            opt->duration_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--warmup-ms") == 0 && i + 1 < argc) {
            opt->warmup_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cooldown-ms") == 0 && i + 1 < argc) {
            opt->cooldown_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--discover-ms") == 0 && i + 1 < argc) {
            opt->discover_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--repeats") == 0 && i + 1 < argc) {
            opt->repeats = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--sample-ns") == 0 && i + 1 < argc) {
            opt->sample_period_ns = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--speedups") == 0 && i + 1 < argc) {
            if (parse_speedups(opt, argv[++i]) != 0)
                return -1;
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            opt->seed = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--stacks") == 0) {
            opt->capture_stacks = 1;
        } else if (strcmp(argv[i], "--leave-running") == 0) {
            opt->leave_running = 1;
        } else if (strcmp(argv[i], "--auto") == 0) {
            opt->auto_candidates = 1;
        } else if (strcmp(argv[i], "--top-candidates") == 0 && i + 1 < argc) {
            opt->top_candidates = atoi(argv[++i]);
            opt->auto_candidates = 1;
        } else if (strcmp(argv[i], "--latency") == 0) {
            opt->latency_enabled = 1;
        } else if (strcmp(argv[i], "--emit-progress-events") == 0) {
            opt->emit_progress_events = 1;
        } else if (strcmp(argv[i], "--no-randomize") == 0) {
            opt->randomize = 0;
        } else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
            opt->json_path = argv[++i];
        } else if (strcmp(argv[i], "--trials-csv") == 0 && i + 1 < argc) {
            opt->trials_csv_path = argv[++i];
        } else if (strcmp(argv[i], "--candidates-csv") == 0 && i + 1 < argc) {
            opt->candidates_csv_path = argv[++i];
        } else if (strcmp(argv[i], "--pause-backend") == 0 && i + 1 < argc) {
            if (parse_pause_backend(argv[++i], &opt->pause_backend) != 0)
                return -1;
        } else {
            return -1;
        }
    }

    if (i >= argc)
        return -1;
    opt->cmd_argv = &argv[i];

    if (!opt->shim_path)
        return -1;
    if ((opt->symbol ? 1 : 0) + (opt->range ? 1 : 0) + (opt->auto_candidates ? 1 : 0) != 1)
        return -1;
    if (opt->duration_ms <= 0 || opt->sample_period_ns == 0 || opt->repeats <= 0)
        return -1;
    if (opt->warmup_ms < 0 || opt->cooldown_ms < 0 || opt->discover_ms < 0)
        return -1;
    if (opt->top_candidates <= 0 || opt->top_candidates > TRAWL_MAX_CANDIDATES)
        return -1;
    if (ensure_zero_speedup(opt) != 0)
        return -1;

    return 0;
}

static int cmp_func_sym(const void *a, const void *b)
{
    const struct func_sym *fa = a;
    const struct func_sym *fb = b;
    if (fa->value < fb->value)
        return -1;
    if (fa->value > fb->value)
        return 1;
    if (fa->size < fb->size)
        return -1;
    if (fa->size > fb->size)
        return 1;
    return strcmp(fa->name, fb->name);
}

static int add_func(struct elf_image *img, const char *name, uint64_t value, uint64_t size)
{
    if (!name || !*name || value == 0 || size == 0)
        return 0;
    if (img->nfuncs == img->capfuncs) {
        size_t newcap = img->capfuncs ? img->capfuncs * 2 : 1024;
        struct func_sym *p = realloc(img->funcs, newcap * sizeof(*p));
        if (!p)
            return -1;
        img->funcs = p;
        img->capfuncs = newcap;
    }
    struct func_sym *f = &img->funcs[img->nfuncs++];
    f->value = value;
    f->size = size;
    snprintf(f->name, sizeof(f->name), "%s", name);
    return 0;
}

static int load_elf_image(struct elf_image *img)
{
    if (img->loaded)
        return 0;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return -1;

    int fd = open(img->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return -1;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        elf_end(elf);
        close(fd);
        return -1;
    }
    img->is_dyn = (ehdr.e_type == ET_DYN);

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data || shdr.sh_entsize == 0)
            continue;

        size_t count = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < count; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, (int)i, &sym))
                continue;
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
                continue;
            const char *sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!sym_name || !*sym_name)
                continue;
            uint64_t size = sym.st_size ? sym.st_size : 1;
            if (add_func(img, sym_name, sym.st_value, size) != 0) {
                elf_end(elf);
                close(fd);
                return -1;
            }
        }
    }

    if (img->nfuncs)
        qsort(img->funcs, img->nfuncs, sizeof(img->funcs[0]), cmp_func_sym);

    img->loaded = 1;
    elf_end(elf);
    close(fd);
    return 0;
}

static struct elf_image *get_elf_image(const char *path)
{
    for (size_t i = 0; i < g_image_count; i++) {
        if (strcmp(g_images[i].path, path) == 0)
            return &g_images[i];
    }
    if (g_image_count >= ARRAY_LEN(g_images))
        return NULL;
    struct elf_image *img = &g_images[g_image_count++];
    memset(img, 0, sizeof(*img));
    snprintf(img->path, sizeof(img->path), "%s", path);
    if (load_elf_image(img) != 0)
        return NULL;
    return img;
}

static const struct func_sym *find_exact_func(const struct elf_image *img, const char *name)
{
    const struct func_sym *best = NULL;
    for (size_t i = 0; i < img->nfuncs; i++) {
        if (strcmp(img->funcs[i].name, name) != 0)
            continue;
        if (!best || img->funcs[i].size > best->size)
            best = &img->funcs[i];
    }
    return best;
}

static const struct func_sym *find_func_by_obj_addr(const struct elf_image *img, uint64_t obj_addr)
{
    if (!img || img->nfuncs == 0)
        return NULL;

    size_t lo = 0, hi = img->nfuncs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (img->funcs[mid].value <= obj_addr)
            lo = mid + 1;
        else
            hi = mid;
    }

    for (size_t back = 0; back < 16 && lo > 0; back++) {
        const struct func_sym *f = &img->funcs[--lo];
        if (obj_addr >= f->value && obj_addr < f->value + f->size)
            return f;
        if (f->value + f->size < obj_addr && back > 0)
            break;
    }
    return NULL;
}

static void free_proc_maps(struct proc_maps *maps)
{
    free(maps->v);
    maps->v = NULL;
    maps->n = 0;
}

static void clean_map_path(char *path)
{
    while (*path && isspace((unsigned char)*path))
        memmove(path, path + 1, strlen(path));
    char *deleted = strstr(path, " (deleted)");
    if (deleted)
        *deleted = 0;
}

static int read_proc_maps(pid_t pid, struct proc_maps *maps)
{
    memset(maps, 0, sizeof(*maps));
    maps->v = calloc(TRAWL_MAX_MAPS, sizeof(maps->v[0]));
    if (!maps->v)
        return -1;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        free_proc_maps(maps);
        return -1;
    }

    char line[TRAWL_PATH_MAX + 256];
    while (fgets(line, sizeof(line), f) && maps->n < TRAWL_MAX_MAPS) {
        struct map_entry *m = &maps->v[maps->n];
        char dev[64] = {0};
        unsigned long inode = 0;
        char path[TRAWL_PATH_MAX] = {0};
        int fields = sscanf(line, "%lx-%lx %7s %lx %63s %lu %4095[^\n]",
                            &m->start, &m->end, m->perms, &m->offset,
                            dev, &inode, path);
        if (fields < 6)
            continue;
        if (fields == 7) {
            clean_map_path(path);
            snprintf(m->path, sizeof(m->path), "%s", path);
        }
        maps->n++;
    }

    fclose(f);
    return 0;
}

static const struct map_entry *find_map_for_ip(const struct proc_maps *maps, uint64_t ip)
{
    for (size_t i = 0; i < maps->n; i++) {
        const struct map_entry *m = &maps->v[i];
        if (ip >= m->start && ip < m->end)
            return m;
    }
    return NULL;
}

static uint64_t map_bias(const struct map_entry *m)
{
    return m->start - m->offset;
}

static int find_runtime_bias(const struct proc_maps *maps, const char *path,
                             uint64_t obj_addr, uint64_t *bias_out)
{
    for (size_t i = 0; i < maps->n; i++) {
        const struct map_entry *m = &maps->v[i];
        if (!path_matches(m->path, path))
            continue;
        uint64_t bias = map_bias(m);
        uint64_t rt = bias + obj_addr;
        if (rt >= m->start && rt < m->end) {
            *bias_out = bias;
            return 0;
        }
    }
    for (size_t i = 0; i < maps->n; i++) {
        const struct map_entry *m = &maps->v[i];
        if (!path_matches(m->path, path))
            continue;
        *bias_out = map_bias(m);
        return 0;
    }
    return -1;
}

static int read_proc_exe(pid_t pid, char *buf, size_t len)
{
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t n = readlink(link, buf, len - 1);
    if (n < 0)
        return -1;
    buf[n] = 0;
    return 0;
}

static int runtime_to_object(pid_t pid, uint64_t ip, char *path_out, size_t path_len,
                             uint64_t *obj_addr_out, struct elf_image **img_out)
{
    struct proc_maps maps;
    if (read_proc_maps(pid, &maps) != 0)
        return -1;
    const struct map_entry *m = find_map_for_ip(&maps, ip);
    if (!m || !m->path[0]) {
        free_proc_maps(&maps);
        return -1;
    }

    struct elf_image *img = get_elf_image(m->path);
    if (!img) {
        free_proc_maps(&maps);
        return -1;
    }

    uint64_t obj = img->is_dyn ? ip - map_bias(m) : ip;
    snprintf(path_out, path_len, "%s", m->path);
    *obj_addr_out = obj;
    if (img_out)
        *img_out = img;
    free_proc_maps(&maps);
    return 0;
}

static int shell_quote(const char *s, char *out, size_t out_len)
{
    size_t j = 0;
    if (j + 1 >= out_len)
        return -1;
    out[j++] = '\'';
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '\'') {
            const char *esc = "'\\''";
            size_t n = strlen(esc);
            if (j + n >= out_len)
                return -1;
            memcpy(out + j, esc, n);
            j += n;
        } else {
            if (j + 1 >= out_len)
                return -1;
            out[j++] = s[i];
        }
    }
    if (j + 2 > out_len)
        return -1;
    out[j++] = '\'';
    out[j] = 0;
    return 0;
}

static int addr2line_lookup(const char *path, uint64_t obj_addr,
                            char *func, size_t func_len,
                            char *fileline, size_t fileline_len)
{
    char qpath[TRAWL_PATH_MAX * 2];
    if (shell_quote(path, qpath, sizeof(qpath)) != 0)
        return -1;

    char cmd[TRAWL_PATH_MAX * 2 + 128];
    snprintf(cmd, sizeof(cmd), "addr2line -f -C -e %s 0x%lx", qpath, (unsigned long)obj_addr);

    FILE *p = popen(cmd, "r");
    if (!p)
        return -1;

    char fbuf[1024] = {0};
    char lbuf[TRAWL_PATH_MAX] = {0};
    if (!fgets(fbuf, sizeof(fbuf), p)) {
        pclose(p);
        return -1;
    }
    if (!fgets(lbuf, sizeof(lbuf), p)) {
        pclose(p);
        return -1;
    }
    pclose(p);

    trim_newline(fbuf);
    trim_newline(lbuf);
    snprintf(func, func_len, "%s", fbuf);
    snprintf(fileline, fileline_len, "%s", lbuf);
    return 0;
}

static int elf_vaddr_to_file_offset(const char *path, uint64_t vaddr, uint64_t *file_off)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        return -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return -1;
    }

    size_t phnum = 0;
    if (elf_getphdrnum(elf, &phnum) != 0) {
        elf_end(elf);
        close(fd);
        return -1;
    }

    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (!gelf_getphdr(elf, (int)i, &phdr))
            continue;
        if (phdr.p_type != PT_LOAD)
            continue;
        uint64_t lo = phdr.p_vaddr;
        uint64_t hi = phdr.p_vaddr + phdr.p_memsz;
        if (vaddr >= lo && vaddr < hi) {
            *file_off = phdr.p_offset + (vaddr - phdr.p_vaddr);
            elf_end(elf);
            close(fd);
            return 0;
        }
    }

    elf_end(elf);
    close(fd);
    return -1;
}

static int resolve_manual_candidate(pid_t pid, const struct options *opt, struct candidate *cand)
{
    memset(cand, 0, sizeof(*cand));
    cand->from_auto = 0;

    if (opt->range) {
        if (parse_u64_hex_range(opt->range, &cand->lo, &cand->hi) != 0)
            return -1;
        snprintf(cand->name, sizeof(cand->name), "manual-range");
        snprintf(cand->path, sizeof(cand->path), "(runtime-address-range)");
        cand->obj_lo = cand->lo;
        cand->obj_hi = cand->hi;
        snprintf(cand->fileline, sizeof(cand->fileline), "unknown");
        return 0;
    }

    char exe[TRAWL_PATH_MAX];
    const char *path = opt->binary_path;
    if (!path) {
        if (read_proc_exe(pid, exe, sizeof(exe)) != 0)
            return -1;
        path = exe;
    }

    struct proc_maps maps;
    if (read_proc_maps(pid, &maps) != 0)
        return -1;

    struct elf_image *img = get_elf_image(path);
    if (!img) {
        free_proc_maps(&maps);
        fprintf(stderr, "failed to load ELF symbols from %s\n", path);
        return -1;
    }

    const struct func_sym *sym = find_exact_func(img, opt->symbol);
    if (!sym) {
        free_proc_maps(&maps);
        fprintf(stderr, "failed to find function symbol %s in %s\n", opt->symbol, path);
        return -1;
    }

    uint64_t bias = 0;
    if (img->is_dyn) {
        if (find_runtime_bias(&maps, path, sym->value, &bias) != 0) {
            free_proc_maps(&maps);
            fprintf(stderr, "failed to find mapping base for %s in pid %d\n", path, pid);
            return -1;
        }
    }

    cand->obj_lo = sym->value;
    cand->obj_hi = sym->value + sym->size;
    cand->lo = img->is_dyn ? bias + sym->value : sym->value;
    cand->hi = cand->lo + sym->size;
    snprintf(cand->name, sizeof(cand->name), "%s", sym->name);
    snprintf(cand->path, sizeof(cand->path), "%s", path);

    char func[1024];
    if (addr2line_lookup(path, sym->value, func, sizeof(func), cand->fileline, sizeof(cand->fileline)) != 0)
        snprintf(cand->fileline, sizeof(cand->fileline), "unknown");

    free_proc_maps(&maps);
    return 0;
}

static int clear_sample_hist(int map_fd)
{
    struct trawl_sample_key key;
    int deleted = 0;
    while (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
        if (bpf_map_delete_elem(map_fd, &key) == 0)
            deleted++;
    }
    return deleted;
}

static int candidate_index_of(struct candidate *cands, int n,
                              const char *path, uint64_t obj_lo, uint64_t obj_hi,
                              const char *name)
{
    for (int i = 0; i < n; i++) {
        if (cands[i].obj_lo == obj_lo && cands[i].obj_hi == obj_hi &&
            strcmp(cands[i].path, path) == 0 && strcmp(cands[i].name, name) == 0)
            return i;
    }
    return -1;
}

static int add_or_update_candidate(struct candidate *cands, int *n,
                                   const char *path, const struct elf_image *img,
                                   const struct func_sym *sym,
                                   uint64_t samples, pid_t pid)
{
    if (!sym || !path || !*path)
        return 0;

    int idx = candidate_index_of(cands, *n, path, sym->value, sym->value + sym->size, sym->name);
    if (idx >= 0) {
        cands[idx].samples += samples;
        return 0;
    }
    if (*n >= TRAWL_MAX_CANDIDATES * 8)
        return 0;

    struct proc_maps maps;
    if (read_proc_maps(pid, &maps) != 0)
        return -1;

    uint64_t bias = 0;
    if (img->is_dyn) {
        if (find_runtime_bias(&maps, path, sym->value, &bias) != 0) {
            free_proc_maps(&maps);
            return 0;
        }
    }

    struct candidate *c = &cands[(*n)++];
    memset(c, 0, sizeof(*c));
    snprintf(c->name, sizeof(c->name), "%s", sym->name);
    snprintf(c->path, sizeof(c->path), "%s", path);
    c->obj_lo = sym->value;
    c->obj_hi = sym->value + sym->size;
    c->lo = img->is_dyn ? bias + sym->value : sym->value;
    c->hi = c->lo + sym->size;
    c->samples = samples;
    c->from_auto = 1;

    char func[1024];
    if (addr2line_lookup(path, sym->value, func, sizeof(func), c->fileline, sizeof(c->fileline)) != 0)
        snprintf(c->fileline, sizeof(c->fileline), "unknown");

    free_proc_maps(&maps);
    return 0;
}

static int cmp_candidate_samples(const void *a, const void *b)
{
    const struct candidate *ca = a;
    const struct candidate *cb = b;
    if (ca->samples < cb->samples)
        return 1;
    if (ca->samples > cb->samples)
        return -1;
    return strcmp(ca->name, cb->name);
}

static int collect_candidates_from_hist(pid_t pid, int sample_map_fd,
                                        struct candidate *out, int max_out)
{
    struct candidate tmp[TRAWL_MAX_CANDIDATES * 8];
    int ntmp = 0;
    memset(tmp, 0, sizeof(tmp));

    struct trawl_sample_key key, next;
    int have_key = 0;
    while (bpf_map_get_next_key(sample_map_fd, have_key ? &key : NULL, &next) == 0) {
        key = next;
        have_key = 1;

        struct trawl_count val;
        if (bpf_map_lookup_elem(sample_map_fd, &key, &val) != 0 || val.count == 0)
            continue;

        char path[TRAWL_PATH_MAX];
        uint64_t obj_addr = 0;
        struct elf_image *img = NULL;
        if (runtime_to_object(pid, key.ip, path, sizeof(path), &obj_addr, &img) != 0)
            continue;
        const struct func_sym *sym = find_func_by_obj_addr(img, obj_addr);
        if (!sym)
            continue;
        add_or_update_candidate(tmp, &ntmp, path, img, sym, val.count, pid);
    }

    if (ntmp == 0)
        return 0;
    qsort(tmp, (size_t)ntmp, sizeof(tmp[0]), cmp_candidate_samples);
    int nout = ntmp < max_out ? ntmp : max_out;
    memcpy(out, tmp, (size_t)nout * sizeof(out[0]));
    return nout;
}

static int update_config(struct trawl_bpf *skel, const struct trawl_config *cfg)
{
    uint32_t zero = 0;
    int fd = bpf_map__fd(skel->maps.config);
    return bpf_map_update_elem(fd, &zero, cfg, BPF_ANY);
}

static uint64_t read_progress_count(int map_fd, uint64_t epoch, uint32_t id, uint32_t kind)
{
    struct trawl_progress_key key = {
        .epoch = epoch,
        .id = id,
        .kind = kind,
    };
    struct trawl_progress_value val;
    memset(&val, 0, sizeof(val));
    if (bpf_map_lookup_elem(map_fd, &key, &val) != 0)
        return 0;
    return val.count;
}

static struct trawl_shm *create_shm(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return NULL;
    if (ftruncate(fd, (off_t)sizeof(struct trawl_shm)) != 0) {
        close(fd);
        return NULL;
    }
    struct trawl_shm *shm = mmap(NULL, sizeof(*shm), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (shm == MAP_FAILED)
        return NULL;
    memset(shm, 0, sizeof(*shm));
    __atomic_store_n(&shm->version, TRAWL_SHM_VERSION, __ATOMIC_RELEASE);
    __atomic_store_n(&shm->max_threads, TRAWL_MAX_THREADS, __ATOMIC_RELEASE);
    __atomic_store_n(&shm->magic, TRAWL_SHM_MAGIC, __ATOMIC_RELEASE);
    return shm;
}

static int prepend_ld_preload(const char *shim, char *buf, size_t len)
{
    const char *old = getenv("LD_PRELOAD");
    if (old && *old)
        return snprintf(buf, len, "%s:%s", shim, old) < (int)len ? 0 : -1;
    return snprintf(buf, len, "%s", shim) < (int)len ? 0 : -1;
}

static pid_t launch_target(const struct options *opt, const char *shm_path)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        char preload[TRAWL_PATH_MAX * 2];
        if (prepend_ld_preload(opt->shim_path, preload, sizeof(preload)) != 0)
            _exit(127);
        setenv("LD_PRELOAD", preload, 1);
        setenv("TRAWL_SHM_PATH", shm_path, 1);
        setenv("TRAWL_HOLD", "1", 1);
        execvp(opt->cmd_argv[0], opt->cmd_argv);
        perror("execvp");
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, WUNTRACED) < 0) {
        kill(pid, SIGKILL);
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "target did not stop in shim constructor\n");
        kill(pid, SIGKILL);
        return -1;
    }

    return pid;
}

static int add_debt_except(struct trawl_shm *shm, uint32_t exclude_tid, uint64_t delay_ns)
{
    int n = 0;
    for (int i = 0; i < TRAWL_MAX_THREADS; i++) {
        uint32_t tid = __atomic_load_n(&shm->slots[i].tid, __ATOMIC_ACQUIRE);
        if (!tid || tid == exclude_tid)
            continue;
        __atomic_fetch_add(&shm->slots[i].debt_ns, delay_ns, __ATOMIC_RELEASE);
        n++;
    }
    if (n == 0)
        __atomic_fetch_add(&shm->dropped_debt_events, 1ULL, __ATOMIC_RELAXED);
    return n;
}

static int all_debt_drained(struct trawl_shm *shm)
{
    for (int i = 0; i < TRAWL_MAX_THREADS; i++) {
        uint32_t tid = __atomic_load_n(&shm->slots[i].tid, __ATOMIC_ACQUIRE);
        if (!tid)
            continue;
        uint64_t debt = __atomic_load_n(&shm->slots[i].debt_ns, __ATOMIC_ACQUIRE);
        uint64_t slept = __atomic_load_n(&shm->slots[i].slept_ns, __ATOMIC_ACQUIRE);
        if (slept < debt)
            return 0;
    }
    return 1;
}

static int thread_set_contains(const struct thread_set *ts, pid_t tid)
{
    for (int i = 0; i < ts->n; i++)
        if (ts->tids[i] == tid)
            return i;
    return -1;
}

static int refresh_thread_set(struct delay_backend *db, int seize_new)
{
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", db->pid);
    DIR *d = opendir(task_path);
    if (!d)
        return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0]))
            continue;
        pid_t tid = (pid_t)strtol(de->d_name, NULL, 10);
        if (tid <= 0)
            continue;
        if (thread_set_contains(&db->threads, tid) >= 0)
            continue;
        if (db->threads.n >= TRAWL_MAX_THREADS)
            continue;
        int idx = db->threads.n++;
        db->threads.tids[idx] = tid;
        db->threads.traced[idx] = 0;
        if (seize_new) {
            if (ptrace(PTRACE_SEIZE, tid, 0, (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) == 0) {
                db->threads.traced[idx] = 1;
            } else if (errno == ESRCH) {
                db->threads.tids[idx] = 0;
            } else {
                fprintf(stderr, "warning: failed to ptrace-seize tid %d: %s\n", tid, strerror(errno));
            }
        }
    }
    closedir(d);
    return 0;
}

static int delay_backend_init(struct delay_backend *db, enum pause_backend_kind kind,
                              pid_t pid, struct trawl_shm *shm)
{
    memset(db, 0, sizeof(*db));
    db->kind = kind;
    db->pid = pid;
    db->shm = shm;
    if (kind == PAUSE_PTRACE) {
        if (refresh_thread_set(db, 1) != 0)
            return -1;
    }
    return 0;
}

static void delay_backend_destroy(struct delay_backend *db)
{
    if (db->kind != PAUSE_PTRACE)
        return;
    for (int i = 0; i < db->threads.n; i++) {
        if (db->threads.tids[i] > 0 && db->threads.traced[i])
            ptrace(PTRACE_DETACH, db->threads.tids[i], 0, 0);
    }
}

static int ptrace_wait_stopped(pid_t tid)
{
    int status = 0;
    for (;;) {
        pid_t r = waitpid(tid, &status, __WALL);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return -1;
        if (WIFSTOPPED(status))
            return 0;
        if (WIFEXITED(status) || WIFSIGNALED(status))
            return -1;
    }
}

static int ptrace_pause_except(struct delay_backend *db, uint32_t exclude_tid, uint64_t delay_ns)
{
    if ((db->refresh_counter++ & 0x3f) == 0)
        refresh_thread_set(db, 1);

    pid_t stopped[TRAWL_MAX_THREADS];
    int nstopped = 0;

    for (int i = 0; i < db->threads.n; i++) {
        pid_t tid = db->threads.tids[i];
        if (tid <= 0 || !db->threads.traced[i] || (uint32_t)tid == exclude_tid)
            continue;
        if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) == 0)
            stopped[nstopped++] = tid;
    }

    int usable = 0;
    for (int i = 0; i < nstopped; i++) {
        if (ptrace_wait_stopped(stopped[i]) == 0)
            usable++;
        else
            stopped[i] = 0;
    }

    if (usable > 0)
        sleep_ns(delay_ns);

    for (int i = 0; i < nstopped; i++) {
        if (stopped[i] > 0)
            ptrace(PTRACE_CONT, stopped[i], 0, 0);
    }
    return usable;
}

static int delay_apply_except(struct delay_backend *db, uint32_t exclude_tid, uint64_t delay_ns)
{
    if (delay_ns == 0)
        return 0;
    if (db->kind == PAUSE_PTRACE)
        return ptrace_pause_except(db, exclude_tid, delay_ns);
    return add_debt_except(db->shm, exclude_tid, delay_ns);
}

static void latency_snapshot_init(struct latency_snapshot *s)
{
    memset(s, 0, sizeof(*s));
    s->min_ns = UINT64_MAX;
}

static unsigned latency_bucket(uint64_t ns)
{
    if (ns == 0)
        return 0;
    unsigned l = 63u - (unsigned)__builtin_clzll(ns);
    unsigned sub = 0;
    if (l >= 3)
        sub = (unsigned)((ns >> (l - 3)) & 7u);
    else
        sub = (unsigned)((ns << (3 - l)) & 7u);
    unsigned idx = l * 8u + sub;
    if (idx >= TRAWL_LAT_BUCKETS)
        idx = TRAWL_LAT_BUCKETS - 1;
    return idx;
}

static uint64_t latency_bucket_midpoint(unsigned idx)
{
    if (idx == 0)
        return 0;
    unsigned l = idx / 8u;
    unsigned sub = idx % 8u;
    if (l >= 63)
        return UINT64_MAX / 2;
    uint64_t base = 1ULL << l;
    uint64_t step = l >= 3 ? (base >> 3) : 1ULL;
    return base + sub * step + step / 2;
}

static void latency_snapshot_add(struct latency_snapshot *s, uint64_t ns)
{
    s->count++;
    s->sum_ns += ns;
    if (ns < s->min_ns)
        s->min_ns = ns;
    if (ns > s->max_ns)
        s->max_ns = ns;

    double x = (double)ns;
    double delta = x - s->mean_ns;
    s->mean_ns += delta / (double)s->count;
    double delta2 = x - s->mean_ns;
    s->m2_ns += delta * delta2;

    s->buckets[latency_bucket(ns)]++;
}

static uint64_t latency_percentile_ns(const struct latency_snapshot *s, double q)
{
    if (!s->count)
        return 0;
    uint64_t rank = (uint64_t)ceil(q * (double)s->count);
    if (rank == 0)
        rank = 1;
    uint64_t acc = 0;
    for (unsigned i = 0; i < TRAWL_LAT_BUCKETS; i++) {
        acc += s->buckets[i];
        if (acc >= rank)
            return latency_bucket_midpoint(i);
    }
    return s->max_ns;
}

static void latency_snapshot_merge(struct latency_snapshot *dst, const struct latency_snapshot *src)
{
    if (!src->count) {
        dst->orphan_begin += src->orphan_begin;
        dst->orphan_end += src->orphan_end;
        dst->stack_overflow += src->stack_overflow;
        return;
    }
    if (!dst->count) {
        *dst = *src;
        return;
    }

    uint64_t n1 = dst->count;
    uint64_t n2 = src->count;
    double mean1 = dst->mean_ns;
    double mean2 = src->mean_ns;
    double delta = mean2 - mean1;
    uint64_t n = n1 + n2;

    dst->mean_ns = mean1 + delta * ((double)n2 / (double)n);
    dst->m2_ns += src->m2_ns + delta * delta * ((double)n1 * (double)n2 / (double)n);
    dst->count = n;
    dst->sum_ns += src->sum_ns;
    if (src->min_ns < dst->min_ns)
        dst->min_ns = src->min_ns;
    if (src->max_ns > dst->max_ns)
        dst->max_ns = src->max_ns;
    for (unsigned i = 0; i < TRAWL_LAT_BUCKETS; i++)
        dst->buckets[i] += src->buckets[i];
    dst->orphan_begin += src->orphan_begin;
    dst->orphan_end += src->orphan_end;
    dst->stack_overflow += src->stack_overflow;
}

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static void latency_tracker_reset(struct latency_tracker *lt, uint64_t epoch)
{
    lt->epoch = epoch;
    latency_snapshot_init(&lt->snap);
    memset(lt->recs, 0, sizeof(lt->recs));
}

static struct begin_record *latency_begin_record(struct latency_tracker *lt,
                                                 uint64_t epoch, uint32_t id,
                                                 uint64_t key, int create)
{
    uint64_t h = mix64(epoch ^ ((uint64_t)id << 32) ^ key);
    for (size_t probe = 0; probe < TRAWL_BEGIN_TABLE_SIZE; probe++) {
        size_t idx = (h + probe) & (TRAWL_BEGIN_TABLE_SIZE - 1);
        struct begin_record *r = &lt->recs[idx];
        if (!r->used) {
            if (!create)
                return NULL;
            r->used = 1;
            r->epoch = epoch;
            r->id = id;
            r->key = key;
            r->depth = 0;
            return r;
        }
        if (r->epoch == epoch && r->id == id && r->key == key)
            return r;
    }
    return NULL;
}

static void latency_on_begin(struct latency_tracker *lt, const struct trawl_event *ev)
{
    uint64_t key = (ev->progress_flags & TRAWL_PROGRESS_F_HAS_TOKEN) ?
        ev->correlation_id : (uint64_t)ev->tid;
    struct begin_record *r = latency_begin_record(lt, ev->epoch, ev->progress_id, key, 1);
    if (!r) {
        lt->snap.orphan_begin++;
        return;
    }
    if (r->depth >= TRAWL_BEGIN_STACK_DEPTH) {
        lt->snap.stack_overflow++;
        return;
    }
    r->ts[r->depth++] = ev->ts_ns;
}

static void latency_on_end(struct latency_tracker *lt, const struct trawl_event *ev)
{
    uint64_t key = (ev->progress_flags & TRAWL_PROGRESS_F_HAS_TOKEN) ?
        ev->correlation_id : (uint64_t)ev->tid;
    struct begin_record *r = latency_begin_record(lt, ev->epoch, ev->progress_id, key, 0);
    if (!r || r->depth == 0) {
        lt->snap.orphan_end++;
        return;
    }
    uint64_t begin = r->ts[--r->depth];
    if (ev->ts_ns >= begin)
        latency_snapshot_add(&lt->snap, ev->ts_ns - begin);
}

static int on_event(void *ctx, void *data, size_t data_sz)
{
    (void)data_sz;
    struct run_state *st = ctx;
    const struct trawl_event *ev = data;

    if (!st->current || ev->epoch != st->epoch)
        return 0;

    if (ev->kind == TRAWL_EVENT_TARGET_HIT && ev->speedup_ppm > 0) {
        uint64_t delay_ns = (ev->sample_period_ns * (uint64_t)ev->speedup_ppm) / TRAWL_SPEEDUP_PPM_DEN;
        int delayed_threads = delay_apply_except(st->delay, ev->tid, delay_ns);
        if (delayed_threads > 0) {
            st->current->target_hits++;
            st->current->virtual_delay_ns += delay_ns;
            __atomic_fetch_add(&st->shm->total_virtual_delay_ns, delay_ns, __ATOMIC_RELAXED);
        }
        return 0;
    }

    if (ev->kind == TRAWL_EVENT_PROGRESS && st->opt->latency_enabled) {
        if (ev->progress_kind == TRAWL_PROGRESS_BEGIN)
            latency_on_begin(&st->latency, ev);
        else if (ev->progress_kind == TRAWL_PROGRESS_END)
            latency_on_end(&st->latency, ev);
    }

    return 0;
}

static int attach_perf_events(struct trawl_bpf *skel, uint64_t sample_period_ns,
                              struct bpf_link ***out_links, int **out_fds, int *out_n)
{
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    struct bpf_link **links = calloc((size_t)ncpu, sizeof(*links));
    int *fds = calloc((size_t)ncpu, sizeof(*fds));
    if (!links || !fds) {
        free(links);
        free(fds);
        return -1;
    }
    for (int i = 0; i < ncpu; i++)
        fds[i] = -1;

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.size = sizeof(attr);
    attr.sample_period = sample_period_ns;
    attr.freq = 0;
    attr.disabled = 0;
    attr.inherit = 1;

    int attached = 0;
    for (int cpu = 0; cpu < ncpu; cpu++) {
        int fd = (int)perf_event_open_sys(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd < 0)
            continue;
        struct bpf_link *link = bpf_program__attach_perf_event(skel->progs.trawl_on_sample, fd);
        if (!link) {
            close(fd);
            continue;
        }
        fds[cpu] = fd;
        links[cpu] = link;
        attached++;
    }

    if (attached == 0) {
        free(links);
        free(fds);
        return -1;
    }

    *out_links = links;
    *out_fds = fds;
    *out_n = ncpu;
    return 0;
}

static void destroy_perf_links(struct bpf_link **links, int *fds, int n)
{
    if (!links || !fds)
        return;
    for (int i = 0; i < n; i++) {
        if (links[i])
            bpf_link__destroy(links[i]);
        if (fds[i] >= 0)
            close(fds[i]);
    }
    free(links);
    free(fds);
}

static int attach_marker_uprobes(struct trawl_bpf *skel, const char *shim_path, pid_t pid,
                                 struct bpf_link **links, size_t nlinks)
{
    if (nlinks < 5)
        return -1;

    struct elf_image *img = get_elf_image(shim_path);
    if (!img)
        return -1;
    const struct func_sym *progress = find_exact_func(img, "trawl_progress");
    const struct func_sym *begin = find_exact_func(img, "trawl_latency_begin");
    const struct func_sym *end = find_exact_func(img, "trawl_latency_end");
    const struct func_sym *begin_id = find_exact_func(img, "trawl_latency_begin_id");
    const struct func_sym *end_id = find_exact_func(img, "trawl_latency_end_id");
    if (!progress || !begin || !end || !begin_id || !end_id) {
        fprintf(stderr, "failed to resolve marker symbols in %s\n", shim_path);
        return -1;
    }

    uint64_t progress_off = progress->value;
    uint64_t begin_off = begin->value;
    uint64_t end_off = end->value;
    uint64_t begin_id_off = begin_id->value;
    uint64_t end_id_off = end_id->value;
    elf_vaddr_to_file_offset(shim_path, progress->value, &progress_off);
    elf_vaddr_to_file_offset(shim_path, begin->value, &begin_off);
    elf_vaddr_to_file_offset(shim_path, end->value, &end_off);
    elf_vaddr_to_file_offset(shim_path, begin_id->value, &begin_id_off);
    elf_vaddr_to_file_offset(shim_path, end_id->value, &end_id_off);

    links[0] = bpf_program__attach_uprobe(skel->progs.trawl_uprobe_progress,
                                          false, pid, shim_path, (size_t)progress_off);
    links[1] = bpf_program__attach_uprobe(skel->progs.trawl_uprobe_latency_begin,
                                          false, pid, shim_path, (size_t)begin_off);
    links[2] = bpf_program__attach_uprobe(skel->progs.trawl_uprobe_latency_end,
                                          false, pid, shim_path, (size_t)end_off);
    links[3] = bpf_program__attach_uprobe(skel->progs.trawl_uprobe_latency_begin_id,
                                          false, pid, shim_path, (size_t)begin_id_off);
    links[4] = bpf_program__attach_uprobe(skel->progs.trawl_uprobe_latency_end_id,
                                          false, pid, shim_path, (size_t)end_id_off);

    return (links[0] && links[1] && links[2] && links[3] && links[4]) ? 0 : -1;
}

static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static int build_trial_plan(const struct options *opt, int ncandidates,
                            struct trial_spec *plan, int max_plan)
{
    int n = 0;
    for (int c = 0; c < ncandidates; c++) {
        for (int r = 0; r < opt->repeats; r++) {
            for (int s = 0; s < opt->speedup_count; s++) {
                if (n >= max_plan)
                    return -1;
                plan[n].candidate_idx = c;
                plan[n].speedup_ppm = opt->speedups_ppm[s];
                n++;
            }
        }
    }

    if (opt->randomize) {
        uint64_t st = opt->seed ? opt->seed : 0x9e3779b97f4a7c15ULL;
        for (int i = n - 1; i > 0; i--) {
            int j = (int)(rng_next(&st) % (uint64_t)(i + 1));
            struct trial_spec tmp = plan[i];
            plan[i] = plan[j];
            plan[j] = tmp;
        }
    }
    return n;
}

static int poll_controller(struct ring_buffer *rb, pid_t child, int ms, int *child_exited)
{
    uint64_t deadline = now_ns() + (uint64_t)ms * 1000000ULL;
    while (now_ns() < deadline) {
        int timeout_ms = 50;
        uint64_t left_ns = deadline - now_ns();
        if (left_ns < 50000000ULL)
            timeout_ms = (int)(left_ns / 1000000ULL) + 1;
        ring_buffer__poll(rb, timeout_ms);

        int status = 0;
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child && (WIFEXITED(status) || WIFSIGNALED(status))) {
            *child_exited = 1;
            return -1;
        }
    }
    return 0;
}

static void wait_for_debt_drain(struct ring_buffer *rb, struct trawl_shm *shm, int cooldown_ms)
{
    if (cooldown_ms <= 0)
        return;
    uint64_t deadline = now_ns() + (uint64_t)cooldown_ms * 1000000ULL;
    while (now_ns() < deadline) {
        ring_buffer__poll(rb, 10);
        if (all_debt_drained(shm))
            break;
        usleep(10000);
    }
}

static int run_discovery(struct trawl_bpf *skel, struct ring_buffer *rb,
                         const struct options *opt, pid_t child,
                         struct candidate *cands, int *ncands,
                         int *child_exited)
{
    clear_sample_hist(bpf_map__fd(skel->maps.sample_hist));

    struct trawl_config cfg = {
        .target_tgid = (uint32_t)child,
        .active = 0,
        .epoch = 0,
        .target_lo = 0,
        .target_hi = 0,
        .speedup_ppm = 0,
        .progress_id = opt->progress_id,
        .sample_period_ns = opt->sample_period_ns,
        .capture_user_stack = (uint32_t)opt->capture_stacks,
        .emit_all_samples = 0,
        .emit_progress_events = 0,
        .latency_enabled = 0,
    };
    if (update_config(skel, &cfg) != 0)
        return -1;

    if (poll_controller(rb, child, opt->discover_ms, child_exited) != 0)
        return -1;

    int n = collect_candidates_from_hist(child, bpf_map__fd(skel->maps.sample_hist),
                                         cands, opt->top_candidates);
    if (n <= 0) {
        fprintf(stderr, "auto-discovery found no symbolized candidates; use --symbol or --range\n");
        return -1;
    }
    *ncands = n;
    return 0;
}

static int run_trial(struct trawl_bpf *skel, struct ring_buffer *rb,
                     const struct options *opt, struct run_state *state,
                     const struct candidate *cand, int cand_idx,
                     struct trial_result *res, int trial_no,
                     uint64_t epoch, uint32_t speedup_ppm,
                     pid_t child, int *child_exited)
{
    memset(res, 0, sizeof(*res));
    res->trial_no = trial_no;
    res->candidate_idx = cand_idx;
    res->speedup_ppm = speedup_ppm;
    res->epoch = epoch;
    res->effective_ns = 0;
    latency_snapshot_init(&res->latency);

    state->current = res;
    state->epoch = epoch;
    latency_tracker_reset(&state->latency, epoch);
    __atomic_store_n(&state->shm->controller_epoch, epoch, __ATOMIC_RELEASE);

    struct trawl_config cfg = {
        .target_tgid = (uint32_t)child,
        .active = 1,
        .epoch = epoch,
        .target_lo = cand->lo,
        .target_hi = cand->hi,
        .speedup_ppm = speedup_ppm,
        .progress_id = opt->progress_id,
        .sample_period_ns = opt->sample_period_ns,
        .capture_user_stack = (uint32_t)opt->capture_stacks,
        .emit_all_samples = 0,
        .emit_progress_events = (uint32_t)opt->emit_progress_events,
        .latency_enabled = (uint32_t)opt->latency_enabled,
    };

    if (update_config(skel, &cfg) != 0) {
        fprintf(stderr, "failed to update BPF config\n");
        state->current = NULL;
        return -1;
    }

    uint64_t t0 = now_ns();
    poll_controller(rb, child, opt->duration_ms, child_exited);
    uint64_t t1 = now_ns();

    cfg.active = 0;
    update_config(skel, &cfg);
    ring_buffer__poll(rb, 100);

    res->elapsed_ns = t1 - t0;
    res->effective_ns = res->elapsed_ns;
    if (res->virtual_delay_ns < res->elapsed_ns)
        res->effective_ns = res->elapsed_ns - res->virtual_delay_ns;
    res->progress_count = read_progress_count(bpf_map__fd(skel->maps.progress_counts),
                                              epoch, opt->progress_id, TRAWL_PROGRESS_STEP);
    res->begin_count = read_progress_count(bpf_map__fd(skel->maps.progress_counts),
                                           epoch, opt->progress_id, TRAWL_PROGRESS_BEGIN);
    res->end_count = read_progress_count(bpf_map__fd(skel->maps.progress_counts),
                                         epoch, opt->progress_id, TRAWL_PROGRESS_END);
    res->rate_per_sec = res->effective_ns ?
        ((double)res->progress_count * 1e9 / (double)res->effective_ns) : 0.0;
    res->latency = state->latency.snap;

    state->current = NULL;
    wait_for_debt_drain(rb, state->shm, opt->cooldown_ms);
    return *child_exited ? -1 : 0;
}

static double tcrit95(int df)
{
    static const double table[] = {
        0.0,
        12.706, 4.303, 3.182, 2.776, 2.571,
        2.447, 2.365, 2.306, 2.262, 2.228,
        2.201, 2.179, 2.160, 2.145, 2.131,
        2.120, 2.110, 2.101, 2.093, 2.086,
        2.080, 2.074, 2.069, 2.064, 2.060,
        2.056, 2.052, 2.048, 2.045, 2.042,
    };
    if (df <= 0)
        return NAN;
    if (df < (int)ARRAY_LEN(table))
        return table[df];
    return 1.960;
}

struct scalar_stats {
    int n;
    double mean;
    double m2;
};

static void scalar_add(struct scalar_stats *s, double x)
{
    s->n++;
    double delta = x - s->mean;
    s->mean += delta / (double)s->n;
    s->m2 += delta * (x - s->mean);
}

static double scalar_variance(const struct scalar_stats *s)
{
    return s->n > 1 ? s->m2 / (double)(s->n - 1) : 0.0;
}

static void write_candidate_table(FILE *out, const struct candidate *cands, int ncands)
{
    fprintf(out, "candidate_idx,name,path,runtime_lo,runtime_hi,obj_lo,obj_hi,samples,fileline\n");
    for (int i = 0; i < ncands; i++) {
        fprintf(out, "%d,\"%s\",\"%s\",0x%lx,0x%lx,0x%lx,0x%lx,%lu,\"%s\"\n",
                i, cands[i].name, cands[i].path,
                (unsigned long)cands[i].lo, (unsigned long)cands[i].hi,
                (unsigned long)cands[i].obj_lo, (unsigned long)cands[i].obj_hi,
                (unsigned long)cands[i].samples, cands[i].fileline);
    }
}

static void write_trial_header(FILE *out)
{
    fprintf(out,
            "trial,candidate_idx,speedup_pct,epoch,progress_count,begin_count,end_count,elapsed_ms,effective_ms,target_hits,virtual_delay_ms,rate_per_sec,lat_count,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms,lat_max_ms,lat_orphan_begin,lat_orphan_end,lat_stack_overflow\n");
}

static void write_trial_row(FILE *out, const struct trial_result *r)
{
    double pct = (double)r->speedup_ppm / 10000.0;
    double lat_mean_ms = r->latency.count ? r->latency.mean_ns / 1e6 : 0.0;
    double lat_p50_ms = (double)latency_percentile_ns(&r->latency, 0.50) / 1e6;
    double lat_p90_ms = (double)latency_percentile_ns(&r->latency, 0.90) / 1e6;
    double lat_p99_ms = (double)latency_percentile_ns(&r->latency, 0.99) / 1e6;
    double lat_max_ms = r->latency.count ? (double)r->latency.max_ns / 1e6 : 0.0;

    fprintf(out, "%d,%d,%.3f,%lu,%lu,%lu,%lu,%.3f,%.3f,%lu,%.3f,%.6f,%lu,%.6f,%.6f,%.6f,%.6f,%.6f,%lu,%lu,%lu\n",
            r->trial_no,
            r->candidate_idx,
            pct,
            (unsigned long)r->epoch,
            (unsigned long)r->progress_count,
            (unsigned long)r->begin_count,
            (unsigned long)r->end_count,
            (double)r->elapsed_ns / 1e6,
            (double)r->effective_ns / 1e6,
            (unsigned long)r->target_hits,
            (double)r->virtual_delay_ns / 1e6,
            r->rate_per_sec,
            (unsigned long)r->latency.count,
            lat_mean_ms,
            lat_p50_ms,
            lat_p90_ms,
            lat_p99_ms,
            lat_max_ms,
            (unsigned long)r->latency.orphan_begin,
            (unsigned long)r->latency.orphan_end,
            (unsigned long)r->latency.stack_overflow);
}

static void summarize_candidate_speedup(FILE *out,
                                        const struct candidate *cands,
                                        int cand_idx,
                                        uint32_t ppm,
                                        const struct trial_result *results,
                                        int nresults)
{
    struct scalar_stats rate = {0};
    struct scalar_stats base = {0};
    struct latency_snapshot lat;
    latency_snapshot_init(&lat);

    for (int i = 0; i < nresults; i++) {
        if (results[i].candidate_idx != cand_idx)
            continue;
        if (results[i].speedup_ppm == 0)
            scalar_add(&base, results[i].rate_per_sec);
        if (results[i].speedup_ppm == ppm) {
            scalar_add(&rate, results[i].rate_per_sec);
            latency_snapshot_merge(&lat, &results[i].latency);
        }
    }
    if (rate.n == 0)
        return;

    double rate_var = scalar_variance(&rate);
    double rate_se = rate.n > 0 ? sqrt(rate_var / (double)rate.n) : 0.0;
    double tc_rate = tcrit95(rate.n - 1);
    double rate_lo = rate.mean - tc_rate * rate_se;
    double rate_hi = rate.mean + tc_rate * rate_se;

    double impact = 0.0, impact_lo = 0.0, impact_hi = 0.0;
    if (ppm != 0 && base.n > 0 && base.mean > 0.0 && rate.mean > 0.0) {
        double base_var = scalar_variance(&base);
        double se_log = sqrt((rate_var / (double)rate.n) / (rate.mean * rate.mean) +
                             (base_var / (double)base.n) / (base.mean * base.mean));
        int df = rate.n < base.n ? rate.n - 1 : base.n - 1;
        double tc = tcrit95(df);
        double log_ratio = log(rate.mean / base.mean);
        impact = (exp(log_ratio) - 1.0) * 100.0;
        impact_lo = (exp(log_ratio - tc * se_log) - 1.0) * 100.0;
        impact_hi = (exp(log_ratio + tc * se_log) - 1.0) * 100.0;
    }

    double pct = (double)ppm / 10000.0;
    fprintf(out,
            "summary,%d,\"%s\",%.3f,%d,%.6f,%.6f,%.6f,%.3f,%.3f,%.3f,%lu,%.6f,%.6f,%.6f,%.6f\n",
            cand_idx, cands[cand_idx].name, pct, rate.n,
            rate.mean, rate_lo, rate_hi,
            impact, impact_lo, impact_hi,
            (unsigned long)lat.count,
            lat.count ? lat.mean_ns / 1e6 : 0.0,
            (double)latency_percentile_ns(&lat, 0.50) / 1e6,
            (double)latency_percentile_ns(&lat, 0.90) / 1e6,
            (double)latency_percentile_ns(&lat, 0.99) / 1e6);
}

static void write_summary(FILE *out, const struct candidate *cands, int ncands,
                          const struct options *opt,
                          const struct trial_result *results, int nresults)
{
    fprintf(out, "summary_type,candidate_idx,name,speedup_pct,n,rate_mean,rate_ci95_low,rate_ci95_high,impact_pct,impact_ci95_low,impact_ci95_high,lat_count,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms\n");
    for (int c = 0; c < ncands; c++) {
        for (int s = 0; s < opt->speedup_count; s++)
            summarize_candidate_speedup(out, cands, c, opt->speedups_ppm[s], results, nresults);
    }
}

static void json_escape(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            fprintf(f, "\\%c", c);
        else if (c == '\n')
            fprintf(f, "\\n");
        else if (c == '\r')
            fprintf(f, "\\r");
        else if (c == '\t')
            fprintf(f, "\\t");
        else if (c < 0x20)
            fprintf(f, "\\u%04x", c);
        else
            fputc(c, f);
    }
    fputc('"', f);
}

static int write_json_report(const char *path, const struct candidate *cands, int ncands,
                             const struct options *opt,
                             const struct trial_result *results, int nresults)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fprintf(f, "{\n");
    fprintf(f, "  \"seed\": %lu,\n", (unsigned long)opt->seed);
    fprintf(f, "  \"repeats\": %d,\n", opt->repeats);
    fprintf(f, "  \"duration_ms\": %d,\n", opt->duration_ms);
    fprintf(f, "  \"sample_period_ns\": %lu,\n", (unsigned long)opt->sample_period_ns);

    fprintf(f, "  \"candidates\": [\n");
    for (int i = 0; i < ncands; i++) {
        fprintf(f, "    {\"idx\": %d, \"name\": ", i);
        json_escape(f, cands[i].name);
        fprintf(f, ", \"path\": ");
        json_escape(f, cands[i].path);
        fprintf(f, ", \"fileline\": ");
        json_escape(f, cands[i].fileline);
        fprintf(f, ", \"runtime_lo\": %lu, \"runtime_hi\": %lu, \"obj_lo\": %lu, \"obj_hi\": %lu, \"samples\": %lu}%s\n",
                (unsigned long)cands[i].lo, (unsigned long)cands[i].hi,
                (unsigned long)cands[i].obj_lo, (unsigned long)cands[i].obj_hi,
                (unsigned long)cands[i].samples,
                i + 1 == ncands ? "" : ",");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"trials\": [\n");
    for (int i = 0; i < nresults; i++) {
        const struct trial_result *r = &results[i];
        fprintf(f, "    {\"trial\": %d, \"candidate_idx\": %d, \"speedup_pct\": %.3f, \"epoch\": %lu, \"progress_count\": %lu, \"elapsed_ms\": %.3f, \"effective_ms\": %.3f, \"target_hits\": %lu, \"rate_per_sec\": %.9f, \"latency\": {\"count\": %lu, \"mean_ms\": %.9f, \"p50_ms\": %.9f, \"p90_ms\": %.9f, \"p99_ms\": %.9f, \"max_ms\": %.9f}}%s\n",
                r->trial_no, r->candidate_idx,
                (double)r->speedup_ppm / 10000.0,
                (unsigned long)r->epoch,
                (unsigned long)r->progress_count,
                (double)r->elapsed_ns / 1e6,
                (double)r->effective_ns / 1e6,
                (unsigned long)r->target_hits,
                r->rate_per_sec,
                (unsigned long)r->latency.count,
                r->latency.count ? r->latency.mean_ns / 1e6 : 0.0,
                (double)latency_percentile_ns(&r->latency, 0.50) / 1e6,
                (double)latency_percentile_ns(&r->latency, 0.90) / 1e6,
                (double)latency_percentile_ns(&r->latency, 0.99) / 1e6,
                r->latency.count ? (double)r->latency.max_ns / 1e6 : 0.0,
                i + 1 == nresults ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    struct options opt;
    if (parse_args(argc, argv, &opt) != 0) {
        usage(argv[0]);
        return 2;
    }

    char shm_path[TRAWL_PATH_MAX];
    snprintf(shm_path, sizeof(shm_path), "/dev/shm/trawl-%ld-%d.shm", (long)getpid(), (int)time(NULL));
    struct trawl_shm *shm = create_shm(shm_path);
    if (!shm) {
        perror("create shared memory");
        return 1;
    }

    pid_t child = launch_target(&opt, shm_path);
    if (child < 0) {
        perror("launch target");
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }

    struct trawl_bpf *skel = trawl_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        kill(child, SIGKILL);
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }

    struct bpf_link **perf_links = NULL;
    int *perf_fds = NULL;
    int nperf = 0;
    if (attach_perf_events(skel, opt.sample_period_ns, &perf_links, &perf_fds, &nperf) != 0) {
        fprintf(stderr, "failed to attach perf_event BPF programs; check CAP_BPF/CAP_PERFMON or run as root\n");
        trawl_bpf__destroy(skel);
        kill(child, SIGKILL);
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }

    struct bpf_link *uprobe_links[5] = {0};
    if (attach_marker_uprobes(skel, opt.shim_path, child, uprobe_links, ARRAY_LEN(uprobe_links)) != 0) {
        fprintf(stderr, "failed to attach marker uprobes\n");
        destroy_perf_links(perf_links, perf_fds, nperf);
        trawl_bpf__destroy(skel);
        kill(child, SIGKILL);
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }

    struct delay_backend delay;
    if (delay_backend_init(&delay, opt.pause_backend, child, shm) != 0) {
        fprintf(stderr, "failed to initialize delay backend\n");
        for (size_t i = 0; i < ARRAY_LEN(uprobe_links); i++)
            if (uprobe_links[i]) bpf_link__destroy(uprobe_links[i]);
        destroy_perf_links(perf_links, perf_fds, nperf);
        trawl_bpf__destroy(skel);
        kill(child, SIGKILL);
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }

    struct run_state *state = calloc(1, sizeof(*state));
    if (!state) {
        fprintf(stderr, "failed to allocate run state\n");
        delay_backend_destroy(&delay);
        for (size_t i = 0; i < ARRAY_LEN(uprobe_links); i++)
            if (uprobe_links[i]) bpf_link__destroy(uprobe_links[i]);
        destroy_perf_links(perf_links, perf_fds, nperf);
        trawl_bpf__destroy(skel);
        kill(child, SIGKILL);
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }
    state->opt = &opt;
    state->shm = shm;
    state->delay = &delay;
    latency_tracker_reset(&state->latency, 0);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, state, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer reader\n");
        free(state);
        delay_backend_destroy(&delay);
        for (size_t i = 0; i < ARRAY_LEN(uprobe_links); i++)
            if (uprobe_links[i]) bpf_link__destroy(uprobe_links[i]);
        destroy_perf_links(perf_links, perf_fds, nperf);
        trawl_bpf__destroy(skel);
        kill(child, SIGKILL);
        munmap(shm, sizeof(*shm));
        unlink(shm_path);
        return 1;
    }

    int child_exited = 0;
    struct candidate *candidates = NULL;
    struct trial_result *results = NULL;

    kill(child, SIGCONT);

    struct trawl_config idle_cfg = {
        .target_tgid = (uint32_t)child,
        .active = 0,
        .epoch = 0,
        .target_lo = 0,
        .target_hi = 0,
        .speedup_ppm = 0,
        .progress_id = opt.progress_id,
        .sample_period_ns = opt.sample_period_ns,
        .capture_user_stack = (uint32_t)opt.capture_stacks,
        .emit_all_samples = 0,
        .emit_progress_events = 0,
        .latency_enabled = 0,
    };
    update_config(skel, &idle_cfg);

    if (opt.warmup_ms > 0)
        poll_controller(rb, child, opt.warmup_ms, &child_exited);
    if (child_exited)
        goto out;

    candidates = calloc(TRAWL_MAX_CANDIDATES * 8, sizeof(*candidates));
    if (!candidates)
        goto out_error;
    int ncandidates = 0;

    if (opt.auto_candidates) {
        if (run_discovery(skel, rb, &opt, child, candidates, &ncandidates, &child_exited) != 0)
            goto out_error;
        if (ncandidates > opt.top_candidates)
            ncandidates = opt.top_candidates;
    } else {
        if (resolve_manual_candidate(child, &opt, &candidates[0]) != 0)
            goto out_error;
        ncandidates = 1;
    }

    fprintf(stderr, "selected candidates:\n");
    for (int i = 0; i < ncandidates; i++) {
        fprintf(stderr, "  [%d] %s %s [%#lx,%#lx) samples=%lu line=%s\n",
                i, candidates[i].name, candidates[i].path,
                (unsigned long)candidates[i].lo,
                (unsigned long)candidates[i].hi,
                (unsigned long)candidates[i].samples,
                candidates[i].fileline);
    }

    if (opt.candidates_csv_path) {
        FILE *cf = fopen(opt.candidates_csv_path, "w");
        if (cf) {
            write_candidate_table(cf, candidates, ncandidates);
            fclose(cf);
        } else {
            fprintf(stderr, "warning: failed to write candidates CSV %s: %s\n",
                    opt.candidates_csv_path, strerror(errno));
        }
    }

    struct trial_spec plan[TRAWL_MAX_TRIALS];
    int nplan = build_trial_plan(&opt, ncandidates, plan, ARRAY_LEN(plan));
    if (nplan <= 0) {
        fprintf(stderr, "failed to build trial plan; reduce candidates/repeats/speedups\n");
        goto out_error;
    }

    results = calloc((size_t)nplan, sizeof(*results));
    if (!results)
        goto out_error;

    FILE *trial_out = stdout;
    if (opt.trials_csv_path) {
        trial_out = fopen(opt.trials_csv_path, "w");
        if (!trial_out) {
            fprintf(stderr, "failed to open %s: %s\n", opt.trials_csv_path, strerror(errno));
            goto out_error;
        }
    }

    fprintf(stderr, "running %d trials; seed=%lu pause_backend=%s latency=%s\n",
            nplan, (unsigned long)opt.seed,
            opt.pause_backend == PAUSE_PTRACE ? "ptrace" : "coop",
            opt.latency_enabled ? "on" : "off");

    write_trial_header(trial_out);
    int nresults = 0;
    for (int i = 0; i < nplan && !child_exited; i++) {
        const struct trial_spec *ts = &plan[i];
        const struct candidate *cand = &candidates[ts->candidate_idx];
        uint64_t epoch = (uint64_t)i + 1;
        if (run_trial(skel, rb, &opt, state, cand, ts->candidate_idx,
                      &results[nresults], i + 1, epoch, ts->speedup_ppm,
                      child, &child_exited) != 0 && child_exited) {
            break;
        }
        write_trial_row(trial_out, &results[nresults]);
        fflush(trial_out);
        nresults++;
    }

    if (trial_out != stdout)
        fclose(trial_out);

    fprintf(stdout, "\n");
    write_summary(stdout, candidates, ncandidates, &opt, results, nresults);
    fflush(stdout);

    if (opt.json_path) {
        if (write_json_report(opt.json_path, candidates, ncandidates, &opt, results, nresults) != 0)
            fprintf(stderr, "warning: failed to write JSON report %s: %s\n", opt.json_path, strerror(errno));
    }

    goto out;

out_error:
    child_exited = 1;
out:
    {
        struct trawl_config off = {0};
        update_config(skel, &off);
    }

    if (!opt.leave_running) {
        kill(child, SIGTERM);
        usleep(200000);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }

    ring_buffer__free(rb);
    free(results);
    free(candidates);
    free(state);
    delay_backend_destroy(&delay);
    for (size_t i = 0; i < ARRAY_LEN(uprobe_links); i++)
        if (uprobe_links[i]) bpf_link__destroy(uprobe_links[i]);
    destroy_perf_links(perf_links, perf_fds, nperf);
    trawl_bpf__destroy(skel);
    munmap(shm, sizeof(*shm));
    unlink(shm_path);

    return child_exited ? 1 : 0;
}
