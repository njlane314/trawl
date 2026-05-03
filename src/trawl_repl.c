#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define REPL_MAX_ARGS       512
#define REPL_MAX_LINE       4096
#define REPL_MAX_LOG        512
#define REPL_MAX_TRIALS     8192
#define REPL_MAX_SUMMARIES  512
#define REPL_MAX_FIELDS     64
#define REPL_MAX_CHECKS     16
#define REPL_NAME_MAX       256
#define REPL_PATH_MAX       4096

struct parsed_profile {
    const char *shim;
    const char *binary;
    const char *symbol;
    const char *range;
    const char *json;
    const char *trials_csv;
    const char *candidates_csv;
    const char *speedups;
    const char *backend;
    const char *seed;
    const char *program;
    int auto_candidates;
    int top_candidates;
    int progress_id;
    int latency;
    int repeats;
    int duration_ms;
    int warmup_ms;
    int cooldown_ms;
    int discover_ms;
    int speedup_count;
    int candidate_count_hint;
    int valid_mode_count;
};

struct repl_opts {
    const char *core_path;
    char *owned_core_path;
    int run_on_start;
    int pass_argc;
    char *pass_argv[REPL_MAX_ARGS];
    unsigned char pass_owned[REPL_MAX_ARGS];
    struct parsed_profile profile;
};

struct check_result {
    char name[48];
    char detail[192];
    int state; /* 0 ok, 1 warn, 2 fail */
};

struct trial_row {
    int trial_no;
    int candidate_idx;
    double speedup_pct;
    uint64_t progress_count;
    uint64_t target_hits;
    double virtual_delay_ms;
    double rate_per_sec;
    uint64_t lat_count;
    double lat_p50_ms;
    double lat_p90_ms;
    double lat_p99_ms;
    int timed_out;
};

struct summary_row {
    char type[64];
    int candidate_idx;
    char name[REPL_NAME_MAX];
    double speedup_pct;
    int n;
    double rate_mean;
    double rate_ci_low;
    double rate_ci_high;
    double impact_pct;
    double impact_ci_low;
    double impact_ci_high;
    double lat_sample_rate_mean;
    uint64_t lat_count;
    double lat_p50_ms;
    double lat_p90_ms;
    double lat_p99_ms;
};

struct pipe_state {
    int fd;
    char pending[REPL_MAX_LINE];
    size_t pending_len;
    const char *label;
};

struct repl_state {
    struct repl_opts opt;
    struct check_result checks[REPL_MAX_CHECKS];
    int check_count;

    struct trial_row trials[REPL_MAX_TRIALS];
    int trial_count;
    struct summary_row summaries[REPL_MAX_SUMMARIES];
    int summary_count;

    char log[REPL_MAX_LOG][REPL_MAX_LINE];
    int log_count;
    int log_head;

    int have_last_status;
    int last_status;
};

static volatile sig_atomic_t g_child_pid = -1;
static volatile sig_atomic_t g_interrupted;

static void on_sigint(int signo)
{
    (void)signo;
    g_interrupted = 1;
    if (g_child_pid > 0)
        kill((pid_t)g_child_pid, SIGTERM);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void trim_line(char *s)
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

static int has_slash(const char *s)
{
    return s && strchr(s, '/') != NULL;
}

static void path_dirname(const char *path, char *out, size_t out_len)
{
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out, out_len, ".");
        return;
    }
    size_t n = (size_t)(slash - path);
    if (n == 0)
        n = 1;
    if (n >= out_len)
        n = out_len - 1;
    memcpy(out, path, n);
    out[n] = 0;
}

static int is_exec_file(const char *path)
{
    return path && access(path, X_OK) == 0;
}

static int is_readable_file(const char *path)
{
    return path && access(path, R_OK) == 0;
}

static int read_small_file(const char *path, char *buf, size_t len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = 0;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        buf[--n] = 0;
    return 0;
}

static int find_in_path(const char *name, char *out, size_t out_len)
{
    const char *path = getenv("PATH");
    if (!path)
        path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    char *tmp = strdup(path);
    if (!tmp)
        return -1;
    char *save = NULL;
    for (char *dir = strtok_r(tmp, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        char cand[REPL_PATH_MAX];
        snprintf(cand, sizeof(cand), "%s/%s", *dir ? dir : ".", name);
        if (is_exec_file(cand)) {
            snprintf(out, out_len, "%s", cand);
            free(tmp);
            return 0;
        }
    }
    free(tmp);
    return -1;
}

static int parse_int_arg(const char *s, int fallback)
{
    if (!s)
        return fallback;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 0);
    if (errno || !end || *end || v < INT32_MIN || v > INT32_MAX)
        return fallback;
    return (int)v;
}

static int count_speedups_csv(const char *csv)
{
    if (!csv || !*csv)
        return 5;
    int n = 0;
    int has_zero = 0;
    char *tmp = strdup(csv);
    if (!tmp)
        return 5;
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (isspace((unsigned char)*tok))
            tok++;
        double v = strtod(tok, NULL);
        if (v == 0.0)
            has_zero = 1;
        n++;
    }
    free(tmp);
    if (n <= 0)
        n = 5;
    if (!has_zero)
        n++;
    return n;
}

static const char *arg_value(int argc, char **argv, int *i)
{
    if (*i + 1 >= argc)
        return NULL;
    (*i)++;
    return argv[*i];
}

static void parse_profile_args(int argc, char **argv, struct parsed_profile *p)
{
    memset(p, 0, sizeof(*p));
    p->progress_id = 1;
    p->repeats = 3;
    p->duration_ms = 5000;
    p->warmup_ms = 1000;
    p->cooldown_ms = 200;
    p->discover_ms = 3000;
    p->top_candidates = 1;
    p->backend = "coop";
    p->speedups = "0,10,25,50,75";

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            if (i + 1 < argc)
                p->program = argv[i + 1];
            break;
        } else if (strcmp(a, "--shim") == 0) {
            p->shim = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--binary") == 0) {
            p->binary = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--symbol") == 0) {
            p->symbol = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--range") == 0) {
            p->range = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--auto") == 0) {
            p->auto_candidates = 1;
        } else if (strcmp(a, "--top-candidates") == 0) {
            p->top_candidates = parse_int_arg(arg_value(argc, argv, &i), p->top_candidates);
            p->auto_candidates = 1;
        } else if (strcmp(a, "--progress-id") == 0) {
            p->progress_id = parse_int_arg(arg_value(argc, argv, &i), p->progress_id);
        } else if (strcmp(a, "--latency") == 0) {
            p->latency = 1;
        } else if (strcmp(a, "--latency-sample") == 0 ||
                   strcmp(a, "--latency-budget") == 0) {
            (void)arg_value(argc, argv, &i);
            p->latency = 1;
        } else if (strcmp(a, "--duration-ms") == 0) {
            p->duration_ms = parse_int_arg(arg_value(argc, argv, &i), p->duration_ms);
        } else if (strcmp(a, "--trial-timeout-ms") == 0) {
            (void)arg_value(argc, argv, &i);
        } else if (strcmp(a, "--warmup-ms") == 0) {
            p->warmup_ms = parse_int_arg(arg_value(argc, argv, &i), p->warmup_ms);
        } else if (strcmp(a, "--cooldown-ms") == 0) {
            p->cooldown_ms = parse_int_arg(arg_value(argc, argv, &i), p->cooldown_ms);
        } else if (strcmp(a, "--discover-ms") == 0) {
            p->discover_ms = parse_int_arg(arg_value(argc, argv, &i), p->discover_ms);
        } else if (strcmp(a, "--repeats") == 0) {
            p->repeats = parse_int_arg(arg_value(argc, argv, &i), p->repeats);
        } else if (strcmp(a, "--speedups") == 0) {
            p->speedups = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--seed") == 0) {
            p->seed = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--pause-backend") == 0) {
            p->backend = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--json") == 0) {
            p->json = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--trials-csv") == 0) {
            p->trials_csv = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--candidates-csv") == 0) {
            p->candidates_csv = arg_value(argc, argv, &i);
        } else if (strcmp(a, "--sample-ns") == 0) {
            (void)arg_value(argc, argv, &i);
        }
    }

    p->valid_mode_count = (p->symbol ? 1 : 0) + (p->range ? 1 : 0) + (p->auto_candidates ? 1 : 0);
    p->speedup_count = count_speedups_csv(p->speedups);
    p->candidate_count_hint = p->auto_candidates ? p->top_candidates : 1;
    if (p->candidate_count_hint <= 0)
        p->candidate_count_hint = 1;
}

static void usage(FILE *f, const char *argv0)
{
    fprintf(f,
        "usage:\n"
        "  trawl repl [repl-options] [trawl-options] -- PROGRAM [ARGS...]\n"
        "  %s [repl-options] [trawl-options] -- PROGRAM [ARGS...]\n\n"
        "repl options:\n"
        "  --trawl-core PATH       controller executable; default: sibling trawlctl or $TRAWL_CORE\n"
        "  --run                   run once before entering the prompt\n"
        "  --help                  show this help\n\n"
        "commands:\n"
        "  help                    show command help\n"
        "  show                    print current controller path, args, and last status\n"
        "  core PATH               set controller executable\n"
        "  args [ARGS...]          show or replace controller arguments\n"
        "  args --lines            print current arguments one per line\n"
        "  args: [ARGS...]         replace arguments from a pasted show line\n"
        "  wizard                  ask questions and build controller arguments\n"
        "  suggest                 explain what is missing and useful next commands\n"
        "  setup                   alias for wizard\n"
        "  set OPTION VALUE        change one controller option\n"
        "  unset OPTION            remove one controller option\n"
        "  programme [ARGS...]     show or replace the command after --\n"
        "  preflight               run environment and argument checks\n"
        "  run [ARGS...]           optionally replace args, then run the controller\n"
        "  results                 print parsed summary rows and recent trials\n"
        "  log [N]                 print the last N log lines; default: 20\n"
        "  clear                   clear parsed results and log\n"
        "  quit                    exit the REPL\n\n"
        "All controller arguments are passed through unchanged. This is a line-oriented\n"
        "interface: no raw terminal mode, alternate screen, cursor addressing, or key loop.\n",
        base_name(argv0));
}

static void clear_pass_args(struct repl_opts *opt)
{
    for (int i = 0; i < opt->pass_argc; i++) {
        if (opt->pass_owned[i])
            free(opt->pass_argv[i]);
        opt->pass_argv[i] = NULL;
        opt->pass_owned[i] = 0;
    }
    opt->pass_argc = 0;
}

static int append_pass_arg(struct repl_opts *opt, const char *s)
{
    if (opt->pass_argc >= REPL_MAX_ARGS - 1)
        return -1;
    char *dup = strdup(s);
    if (!dup)
        return -1;
    opt->pass_argv[opt->pass_argc] = dup;
    opt->pass_owned[opt->pass_argc] = 1;
    opt->pass_argc++;
    opt->pass_argv[opt->pass_argc] = NULL;
    return 0;
}

static int set_pass_args(struct repl_opts *opt, int argc, char **argv)
{
    clear_pass_args(opt);
    for (int i = 0; i < argc; i++) {
        if (append_pass_arg(opt, argv[i]) != 0) {
            fprintf(stderr, "trawl-repl: too many arguments or out of memory\n");
            return -1;
        }
    }
    parse_profile_args(opt->pass_argc, opt->pass_argv, &opt->profile);
    return 0;
}

static int set_core_path(struct repl_opts *opt, const char *path)
{
    char *dup = strdup(path);
    if (!dup)
        return -1;
    free(opt->owned_core_path);
    opt->owned_core_path = dup;
    opt->core_path = opt->owned_core_path;
    return 0;
}

static int parse_repl_opts(int argc, char **argv, struct repl_opts *opt)
{
    memset(opt, 0, sizeof(*opt));
    const char *env_core = getenv("TRAWL_CORE");
    if (env_core && *env_core) {
        if (set_core_path(opt, env_core) != 0)
            return -1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trawl-core") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "trawl-repl: --trawl-core requires a path\n");
                return -1;
            }
            if (set_core_path(opt, argv[++i]) != 0)
                return -1;
        } else if (strcmp(argv[i], "--run") == 0 || strcmp(argv[i], "--auto-start") == 0) {
            opt->run_on_start = 1;
        } else if (strcmp(argv[i], "--no-auto-start") == 0) {
            opt->run_on_start = 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            exit(0);
        } else {
            if (append_pass_arg(opt, argv[i]) != 0) {
                fprintf(stderr, "trawl-repl: too many arguments\n");
                return -1;
            }
        }
    }

    if (!opt->core_path) {
        char derived[REPL_PATH_MAX];
        if (has_slash(argv[0])) {
            char dir[REPL_PATH_MAX];
            path_dirname(argv[0], dir, sizeof(dir));
            size_t dn = strlen(dir);
            if (dn + sizeof("/trawlctl") <= sizeof(derived)) {
                memcpy(derived, dir, dn);
                memcpy(derived + dn, "/trawlctl", sizeof("/trawlctl"));
            } else {
                snprintf(derived, sizeof(derived), "trawlctl");
            }
        } else {
            snprintf(derived, sizeof(derived), "trawlctl");
        }
        if (set_core_path(opt, derived) != 0)
            return -1;
    }

    opt->pass_argv[opt->pass_argc] = NULL;
    parse_profile_args(opt->pass_argc, opt->pass_argv, &opt->profile);
    return 0;
}

static void free_repl_opts(struct repl_opts *opt)
{
    clear_pass_args(opt);
    free(opt->owned_core_path);
    opt->owned_core_path = NULL;
    opt->core_path = NULL;
}

static void add_log(struct repl_state *repl, const char *fmt, ...)
{
    char line[REPL_MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    int slot;
    if (repl->log_count < REPL_MAX_LOG) {
        slot = (repl->log_head + repl->log_count) % REPL_MAX_LOG;
        repl->log_count++;
    } else {
        slot = repl->log_head;
        repl->log_head = (repl->log_head + 1) % REPL_MAX_LOG;
    }
    snprintf(repl->log[slot], sizeof(repl->log[slot]), "%s", line);
}

static void add_check(struct repl_state *repl, const char *name, int state, const char *fmt, ...)
{
    if (repl->check_count >= REPL_MAX_CHECKS)
        return;
    struct check_result *c = &repl->checks[repl->check_count++];
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->state = state;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
    va_end(ap);
}

static void run_preflight(struct repl_state *repl)
{
    repl->check_count = 0;
    const struct parsed_profile *p = &repl->opt.profile;

    if (is_exec_file(repl->opt.core_path))
        add_check(repl, "controller", 0, "%s", repl->opt.core_path);
    else
        add_check(repl, "controller", 2, "not executable: %s", repl->opt.core_path);

    if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO))
        add_check(repl, "input", 0, "interactive tty");
    else
        add_check(repl, "input", 1, "non-tty; scripted REPL input/output is supported");

    if (is_readable_file("/sys/kernel/btf/vmlinux"))
        add_check(repl, "kernel BTF", 0, "/sys/kernel/btf/vmlinux");
    else
        add_check(repl, "kernel BTF", 1, "missing or unreadable; CO-RE attach may fail");

    char perf[64];
    if (read_small_file("/proc/sys/kernel/perf_event_paranoid", perf, sizeof(perf)) == 0) {
        int paranoid = parse_int_arg(perf, 99);
        if (paranoid <= 1 || geteuid() == 0)
            add_check(repl, "perf events", 0, "perf_event_paranoid=%d", paranoid);
        else
            add_check(repl, "perf events", 1, "perf_event_paranoid=%d; root/CAP_PERFMON likely needed", paranoid);
    } else {
        add_check(repl, "perf events", 1, "cannot read perf_event_paranoid");
    }

    if (geteuid() == 0)
        add_check(repl, "privilege", 0, "effective uid is root");
    else
        add_check(repl, "privilege", 1, "not root; CAP_BPF/CAP_PERFMON may still be sufficient");

    if (p->shim) {
        if (is_readable_file(p->shim))
            add_check(repl, "shim", 0, "%s", p->shim);
        else
            add_check(repl, "shim", 2, "not readable: %s", p->shim);
    } else {
        add_check(repl, "shim", 2, "--shim PATH is required by the controller");
    }

    if (p->valid_mode_count == 1)
        add_check(repl, "target mode", 0, "%s", p->auto_candidates ? "auto" : (p->symbol ? "symbol" : "range"));
    else
        add_check(repl, "target mode", 2, "choose exactly one of --symbol, --range, --auto");

    if (p->program)
        add_check(repl, "program", 0, "%s", p->program);
    else
        add_check(repl, "program", 2, "missing -- PROGRAM [ARGS...]");

    char found[REPL_PATH_MAX];
    if (find_in_path("addr2line", found, sizeof(found)) == 0)
        add_check(repl, "addr2line", 0, "%s", found);
    else
        add_check(repl, "addr2line", 1, "not found; source attribution may be degraded");
}

static int preflight_failed(const struct repl_state *repl)
{
    for (int i = 0; i < repl->check_count; i++)
        if (repl->checks[i].state == 2)
            return 1;
    return 0;
}

static void print_preflight(const struct repl_state *repl)
{
    for (int i = 0; i < repl->check_count; i++) {
        const struct check_result *c = &repl->checks[i];
        const char *state = c->state == 0 ? "ok" : (c->state == 1 ? "warn" : "fail");
        printf("%-12s %-4s %s\n", c->name, state, c->detail);
    }
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int split_csv_simple(char *line, char **fields, int max_fields)
{
    int n = 0;
    char *p = line;
    while (n < max_fields) {
        fields[n++] = p;
        char *comma = strchr(p, ',');
        if (!comma)
            break;
        *comma = 0;
        p = comma + 1;
    }
    return n;
}

static int token_is_integer(const char *s)
{
    if (!s || !*s)
        return 0;
    if (*s == '-' || *s == '+')
        s++;
    if (!*s)
        return 0;
    while (*s) {
        if (!isdigit((unsigned char)*s))
            return 0;
        s++;
    }
    return 1;
}

static double field_double(char **f, int n, int idx)
{
    if (idx >= n || !f[idx] || !*f[idx])
        return 0.0;
    return strtod(f[idx], NULL);
}

static uint64_t field_u64(char **f, int n, int idx)
{
    if (idx >= n || !f[idx] || !*f[idx])
        return 0;
    return strtoull(f[idx], NULL, 0);
}

static int field_int(char **f, int n, int idx)
{
    if (idx >= n || !f[idx] || !*f[idx])
        return 0;
    return (int)strtol(f[idx], NULL, 0);
}

static void parse_controller_line(struct repl_state *repl, const char *line_in)
{
    char line[REPL_MAX_LINE];
    snprintf(line, sizeof(line), "%s", line_in);
    trim_line(line);
    if (!*line)
        return;

    char copy[REPL_MAX_LINE];
    snprintf(copy, sizeof(copy), "%s", line);
    char *fields[REPL_MAX_FIELDS];
    int nf = split_csv_simple(copy, fields, REPL_MAX_FIELDS);
    if (nf <= 0)
        return;

    if (strcmp(fields[0], "trial") == 0 || strcmp(fields[0], "summary_type") == 0)
        return;

    if (nf >= 12 && token_is_integer(fields[0])) {
        if (repl->trial_count >= REPL_MAX_TRIALS)
            return;
        struct trial_row *r = &repl->trials[repl->trial_count++];
        memset(r, 0, sizeof(*r));
        r->trial_no = field_int(fields, nf, 0);
        r->candidate_idx = field_int(fields, nf, 1);
        r->speedup_pct = field_double(fields, nf, 2);
        r->progress_count = field_u64(fields, nf, 4);
        r->target_hits = field_u64(fields, nf, 9);
        r->virtual_delay_ms = field_double(fields, nf, 10);
        r->rate_per_sec = field_double(fields, nf, 11);
        r->lat_count = field_u64(fields, nf, 13);
        r->lat_p50_ms = field_double(fields, nf, 15);
        r->lat_p90_ms = field_double(fields, nf, 16);
        r->lat_p99_ms = field_double(fields, nf, 17);
        r->timed_out = field_int(fields, nf, 22);

        printf("trial %-3d cand=%d speedup=%g%% rate=%.3f/s progress=%" PRIu64
               " hits=%" PRIu64 " delay=%.3fms p50=%.3fms%s\n",
               r->trial_no, r->candidate_idx, r->speedup_pct, r->rate_per_sec,
               r->progress_count, r->target_hits, r->virtual_delay_ms, r->lat_p50_ms,
               r->timed_out ? " timed_out" : "");
        fflush(stdout);
        return;
    }

    if (nf >= 11) {
        if (repl->summary_count >= REPL_MAX_SUMMARIES)
            return;
        struct summary_row *s = &repl->summaries[repl->summary_count++];
        memset(s, 0, sizeof(*s));
        snprintf(s->type, sizeof(s->type), "%s", fields[0]);
        s->candidate_idx = field_int(fields, nf, 1);
        snprintf(s->name, sizeof(s->name), "%s", nf > 2 ? fields[2] : "");
        s->speedup_pct = field_double(fields, nf, 3);
        s->n = field_int(fields, nf, 4);
        s->rate_mean = field_double(fields, nf, 5);
        s->rate_ci_low = field_double(fields, nf, 6);
        s->rate_ci_high = field_double(fields, nf, 7);
        s->impact_pct = field_double(fields, nf, 8);
        s->impact_ci_low = field_double(fields, nf, 9);
        s->impact_ci_high = field_double(fields, nf, 10);
        s->lat_sample_rate_mean = field_double(fields, nf, 11);
        s->lat_count = field_u64(fields, nf, 12);
        s->lat_p50_ms = field_double(fields, nf, 14);
        s->lat_p90_ms = field_double(fields, nf, 15);
        s->lat_p99_ms = field_double(fields, nf, 16);

        printf("summary cand=%d %s speedup=%g%% n=%d rate=%.3f/s impact=%.2f%% [%.2f, %.2f]\n",
               s->candidate_idx, s->name, s->speedup_pct, s->n, s->rate_mean,
               s->impact_pct, s->impact_ci_low, s->impact_ci_high);
        fflush(stdout);
    }
}

static void emit_pipe_line(struct repl_state *repl, int is_stdout, const char *line)
{
    if (is_stdout) {
        add_log(repl, "stdout: %s", line);
        parse_controller_line(repl, line);
    } else {
        add_log(repl, "stderr: %s", line);
        fprintf(stderr, "controller: %s\n", line);
    }
}

static void flush_pending_line(struct repl_state *repl, struct pipe_state *p, int is_stdout)
{
    if (p->pending_len == 0)
        return;
    p->pending[p->pending_len] = 0;
    emit_pipe_line(repl, is_stdout, p->pending);
    p->pending_len = 0;
}

static int pump_pipe(struct repl_state *repl, struct pipe_state *p, int is_stdout)
{
    char buf[1024];
    for (;;) {
        ssize_t n = read(p->fd, buf, sizeof(buf));
        if (n > 0) {
            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n') {
                    p->pending[p->pending_len] = 0;
                    emit_pipe_line(repl, is_stdout, p->pending);
                    p->pending_len = 0;
                } else if (p->pending_len + 1 < sizeof(p->pending)) {
                    p->pending[p->pending_len++] = c;
                }
            }
        } else if (n == 0) {
            flush_pending_line(repl, p, is_stdout);
            close(p->fd);
            p->fd = -1;
            return 1;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else {
            add_log(repl, "%s read failed: %s", p->label, strerror(errno));
            close(p->fd);
            p->fd = -1;
            return 1;
        }
    }
}

static void reset_results(struct repl_state *repl)
{
    repl->trial_count = 0;
    repl->summary_count = 0;
}

static int run_controller(struct repl_state *repl)
{
    run_preflight(repl);
    print_preflight(repl);
    if (preflight_failed(repl)) {
        add_log(repl, "repl: preflight has blocking failures");
        puts("preflight has blocking failures; run 'suggest' or 'wizard' to finish setup");
        return -1;
    }

    reset_results(repl);
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        fprintf(stderr, "trawl-repl: pipe failed: %s\n", strerror(errno));
        if (out_pipe[0] >= 0) close(out_pipe[0]);
        if (out_pipe[1] >= 0) close(out_pipe[1]);
        if (err_pipe[0] >= 0) close(err_pipe[0]);
        if (err_pipe[1] >= 0) close(err_pipe[1]);
        return -1;
    }

    char **child_argv = calloc((size_t)repl->opt.pass_argc + 2, sizeof(char *));
    if (!child_argv) {
        fprintf(stderr, "trawl-repl: out of memory\n");
        close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    child_argv[0] = (char *)repl->opt.core_path;
    for (int i = 0; i < repl->opt.pass_argc; i++)
        child_argv[i + 1] = repl->opt.pass_argv[i];
    child_argv[repl->opt.pass_argc + 1] = NULL;

    uint64_t started = now_ns();
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "trawl-repl: fork failed: %s\n", strerror(errno));
        free(child_argv);
        close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        close(out_pipe[0]);
        close(err_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[1]);
        close(err_pipe[1]);
        if (has_slash(repl->opt.core_path))
            execv(repl->opt.core_path, child_argv);
        else
            execvp(repl->opt.core_path, child_argv);
        dprintf(STDERR_FILENO, "trawl-repl: exec %s failed: %s\n", repl->opt.core_path, strerror(errno));
        _exit(127);
    }

    free(child_argv);
    close(out_pipe[1]);
    close(err_pipe[1]);
    set_nonblock(out_pipe[0]);
    set_nonblock(err_pipe[0]);

    struct pipe_state out = {.fd = out_pipe[0], .label = "stdout"};
    struct pipe_state err = {.fd = err_pipe[0], .label = "stderr"};
    g_interrupted = 0;
    g_child_pid = pid;
    add_log(repl, "repl: started controller pid %d", pid);
    printf("started controller pid %d\n", pid);

    int child_status = 0;
    int child_done = 0;
    while (!child_done || out.fd >= 0 || err.fd >= 0) {
        if (g_interrupted && !child_done) {
            kill(pid, SIGTERM);
            add_log(repl, "repl: interrupted; sent SIGTERM to controller pid %d", pid);
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;
        if (out.fd >= 0) {
            FD_SET(out.fd, &rfds);
            if (out.fd > maxfd) maxfd = out.fd;
        }
        if (err.fd >= 0) {
            FD_SET(err.fd, &rfds);
            if (err.fd > maxfd) maxfd = err.fd;
        }
        struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
        int rc = maxfd >= 0 ? select(maxfd + 1, &rfds, NULL, NULL, &tv) : 0;
        if (rc > 0) {
            if (out.fd >= 0 && FD_ISSET(out.fd, &rfds))
                pump_pipe(repl, &out, 1);
            if (err.fd >= 0 && FD_ISSET(err.fd, &rfds))
                pump_pipe(repl, &err, 0);
        } else if (rc < 0 && errno != EINTR) {
            add_log(repl, "repl: select failed: %s", strerror(errno));
        }

        if (!child_done) {
            pid_t w = waitpid(pid, &child_status, WNOHANG);
            if (w == pid)
                child_done = 1;
            else if (w < 0 && errno != EINTR) {
                child_done = 1;
                child_status = 127 << 8;
            }
        }
    }
    if (!child_done)
        waitpid(pid, &child_status, 0);
    g_child_pid = -1;

    int status;
    if (WIFEXITED(child_status))
        status = WEXITSTATUS(child_status);
    else if (WIFSIGNALED(child_status))
        status = 128 + WTERMSIG(child_status);
    else
        status = 1;

    double elapsed = (double)(now_ns() - started) / 1000000000.0;
    repl->last_status = status;
    repl->have_last_status = 1;
    add_log(repl, "repl: controller exited with status %d after %.3fs", status, elapsed);
    printf("controller exited status=%d elapsed=%.3fs\n", status, elapsed);
    return status;
}

static void print_shell_quoted(const char *s)
{
    int simple = 1;
    if (!*s)
        simple = 0;
    for (const char *p = s; *p; p++) {
        if (!(isalnum((unsigned char)*p) || strchr("_+-./:=,", *p))) {
            simple = 0;
            break;
        }
    }
    if (simple) {
        fputs(s, stdout);
        return;
    }
    putchar('\'');
    for (const char *p = s; *p; p++) {
        if (*p == '\'')
            fputs("'\\''", stdout);
        else
            putchar(*p);
    }
    putchar('\'');
}

static int pass_program_index(const struct repl_opts *opt);
static int split_words(char *s, char **out, int max_words);

static void print_args(const struct repl_opts *opt)
{
    for (int i = 0; i < opt->pass_argc; i++) {
        if (i)
            putchar(' ');
        print_shell_quoted(opt->pass_argv[i]);
    }
    putchar('\n');
}

static void print_args_lines(const struct repl_opts *opt)
{
    int sep = pass_program_index(opt);
    puts("controller arguments:");
    for (int i = 0; i < opt->pass_argc; i++) {
        if (i == sep) {
            puts("  --");
            puts("programme:");
            continue;
        }
        printf("  [%02d] ", i);
        print_shell_quoted(opt->pass_argv[i]);
        putchar('\n');
    }
}

static int pass_program_index(const struct repl_opts *opt)
{
    for (int i = 0; i < opt->pass_argc; i++)
        if (strcmp(opt->pass_argv[i], "--") == 0)
            return i;
    return -1;
}

static int controller_option_takes_value(const char *opt)
{
    static const char *value_options[] = {
        "--shim",
        "--binary",
        "--symbol",
        "--range",
        "--top-candidates",
        "--progress-id",
        "--latency-sample",
        "--latency-budget",
        "--duration-ms",
        "--trial-timeout-ms",
        "--warmup-ms",
        "--cooldown-ms",
        "--discover-ms",
        "--repeats",
        "--speedups",
        "--seed",
        "--pause-backend",
        "--json",
        "--trials-csv",
        "--candidates-csv",
        "--sample-ns",
    };

    for (size_t i = 0; i < ARRAY_LEN(value_options); i++)
        if (strcmp(opt, value_options[i]) == 0)
            return 1;
    return 0;
}

static const char *canonical_controller_option(const char *key)
{
    struct alias {
        const char *key;
        const char *opt;
    };
    static const struct alias aliases[] = {
        {"shim", "--shim"},
        {"binary", "--binary"},
        {"symbol", "--symbol"},
        {"range", "--range"},
        {"auto", "--auto"},
        {"top", "--top-candidates"},
        {"top-candidates", "--top-candidates"},
        {"progress", "--progress-id"},
        {"progress-id", "--progress-id"},
        {"latency", "--latency"},
        {"latency-sample", "--latency-sample"},
        {"latency-budget", "--latency-budget"},
        {"duration", "--duration-ms"},
        {"duration-ms", "--duration-ms"},
        {"timeout", "--trial-timeout-ms"},
        {"trial-timeout", "--trial-timeout-ms"},
        {"trial-timeout-ms", "--trial-timeout-ms"},
        {"warmup", "--warmup-ms"},
        {"warmup-ms", "--warmup-ms"},
        {"cooldown", "--cooldown-ms"},
        {"cooldown-ms", "--cooldown-ms"},
        {"discover", "--discover-ms"},
        {"discover-ms", "--discover-ms"},
        {"repeats", "--repeats"},
        {"speedups", "--speedups"},
        {"seed", "--seed"},
        {"backend", "--pause-backend"},
        {"pause-backend", "--pause-backend"},
        {"json", "--json"},
        {"trials", "--trials-csv"},
        {"trials-csv", "--trials-csv"},
        {"candidates", "--candidates-csv"},
        {"candidates-csv", "--candidates-csv"},
        {"sample", "--sample-ns"},
        {"sample-ns", "--sample-ns"},
        {"emit-progress-events", "--emit-progress-events"},
    };

    if (strncmp(key, "--", 2) == 0)
        return key;
    for (size_t i = 0; i < ARRAY_LEN(aliases); i++)
        if (strcmp(key, aliases[i].key) == 0)
            return aliases[i].opt;
    return NULL;
}

static int truth_value(const char *s, int *out)
{
    if (strcmp(s, "1") == 0 || strcmp(s, "on") == 0 || strcmp(s, "true") == 0 ||
        strcmp(s, "yes") == 0 || strcmp(s, "enabled") == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(s, "0") == 0 || strcmp(s, "off") == 0 || strcmp(s, "false") == 0 ||
        strcmp(s, "no") == 0 || strcmp(s, "disabled") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int temp_arg_add(char **tmp, int *n, const char *s)
{
    if (*n >= REPL_MAX_ARGS - 1)
        return -1;
    tmp[*n] = strdup(s);
    if (!tmp[*n])
        return -1;
    (*n)++;
    tmp[*n] = NULL;
    return 0;
}

static void temp_args_free(char **tmp, int n)
{
    for (int i = 0; i < n; i++)
        free(tmp[i]);
}

static int option_in_list(const char *arg, const char **opts, int nopts)
{
    for (int i = 0; i < nopts; i++)
        if (strcmp(arg, opts[i]) == 0)
            return 1;
    return 0;
}

static int replace_controller_options(struct repl_opts *opt,
                                      const char **remove_opts, int remove_count,
                                      const char **add_args, int add_count)
{
    char *tmp[REPL_MAX_ARGS] = {0};
    int n = 0;
    int sep = pass_program_index(opt);
    int inserted = 0;

    for (int i = 0; i < opt->pass_argc; i++) {
        if (i == sep && !inserted) {
            for (int j = 0; j < add_count; j++)
                if (temp_arg_add(tmp, &n, add_args[j]) != 0)
                    goto oom;
            inserted = 1;
        }

        if ((sep < 0 || i < sep) && option_in_list(opt->pass_argv[i], remove_opts, remove_count)) {
            if (controller_option_takes_value(opt->pass_argv[i]) && i + 1 < opt->pass_argc &&
                (sep < 0 || i + 1 < sep))
                i++;
            continue;
        }

        if (temp_arg_add(tmp, &n, opt->pass_argv[i]) != 0)
            goto oom;
    }

    if (!inserted) {
        for (int j = 0; j < add_count; j++)
            if (temp_arg_add(tmp, &n, add_args[j]) != 0)
                goto oom;
    }

    int rc = set_pass_args(opt, n, tmp);
    temp_args_free(tmp, n);
    return rc;

oom:
    temp_args_free(tmp, n);
    fprintf(stderr, "trawl-repl: too many arguments or out of memory\n");
    return -1;
}

static int set_programme_args(struct repl_opts *opt, int argc, char **argv)
{
    char *tmp[REPL_MAX_ARGS] = {0};
    int n = 0;
    int sep = pass_program_index(opt);
    int limit = sep >= 0 ? sep : opt->pass_argc;

    for (int i = 0; i < limit; i++)
        if (temp_arg_add(tmp, &n, opt->pass_argv[i]) != 0)
            goto oom;

    if (argc > 0) {
        if (temp_arg_add(tmp, &n, "--") != 0)
            goto oom;
        for (int i = 0; i < argc; i++)
            if (temp_arg_add(tmp, &n, argv[i]) != 0)
                goto oom;
    }

    int rc = set_pass_args(opt, n, tmp);
    temp_args_free(tmp, n);
    return rc;

oom:
    temp_args_free(tmp, n);
    fprintf(stderr, "trawl-repl: too many arguments or out of memory\n");
    return -1;
}

static void print_programme_args(const struct repl_opts *opt)
{
    int sep = pass_program_index(opt);
    if (sep < 0 || sep + 1 >= opt->pass_argc) {
        puts("(none)");
        return;
    }

    for (int i = sep + 1; i < opt->pass_argc; i++) {
        if (i > sep + 1)
            putchar(' ');
        print_shell_quoted(opt->pass_argv[i]);
    }
    putchar('\n');
}

static int set_controller_arg(struct repl_opts *opt, int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "usage: set OPTION VALUE\n");
        return -1;
    }

    const char *key = argv[0];
    if (strcmp(key, "program") == 0 || strcmp(key, "programme") == 0)
        return set_programme_args(opt, argc - 1, &argv[1]);

    if (strcmp(key, "mode") == 0 || strcmp(key, "target") == 0) {
        if (argc < 2) {
            fprintf(stderr, "usage: set %s symbol NAME | range LO-HI | auto [N]\n", key);
            return -1;
        }
        key = argv[1];
        argv++;
        argc--;
    }

    const char *mode_opts[] = {"--symbol", "--range", "--auto", "--top-candidates"};
    if (strcmp(key, "symbol") == 0 || strcmp(key, "--symbol") == 0) {
        if (argc != 2) {
            fprintf(stderr, "usage: set symbol NAME\n");
            return -1;
        }
        const char *add[] = {"--symbol", argv[1]};
        return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), add, ARRAY_LEN(add));
    }

    if (strcmp(key, "range") == 0 || strcmp(key, "--range") == 0) {
        if (argc != 2) {
            fprintf(stderr, "usage: set range LO-HI\n");
            return -1;
        }
        const char *add[] = {"--range", argv[1]};
        return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), add, ARRAY_LEN(add));
    }

    if (strcmp(key, "auto") == 0 || strcmp(key, "--auto") == 0) {
        const char *add_auto[] = {"--auto"};
        if (argc == 1)
            return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), add_auto, ARRAY_LEN(add_auto));
        int enabled;
        if (truth_value(argv[1], &enabled) == 0) {
            if (!enabled)
                return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), NULL, 0);
            return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), add_auto, ARRAY_LEN(add_auto));
        }
        const char *add_top[] = {"--auto", "--top-candidates", argv[1]};
        return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), add_top, ARRAY_LEN(add_top));
    }

    const char *latency_opts[] = {"--latency", "--latency-sample", "--latency-budget"};
    if (strcmp(key, "latency") == 0 || strcmp(key, "--latency") == 0) {
        if (argc != 2) {
            fprintf(stderr, "usage: set latency on|off\n");
            return -1;
        }
        int enabled;
        if (truth_value(argv[1], &enabled) != 0) {
            fprintf(stderr, "set latency: expected on or off\n");
            return -1;
        }
        if (!enabled)
            return replace_controller_options(opt, latency_opts, ARRAY_LEN(latency_opts), NULL, 0);
        const char *add[] = {"--latency"};
        return replace_controller_options(opt, latency_opts, ARRAY_LEN(latency_opts), add, ARRAY_LEN(add));
    }

    if (strcmp(key, "latency-budget") == 0 || strcmp(key, "--latency-budget") == 0) {
        if (argc != 2) {
            fprintf(stderr, "usage: set latency-budget N\n");
            return -1;
        }
        const char *add[] = {"--latency-budget", argv[1]};
        return replace_controller_options(opt, latency_opts, ARRAY_LEN(latency_opts), add, ARRAY_LEN(add));
    }

    if (strcmp(key, "latency-sample") == 0 || strcmp(key, "--latency-sample") == 0) {
        if (argc != 2) {
            fprintf(stderr, "usage: set latency-sample N\n");
            return -1;
        }
        const char *add[] = {"--latency-sample", argv[1]};
        return replace_controller_options(opt, latency_opts, ARRAY_LEN(latency_opts), add, ARRAY_LEN(add));
    }

    const char *opt_name = canonical_controller_option(key);
    if (!opt_name) {
        fprintf(stderr, "unknown option: %s\n", key);
        return -1;
    }

    const char *remove[] = {opt_name};
    if (controller_option_takes_value(opt_name)) {
        if (argc != 2) {
            fprintf(stderr, "usage: set %s VALUE\n", key);
            return -1;
        }
        const char *add[] = {opt_name, argv[1]};
        return replace_controller_options(opt, remove, ARRAY_LEN(remove), add, ARRAY_LEN(add));
    }

    if (argc > 2) {
        fprintf(stderr, "usage: set %s [on|off]\n", key);
        return -1;
    }
    if (argc == 2) {
        int enabled;
        if (truth_value(argv[1], &enabled) != 0) {
            fprintf(stderr, "set %s: expected on or off\n", key);
            return -1;
        }
        if (!enabled)
            return replace_controller_options(opt, remove, ARRAY_LEN(remove), NULL, 0);
    }
    const char *add[] = {opt_name};
    return replace_controller_options(opt, remove, ARRAY_LEN(remove), add, ARRAY_LEN(add));
}

static int unset_controller_arg(struct repl_opts *opt, const char *key)
{
    if (strcmp(key, "program") == 0 || strcmp(key, "programme") == 0)
        return set_programme_args(opt, 0, NULL);

    const char *mode_opts[] = {"--symbol", "--range", "--auto", "--top-candidates"};
    if (strcmp(key, "mode") == 0 || strcmp(key, "target") == 0 ||
        strcmp(key, "symbol") == 0 || strcmp(key, "range") == 0 ||
        strcmp(key, "auto") == 0 || strcmp(key, "top") == 0 ||
        strcmp(key, "top-candidates") == 0)
        return replace_controller_options(opt, mode_opts, ARRAY_LEN(mode_opts), NULL, 0);

    const char *latency_opts[] = {"--latency", "--latency-sample", "--latency-budget"};
    if (strcmp(key, "latency") == 0)
        return replace_controller_options(opt, latency_opts, ARRAY_LEN(latency_opts), NULL, 0);

    const char *opt_name = canonical_controller_option(key);
    if (!opt_name) {
        fprintf(stderr, "unknown option: %s\n", key);
        return -1;
    }
    const char *remove[] = {opt_name};
    return replace_controller_options(opt, remove, ARRAY_LEN(remove), NULL, 0);
}

static const char *existing_path_or_default(const char *current, const char *fallback)
{
    if (current && *current)
        return current;
    return fallback;
}

static void prompt_default(const char *label, const char *def, char *out, size_t out_len)
{
    char def_copy[REPL_MAX_LINE];
    snprintf(def_copy, sizeof(def_copy), "%s", def ? def : "");

    printf("%s", label);
    if (*def_copy)
        printf(" [%s]", def_copy);
    printf(": ");
    fflush(stdout);

    if (!fgets(out, out_len, stdin)) {
        out[0] = 0;
        return;
    }
    trim_line(out);
    if (!*out)
        snprintf(out, out_len, "%s", def_copy);
}

static int prompt_yesno(const char *label, int def)
{
    char answer[32];
    for (;;) {
        printf("%s [%s]: ", label, def ? "yes" : "no");
        fflush(stdout);
        if (!fgets(answer, sizeof(answer), stdin))
            return def;
        trim_line(answer);
        if (!*answer)
            return def;
        int value;
        if (truth_value(answer, &value) == 0)
            return value;
        puts("Please answer yes or no.");
    }
}

static void first_programme_word(const struct repl_opts *opt, char *out, size_t out_len)
{
    int sep = pass_program_index(opt);
    if (sep >= 0 && sep + 1 < opt->pass_argc) {
        snprintf(out, out_len, "%s", opt->pass_argv[sep + 1]);
        return;
    }
    out[0] = 0;
}

static void default_binary_for_programme(const char *programme, char *out, size_t out_len)
{
    char work[REPL_MAX_LINE];
    char *argv[REPL_MAX_ARGS];
    snprintf(work, sizeof(work), "%s", programme ? programme : "");
    int argc = split_words(work, argv, REPL_MAX_ARGS);
    if (argc <= 0) {
        out[0] = 0;
        return;
    }
    if (has_slash(argv[0]) || is_exec_file(argv[0])) {
        snprintf(out, out_len, "%s", argv[0]);
        return;
    }
    char found[REPL_PATH_MAX];
    if (find_in_path(argv[0], found, sizeof(found)) == 0)
        snprintf(out, out_len, "%s", found);
    else
        snprintf(out, out_len, "%s", argv[0]);
}

static void print_suggestions(const struct repl_state *repl)
{
    const struct parsed_profile *p = &repl->opt.profile;

    puts("suggestions:");
    if (!p->shim) {
        if (is_readable_file("./build/libtrawl_shim.so"))
            puts("  set shim ./build/libtrawl_shim.so");
        else
            puts("  build first, then set shim ./build/libtrawl_shim.so");
    }
    if (!p->program) {
        if (is_exec_file("./examples/demo_server"))
            puts("  programme ./examples/demo_server");
        else
            puts("  programme ./path/to/your_server --flag value");
    }
    if (!p->binary) {
        if (p->program)
            puts("  set binary PATH_TO_THE_ELF_OR_SHARED_OBJECT_WITH_THE_TARGET_SYMBOL");
        else if (is_exec_file("./examples/demo_server"))
            puts("  set binary ./examples/demo_server");
    }
    if (p->valid_mode_count != 1) {
        if (is_exec_file("./examples/demo_server"))
            puts("  set symbol target_work");
        puts("  or: set mode auto 5");
    }
    if (!p->json)
        puts("  set json reports/repl.json");
    if (!p->trials_csv)
        puts("  set trials-csv reports/repl-trials.csv");
    if (!p->candidates_csv)
        puts("  set candidates-csv reports/repl-candidates.csv");

    puts("  wizard");
    puts("  preflight");
    puts("  run");
}

static int add_wizard_arg(char **tmp, int *n, const char *s)
{
    return temp_arg_add(tmp, n, s);
}

static int run_wizard(struct repl_state *repl)
{
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "wizard requires interactive input; use set, programme, or args: in scripts\n");
        return -1;
    }

    const struct parsed_profile *p = &repl->opt.profile;
    char shim[REPL_PATH_MAX];
    char programme[REPL_MAX_LINE];
    char binary[REPL_PATH_MAX];
    char mode[32];
    char target[REPL_PATH_MAX];
    char top_candidates[32];
    char progress_id[32];
    char duration_ms[32];
    char warmup_ms[32];
    char cooldown_ms[32];
    char repeats[32];
    char speedups[256];
    char latency_budget[32];
    char sample_ns[32];
    char report_prefix[REPL_PATH_MAX - 64];

    puts("Trawl setup wizard");
    puts("Press Enter to accept defaults. Use 'auto' target mode if you do not know the hot function yet.");

    const char *shim_default = existing_path_or_default(p->shim, "./build/libtrawl_shim.so");
    prompt_default("LD_PRELOAD shim", shim_default, shim, sizeof(shim));

    char current_programme[REPL_MAX_LINE];
    first_programme_word(&repl->opt, current_programme, sizeof(current_programme));
    if (!*current_programme && is_exec_file("./examples/demo_server"))
        snprintf(current_programme, sizeof(current_programme), "./examples/demo_server");
    prompt_default("Programme command", current_programme, programme, sizeof(programme));

    char binary_default[REPL_PATH_MAX];
    if (p->binary && *p->binary)
        snprintf(binary_default, sizeof(binary_default), "%s", p->binary);
    else
        default_binary_for_programme(programme, binary_default, sizeof(binary_default));
    if (!*binary_default && is_exec_file("./examples/demo_server"))
        snprintf(binary_default, sizeof(binary_default), "./examples/demo_server");
    prompt_default("Binary or shared object to profile", binary_default, binary, sizeof(binary));

    const char *mode_default = p->auto_candidates ? "auto" : (p->range ? "range" : "symbol");
    if (!p->auto_candidates && !p->range && !p->symbol && strcmp(binary, "./examples/demo_server") != 0)
        mode_default = "auto";
    prompt_default("Target mode: symbol, range, or auto", mode_default, mode, sizeof(mode));
    for (char *c = mode; *c; c++)
        *c = (char)tolower((unsigned char)*c);

    target[0] = 0;
    if (strcmp(mode, "symbol") == 0) {
        const char *symbol_default = p->symbol ? p->symbol :
            (strcmp(binary, "./examples/demo_server") == 0 ? "target_work" : "");
        prompt_default("Symbol name", symbol_default, target, sizeof(target));
    } else if (strcmp(mode, "range") == 0) {
        prompt_default("Runtime address range LO-HI", p->range ? p->range : "", target, sizeof(target));
    } else if (strcmp(mode, "auto") != 0) {
        fprintf(stderr, "wizard: unknown target mode '%s'\n", mode);
        return -1;
    } else {
        snprintf(top_candidates, sizeof(top_candidates), "%d", p->top_candidates > 1 ? p->top_candidates : 5);
        prompt_default("Auto candidates", top_candidates, top_candidates, sizeof(top_candidates));
    }

    snprintf(progress_id, sizeof(progress_id), "%d", p->progress_id ? p->progress_id : 1);
    prompt_default("Progress id", progress_id, progress_id, sizeof(progress_id));

    snprintf(duration_ms, sizeof(duration_ms), "%d", p->duration_ms ? p->duration_ms : 3000);
    prompt_default("Trial duration ms", duration_ms, duration_ms, sizeof(duration_ms));

    snprintf(warmup_ms, sizeof(warmup_ms), "%d", p->warmup_ms);
    prompt_default("Warmup ms", warmup_ms, warmup_ms, sizeof(warmup_ms));

    snprintf(cooldown_ms, sizeof(cooldown_ms), "%d", p->cooldown_ms);
    prompt_default("Cooldown ms", cooldown_ms, cooldown_ms, sizeof(cooldown_ms));

    snprintf(repeats, sizeof(repeats), "%d", p->repeats ? p->repeats : 3);
    prompt_default("Repeats", repeats, repeats, sizeof(repeats));

    prompt_default("Speedups", p->speedups ? p->speedups : "0,10,25", speedups, sizeof(speedups));

    int latency = prompt_yesno("Track sampled latency", p->latency || repl->opt.pass_argc == 0);
    if (latency)
        prompt_default("Latency sample budget per second", "5000", latency_budget, sizeof(latency_budget));
    else
        latency_budget[0] = 0;

    prompt_default("CPU sample period ns", "1000000", sample_ns, sizeof(sample_ns));
    prompt_default("Report prefix", "reports/repl", report_prefix, sizeof(report_prefix));

    char json[REPL_PATH_MAX];
    char trials_csv[REPL_PATH_MAX];
    char candidates_csv[REPL_PATH_MAX];
    snprintf(json, sizeof(json), "%s.json", report_prefix);
    snprintf(trials_csv, sizeof(trials_csv), "%s-trials.csv", report_prefix);
    snprintf(candidates_csv, sizeof(candidates_csv), "%s-candidates.csv", report_prefix);

    char *programme_tmp = strdup(programme);
    if (!programme_tmp) {
        fprintf(stderr, "wizard: out of memory\n");
        return -1;
    }
    char *programme_argv[REPL_MAX_ARGS];
    int programme_argc = split_words(programme_tmp, programme_argv, REPL_MAX_ARGS);
    if (programme_argc <= 0) {
        free(programme_tmp);
        fprintf(stderr, "wizard: programme command is required\n");
        return -1;
    }

    char *tmp[REPL_MAX_ARGS] = {0};
    int n = 0;
    if (add_wizard_arg(tmp, &n, "--shim") != 0 ||
        add_wizard_arg(tmp, &n, shim) != 0 ||
        add_wizard_arg(tmp, &n, "--binary") != 0 ||
        add_wizard_arg(tmp, &n, binary) != 0)
        goto oom;

    if (strcmp(mode, "symbol") == 0) {
        if (!*target) {
            fprintf(stderr, "wizard: symbol target is required\n");
            goto fail;
        }
        if (add_wizard_arg(tmp, &n, "--symbol") != 0 ||
            add_wizard_arg(tmp, &n, target) != 0)
            goto oom;
    } else if (strcmp(mode, "range") == 0) {
        if (!*target) {
            fprintf(stderr, "wizard: range target is required\n");
            goto fail;
        }
        if (add_wizard_arg(tmp, &n, "--range") != 0 ||
            add_wizard_arg(tmp, &n, target) != 0)
            goto oom;
    } else {
        if (add_wizard_arg(tmp, &n, "--auto") != 0 ||
            add_wizard_arg(tmp, &n, "--top-candidates") != 0 ||
            add_wizard_arg(tmp, &n, top_candidates) != 0)
            goto oom;
    }

    const char *fixed_args[] = {
        "--progress-id", progress_id,
        "--duration-ms", duration_ms,
        "--warmup-ms", warmup_ms,
        "--cooldown-ms", cooldown_ms,
        "--repeats", repeats,
        "--speedups", speedups,
        "--sample-ns", sample_ns,
        "--json", json,
        "--trials-csv", trials_csv,
        "--candidates-csv", candidates_csv,
    };
    for (size_t i = 0; i < ARRAY_LEN(fixed_args); i++)
        if (add_wizard_arg(tmp, &n, fixed_args[i]) != 0)
            goto oom;

    if (latency && (add_wizard_arg(tmp, &n, "--latency-budget") != 0 ||
                    add_wizard_arg(tmp, &n, latency_budget) != 0))
        goto oom;

    if (add_wizard_arg(tmp, &n, "--") != 0)
        goto oom;
    for (int i = 0; i < programme_argc; i++)
        if (add_wizard_arg(tmp, &n, programme_argv[i]) != 0)
            goto oom;

    int rc = set_pass_args(&repl->opt, n, tmp);
    temp_args_free(tmp, n);
    free(programme_tmp);
    if (rc == 0) {
        puts("Configured controller arguments:");
        print_args_lines(&repl->opt);
        puts("Next: run 'preflight', then 'run'.");
    }
    return rc;

oom:
    fprintf(stderr, "wizard: too many arguments or out of memory\n");
fail:
    temp_args_free(tmp, n);
    free(programme_tmp);
    return -1;
}

static void print_welcome(const struct repl_state *repl)
{
    puts("Trawl REPL");
    if (repl->opt.pass_argc == 0) {
        puts("No profiling target is configured yet.");
        puts("Start with 'wizard', or use 'suggest' for manual setup commands.");
    } else {
        puts("Type 'show' to inspect the current run, 'set' to change one option, or 'run'.");
    }
}

static void print_show(const struct repl_state *repl)
{
    const struct parsed_profile *p = &repl->opt.profile;
    printf("controller: %s\n", repl->opt.core_path);
    printf("args: ");
    print_args(&repl->opt);
    printf("mode: %s\n", p->auto_candidates ? "auto" : (p->symbol ? "symbol" : (p->range ? "range" : "unset")));
    if (p->symbol)
        printf("symbol: %s\n", p->symbol);
    if (p->range)
        printf("range: %s\n", p->range);
    printf("progress-id: %d repeats: %d duration-ms: %d speedups: %s backend: %s latency: %s\n",
           p->progress_id, p->repeats, p->duration_ms, p->speedups ? p->speedups : "",
           p->backend ? p->backend : "", p->latency ? "on" : "off");
    if (repl->have_last_status)
        printf("last-status: %d\n", repl->last_status);
    else
        printf("last-status: none\n");
}

static void print_results(const struct repl_state *repl)
{
    printf("summaries: %d\n", repl->summary_count);
    for (int i = 0; i < repl->summary_count; i++) {
        const struct summary_row *s = &repl->summaries[i];
        printf("  cand=%d %-24s speedup=%g%% n=%d rate=%.3f/s ci=[%.3f, %.3f] impact=%.2f%% ci=[%.2f, %.2f] p50=%.3f p90=%.3f p99=%.3f\n",
               s->candidate_idx, s->name, s->speedup_pct, s->n, s->rate_mean,
               s->rate_ci_low, s->rate_ci_high, s->impact_pct, s->impact_ci_low,
               s->impact_ci_high, s->lat_p50_ms, s->lat_p90_ms, s->lat_p99_ms);
    }

    int start = repl->trial_count > 10 ? repl->trial_count - 10 : 0;
    printf("recent trials: %d%s\n", repl->trial_count, start ? " (last 10)" : "");
    for (int i = start; i < repl->trial_count; i++) {
        const struct trial_row *r = &repl->trials[i];
        printf("  trial=%d cand=%d speedup=%g%% rate=%.3f/s progress=%" PRIu64
               " hits=%" PRIu64 " delay=%.3fms p50=%.3f p90=%.3f p99=%.3f%s\n",
               r->trial_no, r->candidate_idx, r->speedup_pct, r->rate_per_sec,
               r->progress_count, r->target_hits, r->virtual_delay_ms,
               r->lat_p50_ms, r->lat_p90_ms, r->lat_p99_ms,
               r->timed_out ? " timed_out" : "");
    }
}

static void print_log(const struct repl_state *repl, int limit)
{
    if (limit <= 0 || limit > repl->log_count)
        limit = repl->log_count;
    int start = repl->log_count - limit;
    for (int i = start; i < repl->log_count; i++) {
        int slot = (repl->log_head + i) % REPL_MAX_LOG;
        puts(repl->log[slot]);
    }
}

static void clear_repl_state(struct repl_state *repl)
{
    repl->trial_count = 0;
    repl->summary_count = 0;
    repl->log_count = 0;
    repl->log_head = 0;
    repl->have_last_status = 0;
    repl->last_status = 0;
}

static int split_words(char *s, char **out, int max_words)
{
    int n = 0;
    char *p = s;
    while (*p) {
        while (isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;
        if (n >= max_words)
            return -1;
        out[n++] = p;
        char *dst = p;
        int quote = 0;
        while (*p) {
            unsigned char c = (unsigned char)*p++;
            if (quote) {
                if (c == (unsigned char)quote) {
                    quote = 0;
                    continue;
                }
                if (c == '\\' && quote == '"' && *p)
                    c = (unsigned char)*p++;
                *dst++ = (char)c;
            } else {
                if (c == '\'' || c == '"') {
                    quote = (int)c;
                    continue;
                }
                if (isspace(c))
                    break;
                if (c == '\\' && *p)
                    c = (unsigned char)*p++;
                *dst++ = (char)c;
            }
        }
        *dst = 0;
        if (quote)
            return -2;
    }
    return n;
}

static void print_command_help(void)
{
    puts("commands:");
    puts("  help                    show this help");
    puts("  show                    print controller path, current args, and last status");
    puts("  core PATH               set the controller executable");
    puts("  args [ARGS...]          show or replace the controller argument vector");
    puts("  args --lines            print current arguments one per line");
    puts("  args: [ARGS...]         replace arguments from a pasted show line");
    puts("  wizard                  ask questions and build controller arguments");
    puts("  setup                   alias for wizard");
    puts("  suggest                 explain what is missing and useful next commands");
    puts("  set OPTION VALUE        change one controller option");
    puts("                          examples: set duration-ms 5000, set speedups 0,5,10");
    puts("                          set symbol target_work, set latency-budget 3000");
    puts("  unset OPTION            remove an option; examples: unset latency, unset target");
    puts("  programme [ARGS...]     show or replace the command after --");
    puts("  program [ARGS...]       alias for programme");
    puts("  preflight               run checks without starting the controller");
    puts("  run [ARGS...]           optionally replace args, then run the controller");
    puts("  results                 print parsed summaries and recent trials");
    puts("  log [N]                 print recent controller/repl log lines");
    puts("  clear                   clear parsed results and logs");
    puts("  quit                    exit");
}

static int repl_loop(struct repl_state *repl)
{
    char line[REPL_MAX_LINE];
    char work[REPL_MAX_LINE];
    char *argv[REPL_MAX_ARGS];
    int interactive = isatty(STDIN_FILENO);

    if (interactive)
        print_welcome(repl);

    while (1) {
        if (interactive) {
            fputs("trawl> ", stdout);
            fflush(stdout);
        }
        errno = 0;
        if (!fgets(line, sizeof(line), stdin)) {
            if (interactive)
                putchar('\n');
            break;
        }
        trim_line(line);
        snprintf(work, sizeof(work), "%s", line);
        int argc = split_words(work, argv, REPL_MAX_ARGS);
        if (argc == 0)
            continue;
        if (argc < 0) {
            fprintf(stderr, "parse error: %s\n", argc == -2 ? "unterminated quote" : "too many words");
            continue;
        }

        const char *cmd = argv[0];
        if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
            print_command_help();
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) {
            break;
        } else if (strcmp(cmd, "show") == 0 || strcmp(cmd, "status") == 0) {
            print_show(repl);
        } else if (strcmp(cmd, "core") == 0) {
            if (argc != 2) {
                fprintf(stderr, "usage: core PATH\n");
                continue;
            }
            if (set_core_path(&repl->opt, argv[1]) != 0)
                fprintf(stderr, "core: out of memory\n");
        } else if (strcmp(cmd, "args") == 0 || strcmp(cmd, "args:") == 0) {
            if (argc == 1)
                print_args(&repl->opt);
            else if (strcmp(argv[1], "--lines") == 0 || strcmp(argv[1], "-l") == 0)
                print_args_lines(&repl->opt);
            else
                (void)set_pass_args(&repl->opt, argc - 1, &argv[1]);
        } else if (strcmp(cmd, "wizard") == 0 || strcmp(cmd, "setup") == 0) {
            (void)run_wizard(repl);
        } else if (strcmp(cmd, "suggest") == 0 || strcmp(cmd, "suggestions") == 0) {
            print_suggestions(repl);
        } else if (strcmp(cmd, "set") == 0) {
            (void)set_controller_arg(&repl->opt, argc - 1, &argv[1]);
        } else if (strcmp(cmd, "unset") == 0) {
            if (argc != 2) {
                fprintf(stderr, "usage: unset OPTION\n");
                continue;
            }
            (void)unset_controller_arg(&repl->opt, argv[1]);
        } else if (strcmp(cmd, "programme") == 0 || strcmp(cmd, "program") == 0) {
            if (argc == 1)
                print_programme_args(&repl->opt);
            else
                (void)set_programme_args(&repl->opt, argc - 1, &argv[1]);
        } else if (strcmp(cmd, "preflight") == 0 || strcmp(cmd, "check") == 0) {
            run_preflight(repl);
            print_preflight(repl);
        } else if (strcmp(cmd, "run") == 0 || strcmp(cmd, "r") == 0) {
            if (argc > 1 && set_pass_args(&repl->opt, argc - 1, &argv[1]) != 0)
                continue;
            (void)run_controller(repl);
        } else if (strcmp(cmd, "results") == 0 || strcmp(cmd, "summary") == 0) {
            print_results(repl);
        } else if (strcmp(cmd, "log") == 0) {
            int n = argc > 1 ? parse_int_arg(argv[1], 20) : 20;
            print_log(repl, n);
        } else if (strcmp(cmd, "clear") == 0) {
            clear_repl_state(repl);
        } else {
            fprintf(stderr, "unknown command: %s\n", cmd);
        }
    }
    return repl->have_last_status ? repl->last_status : 0;
}

int main(int argc, char **argv)
{
    struct repl_state repl;
    memset(&repl, 0, sizeof(repl));

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    if (parse_repl_opts(argc, argv, &repl.opt) != 0) {
        usage(stderr, argv[0]);
        return 2;
    }

    if (repl.opt.run_on_start)
        (void)run_controller(&repl);

    int rc = repl_loop(&repl);
    free_repl_opts(&repl.opt);
    return rc;
}
