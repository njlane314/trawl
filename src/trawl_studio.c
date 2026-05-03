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
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define STUDIO_MAX_ARGS       512
#define STUDIO_MAX_LINE       4096
#define STUDIO_MAX_LOG        512
#define STUDIO_MAX_TRIALS     8192
#define STUDIO_MAX_SUMMARIES  512
#define STUDIO_MAX_FIELDS     64
#define STUDIO_MAX_CHECKS     16
#define STUDIO_NAME_MAX       256
#define STUDIO_PATH_MAX       4096

struct strbuf {
    char *p;
    size_t len;
    size_t cap;
};

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

struct studio_opts {
    const char *core_path;
    int auto_start;
    int pass_argc;
    char *pass_argv[STUDIO_MAX_ARGS];
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
};

struct summary_row {
    char type[64];
    int candidate_idx;
    char name[STUDIO_NAME_MAX];
    double speedup_pct;
    int n;
    double rate_mean;
    double rate_ci_low;
    double rate_ci_high;
    double impact_pct;
    double impact_ci_low;
    double impact_ci_high;
    uint64_t lat_count;
    double lat_p50_ms;
    double lat_p90_ms;
    double lat_p99_ms;
};

struct pipe_state {
    int fd;
    char pending[STUDIO_MAX_LINE];
    size_t pending_len;
};

struct app_state {
    struct studio_opts opt;
    struct check_result checks[STUDIO_MAX_CHECKS];
    int check_count;

    pid_t child;
    int child_status;
    int running;
    int exit_known;
    uint64_t started_ns;
    uint64_t ended_ns;
    struct pipe_state out;
    struct pipe_state err;

    struct trial_row trials[STUDIO_MAX_TRIALS];
    int trial_count;
    struct summary_row summaries[STUDIO_MAX_SUMMARIES];
    int summary_count;

    char log[STUDIO_MAX_LOG][STUDIO_MAX_LINE];
    int log_count;
    int log_head;
    int show_log;
    int should_quit;
};

static struct termios saved_termios;
static int termios_saved;
static int terminal_active;
static int stdin_flags_saved;
static int saved_stdin_flags;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sb_init(struct strbuf *b)
{
    b->cap = 65536;
    b->p = malloc(b->cap);
    if (!b->p) {
        b->cap = 0;
        b->len = 0;
        return;
    }
    b->p[0] = 0;
    b->len = 0;
}

static void sb_free(struct strbuf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

static void sb_reserve(struct strbuf *b, size_t more)
{
    if (!b->p)
        return;
    if (b->len + more + 1 <= b->cap)
        return;
    size_t cap = b->cap;
    while (b->len + more + 1 > cap)
        cap *= 2;
    char *p = realloc(b->p, cap);
    if (!p)
        return;
    b->p = p;
    b->cap = cap;
}

static void sb_append(struct strbuf *b, const char *s)
{
    size_t n = strlen(s);
    sb_reserve(b, n);
    if (!b->p || b->len + n + 1 > b->cap)
        return;
    memcpy(b->p + b->len, s, n + 1);
    b->len += n;
}

static void sb_appendn(struct strbuf *b, const char *s, size_t n)
{
    sb_reserve(b, n);
    if (!b->p || b->len + n + 1 > b->cap)
        return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void sb_printf(struct strbuf *b, const char *fmt, ...)
{
    char stack[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n < sizeof(stack)) {
        sb_appendn(b, stack, (size_t)n);
        return;
    }
    char *heap = malloc((size_t)n + 1);
    if (!heap)
        return;
    va_start(ap, fmt);
    vsnprintf(heap, (size_t)n + 1, fmt, ap);
    va_end(ap);
    sb_appendn(b, heap, (size_t)n);
    free(heap);
}

static void cleanup_terminal(void)
{
    if (terminal_active) {
        const char *seq = "\033[0m\033[?25h\033[?1049l";
        write(STDOUT_FILENO, seq, strlen(seq));
        terminal_active = 0;
    }
    if (termios_saved)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    if (stdin_flags_saved)
        fcntl(STDIN_FILENO, F_SETFL, saved_stdin_flags);
}

static int setup_terminal(void)
{
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
        return -1;

    if (tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
        termios_saved = 1;
        struct termios raw = saved_termios;
        raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
            return -1;
    }

    saved_stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (saved_stdin_flags >= 0) {
        stdin_flags_saved = 1;
        fcntl(STDIN_FILENO, F_SETFL, saved_stdin_flags | O_NONBLOCK);
    }

    const char *seq = "\033[?1049h\033[?25l\033[2J";
    write(STDOUT_FILENO, seq, strlen(seq));
    terminal_active = 1;
    atexit(cleanup_terminal);
    return 0;
}

static void get_terminal_size(int *rows, int *cols)
{
    struct winsize ws;
    *rows = 24;
    *cols = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_row > 0)
            *rows = ws.ws_row;
        if (ws.ws_col > 0)
            *cols = ws.ws_col;
    }
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

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int has_slash(const char *s)
{
    return s && strchr(s, '/') != NULL;
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
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '\t'))
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
        char cand[STUDIO_PATH_MAX];
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
        } else if (strcmp(a, "--latency-sample") == 0 || strcmp(a, "--latency-budget") == 0) {
            (void)arg_value(argc, argv, &i);
            p->latency = 1;
        } else if (strcmp(a, "--duration-ms") == 0) {
            p->duration_ms = parse_int_arg(arg_value(argc, argv, &i), p->duration_ms);
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
    (void)argv0;
    fprintf(f,
        "usage:\n"
        "  trawl studio [studio-options] --shim PATH (--symbol FUNC | --range LO-HI | --auto) [trawl-options] -- PROGRAM [ARGS...]\n"
        "  trawl-studio [studio-options] --shim PATH (--symbol FUNC | --range LO-HI | --auto) [trawl-options] -- PROGRAM [ARGS...]\n\n"
        "studio options:\n"
        "  --trawl-core PATH       controller executable; default: sibling trawlctl or $TRAWL_CORE\n"
        "  --no-auto-start         open the cockpit but wait for 'r' before running\n"
        "  --help                  show this help\n\n"
        "keys:\n"
        "  r                       run or rerun the current experiment\n"
        "  l                       toggle log view\n"
        "  k                       terminate the running controller\n"
        "  q                       quit; terminates the controller if it is still running\n\n"
        "All non-studio options are passed through to the existing trawl controller.\n");
}

static int parse_studio_opts(int argc, char **argv, struct studio_opts *opt)
{
    memset(opt, 0, sizeof(*opt));
    opt->auto_start = 1;

    const char *env_core = getenv("TRAWL_CORE");
    if (env_core && *env_core)
        opt->core_path = env_core;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trawl-core") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "trawl-studio: --trawl-core requires a path\n");
                return -1;
            }
            opt->core_path = argv[++i];
        } else if (strcmp(argv[i], "--no-auto-start") == 0) {
            opt->auto_start = 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(stdout, base_name(argv[0]));
            exit(0);
        } else {
            if (opt->pass_argc >= STUDIO_MAX_ARGS - 1) {
                fprintf(stderr, "trawl-studio: too many arguments\n");
                return -1;
            }
            opt->pass_argv[opt->pass_argc++] = argv[i];
        }
    }

    if (!opt->core_path) {
        static char derived[STUDIO_PATH_MAX];
        if (has_slash(argv[0])) {
            char dir[STUDIO_PATH_MAX];
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
        opt->core_path = derived;
    }

    opt->pass_argv[opt->pass_argc] = NULL;
    parse_profile_args(opt->pass_argc, opt->pass_argv, &opt->profile);
    return 0;
}

static void add_log(struct app_state *app, const char *fmt, ...)
{
    char line[STUDIO_MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    int slot;
    if (app->log_count < STUDIO_MAX_LOG) {
        slot = (app->log_head + app->log_count) % STUDIO_MAX_LOG;
        app->log_count++;
    } else {
        slot = app->log_head;
        app->log_head = (app->log_head + 1) % STUDIO_MAX_LOG;
    }
    snprintf(app->log[slot], sizeof(app->log[slot]), "%s", line);
}

static void add_check(struct app_state *app, const char *name, int state, const char *fmt, ...)
{
    if (app->check_count >= STUDIO_MAX_CHECKS)
        return;
    struct check_result *c = &app->checks[app->check_count++];
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->state = state;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
    va_end(ap);
}

static void run_preflight(struct app_state *app)
{
    app->check_count = 0;
    const struct parsed_profile *p = &app->opt.profile;

    if (is_exec_file(app->opt.core_path))
        add_check(app, "controller", 0, "%s", app->opt.core_path);
    else
        add_check(app, "controller", 2, "not executable: %s", app->opt.core_path);

    if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO))
        add_check(app, "terminal", 0, "%s", getenv("TERM") ? getenv("TERM") : "tty");
    else
        add_check(app, "terminal", 2, "stdin/stdout must be a tty");

    if (is_readable_file("/sys/kernel/btf/vmlinux"))
        add_check(app, "kernel BTF", 0, "/sys/kernel/btf/vmlinux");
    else
        add_check(app, "kernel BTF", 1, "missing or unreadable; CO-RE attach may fail");

    char perf[64];
    if (read_small_file("/proc/sys/kernel/perf_event_paranoid", perf, sizeof(perf)) == 0) {
        int paranoid = parse_int_arg(perf, 99);
        if (paranoid <= 1 || geteuid() == 0)
            add_check(app, "perf events", 0, "perf_event_paranoid=%d", paranoid);
        else
            add_check(app, "perf events", 1, "perf_event_paranoid=%d; root/CAP_PERFMON likely needed", paranoid);
    } else {
        add_check(app, "perf events", 1, "cannot read perf_event_paranoid");
    }

    if (geteuid() == 0)
        add_check(app, "privilege", 0, "effective uid is root");
    else
        add_check(app, "privilege", 1, "not root; CAP_BPF/CAP_PERFMON may still be sufficient");

    if (p->shim) {
        if (is_readable_file(p->shim))
            add_check(app, "shim", 0, "%s", p->shim);
        else
            add_check(app, "shim", 2, "not readable: %s", p->shim);
    } else {
        add_check(app, "shim", 2, "--shim PATH is required by the controller");
    }

    if (p->valid_mode_count == 1)
        add_check(app, "target mode", 0, "%s", p->auto_candidates ? "auto" : (p->symbol ? "symbol" : "range"));
    else
        add_check(app, "target mode", 2, "choose exactly one of --symbol, --range, --auto");

    if (p->program)
        add_check(app, "program", 0, "%s", p->program);
    else
        add_check(app, "program", 2, "missing -- PROGRAM [ARGS...]");

    char found[STUDIO_PATH_MAX];
    if (find_in_path("addr2line", found, sizeof(found)) == 0)
        add_check(app, "addr2line", 0, "%s", found);
    else
        add_check(app, "addr2line", 1, "not found; source attribution may be degraded");
}

static int preflight_failed(const struct app_state *app)
{
    for (int i = 0; i < app->check_count; i++)
        if (app->checks[i].state == 2)
            return 1;
    return 0;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void reset_run_state(struct app_state *app)
{
    app->trial_count = 0;
    app->summary_count = 0;
    app->exit_known = 0;
    app->child_status = 0;
    app->started_ns = 0;
    app->ended_ns = 0;
    app->out.pending_len = 0;
    app->err.pending_len = 0;
}

static void close_pipe(struct pipe_state *p)
{
    if (p->fd >= 0) {
        close(p->fd);
        p->fd = -1;
    }
    p->pending_len = 0;
}

static void stop_child(struct app_state *app)
{
    if (app->running && app->child > 0) {
        kill(app->child, SIGTERM);
        add_log(app, "studio: sent SIGTERM to controller pid %d", app->child);
    }
}

static int spawn_controller(struct app_state *app)
{
    if (app->running)
        return 0;

    run_preflight(app);
    if (preflight_failed(app)) {
        add_log(app, "studio: preflight has blocking failures; fix them or rerun with corrected arguments");
        return -1;
    }

    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        add_log(app, "studio: pipe failed: %s", strerror(errno));
        if (out_pipe[0] >= 0) close(out_pipe[0]);
        if (out_pipe[1] >= 0) close(out_pipe[1]);
        if (err_pipe[0] >= 0) close(err_pipe[0]);
        if (err_pipe[1] >= 0) close(err_pipe[1]);
        return -1;
    }

    char **child_argv = calloc((size_t)app->opt.pass_argc + 2, sizeof(char *));
    if (!child_argv) {
        add_log(app, "studio: out of memory");
        close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    child_argv[0] = (char *)app->opt.core_path;
    for (int i = 0; i < app->opt.pass_argc; i++)
        child_argv[i + 1] = app->opt.pass_argv[i];
    child_argv[app->opt.pass_argc + 1] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        add_log(app, "studio: fork failed: %s", strerror(errno));
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
        if (has_slash(app->opt.core_path))
            execv(app->opt.core_path, child_argv);
        else
            execvp(app->opt.core_path, child_argv);
        dprintf(STDERR_FILENO, "trawl-studio: exec %s failed: %s\n", app->opt.core_path, strerror(errno));
        _exit(127);
    }

    free(child_argv);
    close(out_pipe[1]);
    close(err_pipe[1]);
    set_nonblock(out_pipe[0]);
    set_nonblock(err_pipe[0]);

    reset_run_state(app);
    app->child = pid;
    app->running = 1;
    app->started_ns = now_ns();
    app->out.fd = out_pipe[0];
    app->err.fd = err_pipe[0];
    add_log(app, "studio: started controller pid %d", pid);
    return 0;
}

static void trim_line(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = 0;
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

static void parse_controller_line(struct app_state *app, const char *line_in)
{
    char line[STUDIO_MAX_LINE];
    snprintf(line, sizeof(line), "%s", line_in);
    trim_line(line);
    if (!*line)
        return;

    char copy[STUDIO_MAX_LINE];
    snprintf(copy, sizeof(copy), "%s", line);
    char *fields[STUDIO_MAX_FIELDS];
    int nf = split_csv_simple(copy, fields, STUDIO_MAX_FIELDS);
    if (nf <= 0)
        return;

    if (strcmp(fields[0], "trial") == 0 || strcmp(fields[0], "summary_type") == 0)
        return;

    if (token_is_integer(fields[0]) && nf >= 21) {
        if (app->trial_count >= STUDIO_MAX_TRIALS)
            return;
        struct trial_row *t = &app->trials[app->trial_count++];
        memset(t, 0, sizeof(*t));
        int lat_base = nf >= 22 ? 13 : 12; /* current schema has lat_sample_rate before lat_count. */
        t->trial_no = field_int(fields, nf, 0);
        t->candidate_idx = field_int(fields, nf, 1);
        t->speedup_pct = field_double(fields, nf, 2);
        t->progress_count = field_u64(fields, nf, 4);
        t->target_hits = field_u64(fields, nf, 9);
        t->virtual_delay_ms = field_double(fields, nf, 10);
        t->rate_per_sec = field_double(fields, nf, 11);
        t->lat_count = field_u64(fields, nf, lat_base);
        t->lat_p50_ms = field_double(fields, nf, lat_base + 2);
        t->lat_p90_ms = field_double(fields, nf, lat_base + 3);
        t->lat_p99_ms = field_double(fields, nf, lat_base + 4);
        return;
    }

    if (nf >= 16 && !token_is_integer(fields[0])) {
        if (app->summary_count >= STUDIO_MAX_SUMMARIES)
            return;
        struct summary_row *s = &app->summaries[app->summary_count++];
        memset(s, 0, sizeof(*s));
        int lat_base = nf >= 17 ? 12 : 11; /* current schema has lat_sample_rate_mean before lat_count. */
        snprintf(s->type, sizeof(s->type), "%s", fields[0]);
        s->candidate_idx = field_int(fields, nf, 1);
        snprintf(s->name, sizeof(s->name), "%s", fields[2]);
        s->speedup_pct = field_double(fields, nf, 3);
        s->n = field_int(fields, nf, 4);
        s->rate_mean = field_double(fields, nf, 5);
        s->rate_ci_low = field_double(fields, nf, 6);
        s->rate_ci_high = field_double(fields, nf, 7);
        s->impact_pct = field_double(fields, nf, 8);
        s->impact_ci_low = field_double(fields, nf, 9);
        s->impact_ci_high = field_double(fields, nf, 10);
        s->lat_count = field_u64(fields, nf, lat_base);
        s->lat_p50_ms = field_double(fields, nf, lat_base + 2);
        s->lat_p90_ms = field_double(fields, nf, lat_base + 3);
        s->lat_p99_ms = field_double(fields, nf, lat_base + 4);
    }
}

static void process_line(struct app_state *app, const char *prefix, const char *line)
{
    char clipped[STUDIO_MAX_LINE];
    snprintf(clipped, sizeof(clipped), "%s", line);
    trim_line(clipped);
    add_log(app, "%s%s", prefix, clipped);
    if (strcmp(prefix, "out: ") == 0)
        parse_controller_line(app, clipped);
}

static void read_pipe_lines(struct app_state *app, struct pipe_state *p, const char *prefix)
{
    if (p->fd < 0)
        return;
    char buf[2048];
    for (;;) {
        ssize_t n = read(p->fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            close_pipe(p);
            return;
        }
        if (n == 0) {
            if (p->pending_len) {
                p->pending[p->pending_len] = 0;
                process_line(app, prefix, p->pending);
                p->pending_len = 0;
            }
            close_pipe(p);
            return;
        }
        for (ssize_t i = 0; i < n; i++) {
            char ch = buf[i];
            if (ch == '\n') {
                p->pending[p->pending_len] = 0;
                process_line(app, prefix, p->pending);
                p->pending_len = 0;
            } else if (p->pending_len + 1 < sizeof(p->pending)) {
                p->pending[p->pending_len++] = ch;
            } else {
                p->pending[p->pending_len] = 0;
                process_line(app, prefix, p->pending);
                p->pending_len = 0;
            }
        }
    }
}

static void reap_child(struct app_state *app)
{
    if (!app->running || app->child <= 0)
        return;
    int status = 0;
    pid_t r = waitpid(app->child, &status, WNOHANG);
    if (r == 0 || r < 0)
        return;
    app->running = 0;
    app->exit_known = 1;
    app->child_status = status;
    app->ended_ns = now_ns();
    read_pipe_lines(app, &app->out, "out: ");
    read_pipe_lines(app, &app->err, "err: ");
    close_pipe(&app->out);
    close_pipe(&app->err);
    if (WIFEXITED(status))
        add_log(app, "studio: controller exited with status %d", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        add_log(app, "studio: controller terminated by signal %d", WTERMSIG(status));
    else
        add_log(app, "studio: controller finished");
}

static int expected_trials(const struct app_state *app)
{
    const struct parsed_profile *p = &app->opt.profile;
    int n = p->repeats * p->speedup_count * p->candidate_count_hint;
    return n > 0 ? n : 1;
}

static uint64_t max_progress_count(const struct app_state *app)
{
    uint64_t v = 0;
    for (int i = 0; i < app->trial_count; i++)
        if (app->trials[i].progress_count > v)
            v = app->trials[i].progress_count;
    return v;
}

static uint64_t max_target_hits_nonzero_speedup(const struct app_state *app)
{
    uint64_t v = 0;
    for (int i = 0; i < app->trial_count; i++) {
        if (app->trials[i].speedup_pct > 0.0 && app->trials[i].target_hits > v)
            v = app->trials[i].target_hits;
    }
    return v;
}

static uint64_t max_latency_count(const struct app_state *app)
{
    uint64_t v = 0;
    for (int i = 0; i < app->trial_count; i++)
        if (app->trials[i].lat_count > v)
            v = app->trials[i].lat_count;
    return v;
}

static double max_virtual_delay_nonzero_speedup(const struct app_state *app)
{
    double v = 0.0;
    for (int i = 0; i < app->trial_count; i++) {
        if (app->trials[i].speedup_pct > 0.0 && app->trials[i].virtual_delay_ms > v)
            v = app->trials[i].virtual_delay_ms;
    }
    return v;
}

static const char *color_reset(void) { return "\033[0m"; }
static const char *color_bold(void) { return "\033[1m"; }
static const char *color_dim(void) { return "\033[2m"; }
static const char *color_ok(void) { return "\033[32m"; }
static const char *color_warn(void) { return "\033[33m"; }
static const char *color_bad(void) { return "\033[31m"; }
static const char *color_cyan(void) { return "\033[36m"; }

static int safe_width(int w)
{
    return w > 0 ? w : 0;
}

static void move_to(struct strbuf *b, int y, int x)
{
    if (y < 1) y = 1;
    if (x < 1) x = 1;
    sb_printf(b, "\033[%d;%dH", y, x);
}

static void erase_screen(struct strbuf *b)
{
    sb_append(b, "\033[2J\033[H");
}

static void print_clipped(struct strbuf *b, int y, int x, int width, const char *fmt, ...)
{
    if (width <= 0)
        return;
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    int n = (int)strlen(tmp);
    if (n > width)
        n = width;
    move_to(b, y, x);
    sb_appendn(b, tmp, (size_t)n);
    for (int i = n; i < width; i++)
        sb_append(b, " ");
}

static void horizontal(struct strbuf *b, int y, int x, int width, char ch)
{
    move_to(b, y, x);
    for (int i = 0; i < width; i++)
        sb_appendn(b, &ch, 1);
}

static void draw_box(struct strbuf *b, int y, int x, int h, int w, const char *title)
{
    if (h < 2 || w < 4)
        return;
    move_to(b, y, x);
    sb_append(b, "+");
    for (int i = 0; i < w - 2; i++)
        sb_append(b, "-");
    sb_append(b, "+");
    for (int r = 1; r < h - 1; r++) {
        move_to(b, y + r, x);
        sb_append(b, "|");
        move_to(b, y + r, x + w - 1);
        sb_append(b, "|");
    }
    move_to(b, y + h - 1, x);
    sb_append(b, "+");
    for (int i = 0; i < w - 2; i++)
        sb_append(b, "-");
    sb_append(b, "+");
    if (title && *title && w > 6) {
        move_to(b, y, x + 2);
        sb_printf(b, "%s %.*s %s", color_bold(), w - 6, title, color_reset());
    }
}

static void draw_bar(struct strbuf *b, int y, int x, int width, double frac)
{
    if (width <= 0)
        return;
    if (frac < 0.0) frac = 0.0;
    if (frac > 1.0) frac = 1.0;
    int filled = (int)(frac * width + 0.5);
    move_to(b, y, x);
    sb_append(b, "[");
    for (int i = 0; i < width; i++)
        sb_append(b, i < filled ? "#" : ".");
    sb_append(b, "]");
}

static const char *state_label(const struct app_state *app)
{
    if (app->running)
        return "running";
    if (app->exit_known) {
        if (WIFEXITED(app->child_status) && WEXITSTATUS(app->child_status) == 0)
            return "complete";
        return "failed";
    }
    if (preflight_failed(app))
        return "blocked";
    return "ready";
}

static const char *state_color(const struct app_state *app)
{
    if (app->running)
        return color_cyan();
    if (app->exit_known) {
        if (WIFEXITED(app->child_status) && WEXITSTATUS(app->child_status) == 0)
            return color_ok();
        return color_bad();
    }
    if (preflight_failed(app))
        return color_bad();
    return color_ok();
}

static void format_elapsed(const struct app_state *app, char *out, size_t out_len)
{
    uint64_t end = app->running ? now_ns() : (app->ended_ns ? app->ended_ns : now_ns());
    uint64_t start = app->started_ns ? app->started_ns : end;
    double sec = (double)(end - start) / 1000000000.0;
    snprintf(out, out_len, "%.1fs", sec);
}

static void draw_header(struct strbuf *b, const struct app_state *app, int rows, int cols)
{
    (void)rows;
    char elapsed[32];
    format_elapsed(app, elapsed, sizeof(elapsed));
    print_clipped(b, 1, 1, cols, "%sTRAWL STUDIO%s  causal profiling cockpit", color_bold(), color_reset());
    print_clipped(b, 1, cols - 34, 35, "state: %s%s%s  elapsed: %s", state_color(app), state_label(app), color_reset(), elapsed);
    horizontal(b, 2, 1, cols, '-');
}

static void kv(struct strbuf *b, int y, int x, int w, const char *k, const char *v)
{
    print_clipped(b, y, x, w, "%s%-14s%s %s", color_dim(), k, color_reset(), v ? v : "-");
}

static void draw_target_panel(struct strbuf *b, const struct app_state *app, int y, int x, int h, int w)
{
    const struct parsed_profile *p = &app->opt.profile;
    draw_box(b, y, x, h, w, "Target");
    int r = y + 1;
    char target[STUDIO_PATH_MAX];
    if (p->auto_candidates)
        snprintf(target, sizeof(target), "auto / top %d", p->top_candidates);
    else if (p->symbol)
        snprintf(target, sizeof(target), "symbol %s", p->symbol);
    else if (p->range)
        snprintf(target, sizeof(target), "range %s", p->range);
    else
        snprintf(target, sizeof(target), "-");

    kv(b, r++, x + 2, w - 4, "program", p->program ? p->program : "-");
    kv(b, r++, x + 2, w - 4, "binary", p->binary ? p->binary : "default /proc/<pid>/exe");
    kv(b, r++, x + 2, w - 4, "target", target);
    char id[64];
    snprintf(id, sizeof(id), "%d", p->progress_id);
    kv(b, r++, x + 2, w - 4, "progress id", id);
    kv(b, r++, x + 2, w - 4, "latency", p->latency ? "enabled" : "disabled");
    kv(b, r++, x + 2, w - 4, "backend", p->backend ? p->backend : "coop");
}

static void draw_experiment_panel(struct strbuf *b, const struct app_state *app, int y, int x, int h, int w)
{
    const struct parsed_profile *p = &app->opt.profile;
    draw_box(b, y, x, h, w, "Experiment");
    int r = y + 1;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%d x %d speedups x %d candidates", p->repeats, p->speedup_count, p->candidate_count_hint);
    kv(b, r++, x + 2, w - 4, "trial grid", tmp);
    snprintf(tmp, sizeof(tmp), "%d ms trial, %d ms warmup", p->duration_ms, p->warmup_ms);
    kv(b, r++, x + 2, w - 4, "timing", tmp);
    snprintf(tmp, sizeof(tmp), "%d ms", p->cooldown_ms);
    kv(b, r++, x + 2, w - 4, "cooldown", tmp);
    snprintf(tmp, sizeof(tmp), "%d ms", p->discover_ms);
    kv(b, r++, x + 2, w - 4, "discovery", p->auto_candidates ? tmp : "not used");
    kv(b, r++, x + 2, w - 4, "speedups", p->speedups ? p->speedups : "-");
    kv(b, r++, x + 2, w - 4, "seed", p->seed ? p->seed : "monotonic time");
    kv(b, r++, x + 2, w - 4, "json", p->json ? p->json : "not requested");
}

static const struct trial_row *latest_trial(const struct app_state *app)
{
    if (app->trial_count <= 0)
        return NULL;
    return &app->trials[app->trial_count - 1];
}

static void draw_live_panel(struct strbuf *b, const struct app_state *app, int y, int x, int h, int w)
{
    draw_box(b, y, x, h, w, "Live trials");
    int total = expected_trials(app);
    double frac = total ? (double)app->trial_count / (double)total : 0.0;
    if (!app->running && app->exit_known && app->trial_count >= total)
        frac = 1.0;
    int bar_w = w - 24;
    if (bar_w < 10)
        bar_w = w - 6;
    print_clipped(b, y + 1, x + 2, w - 4, "observed %d / expected %d trial rows", app->trial_count, total);
    draw_bar(b, y + 2, x + 2, safe_width(bar_w), frac);
    print_clipped(b, y + 2, x + 4 + bar_w, w - bar_w - 6, "%5.1f%%", frac * 100.0);

    const struct trial_row *t = latest_trial(app);
    if (t) {
        print_clipped(b, y + 4, x + 2, w - 4,
            "latest: trial=%d candidate=%d speedup=%.2f%% rate=%.2f/s progress=%" PRIu64 " hits=%" PRIu64,
            t->trial_no, t->candidate_idx, t->speedup_pct, t->rate_per_sec, t->progress_count, t->target_hits);
        print_clipped(b, y + 5, x + 2, w - 4,
            "latency: n=%" PRIu64 " p50=%.3fms p90=%.3fms p99=%.3fms   virtual delay=%.3fms",
            t->lat_count, t->lat_p50_ms, t->lat_p90_ms, t->lat_p99_ms, t->virtual_delay_ms);
    } else {
        print_clipped(b, y + 4, x + 2, w - 4, "%sNo trial rows yet. Press r to run, q to quit.%s", color_dim(), color_reset());
    }
}

static void sort_summary_indices(int *idx, int n, const struct app_state *app)
{
    /* Portable insertion sort; n is small. */
    for (int i = 1; i < n; i++) {
        int v = idx[i];
        int j = i - 1;
        while (j >= 0) {
            const struct summary_row *a = &app->summaries[idx[j]];
            const struct summary_row *b = &app->summaries[v];
            if (a->impact_pct >= b->impact_pct)
                break;
            idx[j + 1] = idx[j];
            j--;
        }
        idx[j + 1] = v;
    }
}

static void draw_candidates_panel(struct strbuf *b, const struct app_state *app, int y, int x, int h, int w)
{
    draw_box(b, y, x, h, w, "Candidates by causal impact");
    if (h <= 3 || w <= 8)
        return;
    print_clipped(b, y + 1, x + 2, w - 4, "%s%-4s %-22s %8s %21s %10s%s",
                  color_dim(), "idx", "name", "speedup", "impact CI", "p99 ms", color_reset());
    int idx[STUDIO_MAX_SUMMARIES];
    int n = app->summary_count;
    if (n > STUDIO_MAX_SUMMARIES)
        n = STUDIO_MAX_SUMMARIES;
    for (int i = 0; i < n; i++)
        idx[i] = i;
    sort_summary_indices(idx, n, app);

    int max_rows = h - 3;
    if (n == 0) {
        print_clipped(b, y + 2, x + 2, w - 4, "%sSummary rows appear here after the controller finishes enough trials.%s", color_dim(), color_reset());
        return;
    }
    for (int row = 0; row < max_rows && row < n; row++) {
        const struct summary_row *s = &app->summaries[idx[row]];
        char name[64];
        snprintf(name, sizeof(name), "%s", s->name[0] ? s->name : "-");
        print_clipped(b, y + 2 + row, x + 2, w - 4,
            "%-4d %-22.22s %7.2f%% %+7.2f [%+6.2f,%+6.2f] %9.3f",
            s->candidate_idx, name, s->speedup_pct, s->impact_pct,
            s->impact_ci_low, s->impact_ci_high, s->lat_p99_ms);
    }
}

static void validity_line(struct strbuf *b, int y, int x, int w, const char *name, int state, const char *detail)
{
    const char *label = state == 0 ? "ok" : (state == 1 ? "warn" : "fail");
    const char *col = state == 0 ? color_ok() : (state == 1 ? color_warn() : color_bad());
    print_clipped(b, y, x, w, "%s%-5s%s %-18s %s", col, label, color_reset(), name, detail);
}

static void draw_validity_panel(struct strbuf *b, const struct app_state *app, int y, int x, int h, int w)
{
    draw_box(b, y, x, h, w, "Validity rail");
    int r = y + 1;
    for (int i = 0; i < app->check_count && r < y + h - 1; i++, r++)
        validity_line(b, r, x + 2, w - 4, app->checks[i].name, app->checks[i].state, app->checks[i].detail);

    if (r < y + h - 1 && app->trial_count > 0) {
        uint64_t progress = max_progress_count(app);
        char tmp[160];
        snprintf(tmp, sizeof(tmp), "max progress_count=%" PRIu64, progress);
        validity_line(b, r++, x + 2, w - 4, "progress", progress > 0 ? 0 : 2, tmp);
    }
    if (r < y + h - 1 && app->trial_count > 0) {
        uint64_t hits = max_target_hits_nonzero_speedup(app);
        char tmp[160];
        snprintf(tmp, sizeof(tmp), "max nonzero-speedup target_hits=%" PRIu64, hits);
        validity_line(b, r++, x + 2, w - 4, "target hits", hits > 0 ? 0 : 1, tmp);
    }
    if (r < y + h - 1 && app->opt.profile.latency && app->trial_count > 0) {
        uint64_t lat = max_latency_count(app);
        char tmp[160];
        snprintf(tmp, sizeof(tmp), "max latency spans=%" PRIu64, lat);
        validity_line(b, r++, x + 2, w - 4, "latency", lat > 0 ? 0 : 1, tmp);
    }
    if (r < y + h - 1 && app->trial_count > 0) {
        double delay = max_virtual_delay_nonzero_speedup(app);
        char tmp[160];
        snprintf(tmp, sizeof(tmp), "max nonzero-speedup virtual_delay=%.3fms", delay);
        validity_line(b, r++, x + 2, w - 4, "virtual delay", delay > 0.0 ? 0 : 1, tmp);
    }
}

static void draw_log_panel(struct strbuf *b, const struct app_state *app, int y, int x, int h, int w)
{
    draw_box(b, y, x, h, w, "Controller log");
    int rows = h - 2;
    int start = app->log_count - rows;
    if (start < 0)
        start = 0;
    for (int i = 0; i < rows && start + i < app->log_count; i++) {
        int slot = (app->log_head + start + i) % STUDIO_MAX_LOG;
        print_clipped(b, y + 1 + i, x + 2, w - 4, "%s", app->log[slot]);
    }
}

static void draw_footer(struct strbuf *b, const struct app_state *app, int rows, int cols)
{
    const char *json = app->opt.profile.json ? app->opt.profile.json : "no json output requested";
    horizontal(b, rows - 1, 1, cols, '-');
    print_clipped(b, rows, 1, cols,
        "keys: r run/rerun  l log  k terminate  q quit    report: %s", json);
}

static void render(struct app_state *app)
{
    int rows, cols;
    get_terminal_size(&rows, &cols);
    struct strbuf b;
    sb_init(&b);
    if (!b.p)
        return;
    erase_screen(&b);

    if (rows < 22 || cols < 78) {
        print_clipped(&b, 1, 1, cols, "TRAWL STUDIO");
        print_clipped(&b, 3, 1, cols, "Terminal too small: need at least 78x22, have %dx%d", cols, rows);
        print_clipped(&b, 5, 1, cols, "Press q to quit.");
        write(STDOUT_FILENO, b.p, b.len);
        sb_free(&b);
        return;
    }

    draw_header(&b, app, rows, cols);
    int y = 3;
    int top_h = 9;
    int live_h = 7;
    int footer_h = 2;
    int lower_h = rows - y - top_h - live_h - footer_h + 1;
    if (lower_h < 7)
        lower_h = 7;
    int left_w = cols / 2;

    draw_target_panel(&b, app, y, 1, top_h, left_w);
    draw_experiment_panel(&b, app, y, left_w + 1, top_h, cols - left_w);
    y += top_h;
    draw_live_panel(&b, app, y, 1, live_h, cols);
    y += live_h;

    if (app->show_log) {
        draw_log_panel(&b, app, y, 1, lower_h, cols);
    } else {
        int cand_w = cols * 58 / 100;
        if (cand_w < 50)
            cand_w = cols / 2;
        draw_candidates_panel(&b, app, y, 1, lower_h, cand_w);
        draw_validity_panel(&b, app, y, cand_w + 1, lower_h, cols - cand_w);
    }
    draw_footer(&b, app, rows, cols);

    write(STDOUT_FILENO, b.p, b.len);
    sb_free(&b);
}

static void handle_key(struct app_state *app, char ch)
{
    switch (ch) {
    case 'q':
    case 'Q':
        if (app->running)
            stop_child(app);
        app->should_quit = 1;
        break;
    case 'l':
    case 'L':
        app->show_log = !app->show_log;
        break;
    case 'k':
    case 'K':
        stop_child(app);
        break;
    case 'r':
    case 'R':
        if (!app->running)
            spawn_controller(app);
        break;
    default:
        break;
    }
}

static void event_loop(struct app_state *app)
{
    render(app);
    if (app->opt.auto_start)
        spawn_controller(app);

    uint64_t last_render = 0;
    while (!app->should_quit) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = STDIN_FILENO;
        FD_SET(STDIN_FILENO, &rfds);
        if (app->out.fd >= 0) {
            FD_SET(app->out.fd, &rfds);
            if (app->out.fd > maxfd) maxfd = app->out.fd;
        }
        if (app->err.fd >= 0) {
            FD_SET(app->err.fd, &rfds);
            if (app->err.fd > maxfd) maxfd = app->err.fd;
        }
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc > 0) {
            if (FD_ISSET(STDIN_FILENO, &rfds)) {
                char keys[64];
                ssize_t n = read(STDIN_FILENO, keys, sizeof(keys));
                for (ssize_t i = 0; i < n; i++)
                    handle_key(app, keys[i]);
            }
            if (app->out.fd >= 0 && FD_ISSET(app->out.fd, &rfds))
                read_pipe_lines(app, &app->out, "out: ");
            if (app->err.fd >= 0 && FD_ISSET(app->err.fd, &rfds))
                read_pipe_lines(app, &app->err, "err: ");
        }
        reap_child(app);
        uint64_t now = now_ns();
        if (now - last_render > 100000000ULL) {
            render(app);
            last_render = now;
        }
    }
}

int main(int argc, char **argv)
{
    struct app_state app;
    memset(&app, 0, sizeof(app));
    app.child = -1;
    app.out.fd = -1;
    app.err.fd = -1;

    if (parse_studio_opts(argc, argv, &app.opt) != 0) {
        usage(stderr, base_name(argv[0]));
        return 2;
    }

    run_preflight(&app);

    if (setup_terminal() != 0) {
        fprintf(stderr, "trawl-studio: requires an interactive terminal\n");
        return 2;
    }

    event_loop(&app);
    cleanup_terminal();

    if (app.exit_known && WIFEXITED(app.child_status))
        return WEXITSTATUS(app.child_status);
    if (app.exit_known && WIFSIGNALED(app.child_status))
        return 128 + WTERMSIG(app.child_status);
    return 0;
}
