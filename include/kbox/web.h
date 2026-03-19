/* SPDX-License-Identifier: MIT */
#ifndef KBOX_WEB_H
#define KBOX_WEB_H

/*
 * web.h - Web-based kernel observatory.
 *
 * Optional component activated by --web[=PORT].  When enabled, the
 * supervisor spawns an embedded HTTP server that streams LKL kernel
 * telemetry to a browser dashboard via SSE.
 *
 * Compile with KBOX_HAS_WEB to include web support.
 * The enable_trace config flag allows --trace-format=json to work
 * without --web (telemetry-only mode, no HTTP server).
 */

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Telemetry counters (updated from dispatch loop, lock-free)          */
/* ------------------------------------------------------------------ */

/*
 * Syscall family classification for dashboard grouping.
 */
enum kbox_syscall_family {
    KBOX_FAM_FILE_IO,   /* read, write, pread64, pwrite64, sendfile */
    KBOX_FAM_DIR,       /* getdents, mkdir, unlink, rename, readlink */
    KBOX_FAM_FD_OPS,    /* open, close, dup, fcntl, fstat, statx */
    KBOX_FAM_IDENTITY,  /* getuid, setuid, getgid, setgid, etc. */
    KBOX_FAM_MEMORY,    /* mmap, mprotect, mremap, brk */
    KBOX_FAM_SIGNALS,   /* rt_sigaction, rt_sigprocmask, kill, tgkill */
    KBOX_FAM_SCHEDULER, /* sched_yield, sched_setscheduler, etc. */
    KBOX_FAM_OTHER,     /* everything else */
    KBOX_FAM_COUNT,
};

/*
 * Dispatch disposition (for per-syscall tracking).
 */
enum kbox_disposition {
    KBOX_DISP_CONTINUE,
    KBOX_DISP_RETURN,
    KBOX_DISP_ENOSYS,
    KBOX_DISP_COUNT,
};

/*
 * Supervisor-internal counters.  Updated atomically from the
 * single-threaded dispatch loop.  Read by the web server thread
 * under a snapshot copy.
 */
struct kbox_telemetry_counters {
    /* Aggregate dispatch stats */
    uint64_t syscall_total;
    uint64_t disp_continue;
    uint64_t disp_return;
    uint64_t disp_enosys;

    /* Per-family dispatch counts */
    uint64_t family[KBOX_FAM_COUNT];

    /* Latency tracking (nanoseconds, cumulative) */
    uint64_t latency_total_ns;
    uint64_t latency_max_ns;

    /* ENOSYS hit counters: per-syscall-number */
    uint64_t enosys_hits[1024];
    uint64_t enosys_overflow;
    int enosys_overflow_last_nr;

    /* Notification lifecycle */
    uint64_t recv_enoent;
    uint64_t send_enoent;

    /* Cross-memory failures */
    uint64_t vm_readv_efault;
    uint64_t vm_readv_esrch;
    uint64_t vm_readv_eperm;
    uint64_t vm_writev_efault;
    uint64_t vm_writev_esrch;

    /* ADDFD operations */
    uint64_t addfd_ok;
    uint64_t addfd_enoent;
    uint64_t addfd_ebadf;
    uint64_t addfd_emfile;
    uint64_t addfd_other_err;
};

/* ------------------------------------------------------------------ */
/* Telemetry snapshot (sampled from LKL /proc)                         */
/* ------------------------------------------------------------------ */

#define KBOX_SNAPSHOT_VERSION 1

struct kbox_telemetry_snapshot {
    uint32_t version;
    uint64_t timestamp_ns;
    uint64_t uptime_ns;

    /* /proc/stat */
    uint64_t context_switches;
    uint64_t softirqs[10]; /* HI, TIMER, NET_TX, NET_RX, BLOCK,
                              IRQ_POLL, TASKLET, SCHED, HRTIMER, RCU */
    uint64_t softirq_total;

    /* /proc/meminfo (kB) */
    uint64_t mem_total;
    uint64_t mem_free;
    uint64_t mem_available;
    uint64_t buffers;
    uint64_t cached;
    uint64_t slab;

    /* /proc/vmstat */
    uint64_t pgfault;
    uint64_t pgmajfault;

    /* /proc/loadavg */
    uint32_t loadavg_1; /* fixed-point: value * 100 */
    uint32_t loadavg_5;
    uint32_t loadavg_15;

    /* FD table (supervisor internal) */
    uint32_t fd_table_used;
    uint32_t fd_table_max;

    /* Copy of dispatch counters at sample time */
    struct kbox_telemetry_counters counters;
};

/* ------------------------------------------------------------------ */
/* Event ring buffer                                                    */
/* ------------------------------------------------------------------ */

#define KBOX_EVENT_RING_SIZE 1024
#define KBOX_EVENT_RING_ROUTINE 768
#define KBOX_EVENT_RING_ERROR 256

enum kbox_event_type {
    KBOX_EVT_SYSCALL,
    KBOX_EVT_PROCESS,
    KBOX_EVT_COUNTER_DELTA,
};

struct kbox_syscall_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    int syscall_nr;
    const char *syscall_name; /* static string, not owned */
    uint64_t args[6];
    enum kbox_disposition disposition;
    int64_t return_value;
    int error_nr;
    uint64_t latency_ns;
};

struct kbox_process_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    int is_exit; /* 1 = exit, 0 = exec */
    int exit_code;
    char command[128];
};

struct kbox_event {
    enum kbox_event_type type;
    uint64_t seq; /* monotonic sequence number for SSE dedup */
    union {
        struct kbox_syscall_event syscall;
        struct kbox_process_event process;
    };
};

/*
 * Event ring buffer.
 * Split: [0, ROUTINE) for sampled routine events,
 *        [ROUTINE, SIZE) for errors/rare events.
 */
struct kbox_event_ring {
    struct kbox_event entries[KBOX_EVENT_RING_SIZE];
    uint64_t write_seq;
    int routine_head;
    int error_head;
};

/* ------------------------------------------------------------------ */
/* Web context (opaque)                                                */
/* ------------------------------------------------------------------ */

struct kbox_web_ctx;
struct kbox_sysnrs;

/*
 * Configuration for the web observatory.
 */
struct kbox_web_config {
    int port;               /* HTTP port (0 = default 8080) */
    const char *bind;       /* Bind address (NULL = "127.0.0.1") */
    int sample_ms;          /* Fast tick interval (0 = default 100) */
    int slow_sample_ms;     /* Slow tick interval (0 = default 500) */
    int enable_web;         /* Start HTTP server */
    int enable_trace;       /* Enable --trace-format=json to fd */
    int trace_fd;           /* FD for JSON trace output */
    const char *guest_name; /* Guest binary name for /stats */
};

/*
 * Initialize the web observatory.
 * The sysnrs pointer must remain valid for the lifetime of the context.
 * Returns an opaque context or NULL on error.
 */
struct kbox_web_ctx *kbox_web_init(const struct kbox_web_config *cfg,
                                   const struct kbox_sysnrs *sysnrs);

/*
 * Shut down the web observatory.  Stops the HTTP server thread
 * and frees all resources.
 */
void kbox_web_shutdown(struct kbox_web_ctx *ctx);

/*
 * Called from the supervisor loop on each iteration.
 * Checks if a sampling tick is due and reads LKL /proc files.
 * Must be called from the main thread.
 */
void kbox_web_tick(struct kbox_web_ctx *ctx);

/*
 * Record a dispatched syscall event.
 * Called from the supervisor loop after dispatch + send.
 */
void kbox_web_record_syscall(struct kbox_web_ctx *ctx,
                             uint32_t pid,
                             int syscall_nr,
                             const char *syscall_name,
                             const uint64_t args[6],
                             enum kbox_disposition disp,
                             int64_t ret_val,
                             int error_nr,
                             uint64_t latency_ns);

/*
 * Record a process lifecycle event (exec or exit).
 */
void kbox_web_record_process(struct kbox_web_ctx *ctx,
                             uint32_t pid,
                             int is_exit,
                             int exit_code,
                             const char *command);

/*
 * Get a pointer to the live counters (for direct increment
 * from the dispatch loop without function call overhead).
 */
struct kbox_telemetry_counters *kbox_web_counters(struct kbox_web_ctx *ctx);

/*
 * Monotonic clock reading in nanoseconds (CLOCK_MONOTONIC).
 */
uint64_t kbox_clock_ns(void);

#endif /* KBOX_WEB_H */
