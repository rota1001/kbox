/* SPDX-License-Identifier: MIT */
/*
 * web-events.c - Event ring buffer for the web observatory.
 *
 * Split ring: 768 entries for sampled routine events, 256 reserved
 * for errors/cancellations.  Tail-based sampling: all errors and
 * rare syscalls (execve, clone3, exit) always captured; high-frequency
 * successes sampled at a configurable rate (default 1%).
 *
 * Single producer (dispatch thread), multiple consumers (SSE clients).
 */

#ifdef KBOX_HAS_WEB

#include "kbox/web.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Ring buffer                                                         */
/* ------------------------------------------------------------------ */

void kbox_event_ring_init(struct kbox_event_ring *ring)
{
    memset(ring, 0, sizeof(*ring));
}

/*
 * Push a routine event (sampled).
 * Overwrites oldest routine entry when full.
 */
static void ring_push_routine(struct kbox_event_ring *ring,
                              struct kbox_event *evt)
{
    int idx = ring->routine_head;
    evt->seq = ++ring->write_seq;
    ring->entries[idx] = *evt;
    ring->routine_head = (idx + 1) % KBOX_EVENT_RING_ROUTINE;
}

/*
 * Push an error/rare event (always captured).
 * Overwrites oldest error entry when full.
 */
static void ring_push_error(struct kbox_event_ring *ring,
                            struct kbox_event *evt)
{
    int idx = KBOX_EVENT_RING_ROUTINE + ring->error_head;
    evt->seq = ++ring->write_seq;
    ring->entries[idx] = *evt;
    ring->error_head = (ring->error_head + 1) % KBOX_EVENT_RING_ERROR;
}

/* ------------------------------------------------------------------ */
/* Sampling policy                                                     */
/* ------------------------------------------------------------------ */

/* Simple PRNG (xorshift32) -- no need for crypto quality */
static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/*
 * Returns 1 if this event should be recorded (passes sampling filter).
 *
 * Policy:
 *   - Errors (negative return, nonzero error): always record
 *   - Rare syscalls (execve, clone3, exit_group): always record
 *   - High-frequency successes (read, write, stat): 1% sample
 */
static int should_sample(const struct kbox_syscall_event *evt,
                         uint32_t *rng_state,
                         int sample_pct)
{
    /* Errors always recorded */
    if (evt->error_nr != 0 || evt->return_value < 0)
        return 1;

    /* ENOSYS always recorded */
    if (evt->disposition == KBOX_DISP_ENOSYS)
        return 1;

    /* Rare syscalls: always record */
    if (evt->syscall_name) {
        if (strcmp(evt->syscall_name, "execve") == 0 ||
            strcmp(evt->syscall_name, "execveat") == 0 ||
            strcmp(evt->syscall_name, "clone3") == 0 ||
            strcmp(evt->syscall_name, "clone") == 0 ||
            strcmp(evt->syscall_name, "exit_group") == 0 ||
            strcmp(evt->syscall_name, "exit") == 0)
            return 1;
    }

    /* Probabilistic sampling for routine successes */
    if (sample_pct >= 100)
        return 1;
    if (sample_pct <= 0)
        return 0;

    return (xorshift32(rng_state) % 100) < (uint32_t) sample_pct;
}

/* ------------------------------------------------------------------ */
/* Event emission                                                      */
/* ------------------------------------------------------------------ */

void kbox_event_push_syscall(struct kbox_event_ring *ring,
                             uint32_t *rng_state,
                             int sample_pct,
                             const struct kbox_syscall_event *evt)
{
    int is_error = (evt->error_nr != 0 || evt->return_value < 0 ||
                    evt->disposition == KBOX_DISP_ENOSYS);

    if (is_error) {
        struct kbox_event e;
        e.type = KBOX_EVT_SYSCALL;
        e.syscall = *evt;
        ring_push_error(ring, &e);
        return;
    }

    if (!should_sample(evt, rng_state, sample_pct))
        return;

    struct kbox_event e;
    e.type = KBOX_EVT_SYSCALL;
    e.syscall = *evt;
    ring_push_routine(ring, &e);
}

void kbox_event_push_process(struct kbox_event_ring *ring,
                             const struct kbox_process_event *evt)
{
    /* Process events are always rare -- push to error ring */
    struct kbox_event e;
    e.type = KBOX_EVT_PROCESS;
    e.process = *evt;
    ring_push_error(ring, &e);
}

/* ------------------------------------------------------------------ */
/* JSON string escaping                                                */
/* ------------------------------------------------------------------ */

/*
 * Escape a string for safe JSON embedding.
 * Handles: " \ and control characters (< 0x20).
 * Returns bytes written (not including NUL).
 */
static int json_escape(const char *src, char *dst, int dstsz)
{
    int pos = 0;
    if (!src) {
        if (dstsz > 0)
            dst[0] = '\0';
        return 0;
    }
    for (; *src && pos < dstsz - 6; src++) {
        unsigned char c = (unsigned char) *src;
        if (c == '"' || c == '\\') {
            dst[pos++] = '\\';
            dst[pos++] = (char) c;
        } else if (c < 0x20) {
            pos += snprintf(dst + pos, (size_t) (dstsz - pos), "\\u%04x", c);
        } else {
            dst[pos++] = (char) c;
        }
    }
    if (pos < dstsz)
        dst[pos] = '\0';
    return pos;
}

/* ------------------------------------------------------------------ */
/* Event JSON serialization                                            */
/* ------------------------------------------------------------------ */

int kbox_event_to_json(const struct kbox_event *evt, char *buf, int bufsz)
{
    switch (evt->type) {
    case KBOX_EVT_SYSCALL: {
        const struct kbox_syscall_event *e = &evt->syscall;
        static const char *disp_names[] = {"continue", "return", "enosys"};
        const char *dname = (e->disposition < KBOX_DISP_COUNT)
                                ? disp_names[e->disposition]
                                : "unknown";
        return snprintf(buf, (size_t) bufsz,
                        "{\"type\":\"syscall\","
                        "\"ts\":%" PRIu64
                        ","
                        "\"pid\":%u,"
                        "\"nr\":%d,"
                        "\"name\":\"%s\","
                        "\"disp\":\"%s\","
                        "\"ret\":%" PRId64
                        ","
                        "\"err\":%d,"
                        "\"lat_ns\":%" PRIu64 "}",
                        e->timestamp_ns, e->pid, e->syscall_nr,
                        e->syscall_name ? e->syscall_name : "?", dname,
                        e->return_value, e->error_nr, e->latency_ns);
    }
    case KBOX_EVT_PROCESS: {
        const struct kbox_process_event *e = &evt->process;
        if (e->is_exit)
            return snprintf(buf, (size_t) bufsz,
                            "{\"type\":\"process\","
                            "\"ts\":%" PRIu64
                            ","
                            "\"pid\":%u,"
                            "\"action\":\"exit\","
                            "\"code\":%d}",
                            e->timestamp_ns, e->pid, e->exit_code);
        char escaped_cmd[256];
        json_escape(e->command, escaped_cmd, sizeof(escaped_cmd));
        return snprintf(buf, (size_t) bufsz,
                        "{\"type\":\"process\","
                        "\"ts\":%" PRIu64
                        ","
                        "\"pid\":%u,"
                        "\"action\":\"exec\","
                        "\"cmd\":\"%s\"}",
                        e->timestamp_ns, e->pid, escaped_cmd);
    }
    case KBOX_EVT_COUNTER_DELTA:
        return snprintf(buf, (size_t) bufsz, "{\"type\":\"counter_delta\"}");
    }
    return 0;
}

/*
 * Iterate events from a given sequence number.
 * Calls cb for each event with seq >= from_seq.
 * Returns the next sequence number to use.
 */
uint64_t kbox_event_ring_iterate(const struct kbox_event_ring *ring,
                                 uint64_t from_seq,
                                 void (*cb)(const struct kbox_event *evt,
                                            void *userdata),
                                 void *userdata)
{
    /*
     * Scan all slots, emit those with seq > from_seq.
     * O(1024) but only runs on SSE client reads, not the hot path.
     */
    for (int i = 0; i < KBOX_EVENT_RING_SIZE; i++) {
        const struct kbox_event *evt = &ring->entries[i];
        if (evt->seq <= from_seq || evt->seq == 0)
            continue;
        cb(evt, userdata);
    }
    return ring->write_seq;
}

#endif /* KBOX_HAS_WEB */
