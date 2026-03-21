/* SPDX-License-Identifier: MIT */
/* Stress test: signal delivery during file I/O.
 * Installs a SIGALRM handler that fires every 10ms, then performs
 * file I/O operations continuously for 2 seconds.  Verifies that
 * I/O completes correctly despite signal interrupts (EINTR handling).
 *
 * Compiled statically, runs inside kbox guest.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DURATION_SEC 2
#define TIMER_USEC 10000 /* 10ms */

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

static volatile sig_atomic_t signal_count;

static void alarm_handler(int sig)
{
    (void) sig;
    signal_count++;
}

/* Write with EINTR retry.  Real programs must handle this, and
 * the supervisor must not corrupt state when signals interrupt
 * a blocked LKL syscall.
 */
static ssize_t write_full(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *) buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t nw = write(fd, p, remaining);
        if (nw < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += nw;
        remaining -= (size_t) nw;
    }
    return (ssize_t) len;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    unsigned char *p = (unsigned char *) buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t nr = read(fd, p, remaining);
        if (nr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (nr == 0)
            break; /* EOF */
        p += nr;
        remaining -= (size_t) nr;
    }
    return (ssize_t) (len - remaining);
}

int main(void)
{
    struct sigaction sa;
    struct itimerval itv;
    struct timespec t_start, t_now;
    unsigned long io_ops = 0;
    unsigned long io_errors = 0;
    const char *path = "/tmp/signal_race_test";
    unsigned char wbuf[256];
    unsigned char rbuf[256];
    int i;

    /* Fill write buffer with a known pattern. */
    for (i = 0; i < (int) sizeof(wbuf); i++)
        wbuf[i] = (unsigned char) (i & 0xFF);

    /* Install SIGALRM handler. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* No SA_RESTART: force EINTR on I/O. */
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction SIGALRM");

    /* Set up interval timer: fire every 10ms. */
    memset(&itv, 0, sizeof(itv));
    itv.it_interval.tv_usec = TIMER_USEC;
    itv.it_value.tv_usec = TIMER_USEC;
    CHECK(setitimer(ITIMER_REAL, &itv, NULL) == 0, "setitimer");

    CHECK(clock_gettime(CLOCK_MONOTONIC, &t_start) == 0, "clock_gettime start");

    /* Run I/O loop for DURATION_SEC seconds. */
    for (;;) {
        CHECK(clock_gettime(CLOCK_MONOTONIC, &t_now) == 0,
              "clock_gettime loop");
        long elapsed = t_now.tv_sec - t_start.tv_sec;
        if (elapsed >= DURATION_SEC)
            break;

        /* Write to file. */
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            io_errors++;
            continue;
        }

        ssize_t nw = write_full(fd, wbuf, sizeof(wbuf));
        close(fd);
        if (nw != (ssize_t) sizeof(wbuf)) {
            io_errors++;
            continue;
        }

        /* Read back and verify. */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            io_errors++;
            continue;
        }

        ssize_t nr = read_full(fd, rbuf, sizeof(rbuf));
        close(fd);
        if (nr != (ssize_t) sizeof(rbuf)) {
            io_errors++;
            continue;
        }

        if (memcmp(wbuf, rbuf, sizeof(wbuf)) != 0) {
            fprintf(stderr, "FAIL: data corruption under signal pressure\n");
            unlink(path);
            return 1;
        }

        io_ops++;
    }

    /* Disarm timer. */
    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);

    unlink(path);

    printf("signal_race: %lu I/O ops, %lu errors, %d signals in %d sec\n",
           io_ops, io_errors, (int) signal_count, DURATION_SEC);

    CHECK(io_ops > 0, "should complete at least one I/O cycle");
    CHECK(signal_count > 0, "should have received at least one signal");

    /* Allow a small number of transient errors (e.g., EINTR on open),
     * but the vast majority of operations should succeed.
     */
    if (io_ops > 0 && io_errors > io_ops / 2) {
        fprintf(stderr, "FAIL: too many I/O errors (%lu/%lu)\n", io_errors,
                io_ops);
        return 1;
    }

    printf("PASS: signal_race\n");
    return 0;
}
