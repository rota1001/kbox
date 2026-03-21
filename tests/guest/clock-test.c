/* SPDX-License-Identifier: MIT */
/* Guest test: verify clock_gettime and gettimeofday return plausible values.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

int main(void)
{
    struct timespec ts;
    struct timeval tv;

    /* CLOCK_REALTIME should return a sane epoch time. */
    CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0, "clock_gettime REALTIME");
    CHECK(ts.tv_sec > 1700000000, "REALTIME is post-2023");
    CHECK(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L,
          "REALTIME nsec in range");

    /* CLOCK_MONOTONIC should succeed and be non-negative. */
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "clock_gettime MONOTONIC");
    CHECK(ts.tv_sec >= 0, "MONOTONIC sec >= 0");

    /* clock_getres should succeed for REALTIME. */
    CHECK(clock_getres(CLOCK_REALTIME, &ts) == 0, "clock_getres REALTIME");
    CHECK(ts.tv_sec == 0, "resolution < 1s");
    CHECK(ts.tv_nsec > 0, "resolution > 0ns");

    /* gettimeofday should return similar values. */
    CHECK(gettimeofday(&tv, NULL) == 0, "gettimeofday");
    CHECK(tv.tv_sec > 1700000000, "gettimeofday post-2023");
    CHECK(tv.tv_usec >= 0 && tv.tv_usec < 1000000, "usec in range");

    printf("PASS: clock_test\n");
    return 0;
}
