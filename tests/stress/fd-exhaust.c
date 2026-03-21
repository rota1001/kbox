/* SPDX-License-Identifier: MIT */
/* Stress test: open files until EMFILE/ENFILE, verify graceful handling,
 * then close all and verify FDs are reusable.
 *
 * Compiled statically, runs inside kbox guest.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FDS 4096

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

int main(void)
{
    int fds[MAX_FDS];
    int count = 0;
    int i;

    /* Phase 1: open files until we hit the limit.
     * Use /dev/null as the target -- it always exists and does not
     * consume real storage.
     */
    for (i = 0; i < MAX_FDS; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] < 0) {
            /* We expect EMFILE (per-process limit) or ENFILE (system limit). */
            CHECK(errno == EMFILE || errno == ENFILE,
                  "open failure should be EMFILE or ENFILE");
            break;
        }
        count++;
    }

    printf("fd_exhaust: opened %d fds before limit\n", count);
    CHECK(count > 0, "should open at least one fd");

    /* Phase 2: close all opened FDs.
     */
    for (i = 0; i < count; i++) {
        int rc = close(fds[i]);
        CHECK(rc == 0, "close should succeed");
    }

    /* Phase 3: verify FDs are reusable after closing.
     * Open a handful of files to confirm the table freed up.
     */
    int reuse_count = (count < 10) ? count : 10;
    for (i = 0; i < reuse_count; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        CHECK(fds[i] >= 0, "fd reuse after close should succeed");
    }
    for (i = 0; i < reuse_count; i++)
        close(fds[i]);

    printf("fd_exhaust: reused %d fds after close\n", reuse_count);

    /* Phase 4: verify double-close returns EBADF, not crash.
     */
    int tmp_fd = open("/dev/null", O_RDONLY);
    CHECK(tmp_fd >= 0, "open for double-close test");
    CHECK(close(tmp_fd) == 0, "first close");
    errno = 0;
    int rc = close(tmp_fd);
    CHECK(rc < 0 && errno == EBADF, "double close should return EBADF");

    printf("PASS: fd_exhaust\n");
    return 0;
}
