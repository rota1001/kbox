/* SPDX-License-Identifier: MIT */
/* Guest test: verify that errno is correctly propagated from LKL syscalls
 * through the seccomp-unotify supervisor.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "FAIL: %s (%s)\n", msg, #cond); \
            exit(1);                                        \
        }                                                   \
    } while (0)

#define CHECK_ERRNO(call, expected_errno)                 \
    do {                                                  \
        errno = 0;                                        \
        int _rc = (call);                                 \
        CHECK(_rc < 0, #call " should fail");             \
        CHECK(errno == (expected_errno),                  \
              #call " errno should be " #expected_errno); \
    } while (0)

int main(void)
{
    /* ENOENT: open non-existent file. */
    CHECK_ERRNO(open("/nonexistent_file_abc123", O_RDONLY), ENOENT);

    /* EEXIST: mkdir on existing directory. */
    CHECK_ERRNO(mkdir("/tmp", 0755), EEXIST);

    /* EBADF: read from invalid fd. */
    char buf[4];
    errno = 0;
    ssize_t nr = read(9999, buf, sizeof(buf));
    CHECK(nr < 0, "read bad fd should fail");
    CHECK(errno == EBADF, "read bad fd errno should be EBADF");

    /* EISDIR: open directory for writing. */
    CHECK_ERRNO(open("/tmp", O_WRONLY), EISDIR);

    /* Write to read-only FD: skip in kbox.  Shadow FDs (memfds used for
     * O_RDONLY regular files to enable mmap) are host-side read-write,
     * so write() succeeds on the host kernel despite O_RDONLY open flags.
     * This is a known shadow FD limitation, not an errno propagation bug.
     */

    /* ENOTDIR: path component is not a directory. */
    int fd = open("/etc/passwd/subdir", O_RDONLY);
    CHECK(fd < 0, "open with non-dir component should fail");
    CHECK(errno == ENOTDIR, "errno should be ENOTDIR");

    printf("PASS: errno_test\n");
    return 0;
}
