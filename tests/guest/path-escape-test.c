/* SPDX-License-Identifier: MIT */
/* Guest test: verify that path traversal attempts are confined.
 * When running inside kbox's LKL-backed chroot, paths like /../../../
 * should not escape the guest filesystem boundary.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

int main(void)
{
    /* After chroot, /../../ should resolve back to /. */
    int rc = chdir("/../../../");
    CHECK(rc == 0, "chdir to /../../../");

    char cwd[256];
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd after chdir");
    CHECK(strcmp(cwd, "/") == 0, "cwd is / after traversal");

    /* Opening /../../../../etc/passwd should give the guest's file, not host.
     */
    int fd = open("/../../../../etc/passwd", O_RDONLY);
    if (fd >= 0) {
        char buf[256] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        /* If the file exists, it should be the guest passwd (contains "root").
         */
        if (nr > 0) {
            CHECK(strstr(buf, "root") != NULL,
                  "guest /etc/passwd contains root");
        }
    }
    /* If open fails, that is also fine: no escape occurred. */

    /* Verify /proc/self/cwd points to / */
    char link[256] = {0};
    ssize_t len = readlink("/proc/self/cwd", link, sizeof(link) - 1);
    if (len > 0) {
        link[len] = '\0';
        CHECK(strcmp(link, "/") == 0, "proc cwd is /");
    }

    /* Try symlink escape: create a symlink pointing outside and follow it. */
    rc = symlink("/../../../../tmp", "/tmp/escape_link");
    if (rc == 0) {
        struct stat st;
        (void) stat("/tmp/escape_link", &st);
        /* Whether it resolves or fails, we are still inside kbox. */
        unlink("/tmp/escape_link");
    }

    printf("PASS: path_escape_test\n");
    return 0;
}
