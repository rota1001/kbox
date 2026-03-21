/* SPDX-License-Identifier: MIT */
/* Stress test: exercise all MVP syscalls in a loop for a configurable
 * duration (default 10 seconds).  Each iteration performs:
 *   open, write, read, stat, readdir, mkdir, rmdir, chdir, getcwd,
 *   getpid, clock_gettime, pipe, close
 *
 * Tracks iteration count and errors.  Prints summary and PASS/FAIL.
 *
 * Usage: long_running [duration_seconds]
 *
 * Compiled statically, runs inside kbox guest.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_DURATION 10

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

static int run_one_iteration(int iter)
{
    char path[128];
    char dir_path[128];
    char buf[128];
    struct stat st;

    snprintf(path, sizeof(path), "/tmp/lr_test_%d", iter % 64);
    snprintf(dir_path, sizeof(dir_path), "/tmp/lr_dir_%d", iter % 64);

    /* open + write */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    const char *data = "long_running_test_data";
    ssize_t nw = write(fd, data, strlen(data));
    if (nw != (ssize_t) strlen(data)) {
        close(fd);
        return -2;
    }
    close(fd);

    /* open + read back */
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -3;

    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    if (nr != (ssize_t) strlen(data)) {
        close(fd);
        return -4;
    }
    buf[nr] = '\0';
    if (strcmp(buf, data) != 0) {
        close(fd);
        return -5;
    }
    close(fd);

    /* stat */
    if (stat(path, &st) != 0)
        return -6;
    if ((size_t) st.st_size != strlen(data))
        return -7;

    /* mkdir + readdir + rmdir */
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST)
        return -8;

    DIR *d = opendir(dir_path);
    if (!d)
        return -9;
    /* Just read entries; empty dir has . and .. */
    struct dirent *ent;
    int entry_count = 0;
    while ((ent = readdir(d)) != NULL)
        entry_count++;
    closedir(d);
    if (entry_count < 2)
        return -10; /* missing . or .. */

    if (rmdir(dir_path) != 0 && errno != ENOTEMPTY)
        return -11;

    /* chdir + getcwd */
    char saved_cwd[256];
    if (getcwd(saved_cwd, sizeof(saved_cwd)) == NULL)
        return -12;

    if (chdir("/tmp") != 0)
        return -13;

    char cwd[256];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return -14;
    if (strcmp(cwd, "/tmp") != 0)
        return -15;

    /* Return to original directory. */
    if (chdir(saved_cwd) != 0)
        return -16;

    /* getpid: should return a positive value. */
    pid_t pid = getpid();
    if (pid <= 0)
        return -17;

    /* clock_gettime */
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -18;

    /* pipe + write + read + close */
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return -19;

    nw = write(pipefd[1], "p", 1);
    if (nw != 1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -20;
    }

    char pbuf;
    nr = read(pipefd[0], &pbuf, 1);
    close(pipefd[0]);
    close(pipefd[1]);
    if (nr != 1 || pbuf != 'p')
        return -21;

    /* Cleanup test file. */
    unlink(path);

    return 0;
}

int main(int argc, char **argv)
{
    int duration = DEFAULT_DURATION;
    struct timespec t_start, t_now;
    unsigned long iterations = 0;
    unsigned long errors = 0;

    if (argc > 1) {
        duration = atoi(argv[1]);
        if (duration <= 0 || duration > 3600)
            duration = DEFAULT_DURATION;
    }

    printf("long_running: starting %d second soak test\n", duration);

    CHECK(clock_gettime(CLOCK_MONOTONIC, &t_start) == 0, "clock_gettime start");

    for (;;) {
        CHECK(clock_gettime(CLOCK_MONOTONIC, &t_now) == 0,
              "clock_gettime loop");
        long elapsed = t_now.tv_sec - t_start.tv_sec;
        if (elapsed >= duration)
            break;

        int rc = run_one_iteration((int) iterations);
        if (rc != 0) {
            errors++;
            if (errors <= 5)
                fprintf(stderr, "long_running: iter %lu error %d\n", iterations,
                        rc);
        }
        iterations++;
    }

    printf("long_running: %lu iterations, %lu errors in %d seconds\n",
           iterations, errors, duration);

    if (errors > 0) {
        fprintf(stderr, "FAIL: long_running (%lu errors)\n", errors);
        return 1;
    }

    printf("PASS: long_running\n");
    return 0;
}
