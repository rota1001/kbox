/* SPDX-License-Identifier: MIT */
/* Stress test: fork many short-lived child processes in sequence.
 * Verifies no zombie accumulation, correct wait semantics, and no
 * supervisor resource leaks across 100 fork/exit cycles.
 *
 * Compiled statically, runs inside kbox guest.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 100

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

static long timespec_diff_ms(struct timespec *start, struct timespec *end)
{
    long sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    return sec * 1000 + nsec / 1000000;
}

int main(void)
{
    struct timespec t_start, t_end;
    int pipefd[2];
    int i;

    CHECK(clock_gettime(CLOCK_MONOTONIC, &t_start) == 0, "clock_gettime start");

    for (i = 0; i < ITERATIONS; i++) {
        CHECK(pipe(pipefd) == 0, "pipe creation");

        pid_t pid = fork();
        CHECK(pid >= 0, "fork should succeed");

        if (pid == 0) {
            /* Child: write iteration number to pipe, then exit. */
            close(pipefd[0]);
            unsigned char val = (unsigned char) (i & 0xFF);
            ssize_t nw = write(pipefd[1], &val, 1);
            close(pipefd[1]);
            _exit(nw == 1 ? 0 : 1);
        }

        /* Parent: read from pipe, wait for child. */
        close(pipefd[1]);

        unsigned char got = 0;
        ssize_t nr = read(pipefd[0], &got, 1);
        close(pipefd[0]);

        CHECK(nr == 1, "parent should read 1 byte from child");
        CHECK(got == (unsigned char) (i & 0xFF), "child wrote correct value");

        int status;
        pid_t waited = waitpid(pid, &status, 0);
        CHECK(waited == pid, "waitpid should return child pid");
        CHECK(WIFEXITED(status), "child should exit normally");
        CHECK(WEXITSTATUS(status) == 0, "child exit code should be 0");
    }

    CHECK(clock_gettime(CLOCK_MONOTONIC, &t_end) == 0, "clock_gettime end");

    long elapsed_ms = timespec_diff_ms(&t_start, &t_end);

    /* Verify no zombies remain.  Try waitpid with WNOHANG -- should
     * return 0 (no children) or -1 with ECHILD.
     */
    int status;
    pid_t zcheck = waitpid(-1, &status, WNOHANG);
    CHECK(zcheck <= 0, "no zombie children should remain");
    if (zcheck < 0)
        CHECK(errno == ECHILD, "waitpid error should be ECHILD");

    printf("rapid_fork: %d iterations in %ld ms (%.1f ms/fork)\n", ITERATIONS,
           elapsed_ms, (double) elapsed_ms / ITERATIONS);
    printf("PASS: rapid_fork\n");
    return 0;
}
