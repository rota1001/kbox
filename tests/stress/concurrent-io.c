/* SPDX-License-Identifier: MIT */
/* Stress test: concurrent file I/O from multiple threads.
 * Creates 4 threads, each creating a file, writing a pattern, reading it
 * back, and verifying data integrity.
 *
 * Compiled statically, runs inside kbox guest.
 * Link with -lpthread (included in static glibc/musl).
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NUM_THREADS 4
#define BUF_SIZE 4096
#define ITERATIONS 50

struct thread_result {
    int thread_id;
    int passed;
    char errmsg[128];
};

static void *worker(void *arg)
{
    struct thread_result *res = (struct thread_result *) arg;
    char path[64];
    unsigned char wbuf[BUF_SIZE];
    unsigned char rbuf[BUF_SIZE];
    int iter;

    res->passed = 0;
    res->errmsg[0] = '\0';

    snprintf(path, sizeof(path), "/tmp/cio_thread_%d", res->thread_id);

    for (iter = 0; iter < ITERATIONS; iter++) {
        /* Fill write buffer with a pattern unique to this thread
         * and iteration, so cross-thread corruption is detectable.
         */
        unsigned char seed = (unsigned char) (res->thread_id * 37 + iter);
        int i;
        for (i = 0; i < BUF_SIZE; i++)
            wbuf[i] = (unsigned char) ((seed + i) & 0xFF);

        /* Write pattern to file. */
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            snprintf(res->errmsg, sizeof(res->errmsg),
                     "iter %d: open for write failed: %s", iter,
                     strerror(errno));
            return NULL;
        }

        ssize_t nw = write(fd, wbuf, BUF_SIZE);
        if (nw != BUF_SIZE) {
            snprintf(res->errmsg, sizeof(res->errmsg),
                     "iter %d: write returned %zd", iter, nw);
            close(fd);
            return NULL;
        }
        close(fd);

        /* Read back and verify. */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            snprintf(res->errmsg, sizeof(res->errmsg),
                     "iter %d: open for read failed: %s", iter,
                     strerror(errno));
            return NULL;
        }

        ssize_t nr = read(fd, rbuf, BUF_SIZE);
        if (nr != BUF_SIZE) {
            snprintf(res->errmsg, sizeof(res->errmsg),
                     "iter %d: read returned %zd", iter, nr);
            close(fd);
            return NULL;
        }
        close(fd);

        if (memcmp(wbuf, rbuf, BUF_SIZE) != 0) {
            snprintf(res->errmsg, sizeof(res->errmsg),
                     "iter %d: data corruption detected", iter);
            return NULL;
        }
    }

    /* Cleanup. */
    unlink(path);
    res->passed = 1;
    return NULL;
}

int main(void)
{
    pthread_t threads[NUM_THREADS];
    struct thread_result results[NUM_THREADS];
    int i;
    int all_passed = 1;

    /* Initialize result structs. */
    for (i = 0; i < NUM_THREADS; i++) {
        results[i].thread_id = i;
        results[i].passed = 0;
        results[i].errmsg[0] = '\0';
    }

    /* Launch threads. */
    for (i = 0; i < NUM_THREADS; i++) {
        int rc = pthread_create(&threads[i], NULL, worker, &results[i]);
        if (rc != 0) {
            fprintf(stderr, "FAIL: pthread_create thread %d: %s\n", i,
                    strerror(rc));
            return 1;
        }
    }

    /* Join threads. */
    for (i = 0; i < NUM_THREADS; i++) {
        int rc = pthread_join(threads[i], NULL);
        if (rc != 0) {
            fprintf(stderr, "FAIL: pthread_join thread %d: %s\n", i,
                    strerror(rc));
            return 1;
        }
    }

    /* Report per-thread results. */
    for (i = 0; i < NUM_THREADS; i++) {
        if (results[i].passed) {
            printf("concurrent_io: thread %d: PASS (%d iterations)\n", i,
                   ITERATIONS);
        } else {
            printf("concurrent_io: thread %d: FAIL: %s\n", i,
                   results[i].errmsg);
            all_passed = 0;
        }
    }

    if (all_passed) {
        printf("PASS: concurrent_io\n");
        return 0;
    }

    fprintf(stderr, "FAIL: concurrent_io\n");
    return 1;
}
