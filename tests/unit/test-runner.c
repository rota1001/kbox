/* SPDX-License-Identifier: MIT */
/* Minimal C test harness.  No external dependencies.
 *
 * Each test file registers tests via TEST_REGISTER() in its
 * init function.  test-runner.c calls all init functions, then
 * runs all registered tests.
 */

#include "test-runner.h"

#define MAX_TESTS 256

struct test_entry {
    const char *name;
    test_fn fn;
};

static struct test_entry tests[MAX_TESTS];
static int test_count;
static int pass_count;
static int fail_count;

void test_register(const char *name, test_fn fn)
{
    if (test_count >= MAX_TESTS) {
        fprintf(stderr, "too many tests (max %d)\n", MAX_TESTS);
        exit(1);
    }
    tests[test_count].name = name;
    tests[test_count].fn = fn;
    test_count++;
}

void test_fail(const char *file, int line, const char *expr)
{
    fprintf(stderr, "  FAIL: %s:%d: %s\n", file, line, expr);
    fail_count++;
}

void test_fail_eq_long(const char *file,
                       int line,
                       const char *lhs,
                       const char *rhs,
                       long a,
                       long b)
{
    fprintf(stderr, "  FAIL: %s:%d: %s == %s (%ld != %ld)\n", file, line, lhs,
            rhs, a, b);
    fail_count++;
}

void test_fail_ne_long(const char *file,
                       int line,
                       const char *lhs,
                       const char *rhs,
                       long a)
{
    fprintf(stderr, "  FAIL: %s:%d: %s != %s (both %ld)\n", file, line, lhs,
            rhs, a);
    fail_count++;
}

void test_fail_streq(const char *file, int line, const char *a, const char *b)
{
    fprintf(stderr, "  FAIL: %s:%d: \"%s\" != \"%s\"\n", file, line, a, b);
    fail_count++;
}

void test_pass(void)
{
    pass_count++;
}

/* External init functions from each test file */
extern void test_fd_table_init(void);
extern void test_path_init(void);
extern void test_identity_init(void);
extern void test_syscall_nr_init(void);
extern void test_elf_init(void);

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    /* Register all test suites */
    test_fd_table_init();
    test_path_init();
    test_identity_init();
    test_syscall_nr_init();
    test_elf_init();

    /* Run all tests */
    int suite_fails = 0;
    printf("Running %d tests...\n", test_count);
    for (int i = 0; i < test_count; i++) {
        int before_fail = fail_count;
        printf("  [%d/%d] %s... ", i + 1, test_count, tests[i].name);
        fflush(stdout);
        tests[i].fn();
        /* cppcheck-suppress knownConditionTrueFalse */
        if (fail_count > before_fail) {
            suite_fails++;
            printf("FAILED\n");
        } else {
            printf("ok\n");
        }
    }

    printf("\n%d tests, %d passed, %d failed\n", test_count,
           test_count - suite_fails, suite_fails);

    return suite_fails > 0 ? 1 : 0;
}
