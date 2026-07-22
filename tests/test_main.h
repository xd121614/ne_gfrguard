/* Minimal unit test framework — no external dependencies.
 *
 * Assertions are NON-FATAL: a failed ASSERT records the failure and the
 * test continues.  The old fatal `return` silently skipped every later
 * assertion in the same test — suites looked green while later checks
 * never ran (coverage inflation, masked bugs).  A test that dereferences
 * a genuinely broken precondition now fails loudly instead of silently;
 * that is the point. */
#ifndef TEST_MAIN_H
#define TEST_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int _tests_run = 0;
static int _tests_fail = 0;

#define TEST(name) static void test_##name(void)

#define ASSERT_EQ(a, b) do { \
    _tests_run++; \
    if ((long)(a) != (long)(b)) { \
        fprintf(stderr, "  FAIL %s:%d: %s == %s  (%ld != %ld)\n", \
                __FILE__, __LINE__, #a, #b, (long)(a), (long)(b)); \
        _tests_fail++; \
    } \
} while (0)

#define ASSERT_TRUE(x)   ASSERT_EQ((x) ? 1 : 0, 1)
#define ASSERT_FALSE(x)  ASSERT_EQ((x) ? 1 : 0, 0)

/* Helper, not a macro: passing string literals into a macro's
 * `(a) ? (a) : "(null)"` trips -Waddress (literal address is always
 * true).  Inside a function the pointers are opaque — same semantics,
 * no warning. */
static inline void _assert_streq_impl(const char *a, const char *b,
                                      const char *sa, const char *sb,
                                      const char *file, int line)
{
    _tests_run++;
    if (!a || !b || strcmp(a, b) != 0) {
        fprintf(stderr, "  FAIL %s:%d: %s == %s  (\"%s\" != \"%s\")\n",
                file, line, sa, sb,
                a ? a : "(null)", b ? b : "(null)");
        _tests_fail++;
    }
}

#define ASSERT_STREQ(a, b) \
    _assert_streq_impl((a), (b), #a, #b, __FILE__, __LINE__)

#define ASSERT_FLOAT_NEAR(a, b, epsilon) do { \
    _tests_run++; \
    double _diff = (a) - (b); \
    if (_diff < 0) _diff = -_diff; \
    if (_diff > (epsilon)) { \
        fprintf(stderr, "  FAIL %s:%d: %s ~ %s  (%f != %f)\n", \
                __FILE__, __LINE__, #a, #b, (double)(a), (double)(b)); \
        _tests_fail++; \
    } \
} while (0)

#define RUN_TEST(name) do { \
    extern void test_##name(void); \
    test_##name(); \
} while (0)

static inline int test_summary(void) {
    printf("\nResults: %d run, %d failed\n", _tests_run, _tests_fail);
    return _tests_fail > 0 ? 1 : 0;
}

#endif /* TEST_MAIN_H */
