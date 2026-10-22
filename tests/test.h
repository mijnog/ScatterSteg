#ifndef TEST_H
#define TEST_H

/* Minimal test harness: each test is a void function; CHECK records a
   failure and keeps going so one run reports every broken assertion. */

#include <stdio.h>

static int test_failures = 0;
static int test_checks   = 0;

#define CHECK(cond) do {                                                  \
        test_checks++;                                                    \
        if (!(cond)) {                                                    \
            test_failures++;                                              \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

#define RUN(fn) do {                                                      \
        int before_ = test_failures;                                      \
        fn();                                                             \
        printf("%s %s\n", test_failures == before_ ? "ok  " : "FAIL", #fn); \
    } while (0)

#define TEST_SUMMARY() (                                                  \
        printf("%d checks, %d failed\n", test_checks, test_failures),     \
        test_failures ? 1 : 0)

#endif /* TEST_H */
