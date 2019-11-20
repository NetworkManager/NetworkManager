/*
 * API Visibility Tests
 * This verifies the visibility and availability of the exported API.
 */

#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c-stdaux.h"

static _c_const_ int const_fn(void) { return 0; }
static _c_deprecated_ _c_unused_ int deprecated_fn(void) { return 0; }
_c_hidden_ int c_internal_hidden_fn(void) { return 0; }
static _c_printf_(1, 2) int printf_fn(const char *f, ...) { return 0; }
_c_public_ int c_internal_public_fn(void) { return 0; }
static _c_pure_ int pure_fn(void) { return 0; }
static _c_sentinel_ int sentinel_fn(const char *f, ...) { return 0; }
static _c_unused_ int unused_fn(void) { return 0; }

static void cleanup_fn(int p) {}
static void direct_cleanup_fn(int p) {}
C_DEFINE_CLEANUP(int, cleanup_fn);
C_DEFINE_DIRECT_CLEANUP(int, direct_cleanup_fn);

static void test_api_macros(void) {
        /* _c_cleanup_ */
        {
                _c_cleanup_(c_freep) void *foo = NULL;
                c_assert(!foo);
        }

        /* _c_const_ */
        {
                c_assert(!const_fn());
        }

        /* _c_deprecated_ */
        {
                /* see deprecated_fn() */
        }

        /* _c_hidden_ */
        {
                c_assert(!c_internal_hidden_fn());
        }

        /* _c_likely_ */
        {
                c_assert(_c_likely_(true));
        }

        /* _c_packed_ */
        {
                struct _c_packed_ FooBar {
                        int member;
                } foobar = {};

                c_assert(!foobar.member);
        }

        /* _c_printf_ */
        {
                c_assert(!printf_fn("%d", 1));
        }

        /* _c_public_ */
        {
                c_assert(!c_internal_public_fn());
        }

        /* _c_pure_ */
        {
                c_assert(!pure_fn());
        }

        /* _c_sentinel_ */
        {
                c_assert(!sentinel_fn("", NULL));
        }

        /* _c_unlikely_ */
        {
                c_assert(!_c_unlikely_(false));
        }

        /* _c_unused_ */
        {
                c_assert(!unused_fn());
        }

        /* C_EXPR_ASSERT */
        {
                int v = C_EXPR_ASSERT(0, true, "");

                c_assert(!v);
        }

        /* C_STRINGIFY */
        {
                const char v[] = C_STRINGIFY(foobar);

                c_assert(!strcmp(v, "foobar"));
        }

        /* C_CONCATENATE */
        {
                int C_CONCATENATE(a, b) = 0;

                c_assert(!ab);
        }

        /* C_EXPAND */
        {
                int x[] = { C_EXPAND((0, 1)) };

                c_assert(sizeof(x) / sizeof(*x) == 2);
        }

        /* C_VAR */
        {
                int C_VAR = 0; c_assert(!C_VAR); /* must be on the same line */
        }

        /* C_CC_MACRO1, C_CC_MACRO2, C_CC_MACRO3 */
        {
#define MACRO_REAL(_x1, _x2, _x3) ((_x1 + _x2 + _x3) * 0)
#define MACRO1(_x1) C_CC_MACRO1(MACRO_REAL, _x1, 0, 0)
#define MACRO2(_x1, _x2) C_CC_MACRO2(MACRO_REAL, _x1, _x2, 0)
#define MACRO3(_x1, _x2, _x3) C_CC_MACRO3(MACRO_REAL, _x1, _x2, _x3)
                c_assert(!MACRO1(1));
                c_assert(!MACRO2(1, 1));
                c_assert(!MACRO3(1, 1, 1));
#undef MACRO3
#undef MACRO2
#undef MACRO1
        }

        /* C_ARRAY_SIZE */
        {
                int v[] = { 0, 1, 2 };
                c_assert(C_ARRAY_SIZE(v) == 3);
        }

        /* C_DECIMAL_MAX */
        {
                c_assert(C_DECIMAL_MAX(uint8_t) == 4);
        }

        /* c_container_of */
        {
                struct FooBarContainer {
                        int member;
                } v = {};

                c_assert(c_container_of(&v.member, struct FooBarContainer, member) == &v);
        }

        /* c_max, c_min, c_less_by, c_clamp, c_div_round_up */
        {
                c_assert(c_max(0, 0) == 0);
                c_assert(c_min(0, 0) == 0);
                c_assert(c_less_by(0, 0) == 0);
                c_assert(c_clamp(0, 0, 0) == 0);
                c_assert(c_div_round_up(1, 1) == 1);
        }

        /* c_align_to */
        {
                c_assert(c_align_to(0, 0) == 0);
        }

        /* c_assert */
        {
                c_assert(true);
        }

        /* C_DEFINE_CLEANUP / C_DEFINE_DIRECT_CLEANUP */
        {
                int v = 0;

                cleanup_fnp(&v);
                direct_cleanup_fnp(&v);
        }
}

static void test_api_functions(void) {
        void *fns[] = {
                (void *)c_errno,
                (void *)c_free,
                (void *)c_close,
                (void *)c_fclose,
                (void *)c_closedir,
                (void *)c_freep,
                (void *)c_closep,
                (void *)c_fclosep,
                (void *)c_closedirp,
        };
        size_t i;

        for (i = 0; i < sizeof(fns) / sizeof(*fns); ++i)
                c_assert(!!fns[i]);
}

int main(int argc, char **argv) {
        test_api_macros();
        test_api_functions();
        return 0;
}
