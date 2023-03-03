/*
 * API Visibility Tests
 * This verifies the visibility and availability of the exported API.
 */

#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c-stdaux.h"

#if defined(C_MODULE_GENERIC)

static inline _c_always_inline_ int always_inline_fn(void) { return 0; }
_c_public_ int c_internal_public_fn(void);
_c_public_ int c_internal_public_fn(void) { return 0; }

static void cleanup_fn(int p) { (void)p; }
static void direct_cleanup_fn(int p) { (void)p; }
C_DEFINE_CLEANUP(int, cleanup_fn);
C_DEFINE_DIRECT_CLEANUP(int, direct_cleanup_fn);

static void test_api_generic(void) {
        /* C_COMPILER_* */
        {
#ifdef __clang__
                c_assert(C_COMPILER_CLANG);
#endif
#ifdef __GNUC__
                c_assert(C_COMPILER_GNUC);
#endif
#ifdef _MSC_VER
                c_assert(C_COMPILER_MSVC);
#endif
        }

        /* C_OS_* */
        {
#ifdef __linux__
                c_assert(C_OS_LINUX);
#endif
#ifdef __APPLE__
                c_assert(C_OS_MACOS);
#endif
#ifdef _WIN32
                c_assert(C_OS_WINDOWS);
#endif
        }

        /* _c_always_inline_ */
        {
                c_assert(!always_inline_fn());
        }

        /* _c_boolean_expr_ */
        {
                c_assert(_c_boolean_expr_(true));
        }

        /* _c_likely_ */
        {
                c_assert(_c_likely_(true));
        }

        /* _c_public_ */
        {
                c_assert(!c_internal_public_fn());
        }

        /* _c_unlikely_ */
        {
                c_assert(!_c_unlikely_(false));
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

        /* c_assume_aligned */
        {
                _Alignas(16) uint8_t data[8] = { 0 };

                c_assert(c_assume_aligned(data, 16, 0));
        }

        /* c_assert */
        {
                c_assert(true);
        }

        /* c_load */
        {
                uint64_t data[128] = { 0 };

                c_assert(c_load(uint64_t, le, aligned, data, 0) == 0);
        }

        /* C_DEFINE_CLEANUP / C_DEFINE_DIRECT_CLEANUP */
        {
                int v = 0;

                cleanup_fnp(&v);
                direct_cleanup_fnp(&v);
        }

        /* test availability of C symbols */
        {
                void *fns[] = {
                        (void *)c_errno,
                        (void *)c_memset,
                        (void *)c_memzero,
                        (void *)c_memcpy,
                        (void *)c_load_8,
                        (void *)c_load_16be_unaligned,
                        (void *)c_load_16be_aligned,
                        (void *)c_load_16le_unaligned,
                        (void *)c_load_16le_aligned,
                        (void *)c_load_32be_unaligned,
                        (void *)c_load_32be_aligned,
                        (void *)c_load_32le_unaligned,
                        (void *)c_load_32le_aligned,
                        (void *)c_load_64be_unaligned,
                        (void *)c_load_64be_aligned,
                        (void *)c_load_64le_unaligned,
                        (void *)c_load_64le_aligned,
                        (void *)c_free,
                        (void *)c_fclose,
                        (void *)c_freep,
                        (void *)c_fclosep,
                };
                size_t i;

                for (i = 0; i < sizeof(fns) / sizeof(*fns); ++i)
                        c_assert(!!fns[i]);
        }
}

#else /* C_MODULE_GENERIC */

static void test_api_generic(void) {
}

#endif /* C_MODULE_GENERIC */

#if defined(C_MODULE_GNUC)

static _c_const_ int const_fn(void) { return 0; }
static _c_deprecated_ _c_unused_ int deprecated_fn(void) { return 0; }
_c_hidden_ int c_internal_hidden_fn(void);
_c_hidden_ int c_internal_hidden_fn(void) { return 0; }
static _c_printf_(1, 2) int printf_fn(const _c_unused_ char *f, ...) { return 0; }
static _c_pure_ int pure_fn(void) { return 0; }
static _c_sentinel_ int sentinel_fn(const _c_unused_ char *f, ...) { return 0; }
static _c_unused_ int unused_fn(void) { return 0; }

static void test_api_gnuc(void) {
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

        /* _c_pure_ */
        {
                c_assert(!pure_fn());
        }

        /* _c_sentinel_ */
        {
                c_assert(!sentinel_fn("", NULL));
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
}

#else /* C_MODULE_GNUC */

static void test_api_gnuc(void) {
}

#endif /* C_MODULE_GNUC */

#if defined(C_MODULE_UNIX)

static void test_api_unix(void) {
        /* test availability of C symbols */
        {
                void *fns[] = {
                        (void *)c_close,
                        (void *)c_closedir,
                        (void *)c_closep,
                        (void *)c_closedirp,
                };
                size_t i;

                for (i = 0; i < sizeof(fns) / sizeof(*fns); ++i)
                        c_assert(!!fns[i]);
        }
}

#else /* C_MODULE_UNIX */

static void test_api_unix(void) {
}

#endif /* C_MODULE_UNIX */

int main(void) {
        test_api_generic();
        test_api_gnuc();
        test_api_unix();
        return 0;
}
