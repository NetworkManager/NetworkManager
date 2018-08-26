/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#define _printf_(a, b) __attribute__ ((format (printf, a, b)))
#ifdef __clang__
#  define _alloc_(...)
#else
#  define _alloc_(...) __attribute__ ((alloc_size(__VA_ARGS__)))
#endif
#define _sentinel_ __attribute__ ((sentinel))
#define _unused_ __attribute__ ((unused))
#define _destructor_ __attribute__ ((destructor))
#define _pure_ __attribute__ ((pure))
#define _const_ __attribute__ ((const))
#define _deprecated_ __attribute__ ((deprecated))
#define _packed_ __attribute__ ((packed))
#define _malloc_ __attribute__ ((malloc))
#define _weak_ __attribute__ ((weak))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _public_ __attribute__ ((visibility("default")))
#define _hidden_ __attribute__ ((visibility("hidden")))
#define _weakref_(x) __attribute__((weakref(#x)))
#define _alignas_(x) __attribute__((aligned(__alignof(x))))
#define _cleanup_(x) __attribute__((cleanup(x)))
#if __GNUC__ >= 7
#define _fallthrough_ __attribute__((fallthrough))
#else
#define _fallthrough_
#endif
/* Define C11 noreturn without <stdnoreturn.h> and even on older gcc
 * compiler versions */
#ifndef _noreturn_
#if __STDC_VERSION__ >= 201112L
#define _noreturn_ _Noreturn
#else
#define _noreturn_ __attribute__((noreturn))
#endif
#endif

#if !defined(HAS_FEATURE_MEMORY_SANITIZER)
#  if defined(__has_feature)
#    if __has_feature(memory_sanitizer)
#      define HAS_FEATURE_MEMORY_SANITIZER 1
#    endif
#  endif
#  if !defined(HAS_FEATURE_MEMORY_SANITIZER)
#    define HAS_FEATURE_MEMORY_SANITIZER 0
#  endif
#endif

#if (defined (__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))) || defined (__clang__)
/* Temporarily disable some warnings */
#define DISABLE_WARNING_DECLARATION_AFTER_STATEMENT                     \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")

#define DISABLE_WARNING_FORMAT_NONLITERAL                               \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"")

#define DISABLE_WARNING_MISSING_PROTOTYPES                              \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wmissing-prototypes\"")

#define DISABLE_WARNING_NONNULL                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wnonnull\"")

#define DISABLE_WARNING_SHADOW                                          \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wshadow\"")

#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                      \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")

#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")
#else
#define DISABLE_WARNING_DECLARATION_AFTER_STATEMENT
#define DISABLE_WARNING_FORMAT_NONLITERAL
#define DISABLE_WARNING_MISSING_PROTOTYPES
#define DISABLE_WARNING_NONNULL
#define DISABLE_WARNING_SHADOW
#define REENABLE_WARNING
#endif

/* automake test harness */
#define EXIT_TEST_SKIP 77

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

/* builtins */
#if __SIZEOF_INT__ == 4
#define BUILTIN_FFS_U32(x) __builtin_ffs(x);
#elif __SIZEOF_LONG__ == 4
#define BUILTIN_FFS_U32(x) __builtin_ffsl(x);
#else
#error "neither int nor long are four bytes long?!?"
#endif

/* Rounds up */

#define ALIGN4(l) (((l) + 3) & ~3)
#define ALIGN8(l) (((l) + 7) & ~7)

#if __SIZEOF_POINTER__ == 8
#define ALIGN(l) ALIGN8(l)
#elif __SIZEOF_POINTER__ == 4
#define ALIGN(l) ALIGN4(l)
#else
#error "Wut? Pointers are neither 4 nor 8 bytes long?"
#endif

#define ALIGN_PTR(p) ((void*) ALIGN((unsigned long) (p)))
#define ALIGN4_PTR(p) ((void*) ALIGN4((unsigned long) (p)))
#define ALIGN8_PTR(p) ((void*) ALIGN8((unsigned long) (p)))

static inline size_t ALIGN_TO(size_t l, size_t ali) {
        return ((l + ali - 1) & ~(ali - 1));
}

#define ALIGN_TO_PTR(p, ali) ((void*) ALIGN_TO((unsigned long) (p), (ali)))

/* align to next higher power-of-2 (except for: 0 => 0, overflow => 0) */
static inline unsigned long ALIGN_POWER2(unsigned long u) {
        /* clz(0) is undefined */
        if (u == 1)
                return 1;

        /* left-shift overflow is undefined */
        if (__builtin_clzl(u - 1UL) < 1)
                return 0;

        return 1UL << (sizeof(u) * 8 - __builtin_clzl(u - 1UL));
}

#ifndef __COVERITY__
#  define VOID_0 ((void)0)
#else
#  define VOID_0 ((void*)0)
#endif

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                VOID_0))

/*
 * STRLEN - return the length of a string literal, minus the trailing NUL byte.
 *          Contrary to strlen(), this is a constant expression.
 * @x: a string literal.
 */
#define STRLEN(x) (sizeof(""x"") - 1)

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define container_of(ptr, type, member) __container_of(UNIQ, (ptr), type, member)
#define __container_of(uniq, ptr, type, member)                         \
        ({                                                              \
                const typeof( ((type*)0)->member ) *UNIQ_T(A, uniq) = (ptr); \
                (type*)( (char *)UNIQ_T(A, uniq) - offsetof(type, member) ); \
        })

#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

/* evaluates to (void) if _A or _B are not constant or of different types */
#define CONST_MAX(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                VOID_0))

/* takes two types and returns the size of the larger one */
#define MAXSIZE(A, B) (sizeof(union _packed_ { typeof(A) a; typeof(B) b; }))

#define MAX3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MAX(x, y);         \
                MAX(_c, z);                             \
        })

#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

#define MIN3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MIN(x, y);         \
                MIN(_c, z);                             \
        })

#define LESS_BY(a, b) __LESS_BY(UNIQ, (a), UNIQ, (b))
#define __LESS_BY(aq, a, bq, b)                         \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) - UNIQ_T(B, bq) : 0; \
        })

#define CMP(a, b) __CMP(UNIQ, (a), UNIQ, (b))
#define __CMP(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? -1 :    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? 1 : 0;  \
        })

#undef CLAMP
#define CLAMP(x, low, high) __CLAMP(UNIQ, (x), UNIQ, (low), UNIQ, (high))
#define __CLAMP(xq, x, lowq, low, highq, high)                          \
        ({                                                              \
                const typeof(x) UNIQ_T(X, xq) = (x);                    \
                const typeof(low) UNIQ_T(LOW, lowq) = (low);            \
                const typeof(high) UNIQ_T(HIGH, highq) = (high);        \
                        UNIQ_T(X, xq) > UNIQ_T(HIGH, highq) ?           \
                                UNIQ_T(HIGH, highq) :                   \
                                UNIQ_T(X, xq) < UNIQ_T(LOW, lowq) ?     \
                                        UNIQ_T(LOW, lowq) :             \
                                        UNIQ_T(X, xq);                  \
        })

/* [(x + y - 1) / y] suffers from an integer overflow, even though the
 * computation should be possible in the given type. Therefore, we use
 * [x / y + !!(x % y)]. Note that on "Real CPUs" a division returns both the
 * quotient and the remainder, so both should be equally fast. */
#define DIV_ROUND_UP(_x, _y)                                            \
        ({                                                              \
                const typeof(_x) __x = (_x);                            \
                const typeof(_y) __y = (_y);                            \
                (__x / __y + !!(__x % __y));                            \
        })

#ifdef __COVERITY__

/* Use special definitions of assertion macros in order to prevent
 * false positives of ASSERT_SIDE_EFFECT on Coverity static analyzer
 * for uses of assert_se() and assert_return().
 *
 * These definitions make expression go through a (trivial) function
 * call to ensure they are not discarded. Also use ! or !! to ensure
 * the boolean expressions are seen as such.
 *
 * This technique has been described and recommended in:
 * https://community.synopsys.com/s/question/0D534000046Yuzb/suppressing-assertsideeffect-for-functions-that-allow-for-sideeffects
 */

extern void __coverity_panic__(void);

static inline int __coverity_check__(int condition) {
        return condition;
}

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (__coverity_check__(!(expr)))                        \
                        __coverity_panic__();                           \
        } while (false)

#define assert_log(expr, message) __coverity_check__(!!(expr))

#else  /* ! __COVERITY__ */

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(message, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, __FILE__, __LINE__, __PRETTY_FUNCTION__), false))

#endif  /* __COVERITY__ */

#define assert_se(expr) assert_message_se(expr, #expr)

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) do {} while (false)
#else
#define assert(expr) assert_message_se(expr, #expr)
#endif

#define assert_not_reached(t)                                           \
        do {                                                            \
                log_assert_failed_unreachable(t, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

#if defined(static_assert)
/* static_assert() is sometimes defined in a way that trips up
 * -Wdeclaration-after-statement, hence let's temporarily turn off
 * this warning around it. */
#define assert_cc(expr)                                                 \
        DISABLE_WARNING_DECLARATION_AFTER_STATEMENT;                    \
        static_assert(expr, #expr);                                     \
        REENABLE_WARNING
#else
#define assert_cc(expr)                                                 \
        DISABLE_WARNING_DECLARATION_AFTER_STATEMENT;                    \
        struct CONCATENATE(_assert_struct_, __COUNTER__) {              \
                char x[(expr) ? 0 : -1];                                \
        };                                                              \
        REENABLE_WARNING
#endif

#define assert_return(expr, r)                                          \
        do {                                                            \
                if (!assert_log(expr, #expr))                           \
                        return (r);                                     \
        } while (false)

#define assert_return_errno(expr, r, err)                               \
        do {                                                            \
                if (!assert_log(expr, #expr)) {                         \
                        errno = err;                                    \
                        return (r);                                     \
                }                                                       \
        } while (false)

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define LONG_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define ULONG_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define INT32_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define UINT32_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_INT64(p) ((int64_t) ((intptr_t) (p)))
#define INT64_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT64(p) ((uint64_t) ((uintptr_t) (p)))
#define UINT64_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_SIZE(p) ((size_t) ((uintptr_t) (p)))
#define SIZE_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define CHAR_TO_STR(x) ((char[2]) { x, 0 })

#define char_array_0(x) x[sizeof(x)-1] = 0;

/* Returns the number of chars needed to format variables of the
 * specified type as a decimal string. Adds in extra space for a
 * negative '-' prefix (hence works correctly on signed
 * types). Includes space for the trailing NUL. */
#define DECIMAL_STR_MAX(type)                                           \
        (2+(sizeof(type) <= 1 ? 3 :                                     \
            sizeof(type) <= 2 ? 5 :                                     \
            sizeof(type) <= 4 ? 10 :                                    \
            sizeof(type) <= 8 ? 20 : sizeof(int[-2*(sizeof(type) > 8)])))

#define DECIMAL_STR_WIDTH(x)                            \
        ({                                              \
                typeof(x) _x_ = (x);                    \
                unsigned ans = 1;                       \
                while ((_x_ /= 10) != 0)                \
                        ans++;                          \
                ans;                                    \
        })

#define SET_FLAG(v, flag, b) \
        (v) = (b) ? ((v) | (flag)) : ((v) & ~(flag))
#define FLAGS_SET(v, flags) \
        (((v) & (flags)) == (flags))

#define CASE_F(X) case X:
#define CASE_F_1(CASE, X) CASE_F(X)
#define CASE_F_2(CASE, X, ...)  CASE(X) CASE_F_1(CASE, __VA_ARGS__)
#define CASE_F_3(CASE, X, ...)  CASE(X) CASE_F_2(CASE, __VA_ARGS__)
#define CASE_F_4(CASE, X, ...)  CASE(X) CASE_F_3(CASE, __VA_ARGS__)
#define CASE_F_5(CASE, X, ...)  CASE(X) CASE_F_4(CASE, __VA_ARGS__)
#define CASE_F_6(CASE, X, ...)  CASE(X) CASE_F_5(CASE, __VA_ARGS__)
#define CASE_F_7(CASE, X, ...)  CASE(X) CASE_F_6(CASE, __VA_ARGS__)
#define CASE_F_8(CASE, X, ...)  CASE(X) CASE_F_7(CASE, __VA_ARGS__)
#define CASE_F_9(CASE, X, ...)  CASE(X) CASE_F_8(CASE, __VA_ARGS__)
#define CASE_F_10(CASE, X, ...) CASE(X) CASE_F_9(CASE, __VA_ARGS__)
#define CASE_F_11(CASE, X, ...) CASE(X) CASE_F_10(CASE, __VA_ARGS__)
#define CASE_F_12(CASE, X, ...) CASE(X) CASE_F_11(CASE, __VA_ARGS__)
#define CASE_F_13(CASE, X, ...) CASE(X) CASE_F_12(CASE, __VA_ARGS__)
#define CASE_F_14(CASE, X, ...) CASE(X) CASE_F_13(CASE, __VA_ARGS__)
#define CASE_F_15(CASE, X, ...) CASE(X) CASE_F_14(CASE, __VA_ARGS__)
#define CASE_F_16(CASE, X, ...) CASE(X) CASE_F_15(CASE, __VA_ARGS__)
#define CASE_F_17(CASE, X, ...) CASE(X) CASE_F_16(CASE, __VA_ARGS__)
#define CASE_F_18(CASE, X, ...) CASE(X) CASE_F_17(CASE, __VA_ARGS__)
#define CASE_F_19(CASE, X, ...) CASE(X) CASE_F_18(CASE, __VA_ARGS__)
#define CASE_F_20(CASE, X, ...) CASE(X) CASE_F_19(CASE, __VA_ARGS__)

#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,NAME,...) NAME
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12,CASE_F_11, \
                               CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (CASE_F,__VA_ARGS__)

#define IN_SET(x, ...)                          \
        ({                                      \
                bool _found = false;            \
                /* If the build breaks in the line below, you need to extend the case macros */ \
                static _unused_ char _static_assert__macros_need_to_be_extended[20 - sizeof((int[]){__VA_ARGS__})/sizeof(int)]; \
                switch(x) {                     \
                FOR_EACH_MAKE_CASE(__VA_ARGS__) \
                        _found = true;          \
                        break;                  \
                default:                        \
                        break;                  \
                }                               \
                _found;                         \
        })

#define SWAP_TWO(x, y) do {                        \
                typeof(x) _t = (x);                \
                (x) = (y);                         \
                (y) = (_t);                        \
        } while (false)

/* Define C11 thread_local attribute even on older gcc compiler
 * version */
#ifndef thread_local
/*
 * Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769
 */
#if __STDC_VERSION__ >= 201112L && !(defined(__STDC_NO_THREADS__) || (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16))
#define thread_local _Thread_local
#else
#define thread_local __thread
#endif
#endif

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }

#include "log.h"
