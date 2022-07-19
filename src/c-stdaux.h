#pragma once

/*
 * c-stdaux: Auxiliary macros and functions for the C standard library
 *
 * Main public header of the c-stdaux library. All includes of this header are
 * part of the API!
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DOC:
 *
 * The ``c-stdaux.h`` header contains a collection of auxiliary macros and
 * helper functions around the functionality provided by the different C
 * standard library implementations, as well as other specifications
 * implemented by them.
 *
 * Most of the helpers provided here provide aliases for common library and
 * compiler features. Furthermore, several helpers simply provide other calling
 * conventions than their standard counterparts (e.g., they allow for NULL to
 * be passed with an object length of 0 where it makes sense to accept empty
 * input).
 *
 * The namespace used by this project is:
 *
 * -  ``c_*`` for all common C symbols or definitions that behave like proper C
 *    entities (e.g., macros that protect against double-evaluation would use
 *    lower-case names).
 *
 * -  ``C_*`` for all constants, as well as macros that may not be safe against
 *    double evaluation.
 *
 * -  ``c_internal_*`` and ``C_INTERNAL_*`` for all internal symbols that
 *    should not be invoked by the caller and are not part of the API
 *    guarantees.
 */
/**/

/**
 * DOC: Guaranteed Includes
 *
 * The ``c-stdaux.h`` header includes a set of C Standard Library headers as
 * well as UNIX headers. All those includes are guaranteed and part of the API.
 * See the actual header for a comprehensive list.
 */
/**/

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/**
 * DOC: Compiler Attributes
 *
 * The GCC compiler uses the ``__attribute__((__xyz__()))`` syntax to annotate
 * language entities with special attributes. Aliases are provided by this
 * header which map one-to-one to the respective compiler attributes.
 *
 * These attributes are not supported by all compilers, but are always provided
 * by this header. They are pre-processor macros and do not affect the
 * compilation, unless used. Note that most compilers support these, not just
 * GCC.
 */
/**/

/**
 * _c_cleanup_() - Cleanup attribute
 * @_x:                 Cleanup function to use
 *
 * Alias for ``__attribute__((__cleanup__(_x)))``.
 */
#define _c_cleanup_(_x) __attribute__((__cleanup__(_x)))

/**
 * _c_const_() - Const attribute
 *
 * Alias for ``__attribute__((__const__))``.
 */
#define _c_const_ __attribute__((__const__))

/**
 * _c_deprecated_() - Deprecated attribute
 *
 * Alias for ``__attribute__((__deprecated__))``.
 */
#define _c_deprecated_ __attribute__((__deprecated__))

/**
 * _c_hidden_() - Hidden attribute
 *
 * Alias for ``__attribute__((__visibility__("hidden")))``.
 */
#define _c_hidden_ __attribute__((__visibility__("hidden")))

/**
 * _c_packed_() - Packed attribute
 *
 * Alias for ``__attribute__((__packed__))``.
 */
#define _c_packed_ __attribute__((__packed__))

/**
 * _c_printf_() - Printf attribute
 * @_a:                 Format expression argument index
 * @_b:                 First format-parameter argument index
 *
 * Alias for ``__attribute__((__format__(printf, _a, _b)))``.
 */
#define _c_printf_(_a, _b) __attribute__((__format__(printf, _a, _b)))

/**
 * _c_public_() - Public attribute
 *
 * Alias for ``__attribute__((__visibility__("default")))``.
 */
#define _c_public_ __attribute__((__visibility__("default")))

/**
 * _c_pure_() - Pure attribute
 *
 * Alias for ``__attribute__((__pure__))``.
 */
#define _c_pure_ __attribute__((__pure__))

/**
 * _c_sentinel_() - Sentinel attribute
 *
 * Alias for ``__attribute__((__sentinel__))``.
 */
#define _c_sentinel_ __attribute__((__sentinel__))

/**
 * _c_unused_() - Unused attribute
 *
 * Alias for ``__attribute__((__unused__))``.
 */
#define _c_unused_ __attribute__((__unused__))

/**
 * DOC: Compiler Intrinsics
 *
 * Aliases for common compiler extensions and intrinsics are provided similar
 * to the compiler attributes. They are pure preprocessor aliases and do not
 * affect compilation unless used.
 */
/**/

/**
 * _c_likely_() - Likely attribute
 * @_x:                 Expression to evaluate
 *
 * Alias for ``__builtin_expect(!!(_x), 1)``.
 *
 * Return: The expression ``_x`` is evaluated and returned.
 */
#define _c_likely_(_x) (__builtin_expect(!!(_x), 1))

/**
 * _c_unlikely_() - Unlikely attribute
 * @_x:                 Expression to evaluate
 *
 * Alias for ``__builtin_expect(!!(_x), 0)``.
 *
 * Return: The expression ``_x`` is evaluated and returned.
 */
#define _c_unlikely_(_x) (__builtin_expect(!!(_x), 0))

/**
 * DOC: Utility Macros
 *
 * A set of utility macros is provided which aids in creating safe macros
 * suitable for use in other pre-processor statements as well as in C
 * expressions.
 */
/**/

/**
 * C_EXPR_ASSERT() - Create expression with assertion
 * @_expr:              Expression to evaluate to
 * @_assertion:         Arbitrary assertion
 * @_message:           Message associated with the assertion
 *
 * This macro simply evaluates to ``_expr``. That is, it can be used in any
 * context that expects an expression like ``_expr``. Additionally, it takes an
 * assertion as ``_assertion`` and evaluates it through ``_Static_assert()``,
 * using ``_message`` as debug message.
 *
 * The ``_Static_assert()`` builtin of C11 is defined as statement and thus
 * cannot be used in expressions. This macro circumvents this restriction.
 *
 * Return: Evaluates to ``_expr``.
 */
#define C_EXPR_ASSERT(_expr, _assertion, _message) C_INTERNAL_EXPR_ASSERT((_expr), (_assertion), _message)
#if defined(__COVERITY__) // Coverity cannot const-fold __builtin_choose_expr()
#  define C_INTERNAL_EXPR_ASSERT(_expr, _assertion, _message) (_expr)
#else
#  define C_INTERNAL_EXPR_ASSERT(_expr, _assertion, _message)           \
        /* indentation and line-split to get better diagnostics */      \
        (__builtin_choose_expr(                                         \
                !!(1 + 0 * sizeof(                                      \
                        struct {                                        \
_Static_assert(_assertion, _message); \
                        }                                               \
                )),                                                     \
                (_expr),                                                \
                ((void)0)                                               \
        ))
#endif

/**
 * C_STRINGIFY() - Stringify a token, but evaluate it first
 * @_x:         Token to evaluate and stringify
 *
 * Return: Evaluates to a constant string literal
 */
#define C_STRINGIFY(_x) C_INTERNAL_STRINGIFY(_x)
#define C_INTERNAL_STRINGIFY(_x) #_x

/**
 * C_CONCATENATE() - Concatenate two tokens, but evaluate them first
 * @_x:         First token
 * @_y:         Second token
 *
 * Return: Evaluates to a constant identifier
 */
#define C_CONCATENATE(_x, _y) C_INTERNAL_CONCATENATE(_x, _y)
#define C_INTERNAL_CONCATENATE(_x, _y) _x ## _y

/**
 * C_EXPAND() - Expand a tuple to a series of its values
 * @_x:         Tuple to expand
 *
 * Return: Evaluates to the expanded tuple
 */
#define C_EXPAND(_x) C_INTERNAL_EXPAND _x
#define C_INTERNAL_EXPAND(...) __VA_ARGS__

/**
 * C_VAR() - Generate unique variable name
 * @_x:         Name of variable, optional
 * @_uniq:      Unique prefix, usually provided by ``__COUNTER__``, optional
 *
 * This macro shall be used to generate unique variable names, that will not be
 * shadowed by recursive macro invocations. It is effectively a
 * :c:macro:`C_CONCATENATE` of both arguments, but also provides a globally
 * separated prefix and makes the code better readable.
 *
 * The second argument is optional. If not given, ``__LINE__`` is implied, and
 * as such the macro will generate the same identifier if used multiple times
 * on the same code-line (or within a macro). This should be used if recursive
 * calls into the macro are not expected. In fact, no argument is necessary in
 * this case, as a mere ``C_VAR`` will evaluate to a valid variable name.
 *
 * This helper may be used by macro implementations that might reasonable well
 * be called in a stacked fasion, like:
 *
 * .. code-block:: c
 *
 *     c_max(foo, c_max(bar, baz))
 *
 * Such a stacked call of :c:macro:`c_max()` might cause compiler warnings of
 * shadowed variables in the definition of :c:macro:`c_max()`. By using
 * ``C_VAR()``, such warnings can be silenced as each evaluation of
 * :c:macro:`c_max()` uses unique variable names.
 *
 * Return: This evaluates to a constant identifier.
 */
#define C_VAR(...) C_INTERNAL_VAR(__VA_ARGS__, 2, 1)
#define C_INTERNAL_VAR(_x, _uniq, _num, ...) C_VAR ## _num (_x, _uniq)
#define C_VAR1(_x, _unused) C_VAR2(_x, C_CONCATENATE(line, __LINE__))
#define C_VAR2(_x, _uniq) C_CONCATENATE(c_internal_var_unique_, C_CONCATENATE(_uniq, _x))

/**
 * C_CC_MACRO1() - Provide safe environment to a macro
 * @_call:      Macro to call
 * @_x1:        First argument
 * @...:        Further arguments to forward unmodified to ``_call``
 *
 * This function simplifies the implementation of macros. Whenever you
 * implement a macro, provide the internal macro name as ``_call`` and its
 * argument as ``_x1``. Inside of your internal macro, you...
 *
 * -  are safe against multiple evaluation errors, since ``C_CC_MACRO1``
 *    will store the initial parameters in temporary variables.
 *
 * -  support constant folding, as ``C_CC_MACRO1`` takes care to invoke your
 *    macro with the original values, if they are compile-time constant.
 *
 * -  have unique variable names for recursive callers and will not run into
 *    variable-shadowing-warnings accidentally.
 *
 * -  have properly typed arguments as ``C_CC_MACRO1`` stores the original
 *    arguments in an ``__auto_type`` temporary variable.
 *
 * Return: Result of ``_call`` is returned.
 */
#define C_CC_MACRO1(_call, _x1, ...) C_INTERNAL_CC_MACRO1(_call, __COUNTER__, (_x1), ## __VA_ARGS__)
#define C_INTERNAL_CC_MACRO1(_call, _x1q, _x1, ...)                     \
        __builtin_choose_expr(                                          \
                __builtin_constant_p(_x1),                              \
                _call(_x1, ## __VA_ARGS__),                             \
                __extension__ ({                                        \
                        const __auto_type C_VAR(X1, _x1q) = (_x1);      \
                        _call(C_VAR(X1, _x1q), ## __VA_ARGS__);         \
                }))

/**
 * C_CC_MACRO2() - Provide safe environment to a macro
 * @_call:      Macro to call
 * @_x1:        First argument
 * @_x2:        Second argument
 * @...:        Further arguments to forward unmodified to ``_call``
 *
 * This is the 2-argument equivalent of :c:macro:`C_CC_MACRO1()`.
 *
 * Return: Result of ``_call`` is returned.
 */
#define C_CC_MACRO2(_call, _x1, _x2, ...) C_INTERNAL_CC_MACRO2(_call, __COUNTER__, (_x1), __COUNTER__, (_x2), ## __VA_ARGS__)
#define C_INTERNAL_CC_MACRO2(_call, _x1q, _x1, _x2q, _x2, ...)                          \
        __builtin_choose_expr(                                                          \
                (__builtin_constant_p(_x1) && __builtin_constant_p(_x2)),               \
                _call((_x1), (_x2), ## __VA_ARGS__),                                    \
                __extension__ ({                                                        \
                        const __auto_type C_VAR(X1, _x1q) = (_x1);                      \
                        const __auto_type C_VAR(X2, _x2q) = (_x2);                      \
                        _call(C_VAR(X1, _x1q), C_VAR(X2, _x2q), ## __VA_ARGS__);        \
                }))

/**
 * C_CC_MACRO3() - Provide safe environment to a macro
 * @_call:      Macro to call
 * @_x1:        First argument
 * @_x2:        Second argument
 * @_x3:        Third argument
 * @...:        Further arguments to forward unmodified to ``_call``
 *
 * This is the 3-argument equivalent of :c:macro:`C_CC_MACRO1()`.
 *
 * Return: Result of ``_call`` is returned.
 */
#define C_CC_MACRO3(_call, _x1, _x2, _x3, ...) C_INTERNAL_CC_MACRO3(_call, __COUNTER__, (_x1), __COUNTER__, (_x2), __COUNTER__, (_x3), ## __VA_ARGS__)
#define C_INTERNAL_CC_MACRO3(_call, _x1q, _x1, _x2q, _x2, _x3q, _x3, ...)                               \
        __builtin_choose_expr(                                                                          \
                (__builtin_constant_p(_x1) && __builtin_constant_p(_x2) && __builtin_constant_p(_x3)),  \
                _call((_x1), (_x2), (_x3), ## __VA_ARGS__),                                             \
                __extension__ ({                                                                        \
                        const __auto_type C_VAR(X1, _x1q) = (_x1);                                      \
                        const __auto_type C_VAR(X2, _x2q) = (_x2);                                      \
                        const __auto_type C_VAR(X3, _x3q) = (_x3);                                      \
                        _call(C_VAR(X1, _x1q), C_VAR(X2, _x2q), C_VAR(X3, _x3q), ## __VA_ARGS__);       \
                }))

/**
 * DOC: Standard Library Utilities
 *
 * The C Standard Library lacks some crucial and basic support functions. This
 * section describes the set of helpers provided as extension to the standard
 * library.
 */
/**/

/**
 * C_ARRAY_SIZE() - Calculate number of array elements at compile time
 * @_x:         Array to calculate size of
 *
 * Return: Evaluates to a constant integer expression.
 */
#define C_ARRAY_SIZE(_x)                                                \
        C_EXPR_ASSERT(sizeof(_x) / sizeof((_x)[0]),                     \
               /*                                                       \
                * Verify that `_x' is an array, not a pointer. Rely on  \
                * `&_x[0]' degrading arrays to pointers.                \
                */                                                      \
                !__builtin_types_compatible_p(                          \
                        __typeof__(_x),                                 \
                        __typeof__(&(*(__typeof__(_x)*)0)[0])           \
                ),                                                      \
                "C_ARRAY_SIZE() called with non-array argument"         \
        )

/**
 * C_DECIMAL_MAX() - Calculate maximum length of a decimal representation
 * @_type: Integer variable/type
 *
 * This calculates the bytes required for the decimal representation of an
 * integer of the given type. It accounts for a possible +/- prefix, but it
 * does *NOT* include the trailing terminating zero byte.
 *
 * Return: Evaluates to a constant integer expression
 */
#define C_DECIMAL_MAX(_arg)                                                             \
        (_Generic((__typeof__(_arg)){ 0 },                                              \
                        char: C_INTERNAL_DECIMAL_MAX(sizeof(char)),                     \
                 signed char: C_INTERNAL_DECIMAL_MAX(sizeof(signed char)),              \
               unsigned char: C_INTERNAL_DECIMAL_MAX(sizeof(unsigned char)),            \
                signed short: C_INTERNAL_DECIMAL_MAX(sizeof(signed short)),             \
              unsigned short: C_INTERNAL_DECIMAL_MAX(sizeof(unsigned short)),           \
                  signed int: C_INTERNAL_DECIMAL_MAX(sizeof(signed int)),               \
                unsigned int: C_INTERNAL_DECIMAL_MAX(sizeof(unsigned int)),             \
                 signed long: C_INTERNAL_DECIMAL_MAX(sizeof(signed long)),              \
               unsigned long: C_INTERNAL_DECIMAL_MAX(sizeof(unsigned long)),            \
            signed long long: C_INTERNAL_DECIMAL_MAX(sizeof(signed long long)),         \
          unsigned long long: C_INTERNAL_DECIMAL_MAX(sizeof(unsigned long long))))
#define C_INTERNAL_DECIMAL_MAX(_bytes)                                          \
        C_EXPR_ASSERT(                                                          \
                1 + ((_bytes) <= 1 ?  3 :                                       \
                     (_bytes) <= 2 ?  5 :                                       \
                     (_bytes) <= 4 ? 10 :                                       \
                                     20),                                       \
                (_bytes) <= 8,                                                  \
                "Invalid use of C_INTERNAL_DECIMAL_MAX()"                       \
        )

/**
 * c_container_of() - Cast a member of a structure out to the containing type
 * @_ptr:       Pointer to the member or NULL
 * @_type:      Type of the container struct this is embedded in
 * @_member:    Name of the member within the struct
 *
 * This uses ``offsetof(3)`` to turn a pointer to a structure-member into a
 * pointer to the surrounding structure.
 *
 * Return: Pointer to the surrounding object.
 */
#define c_container_of(_ptr, _type, _member) C_CC_MACRO1(C_CONTAINER_OF, (_ptr), _type, _member)
#define C_CONTAINER_OF(_ptr, _type, _member)                                            \
        C_EXPR_ASSERT(                                                                  \
                (_ptr ? (_type*)c_internal_container_of((void *)_ptr, offsetof(_type, _member)) : NULL),     \
                __builtin_types_compatible_p(                                           \
                        __typeof__(*(_ptr)),                                            \
                        __typeof__(((_type){})._member)                                 \
                ) || __builtin_types_compatible_p(                                      \
                        __typeof__(_ptr),                                               \
                        __typeof__(NULL)                                                \
                ),                                                                      \
                "Invalid use of C_CONTAINER_OF()"                                       \
        )
static inline void *c_internal_container_of(void *ptr, size_t offset) {
        /*
         * Arithmetic on NULL is UB, even if in dead-code. Hide it in a proper
         * C function, so the macro never emits it as code.
         */
        return (char *)ptr - offset;
}

/**
 * c_max() - Compute maximum of two values
 * @_a:         Value A
 * @_b:         Value B
 *
 * Calculate the maximum of both passed values. Both arguments are evaluated
 * exactly once, under all circumstances. Furthermore, if both values are
 * constant expressions, the result will be constant as well.
 *
 * The comparison of their values is performed with the types given by the
 * caller. It is the caller's responsibility to convert them to suitable types
 * if necessary.
 *
 * Return: Maximum of both values is returned.
 */
#define c_max(_a, _b) C_CC_MACRO2(C_MAX, (_a), (_b))
#define C_MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

/**
 * c_min() - Compute minimum of two values
 * @_a:         Value A
 * @_b:         Value B
 *
 * Calculate the minimum of both passed values. Both arguments are evaluated
 * exactly once, under all circumstances. Furthermore, if both values are
 * constant expressions, the result will be constant as well.
 *
 * The comparison of their values is performed with the types given by the
 * caller. It is the caller's responsibility to convert them to suitable types
 * if necessary.
 *
 * Return: Minimum of both values is returned.
 */
#define c_min(_a, _b) C_CC_MACRO2(C_MIN, (_a), (_b))
#define C_MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))

/**
 * c_less_by() - Calculate clamped difference of two values
 * @_a:         Minuend
 * @_b:         Subtrahend
 *
 * Calculate ``_a - _b``, but clamp the result to 0. Both arguments are
 * evaluated exactly once, under all circumstances. Furthermore, if both values
 * are constant expressions, the result will be constant as well.
 *
 * The comparison of their values is performed with the types given by the
 * caller. It is the caller's responsibility to convert them to suitable types
 * if necessary.
 *
 * Return: This computes ``_a - _b``, if ``_a > _b``. Otherwise, 0 is returned.
 */
#define c_less_by(_a, _b) C_CC_MACRO2(C_LESS_BY, (_a), (_b))
#define C_LESS_BY(_a, _b) ((_a) > (_b) ? (_a) - (_b) : 0)

/**
 * c_clamp() - Clamp value to lower and upper boundary
 * @_x:         Value to clamp
 * @_low:       Lower boundary
 * @_high:      Higher boundary
 *
 * This clamps ``_x`` to the lower and higher bounds given as ``_low`` and
 * ``_high``. All arguments are evaluated exactly once, and yield a constant
 * expression if all arguments are constant as well.
 *
 * The comparison of their values is performed with the types given by the
 * caller. It is the caller's responsibility to convert them to suitable types
 * if necessary.
 *
 * Return: Clamped integer value.
 */
#define c_clamp(_x, _low, _high) C_CC_MACRO3(C_CLAMP, (_x), (_low), (_high))
#define C_CLAMP(_x, _low, _high) ((_x) > (_high) ? (_high) : (_x) < (_low) ? (_low) : (_x))

/**
 * c_div_round_up() - Calculate integer quotient but round up
 * @_x:         Dividend
 * @_y:         Divisor
 *
 * Calculates ``x / y`` but rounds up the result to the next integer. All
 * arguments are evaluated exactly once, and yield a constant expression if all
 * arguments are constant.
 *
 * **Note:**
 * ``(x + y - 1) / y`` suffers from an integer overflow, even though the
 * computation should be possible in the given type. Therefore, we use
 * ``x / y + !!(x % y)``. Note that on most CPUs a division returns both the
 * quotient and the remainder, so both should be equally fast. Furthermore, if
 * the divisor is a power of two, the compiler will optimize it, anyway.
 *
 * The operationsare performed with the types given by the caller. It is the
 * caller's responsibility to convert the arguments to suitable types if
 * necessary.
 *
 * Return: The quotient is returned.
 */
#define c_div_round_up(_x, _y) C_CC_MACRO2(C_DIV_ROUND_UP, (_x), (_y))
#define C_DIV_ROUND_UP(_x, _y) ((_x) / (_y) + !!((_x) % (_y)))

/**
 * c_align_to() - Align value to a multiple
 * @_val:       Value to align
 * @_to:        Align to multiple of this
 *
 * This aligns ``_val`` to a multiple of ``_to``. If ``_val`` is already a
 * multiple of ``_to``, ``_val`` is returned unchanged. This function operates
 * within the boundaries of the type of ``_val`` and ``_to``. Make sure to cast
 * them if needed.
 *
 * The arguments of this macro are evaluated exactly once. If both arguments
 * are a constant expression, this also yields a constant return value.
 *
 * Note that ``_to`` must be a power of 2, otherwise the behavior will not
 * match expectations.
 *
 * Return: ``_val`` aligned to a multiple of ``_to``.
 */
#define c_align_to(_val, _to) C_CC_MACRO2(C_ALIGN_TO, (_val), (_to))
#define C_ALIGN_TO(_val, _to) (((_val) + (_to) - 1) & ~((_to) - 1))

/**
 * c_assert() - Runtime assertions
 * @expr_result:                Result of an expression
 *
 * This function behaves like the standard ``assert(3)`` macro. That is, if
 * ``NDEBUG`` is defined, it is a no-op. In all other cases it will assert that
 * the result of the passed expression is true.
 *
 * Unlike the standard ``assert(3)`` macro, this function always evaluates its
 * argument. This means side-effects will always be evaluated! However, if the
 * macro is used with constant expressions, the compiler will be able to
 * optimize it away.
 */
#define c_assert(_x) ({                                                         \
                const _c_unused_ bool c_assert_result = (_x);                   \
                assert(c_assert_result && #_x);                                 \
        })

/**
 * c_errno() - Return valid errno
 *
 * This helper should be used to shut up gcc if you know ``errno`` is valid
 * (ie., ``errno`` is greater than 0). Instead of ``return -errno;``, use
 * ``return -c_errno();`` It will suppress bogus gcc warnings in case it
 * assumes ``errno`` might be 0 (or smaller than 0) and thus the caller's
 * error-handling might not be triggered.
 *
 * This helper should be avoided whenever possible. However, occasionally we
 * really want to shut up gcc (especially with static/inline functions). In
 * those cases, gcc usually cannot deduce that some error paths are guaranteed
 * to be taken. Hence, making the return value explicit allows gcc to better
 * optimize the code.
 *
 * Note that you really should never use this helper to work around broken libc
 * calls or syscalls, not setting 'errno' correctly.
 *
 * Return: Positive error code is returned.
 */
static inline int c_errno(void) {
        return _c_likely_(errno > 0) ? errno : ENOTRECOVERABLE;
}

/**
 * c_memset() - Fill memory region with constant byte
 * @p:          Pointer to memory region, if non-empty
 * @c:          Value to fill with
 * @n:          Size of the memory region in bytes
 *
 * This function works like ``memset(3)`` if ``n`` is non-zero. If ``n`` is
 * zero, this function is a no-op. Therefore, unlike ``memset(3)`` it is safe
 * to call this function with ``NULL`` as ``p`` if ``n`` is 0.
 *
 * Return: ``p`` is returned.
 */
static inline void *c_memset(void *p, int c, size_t n) {
        if (n > 0)
                memset(p, c, n);
        return p;
}

/**
 * c_memzero() - Clear memory area
 * @p:          Pointer to memory region, if non-empty
 * @n:          Size of the memory region in bytes
 *
 * Clear a memory area to 0. If the memory area is empty, this is a no-op.
 * Similar to ``c_memset()``, this function allows ``p`` to be ``NULL`` if the
 * area is empty.
 *
 * Return: ``p`` is returned.
 */
static inline void *c_memzero(void *p, size_t n) {
        return c_memset(p, 0, n);
}

/**
 * c_memcpy() - Copy memory area
 * @dst:        Pointer to target area
 * @src:        Pointer to source area
 * @n:          Length of area to copy
 *
 * Copy the memory of size ``n`` from ``src`` to ``dst``, just as ``memcpy(3)``
 * does, except this function allows either to be ``NULL`` if ``n`` is zero. In
 * the latter case, the operation is a no-op.
 *
 * Return: ``p`` is returned.
 */
static inline void *c_memcpy(void *dst, const void *src, size_t n) {
        if (n > 0)
                memcpy(dst, src, n);
        return dst;
}

/**
 * c_memcmp() - Compare memory areas
 * @s1:         Pointer to one area
 * @s2:         Pointer to other area
 * @n:          Length of area to compare
 *
 * Compare the memory of size ``n`` of ``s1`` and ``s2``, just as ``memcmp(3)``
 * does, except this function allows either to be ``NULL`` if ``n`` is zero.
 *
 * Return: Comparison result for ordering is returned.
 */
static inline int c_memcmp(const void *s1, const void *s2, size_t n) {
        if (n > 0)
                return memcmp(s1, s2, n);
        return 0;
}

/**
 * DOC: Common Destructors
 *
 * A set of destructors is provided which extends standard library destructors
 * to adhere to some adjuvant rules. In particular, they return an invalid
 * value of the particular object, rather than void. This allows direct
 * assignment to any member-field and/or variable they are defined in, like:
 *
 * .. code-block:: c
 *
 *     foo = c_free(foo);
 *     foo->bar = c_close(foo->bar);
 *
 * Furthermore, all those destructors can be safely called with the "INVALID"
 * value as argument, and they will be a no-op.
 */
/**/

/**
 * c_free() - Destructor-wrapper for free()
 * @p:          Value to pass to destructor, or NULL
 *
 * Wrapper around ``free()``, but always returns ``NULL``.
 *
 * Return: NULL is returned.
 */
static inline void *c_free(void *p) {
        free(p);
        return NULL;
}

/**
 * c_close() - Destructor-wrapper for close()
 * @fd:         File-descriptor to pass to destructor, or negative value
 *
 * Wrapper around ``close()``, but a no-op if a negative value is provided.
 * Always returns ``-1``.
 *
 * Return: -1 is returned.
 */
static inline int c_close(int fd) {
        if (fd >= 0)
                close(fd);
        return -1;
}

/**
 * c_fclose() - Destructor-wrapper for fclose()
 * @f:          File handle to pass to destructor, or NULL
 *
 * Wrapper around ``fclose()``, but a no-op if ``NULL`` is passed. Always
 * returns ``NULL``.
 *
 * Return: NULL is returned.
 */
static inline FILE *c_fclose(FILE *f) {
        if (f)
                fclose(f);
        return NULL;
}

/**
 * c_closedir() - Destructor-wrapper for closedir)
 * @d:          Directory handle to pass to destructor, or NULL
 *
 * Wrapper around ``closedir()``, but a no-op if ``NULL`` is passed. Always
 * returns ``NULL``.
 *
 * Return: NULL is returned.
 */
static inline DIR *c_closedir(DIR *d) {
        if (d)
                closedir(d);
        return NULL;
}

/**
 * DOC: Common Cleanup Helpers
 *
 * A set of helpers that aid in creating functions suitable for use with
 * :c:macro:`_c_cleanup_()`. Furthermore, a collection of predefined cleanup
 * functions of a set of standard library objects ready for use with
 * :c:macro:`_c_cleanup_()`.
 * Those cleanup helpers are always suffixed with a ``p``.
 *
 * The helpers that are provided are:
 *
 * - ``c_freep()``: Wrapper around :c:func:`c_free()`.
 * - ``c_closep()``: Wrapper around :c:func:`c_close()`.
 * - ``c_fclosep()``: Wrapper around :c:func:`c_fclose()`.
 * - ``c_closedirp()``: Wrapper around :c:func:`c_closedir()`.
 */
/**/

/**
 * C_DEFINE_CLEANUP() - Define cleanup helper
 * @_type:                      Type of object to cleanup
 * @_func:                      Destructor of the respective type
 *
 * Define a C static inline function that takes a single argument of type
 * `_type` and calls `_func` on it, if its dereferenced value of its argument
 * evaluates to true. Otherwise, it is a no-op.
 *
 * This macro allows for very simple and fast creation of cleanup helpers for
 * use with ``_c_cleanup_()``, based on any destructor and type you provide to
 * it.
 */
#define C_DEFINE_CLEANUP(_type, _func)                                          \
        static inline void _func ## p(_type *p) {                               \
                if (*p)                                                         \
                        _func(*p);                                              \
        } struct c_internal_trailing_semicolon

/**
 * C_DEFINE_DIRECT_CLEANUP() - Define direct cleanup helper
 * @_type:                      Type of object to cleanup
 * @_func:                      Destructor of the respective type
 *
 * This works like :c:macro:`C_DEFINE_CLEANUP()` but does not check the
 * dereferenced value of its argument. It always unconditionally invokes the
 * destructor.
 */
#define C_DEFINE_DIRECT_CLEANUP(_type, _func)                                   \
        static inline void _func ## p(_type *p) {                               \
                _func(*p);                                                      \
        } struct c_internal_trailing_semicolon

static inline void c_freep(void *p) {
        /*
         * `foobar **` does not coerce to `void **`, so we need `void *` as
         * argument type, and then we dereference manually.
         */
        c_free(*(void **)p);
}

C_DEFINE_DIRECT_CLEANUP(int, c_close);
C_DEFINE_CLEANUP(FILE *, c_fclose);
C_DEFINE_CLEANUP(DIR *, c_closedir);

#ifdef __cplusplus
}
#endif
