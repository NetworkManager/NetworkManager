#pragma once

/*
 * c-stdaux-gnuc: GNUC-specific auxiliary macros and functions
 *
 * This header contains all GNUC-specific features of c-stdaux.h, usually only
 * available when compiled via GCC or clang.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <c-stdaux-generic.h>

/* Documented alongside target properties. */
#define C_MODULE_GNUC 1

/**
 * DOC: GNUC Compiler Attributes
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
 * DOC: GNUC-Specific Utility Macros
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

#ifdef __cplusplus
}
#endif
