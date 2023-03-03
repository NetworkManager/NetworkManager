#pragma once

/*
 * c-stdaux-generic: Generic auxiliary macros and functions
 *
 * This header contains all generic features of c-stdaux.h, which are not
 * specific to a target platform.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Documented alongside target properties. */
#define C_MODULE_GENERIC 1

/**
 * DOC: Target Properties
 *
 * Since multiple target compilers and systems are supported, c-stdaux
 * exports a set of symbols that identify the target of the current compilation.
 * The following pre-processor constants are defined (and evaluate to ``1``) if
 * the current compilation targets the specific system. Note that multiple
 * constants might be defined at the same time if compatibility to multiple
 * targets is available.
 *
 * - ``C_COMPILER_CLANG``: The compiling software is compatible to the CLang
 *   LLVM Compiler.
 * - ``C_COMPILER_DOCS``: The compilation is part of generating documentation.
 * - ``C_COMPILER_GNUC``: The compiling software is compatible to the GNU C
 *   Compiler.
 * - ``C_COMPILER_MSVC``: The compiling software is compatible to Microsoft
 *   Visual Studio (use ``_MSC_VER`` to check for specific version support).
 * - ``C_OS_LINUX``: The target system is compatible to Linux.
 * - ``C_OS_MACOS``: The target system is compatible to Apple MacOS.
 * - ``C_OS_WINDOWS``: The target system is compatible to Microsoft Windows.
 * - ``C_MODULE_GENERIC``: The `*-generic.h` module was included.
 * - ``C_MODULE_GNUC``: The `*-gnuc.h` module was included.
 * - ``C_MODULE_UNIX``: The `*-unix.h` module was included.
 *
 * Note that other exported symbols might depend on one of these constants to
 * be set in order to be exposed. See the documentation of each symbol for
 * details. Furthermore, if stub implementations do not violate the guarantees
 * of a symbol, they will be provided for targets that do not provide the
 * necessary infrastructure (e.g., ``_c_likely_()`` is a no-op on MSVC).
 */
/**/

#if defined(__clang__)
#  define C_COMPILER_CLANG 1
#endif

/* #define C_COMPILER_DOCS 1 */

#if defined(__GNUC__)
#  define C_COMPILER_GNUC 1
#endif

#if defined(_MSC_VER)
#  define C_COMPILER_MSVC 1
#endif

#if defined(__linux__)
#  define C_OS_LINUX 1
#endif

#if defined(__MACH__) && defined(__APPLE__)
#  define C_OS_MACOS 1
#endif

#if defined(_WIN32) || defined(_WIN64)
#  define C_OS_WINDOWS 1
#endif

/**
 * DOC: Guaranteed STD-C Includes
 *
 * c-stdaux includes a set of C Standard Library headers. All those includes
 * are guaranteed and part of the API. See the actual header for a
 * comprehensive list.
 */
/**/

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <time.h>

/**
 * DOC: Generic Compiler Intrinsics
 *
 * This section provides access to compiler extensions and intrinsics which are
 * either portable or have generic fallbacks.
 */
/**/

/**
 * _c_always_inline_() - Always-inline attribute
 *
 * Annotate a symbol to be inlined more aggressively. On GNUC targets this is
 * an alias for ``__attribute__((__always_inline__))``. On MSVC targets this is
 * and alias for ``__forceinline``. On other systems, this is a no-op.
 */
#define _c_always_inline_ _c_internal_always_inline_
#if defined(C_COMPILER_GNUC)
#  define _c_internal_always_inline_ __attribute__((__always_inline__))
#elif defined(C_COMPILER_MSVC)
#  define _c_internal_always_inline_ __forceinline
#else
#  define _c_internal_always_inline_
#endif

/**
 * _c_boolean_expr_() - Evaluate a boolean expression
 * @_x:                 Expression to evaluate
 *
 * Evaluate the given expression and convert the result to 1 or 0. In most
 * cases this is equivalent to ``(!!(_x))``. However, for given compilers this
 * avoids the parentheses to improve diagnostics with ``-Wparentheses``.
 *
 * Outside of macros, this has no added value.
 *
 * Return: Evaluates to the value of ``!!_x``.
 */
#define _c_boolean_expr_(_x) _c_internal_boolean_expr_(__COUNTER__, _x)
#if defined(C_COMPILER_GNUC) && __GNUC__ > 4
#  define _c_internal_boolean_expr_(_uniq, _x)                                  \
        __builtin_choose_expr(                                                  \
                __builtin_constant_p(_x),                                       \
                (!!(_x)),                                                       \
                (__extension__ ({                                               \
                        int C_VAR(b, _uniq);                                    \
                                                                                \
                        /*                                                      \
                         * Avoid any extra parentheses around the evaluation of \
                         * `_x` to allow `-Wparentheses` to warn about use of   \
                         * `x = ...` and instead suggest `(x = ...)` or         \
                         * `x == ...`.                                          \
                         */                                                     \
                                                                                \
                        if (_x)                                                 \
                                C_VAR(b, _uniq) = 1;                            \
                        else                                                    \
                                C_VAR(b, _uniq) = 0;                            \
                                                                                \
                        C_VAR(b, _uniq);                                        \
                })))
#else
#  define _c_internal_boolean_expr_(_uniq, _x) (!!(_x))
#endif

/**
 * _c_likely_() - Likely attribute
 * @_x:                 Expression to evaluate
 *
 * Alias for ``__builtin_expect(!!(_x), 1)``.
 *
 * Return: The expression ``!!_x`` is evaluated and returned.
 */
#define _c_likely_(_x) _c_internal_likely_(_x)
#if defined(C_COMPILER_GNUC)
#  define _c_internal_likely_(_x) (__builtin_expect(_c_boolean_expr_(_x), 1))
#else
#  define _c_internal_likely_(_x) (_c_boolean_expr_(_x))
#endif

/**
 * _c_public_() - Public attribute
 *
 * Mark a symbol definition as public, to be exported by the linker. On
 * GNUC-compatible systems, this is an alias for
 * ``__attribute__((__visibility__("default")))``. On all other systems, this
 * is a no-op.
 *
 * Note that this explicitly does not resolve to ``__declspec(dllexport)`` on
 * MSVC targets, since that would require knowing whether to compile for export
 * or inport and whether to compile for static or dynamic linking. Instead,
 * the ``_c_public_`` attribute is meant to be used unconditionally on
 * definition only. For MSVC exports, we recommend module definition files.
 */
#define _c_public_ _c_internal_public_
#if defined(C_COMPILER_GNUC)
#  define _c_internal_public_ __attribute__((__visibility__("default")))
#else
#  define _c_internal_public_
#endif

/**
 * _c_unlikely_() - Unlikely attribute
 * @_x:                 Expression to evaluate
 *
 * Alias for ``__builtin_expect(!!(_x), 0)``.
 *
 * Return: The expression ``!!_x`` is evaluated and returned.
 */
#define _c_unlikely_(_x) _c_internal_unlikely_(_x)
#if defined(C_COMPILER_GNUC)
#  define _c_internal_unlikely_(_x) (__builtin_expect(_c_boolean_expr_(_x), 0))
#else
#  define _c_internal_unlikely_(_x) (_c_boolean_expr_(_x))
#endif

/**
 * DOC: Generic Utility Macros
 *
 * A set of utility macros which is portable to all supported platforms or has
 * generic fallback variants.
 */
/**/

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
 * DOC: Generic Standard Library Utilities
 *
 * The C Standard Library lacks some crucial and basic support functions. This
 * section describes the set of helpers provided as extension to the standard
 * library.
 */
/**/

/**
 * c_assume_aligned() - Hint alignment to compiler
 * @_ptr:               Pointer to provide alignment hint for
 * @_alignment:         Alignment in bytes
 * @_offset:            Misalignment offset
 *
 * This hints to the compiler that `_ptr - _offset` is aligned to the alignment
 * specified in `_alignment`.
 *
 * On platforms without support for `__builtin_assume_aligned()` this is a
 * no-op.
 *
 * Return: `_ptr` is returned.
 */
#define c_assume_aligned(_ptr, _alignment, _offset) c_internal_assume_aligned((_ptr), (_alignment), (_offset))
#if (defined(C_COMPILER_GNUC) && __GNUC__ > 5) || (defined(C_COMPILER_CLANG) && __clang_major__ > 3)
#  define c_internal_assume_aligned(_ptr, _alignment, _offset) __builtin_assume_aligned((_ptr), (_alignment), (_offset))
#else
#  define c_internal_assume_aligned(_ptr, _alignment, _offset) ((void)(_alignment), (void)(_offset), (_ptr))
#endif

/**
 * c_assert() - Runtime assertions
 * @_x:                 Result of an expression
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
#define c_assert(_x) (                                                          \
                _c_likely_(_x)                                                  \
                        ? assert(true && #_x)                                   \
                        : assert(false && #_x)                                  \
        )

/**
 * c_errno() - Return valid errno
 *
 * This helper should be used to silence warnings if you know ``errno`` is valid
 * (ie., ``errno`` is greater than 0). Instead of ``return -errno;``, use
 * ``return -c_errno();`` It will suppress bogus warnings in case the compiler
 * assumes ``errno`` might be 0 (or smaller than 0) and thus the caller's
 * error-handling might not be triggered.
 *
 * This helper should be avoided whenever possible. However, occasionally we
 * really want to silence warnings (especially with static/inline functions). In
 * those cases, the compiler usually cannot deduce that some error paths are
 * guaranteed to be taken. Hence, making the return value explicit allows it to
 * better optimize the code.
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
 * DOC: Memory Access
 *
 * This section provides helpers to read and write arbitrary memory locations.
 * They are carefully designed to follow all language restrictions and thus
 * work with strict-aliasing and alignment rules.
 *
 * The C language does not allow aliasing an object with a pointer of an
 * incompatible type (with few exceptions). Furthermore, memory access must be
 * aligned. This function uses exceptions in the language to circumvent both
 * restrictions.
 *
 * Note that pointer-offset calculations should avoid exceeding the extents of
 * the object, even if the object is surrounded by other objects. That is,
 * `ptr+offset` should point to the same object as `ptr`. Otherwise, pointer
 * provenance will have to be considered.
 */
/**/

/**
 * c_load_8() - Read a u8 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unsigned 8-bit integer at the offset of the specified memory
 * location.
 *
 * Return: The read value is returned.
 */
static inline uint8_t c_load_8(const void *memory, size_t offset) {
        return ((const uint8_t *)memory)[offset];
}

/**
 * c_load_16be_unaligned() - Read an unaligned big-endian u16 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unaligned big-endian unsigned 16-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint16_t c_load_16be_unaligned(const void *memory, size_t offset) {
        const uint8_t *m = (const uint8_t *)memory + offset;
        return ((uint16_t)m[1] << 0) | ((uint16_t)m[0] << 8);
}

/**
 * c_load_16be_aligned() - Read an aligned big-endian u16 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an aligned big-endian unsigned 16-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint16_t c_load_16be_aligned(const void *memory, size_t offset) {
        const uint8_t *m = c_assume_aligned((const uint8_t *)memory + offset, 2, 0);
        return ((uint16_t)m[1] << 0) | ((uint16_t)m[0] << 8);
}

/**
 * c_load_16le_unaligned() - Read an unaligned little-endian u16 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unaligned little-endian unsigned 16-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint16_t c_load_16le_unaligned(const void *memory, size_t offset) {
        const uint8_t *m = (const uint8_t *)memory + offset;
        return ((uint16_t)m[0] << 0) | ((uint16_t)m[1] << 8);
}

/**
 * c_load_16le_aligned() - Read an aligned little-endian u16 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an aligned little-endian unsigned 16-bit integer at the offset of
 * the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint16_t c_load_16le_aligned(const void *memory, size_t offset) {
        const uint8_t *m = c_assume_aligned((const uint8_t *)memory + offset, 2, 0);
        return ((uint16_t)m[0] << 0) | ((uint16_t)m[1] << 8);
}

/**
 * c_load_32be_unaligned() - Read an unaligned big-endian u32 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unaligned big-endian unsigned 32-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint32_t c_load_32be_unaligned(const void *memory, size_t offset) {
        const uint8_t *m = (const uint8_t *)memory + offset;
        return ((uint32_t)m[3] <<  0) | ((uint32_t)m[2] <<  8) |
               ((uint32_t)m[1] << 16) | ((uint32_t)m[0] << 24);
}

/**
 * c_load_32be_aligned() - Read an aligned big-endian u32 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an aligned big-endian unsigned 32-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint32_t c_load_32be_aligned(const void *memory, size_t offset) {
        const uint8_t *m = c_assume_aligned((const uint8_t *)memory + offset, 4, 0);
        return ((uint32_t)m[3] <<  0) | ((uint32_t)m[2] <<  8) |
               ((uint32_t)m[1] << 16) | ((uint32_t)m[0] << 24);
}

/**
 * c_load_32le_unaligned() - Read an unaligned little-endian u32 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unaligned little-endian unsigned 32-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint32_t c_load_32le_unaligned(const void *memory, size_t offset) {
        const uint8_t *m = (const uint8_t *)memory + offset;
        return ((uint32_t)m[0] <<  0) | ((uint32_t)m[1] <<  8) |
               ((uint32_t)m[2] << 16) | ((uint32_t)m[3] << 24);
}

/**
 * c_load_32le_aligned() - Read an aligned little-endian u32 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an aligned little-endian unsigned 32-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint32_t c_load_32le_aligned(const void *memory, size_t offset) {
        const uint8_t *m = c_assume_aligned((const uint8_t *)memory + offset, 4, 0);
        return ((uint32_t)m[0] <<  0) | ((uint32_t)m[1] <<  8) |
               ((uint32_t)m[2] << 16) | ((uint32_t)m[3] << 24);
}

/**
 * c_load_64be_unaligned() - Read an unaligned big-endian u64 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unaligned big-endian unsigned 64-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint64_t c_load_64be_unaligned(const void *memory, size_t offset) {
        const uint8_t *m = (const uint8_t *)memory + offset;
        return ((uint64_t)m[7] <<  0) | ((uint64_t)m[6] <<  8) |
               ((uint64_t)m[5] << 16) | ((uint64_t)m[4] << 24) |
               ((uint64_t)m[3] << 32) | ((uint64_t)m[2] << 40) |
               ((uint64_t)m[1] << 48) | ((uint64_t)m[0] << 56);
}

/**
 * c_load_64be_aligned() - Read an aligned big-endian u64 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an aligned big-endian unsigned 64-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint64_t c_load_64be_aligned(const void *memory, size_t offset) {
        const uint8_t *m = c_assume_aligned((const uint8_t *)memory + offset, 8, 0);
        return ((uint64_t)m[7] <<  0) | ((uint64_t)m[6] <<  8) |
               ((uint64_t)m[5] << 16) | ((uint64_t)m[4] << 24) |
               ((uint64_t)m[3] << 32) | ((uint64_t)m[2] << 40) |
               ((uint64_t)m[1] << 48) | ((uint64_t)m[0] << 56);
}

/**
 * c_load_64le_unaligned() - Read an unaligned little-endian u64 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an unaligned little-endian unsigned 64-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint64_t c_load_64le_unaligned(const void *memory, size_t offset) {
        const uint8_t *m = (const uint8_t *)memory + offset;
        return ((uint64_t)m[0] <<  0) | ((uint64_t)m[1] <<  8) |
               ((uint64_t)m[2] << 16) | ((uint64_t)m[3] << 24) |
               ((uint64_t)m[4] << 32) | ((uint64_t)m[5] << 40) |
               ((uint64_t)m[6] << 48) | ((uint64_t)m[7] << 56);
}

/**
 * c_load_64le_aligned() - Read an aligned little-endian u64 from memory
 * @memory:     Memory location to operate on
 * @offset:     Offset in bytes from the pointed memory location
 *
 * This reads an aligned little-endian unsigned 64-bit integer at the offset
 * of the specified memory location.
 *
 * Return: The read value is returned.
 */
static inline uint64_t c_load_64le_aligned(const void *memory, size_t offset) {
        const uint8_t *m = c_assume_aligned((const uint8_t *)memory + offset, 8, 0);
        return ((uint64_t)m[0] <<  0) | ((uint64_t)m[1] <<  8) |
               ((uint64_t)m[2] << 16) | ((uint64_t)m[3] << 24) |
               ((uint64_t)m[4] << 32) | ((uint64_t)m[5] << 40) |
               ((uint64_t)m[6] << 48) | ((uint64_t)m[7] << 56);
}

/**
 * c_load() - Read from memory
 * @_type:      Datatype to read
 * @_endian:    Endianness
 * @_aligned:   Aligned or unaligned access
 * @_memory:     Memory location to operate on
 * @_offset:     Offset in bytes from the pointed memory location
 *
 * This reads a value of the same size as `_type` at the offset of the
 * specified memory location. `_endian` must be either `be` or `le`, `_aligned`
 * must be either `aligned` or `unaligned`.
 *
 * This is a generic macro that maps to the respective `c_load_*()` function.
 *
 * Return: The read value is returned.
 */
#define c_load(_type, _endian, _aligned, _memory, _offset)                              \
        (_Generic((_type){ 0 },                                                         \
                uint16_t: c_load_16 ## _endian ## _ ## _aligned ((_memory), (_offset)), \
                uint32_t: c_load_32 ## _endian ## _ ## _aligned ((_memory), (_offset)), \
                uint64_t: c_load_64 ## _endian ## _ ## _aligned ((_memory), (_offset))  \
        ))

/**
 * DOC: Generic Destructors
 *
 * A set of destructors is provided which extends standard library destructors
 * to adhere to some adjuvant rules. In particular, they return an invalid
 * value of the particular object, rather than void. This allows direct
 * assignment to any member-field and/or variable they are defined in, like:
 *
 * .. code-block:: c
 *
 *     foo = c_free(foo);
 *     foo->bar = c_fclose(foo->bar);
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
 * DOC: Generic Cleanup Helpers
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
 * - ``c_fclosep()``: Wrapper around :c:func:`c_fclose()`.
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

C_DEFINE_CLEANUP(FILE *, c_fclose);

#ifdef __cplusplus
}
#endif
