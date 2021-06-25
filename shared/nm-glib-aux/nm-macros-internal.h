/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 Colin Walters <walters@verbum.org>.
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_MACROS_INTERNAL_H__
#define __NM_MACROS_INTERNAL_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <gio/gio.h>

/*****************************************************************************/

/* most of our code is single-threaded with a mainloop. Hence, we usually don't need
 * any thread-safety. Sometimes, we do need thread-safety (nm-logging), but we can
 * avoid locking if we are on the main-thread by:
 *
 *   - modifications of shared data is done infrequently and only from the
 *     main-thread (nm_logging_setup())
 *   - read-only access is done frequently (nm_logging_enabled())
 *     - from the main-thread, we can do that without locking (because
 *       all modifications are also done on the main thread.
 *     - from other threads, we need locking. But this is expected to be
 *       done infrequently too. Important is the lock-free fast-path on the
 *       main-thread.
 *
 * By defining NM_THREAD_SAFE_ON_MAIN_THREAD you indicate that this code runs
 * on the main-thread. It is by default defined to "1". If you have code that
 * is also used on another thread, redefine the define to 0 (to opt in into
 * the slow-path).
 */
#define NM_THREAD_SAFE_ON_MAIN_THREAD 1

/*****************************************************************************/

#include "nm-glib.h"

/*****************************************************************************/

#define nm_offsetofend(t, m) (G_STRUCT_OFFSET(t, m) + sizeof(((t *) NULL)->m))

/*****************************************************************************/

#define gs_free            nm_auto_g_free
#define gs_unref_object    nm_auto_unref_object
#define gs_unref_variant   nm_auto_unref_variant
#define gs_unref_array     nm_auto_unref_array
#define gs_unref_ptrarray  nm_auto_unref_ptrarray
#define gs_unref_hashtable nm_auto_unref_hashtable
#define gs_unref_bytes     nm_auto_unref_bytes
#define gs_strfreev        nm_auto_strfreev
#define gs_free_error      nm_auto_free_error

/*****************************************************************************/

NM_AUTO_DEFINE_FCN_VOID0(void *, _nm_auto_g_free, g_free);
#define nm_auto_g_free nm_auto(_nm_auto_g_free)

NM_AUTO_DEFINE_FCN_VOID0(GObject *, _nm_auto_unref_object, g_object_unref);
#define nm_auto_unref_object nm_auto(_nm_auto_unref_object)

NM_AUTO_DEFINE_FCN0(GVariant *, _nm_auto_unref_variant, g_variant_unref);
#define nm_auto_unref_variant nm_auto(_nm_auto_unref_variant)

NM_AUTO_DEFINE_FCN0(GArray *, _nm_auto_unref_array, g_array_unref);
#define nm_auto_unref_array nm_auto(_nm_auto_unref_array)

NM_AUTO_DEFINE_FCN0(GPtrArray *, _nm_auto_unref_ptrarray, g_ptr_array_unref);
#define nm_auto_unref_ptrarray nm_auto(_nm_auto_unref_ptrarray)

NM_AUTO_DEFINE_FCN0(GHashTable *, _nm_auto_unref_hashtable, g_hash_table_unref);
#define nm_auto_unref_hashtable nm_auto(_nm_auto_unref_hashtable)

NM_AUTO_DEFINE_FCN0(GSList *, _nm_auto_free_slist, g_slist_free);
#define nm_auto_free_slist nm_auto(_nm_auto_free_slist)

NM_AUTO_DEFINE_FCN0(GBytes *, _nm_auto_unref_bytes, g_bytes_unref);
#define nm_auto_unref_bytes nm_auto(_nm_auto_unref_bytes)

NM_AUTO_DEFINE_FCN0(char **, _nm_auto_strfreev, g_strfreev);
#define nm_auto_strfreev nm_auto(_nm_auto_strfreev)

NM_AUTO_DEFINE_FCN0(GError *, _nm_auto_free_error, g_error_free);
#define nm_auto_free_error nm_auto(_nm_auto_free_error)

NM_AUTO_DEFINE_FCN0(GKeyFile *, _nm_auto_unref_keyfile, g_key_file_unref);
#define nm_auto_unref_keyfile nm_auto(_nm_auto_unref_keyfile)

NM_AUTO_DEFINE_FCN0(GVariantIter *, _nm_auto_free_variant_iter, g_variant_iter_free);
#define nm_auto_free_variant_iter nm_auto(_nm_auto_free_variant_iter)

NM_AUTO_DEFINE_FCN0(GVariantBuilder *, _nm_auto_unref_variant_builder, g_variant_builder_unref);
#define nm_auto_unref_variant_builder nm_auto(_nm_auto_unref_variant_builder)

#define nm_auto_clear_variant_builder nm_auto(g_variant_builder_clear)

NM_AUTO_DEFINE_FCN0(GList *, _nm_auto_free_list, g_list_free);
#define nm_auto_free_list nm_auto(_nm_auto_free_list)

NM_AUTO_DEFINE_FCN0(GChecksum *, _nm_auto_checksum_free, g_checksum_free);
#define nm_auto_free_checksum nm_auto(_nm_auto_checksum_free)

#define nm_auto_unset_gvalue nm_auto(g_value_unset)

NM_AUTO_DEFINE_FCN_VOID0(void *, _nm_auto_unref_gtypeclass, g_type_class_unref);
#define nm_auto_unref_gtypeclass nm_auto(_nm_auto_unref_gtypeclass)

NM_AUTO_DEFINE_FCN0(GByteArray *, _nm_auto_unref_bytearray, g_byte_array_unref);
#define nm_auto_unref_bytearray nm_auto(_nm_auto_unref_bytearray)

static inline void
_nm_auto_free_gstring(GString **str)
{
    if (*str)
        g_string_free(*str, TRUE);
}
#define nm_auto_free_gstring nm_auto(_nm_auto_free_gstring)

NM_AUTO_DEFINE_FCN0(GSource *, _nm_auto_unref_gsource, g_source_unref);
#define nm_auto_unref_gsource nm_auto(_nm_auto_unref_gsource)

NM_AUTO_DEFINE_FCN0(guint, _nm_auto_remove_source, g_source_remove);
#define nm_auto_remove_source nm_auto(_nm_auto_remove_source)

NM_AUTO_DEFINE_FCN0(GIOChannel *, _nm_auto_unref_io_channel, g_io_channel_unref);
#define nm_auto_unref_io_channel nm_auto(_nm_auto_unref_io_channel)

NM_AUTO_DEFINE_FCN0(GMainLoop *, _nm_auto_unref_gmainloop, g_main_loop_unref);
#define nm_auto_unref_gmainloop nm_auto(_nm_auto_unref_gmainloop)

NM_AUTO_DEFINE_FCN0(GOptionContext *, _nm_auto_free_option_context, g_option_context_free);
#define nm_auto_free_option_context nm_auto(_nm_auto_free_option_context)

static inline void
_nm_auto_freev(gpointer ptr)
{
    gpointer **p = ptr;
    gpointer * _ptr;

    if (*p) {
        for (_ptr = *p; *_ptr; _ptr++)
            g_free(*_ptr);
        g_free(*p);
    }
}
/* g_free a NULL terminated array of pointers, with also freeing each
 * pointer with g_free(). It essentially does the same as
 * gs_strfreev / g_strfreev(), but not restricted to strv arrays. */
#define nm_auto_freev nm_auto(_nm_auto_freev)

/*****************************************************************************/

#define _NM_MACRO_SELECT_ARG_64(_1,  \
                                _2,  \
                                _3,  \
                                _4,  \
                                _5,  \
                                _6,  \
                                _7,  \
                                _8,  \
                                _9,  \
                                _10, \
                                _11, \
                                _12, \
                                _13, \
                                _14, \
                                _15, \
                                _16, \
                                _17, \
                                _18, \
                                _19, \
                                _20, \
                                _21, \
                                _22, \
                                _23, \
                                _24, \
                                _25, \
                                _26, \
                                _27, \
                                _28, \
                                _29, \
                                _30, \
                                _31, \
                                _32, \
                                _33, \
                                _34, \
                                _35, \
                                _36, \
                                _37, \
                                _38, \
                                _39, \
                                _40, \
                                _41, \
                                _42, \
                                _43, \
                                _44, \
                                _45, \
                                _46, \
                                _47, \
                                _48, \
                                _49, \
                                _50, \
                                _51, \
                                _52, \
                                _53, \
                                _54, \
                                _55, \
                                _56, \
                                _57, \
                                _58, \
                                _59, \
                                _60, \
                                _61, \
                                _62, \
                                _63, \
                                N,   \
                                ...) \
    N

/* http://stackoverflow.com/a/2124385/354393
 * https://stackoverflow.com/questions/11317474/macro-to-count-number-of-arguments
 */

#define NM_NARG(...)                       \
    _NM_MACRO_SELECT_ARG_64(,              \
                            ##__VA_ARGS__, \
                            62,            \
                            61,            \
                            60,            \
                            59,            \
                            58,            \
                            57,            \
                            56,            \
                            55,            \
                            54,            \
                            53,            \
                            52,            \
                            51,            \
                            50,            \
                            49,            \
                            48,            \
                            47,            \
                            46,            \
                            45,            \
                            44,            \
                            43,            \
                            42,            \
                            41,            \
                            40,            \
                            39,            \
                            38,            \
                            37,            \
                            36,            \
                            35,            \
                            34,            \
                            33,            \
                            32,            \
                            31,            \
                            30,            \
                            29,            \
                            28,            \
                            27,            \
                            26,            \
                            25,            \
                            24,            \
                            23,            \
                            22,            \
                            21,            \
                            20,            \
                            19,            \
                            18,            \
                            17,            \
                            16,            \
                            15,            \
                            14,            \
                            13,            \
                            12,            \
                            11,            \
                            10,            \
                            9,             \
                            8,             \
                            7,             \
                            6,             \
                            5,             \
                            4,             \
                            3,             \
                            2,             \
                            1,             \
                            0)
#define NM_NARG_MAX1(...)                  \
    _NM_MACRO_SELECT_ARG_64(,              \
                            ##__VA_ARGS__, \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            1,             \
                            0)
#define NM_NARG_MAX2(...)                  \
    _NM_MACRO_SELECT_ARG_64(,              \
                            ##__VA_ARGS__, \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            2,             \
                            1,             \
                            0)

#define _NM_MACRO_CALL(macro, ...) macro(__VA_ARGS__)

/*****************************************************************************/

#define _NM_MACRO_COMMA_IF_ARGS(...) \
    _NM_MACRO_CALL(G_PASTE(__NM_MACRO_COMMA_IF_ARGS_, NM_NARG_MAX1(__VA_ARGS__)), __VA_ARGS__)
#define __NM_MACRO_COMMA_IF_ARGS_0()
#define __NM_MACRO_COMMA_IF_ARGS_1(...) ,

/*****************************************************************************/

/* http://stackoverflow.com/a/11172679 */
#define _NM_UTILS_MACRO_FIRST(...)                __NM_UTILS_MACRO_FIRST_HELPER(__VA_ARGS__, throwaway)
#define __NM_UTILS_MACRO_FIRST_HELPER(first, ...) first

#define _NM_UTILS_MACRO_REST(...) \
    _NM_MACRO_CALL(G_PASTE(__NM_UTILS_MACRO_REST_, NM_NARG_MAX2(__VA_ARGS__)), __VA_ARGS__)
#define __NM_UTILS_MACRO_REST_0()
#define __NM_UTILS_MACRO_REST_1(first)
#define __NM_UTILS_MACRO_REST_2(first, ...) , __VA_ARGS__

/*****************************************************************************/

#if defined(__GNUC__)
    #define _NM_PRAGMA_WARNING_DO(warning) G_STRINGIFY(GCC diagnostic ignored warning)
#elif defined(__clang__)
    #define _NM_PRAGMA_WARNING_DO(warning) G_STRINGIFY(clang diagnostic ignored warning)
#endif

/* you can only suppress a specific warning that the compiler
 * understands. Otherwise you will get another compiler warning
 * about invalid pragma option.
 * It's not that bad however, because gcc and clang often have the
 * same name for the same warning. */

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
    #define NM_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("GCC diagnostic push") _Pragma(_NM_PRAGMA_WARNING_DO(warning))
#elif defined(__clang__)
    #define NM_PRAGMA_WARNING_DISABLE(warning)                         \
        _Pragma("clang diagnostic push")                               \
            _Pragma(_NM_PRAGMA_WARNING_DO("-Wunknown-warning-option")) \
                _Pragma(_NM_PRAGMA_WARNING_DO(warning))
#else
    #define NM_PRAGMA_WARNING_DISABLE(warning)
#endif

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
    #define NM_PRAGMA_WARNING_REENABLE _Pragma("GCC diagnostic pop")
#elif defined(__clang__)
    #define NM_PRAGMA_WARNING_REENABLE _Pragma("clang diagnostic pop")
#else
    #define NM_PRAGMA_WARNING_REENABLE
#endif

/*****************************************************************************/

/**
 * NM_G_ERROR_MSG:
 * @error: (allow-none): the #GError instance
 *
 * All functions must follow the convention that when they
 * return a failure, they must also set the GError to a valid
 * message. For external API however, we want to be extra
 * careful before accessing the error instance. Use NM_G_ERROR_MSG()
 * which is safe to use on NULL.
 *
 * Returns: the error message.
 **/
static inline const char *
NM_G_ERROR_MSG(GError *error)
{
    return error ? (error->message ?: "(null)") : "(no-error)";
}

/*****************************************************************************/

#ifndef _NM_CC_SUPPORT_AUTO_TYPE
    #if (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)))
        #define _NM_CC_SUPPORT_AUTO_TYPE 1
    #else
        #define _NM_CC_SUPPORT_AUTO_TYPE 0
    #endif
#endif

#ifndef _NM_CC_SUPPORT_GENERIC
    /* In the meantime, NetworkManager requires C11 and _Generic() should always be available.
 * However, shared/nm-utils may also be used in VPN/applet, which possibly did not yet
 * bump the C standard requirement. Leave this for the moment, but eventually we can
 * drop it. */
    #if (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9))) \
        || (defined(__clang__))
        #define _NM_CC_SUPPORT_GENERIC 1
    #else
        #define _NM_CC_SUPPORT_GENERIC 0
    #endif
#endif

#if _NM_CC_SUPPORT_AUTO_TYPE
    #define _nm_auto_type __auto_type
#endif

#if _NM_CC_SUPPORT_GENERIC
    #define _NM_CONSTCAST_FULL_1(type, obj_expr, obj) \
        (_Generic ((obj_expr), \
               const void        *const: ((const type *) (obj)), \
               const void        *     : ((const type *) (obj)), \
                     void        *const: ((      type *) (obj)), \
                     void        *     : ((      type *) (obj)), \
               const type        *const: ((const type *) (obj)), \
               const type        *     : ((const type *) (obj)), \
                     type        *const: ((      type *) (obj)), \
                     type        *     : ((      type *) (obj))))
    #define _NM_CONSTCAST_FULL_2(type, obj_expr, obj, alias_type2) \
        (_Generic ((obj_expr), \
               const void        *const: ((const type *) (obj)), \
               const void        *     : ((const type *) (obj)), \
                     void        *const: ((      type *) (obj)), \
                     void        *     : ((      type *) (obj)), \
               const alias_type2 *const: ((const type *) (obj)), \
               const alias_type2 *     : ((const type *) (obj)), \
                     alias_type2 *const: ((      type *) (obj)), \
                     alias_type2 *     : ((      type *) (obj)), \
               const type        *const: ((const type *) (obj)), \
               const type        *     : ((const type *) (obj)), \
                     type        *const: ((      type *) (obj)), \
                     type        *     : ((      type *) (obj))))
    #define _NM_CONSTCAST_FULL_3(type, obj_expr, obj, alias_type2, alias_type3) \
        (_Generic ((obj_expr), \
               const void        *const: ((const type *) (obj)), \
               const void        *     : ((const type *) (obj)), \
                     void        *const: ((      type *) (obj)), \
                     void        *     : ((      type *) (obj)), \
               const alias_type2 *const: ((const type *) (obj)), \
               const alias_type2 *     : ((const type *) (obj)), \
                     alias_type2 *const: ((      type *) (obj)), \
                     alias_type2 *     : ((      type *) (obj)), \
               const alias_type3 *const: ((const type *) (obj)), \
               const alias_type3 *     : ((const type *) (obj)), \
                     alias_type3 *const: ((      type *) (obj)), \
                     alias_type3 *     : ((      type *) (obj)), \
               const type        *const: ((const type *) (obj)), \
               const type        *     : ((const type *) (obj)), \
                     type        *const: ((      type *) (obj)), \
                     type        *     : ((      type *) (obj))))
    #define _NM_CONSTCAST_FULL_4(type, obj_expr, obj, alias_type2, alias_type3, alias_type4) \
        (_Generic ((obj_expr), \
               const void        *const: ((const type *) (obj)), \
               const void        *     : ((const type *) (obj)), \
                     void        *const: ((      type *) (obj)), \
                     void        *     : ((      type *) (obj)), \
               const alias_type2 *const: ((const type *) (obj)), \
               const alias_type2 *     : ((const type *) (obj)), \
                     alias_type2 *const: ((      type *) (obj)), \
                     alias_type2 *     : ((      type *) (obj)), \
               const alias_type3 *const: ((const type *) (obj)), \
               const alias_type3 *     : ((const type *) (obj)), \
                     alias_type3 *const: ((      type *) (obj)), \
                     alias_type3 *     : ((      type *) (obj)), \
               const alias_type4 *const: ((const type *) (obj)), \
               const alias_type4 *     : ((const type *) (obj)), \
                     alias_type4 *const: ((      type *) (obj)), \
                     alias_type4 *     : ((      type *) (obj)), \
               const type        *const: ((const type *) (obj)), \
               const type        *     : ((const type *) (obj)), \
                     type        *const: ((      type *) (obj)), \
                     type        *     : ((      type *) (obj))))
    #define _NM_CONSTCAST_FULL_x(type, obj_expr, obj, n, ...) \
        (_NM_CONSTCAST_FULL_##n(type, obj_expr, obj, ##__VA_ARGS__))
    #define _NM_CONSTCAST_FULL_y(type, obj_expr, obj, n, ...) \
        (_NM_CONSTCAST_FULL_x(type, obj_expr, obj, n, ##__VA_ARGS__))
    #define NM_CONSTCAST_FULL(type, obj_expr, obj, ...) \
        (_NM_CONSTCAST_FULL_y(type, obj_expr, obj, NM_NARG(dummy, ##__VA_ARGS__), ##__VA_ARGS__))
#else
    #define NM_CONSTCAST_FULL(type, obj_expr, obj, ...) ((type *) (obj))
#endif

#define NM_CONSTCAST(type, obj, ...) NM_CONSTCAST_FULL(type, (obj), (obj), ##__VA_ARGS__)

#if _NM_CC_SUPPORT_GENERIC
    #define NM_UNCONST_PTR(type, arg) \
        _Generic((arg), const type * : ((type *) (arg)), type * : ((type *) (arg)))
#else
    #define NM_UNCONST_PTR(type, arg) ((type *) (arg))
#endif

#if _NM_CC_SUPPORT_GENERIC
    #define NM_UNCONST_PPTR(type, arg) \
        _Generic ((arg), \
              const type *     *: ((type **) (arg)), \
                    type *     *: ((type **) (arg)), \
              const type *const*: ((type **) (arg)), \
                    type *const*: ((type **) (arg)))
#else
    #define NM_UNCONST_PPTR(type, arg) ((type **) (arg))
#endif

#define NM_GOBJECT_CAST(type, obj, is_check, ...)                     \
    ({                                                                \
        const void *_obj = (obj);                                     \
                                                                      \
        nm_assert(_obj || (is_check(_obj)));                          \
        NM_CONSTCAST_FULL(type, (obj), _obj, GObject, ##__VA_ARGS__); \
    })

#define NM_GOBJECT_CAST_NON_NULL(type, obj, is_check, ...)            \
    ({                                                                \
        const void *_obj = (obj);                                     \
                                                                      \
        nm_assert(is_check(_obj));                                    \
        NM_CONSTCAST_FULL(type, (obj), _obj, GObject, ##__VA_ARGS__); \
    })

#define NM_ENSURE_NOT_NULL(ptr)   \
    ({                            \
        typeof(ptr) _ptr = (ptr); \
                                  \
        nm_assert(_ptr != NULL);  \
        _ptr;                     \
    })

#if _NM_CC_SUPPORT_GENERIC
    /* returns @value, if the type of @value matches @type.
     * This requires support for C11 _Generic(). If no support is
     * present, this returns @value directly.
     *
     * It's useful to check the let the compiler ensure that @value is
     * of a certain type. */
    #define _NM_ENSURE_TYPE(type, value) (_Generic((value), type : (value)))
    #define _NM_ENSURE_TYPE_CONST(type, value)              \
        (_Generic((value), const type                       \
                  : ((const type)(value)), const type const \
                  : ((const type)(value)), type             \
                  : ((const type)(value)), type const       \
                  : ((const type)(value))))
#else
    #define _NM_ENSURE_TYPE(type, value)       (value)
    #define _NM_ENSURE_TYPE_CONST(type, value) ((const type)(value))
#endif

#if _NM_CC_SUPPORT_GENERIC && (!defined(__clang__) || __clang_major__ > 3)
    #define NM_STRUCT_OFFSET_ENSURE_TYPE(type, container, field) \
        (_Generic((&(((container *) NULL)->field))[0], type : G_STRUCT_OFFSET(container, field)))
#else
    #define NM_STRUCT_OFFSET_ENSURE_TYPE(type, container, field) G_STRUCT_OFFSET(container, field)
#endif

#if _NM_CC_SUPPORT_GENERIC
    /* these macros cast (value) to
 *  - "const char **"      (for "MC", mutable-const)
 *  - "const char *const*" (for "CC", const-const)
 * The point is to do this cast, but only accepting pointers
 * that are compatible already.
 *
 * The problem is, if you add a function like g_strdupv(), the input
 * argument is not modified (CC), but you want to make it work also
 * for "char **". C doesn't allow this form of casting (for good reasons),
 * so the function makes a choice like g_strdupv(char**). That means,
 * every time you want to call it with a const argument, you need to
 * explicitly cast it.
 *
 * These macros do the cast, but they only accept a compatible input
 * type, otherwise they will fail compilation.
 */
    #define NM_CAST_STRV_MC(value) \
        (_Generic ((value), \
               const char *     *: (const char *     *) (value), \
                     char *     *: (const char *     *) (value), \
                           void *: (const char *     *) (value)))
    #define NM_CAST_STRV_CC(value) \
        (_Generic ((value), \
               const char *const*: (const char *const*) (value), \
               const char *     *: (const char *const*) (value), \
                     char *const*: (const char *const*) (value), \
                     char *     *: (const char *const*) (value), \
                     const void *: (const char *const*) (value), \
                           void *: (const char *const*) (value), \
               const char *const*const: (const char *const*) (value), \
               const char *     *const: (const char *const*) (value), \
                     char *const*const: (const char *const*) (value), \
                     char *     *const: (const char *const*) (value), \
                     const void *const: (const char *const*) (value), \
                           void *const: (const char *const*) (value)))
#else
    #define NM_CAST_STRV_MC(value) ((const char **) (value))
    #define NM_CAST_STRV_CC(value) ((const char *const *) (value))
#endif

#if _NM_CC_SUPPORT_GENERIC
    #define NM_PROPAGATE_CONST(test_expr, ptr) \
        (_Generic ((test_expr), \
               const typeof (*(test_expr)) *: ((const typeof (*(ptr)) *) (ptr)), \
                                     default: (_Generic ((test_expr), \
                                                         typeof (*(test_expr)) *: (ptr)))))
#else
    #define NM_PROPAGATE_CONST(test_expr, ptr) (ptr)
#endif

/* with the way it is implemented, the caller may or may not pass a trailing
 * ',' and it will work. However, this makes the macro unsuitable for initializing
 * an array. */
#define NM_MAKE_STRV(...)                                                                     \
    ((const char *const[(sizeof(((const char *const[]){__VA_ARGS__})) / sizeof(const char *)) \
                        + 1]){__VA_ARGS__})

/*****************************************************************************/

/* NM_CACHED_QUARK() returns the GQuark for @string, but caches
 * it in a static variable to speed up future lookups.
 *
 * @string must be a string literal.
 */
#define NM_CACHED_QUARK(string)                                                \
    ({                                                                         \
        static GQuark _nm_cached_quark = 0;                                    \
                                                                               \
        (G_LIKELY(_nm_cached_quark != 0)                                       \
             ? _nm_cached_quark                                                \
             : (_nm_cached_quark = g_quark_from_static_string("" string ""))); \
    })

/* NM_CACHED_QUARK_FCN() is essentially the same as G_DEFINE_QUARK
 * with two differences:
 * - @string must be a quoted string-literal
 * - @fcn must be the full function name, while G_DEFINE_QUARK() appends
 *   "_quark" to the function name.
 * Both properties of G_DEFINE_QUARK() are non favorable, because you can no
 * longer grep for string/fcn -- unless you are aware that you are searching
 * for G_DEFINE_QUARK() and omit quotes / append _quark(). With NM_CACHED_QUARK_FCN(),
 * ctags/cscope can locate the use of @fcn (though it doesn't recognize that
 * NM_CACHED_QUARK_FCN() defines it).
 */
#define NM_CACHED_QUARK_FCN(string, fcn) \
    GQuark fcn(void)                     \
    {                                    \
        return NM_CACHED_QUARK(string);  \
    }                                    \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

/*****************************************************************************/

static inline GString *
nm_gstring_prepare(GString **l)
{
    if (*l)
        g_string_set_size(*l, 0);
    else
        *l = g_string_sized_new(30);
    return *l;
}

static inline GString *
nm_gstring_add_space_delimiter(GString *str)
{
    if (str->len > 0)
        g_string_append_c(str, ' ');
    return str;
}

static inline gboolean
nm_str_is_empty(const char *str)
{
    /* %NULL is also accepted, and also "empty". */
    return !str || !str[0];
}

static inline const char *
nm_str_not_empty(const char *str)
{
    return !nm_str_is_empty(str) ? str : NULL;
}

static inline char *
nm_strdup_not_empty(const char *str)
{
    return !nm_str_is_empty(str) ? g_strdup(str) : NULL;
}

static inline char *
nm_str_realloc(char *str)
{
    gs_free char *s = str;

    /* Returns a new clone of @str and frees @str. The point is that @str
     * possibly points to a larger chunck of memory. We want to freshly allocate
     * a buffer.
     *
     * We could use realloc(), but that might not do anything or leave
     * @str in its memory pool for chunks of a different size (bad for
     * fragmentation).
     *
     * This is only useful when we want to keep the buffer around for a long
     * time and want to re-allocate a more optimal buffer. */

    return g_strdup(s);
}

/*****************************************************************************/

#define NM_PRINT_FMT_QUOTED2(cond, prefix, str, str_else) \
    (cond) ? (prefix) : "", (cond) ? (str) : (str_else)
#define NM_PRINT_FMT_QUOTED(cond, prefix, str, suffix, str_else) \
    (cond) ? (prefix) : "", (cond) ? (str) : (str_else), (cond) ? (suffix) : ""
#define NM_PRINT_FMT_QUOTE_STRING(arg) NM_PRINT_FMT_QUOTED((arg), "\"", (arg), "\"", "(null)")
#define NM_PRINT_FMT_QUOTE_REF_STRING(arg) \
    NM_PRINT_FMT_QUOTED((arg), "\"", (arg)->str, "\"", "(null)")

/*****************************************************************************/

/* redefine assertions to use g_assert*() */
#undef _nm_assert_call
#undef _nm_assert_call_not_reached
#define _nm_assert_call(cond)         g_assert(cond)
#define _nm_assert_call_not_reached() g_assert_not_reached()

/* Usage:
 *
 *   if (NM_MORE_ASSERT_ONCE (5)) { extra_check (); }
 *
 * This will only run the check once, and only if NM_MORE_ASSERT is >= than
 * more_assert_level.
 */
#define NM_MORE_ASSERT_ONCE(more_assert_level)                                                    \
    ((NM_MORE_ASSERTS >= (more_assert_level)) && ({                                               \
         static volatile int _assert_once = 0;                                                    \
                                                                                                  \
         G_STATIC_ASSERT_EXPR((more_assert_level) > 0);                                           \
                                                                                                  \
         G_UNLIKELY(_assert_once == 0 && g_atomic_int_compare_and_exchange(&_assert_once, 0, 1)); \
     }))

/*****************************************************************************/

#define NM_GOBJECT_PROPERTIES_DEFINE_BASE_FULL(suffix, ...)                     \
    typedef enum {                                                              \
        PROP_0##suffix,                                                         \
        __VA_ARGS__ _PROPERTY_ENUMS_LAST##suffix,                               \
    } _PropertyEnums##suffix;                                                   \
    static GParamSpec *obj_properties##suffix[_PROPERTY_ENUMS_LAST##suffix] = { \
        NULL,                                                                   \
    }

#define NM_GOBJECT_PROPERTIES_DEFINE_NOTIFY(suffix, obj_type)                                 \
    static inline void _nm_gobject_notify_together_impl##suffix(                              \
        obj_type *                    obj,                                                    \
        guint                         n,                                                      \
        const _PropertyEnums##suffix *props)                                                  \
    {                                                                                         \
        GObject *const gobj        = (GObject *) obj;                                         \
        GParamSpec *   pspec_first = NULL;                                                    \
        gboolean       frozen      = FALSE;                                                   \
                                                                                              \
        nm_assert(G_IS_OBJECT(obj));                                                          \
        nm_assert(n > 0);                                                                     \
                                                                                              \
        while (n-- > 0) {                                                                     \
            const _PropertyEnums##suffix prop = *props++;                                     \
            GParamSpec *                 pspec;                                               \
                                                                                              \
            if (prop == PROP_0##suffix)                                                       \
                continue;                                                                     \
                                                                                              \
            nm_assert((gsize) prop < G_N_ELEMENTS(obj_properties##suffix));                   \
            pspec = obj_properties##suffix[prop];                                             \
            nm_assert(pspec);                                                                 \
                                                                                              \
            if (!frozen) {                                                                    \
                if (!pspec_first) {                                                           \
                    pspec_first = pspec;                                                      \
                    continue;                                                                 \
                }                                                                             \
                frozen = TRUE;                                                                \
                g_object_freeze_notify(gobj);                                                 \
                g_object_notify_by_pspec(gobj, pspec_first);                                  \
            }                                                                                 \
            g_object_notify_by_pspec(gobj, pspec);                                            \
        }                                                                                     \
                                                                                              \
        if (frozen)                                                                           \
            g_object_thaw_notify(gobj);                                                       \
        else if (pspec_first)                                                                 \
            g_object_notify_by_pspec(gobj, pspec_first);                                      \
    }                                                                                         \
                                                                                              \
    _nm_unused static inline void _notify##suffix(obj_type *obj, _PropertyEnums##suffix prop) \
    {                                                                                         \
        _nm_gobject_notify_together_impl##suffix(obj, 1, &prop);                              \
    }                                                                                         \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_GOBJECT_PROPERTIES_DEFINE_BASE(...) \
    NM_GOBJECT_PROPERTIES_DEFINE_BASE_FULL(, __VA_ARGS__);

#define NM_GOBJECT_PROPERTIES_DEFINE_FULL(suffix, obj_type, ...) \
    NM_GOBJECT_PROPERTIES_DEFINE_BASE_FULL(suffix, __VA_ARGS__); \
    NM_GOBJECT_PROPERTIES_DEFINE_NOTIFY(suffix, obj_type)

#define NM_GOBJECT_PROPERTIES_DEFINE(obj_type, ...) \
    NM_GOBJECT_PROPERTIES_DEFINE_FULL(, obj_type, __VA_ARGS__)

/* invokes _notify() for all arguments (of type _PropertyEnums). Note, that if
 * there are more than one prop arguments, this will involve a freeze/thaw
 * of GObject property notifications. */
#define nm_gobject_notify_together_full(suffix, obj, ...)          \
    _nm_gobject_notify_together_impl##suffix(obj,                  \
                                             NM_NARG(__VA_ARGS__), \
                                             (const _PropertyEnums##suffix[]){__VA_ARGS__})

#define nm_gobject_notify_together(obj, ...) nm_gobject_notify_together_full(, obj, __VA_ARGS__)

/*****************************************************************************/

#define _NM_GET_PRIVATE(self, type, is_check, ...) \
    (&(NM_GOBJECT_CAST_NON_NULL(type, (self), is_check, ##__VA_ARGS__)->_priv))
#if _NM_CC_SUPPORT_AUTO_TYPE
    #define _NM_GET_PRIVATE_PTR(self, type, is_check, ...)                       \
        ({                                                                       \
            _nm_auto_type _self_get_private =                                    \
                NM_GOBJECT_CAST_NON_NULL(type, (self), is_check, ##__VA_ARGS__); \
                                                                                 \
            NM_PROPAGATE_CONST(_self_get_private, _self_get_private->_priv);     \
        })
#else
    #define _NM_GET_PRIVATE_PTR(self, type, is_check, ...) \
        (NM_GOBJECT_CAST_NON_NULL(type, (self), is_check, ##__VA_ARGS__)->_priv)
#endif

/*****************************************************************************/

static inline gpointer
nm_g_object_ref(gpointer obj)
{
    /* g_object_ref() doesn't accept NULL. */
    if (obj)
        g_object_ref(obj);
    return obj;
}
#define nm_g_object_ref(obj) ((typeof(obj)) nm_g_object_ref(obj))

static inline void
nm_g_object_unref(gpointer obj)
{
    /* g_object_unref() doesn't accept NULL. Usually, we workaround that
     * by using g_clear_object(), but sometimes that is not convenient
     * (for example as destroy function for a hash table that can contain
     * NULL values). */
    if (obj)
        g_object_unref(obj);
}

/* Assigns GObject @obj to destination @pp, and takes an additional ref.
 * The previous value of @pp is unrefed.
 *
 * It makes sure to first increase the ref-count of @obj, and handles %NULL
 * @obj correctly.
 * */
#define nm_g_object_ref_set(pp, obj)                   \
    ({                                                 \
        typeof(*(pp)) *const _pp = (pp);               \
        typeof(*_pp) const _obj  = (obj);              \
        typeof(*_pp) _p;                               \
        gboolean _changed = FALSE;                     \
                                                       \
        nm_assert(!_pp || !*_pp || G_IS_OBJECT(*_pp)); \
        nm_assert(!_obj || G_IS_OBJECT(_obj));         \
                                                       \
        if (_pp && ((_p = *_pp) != _obj)) {            \
            nm_g_object_ref(_obj);                     \
            *_pp = _obj;                               \
            nm_g_object_unref(_p);                     \
            _changed = TRUE;                           \
        }                                              \
        _changed;                                      \
    })

#define nm_g_object_ref_set_take(pp, obj)              \
    ({                                                 \
        typeof(*(pp)) *const _pp = (pp);               \
        typeof(*_pp) const _obj  = (obj);              \
        typeof(*_pp) _p;                               \
        gboolean _changed = FALSE;                     \
                                                       \
        nm_assert(!_pp || !*_pp || G_IS_OBJECT(*_pp)); \
        nm_assert(!_obj || G_IS_OBJECT(_obj));         \
                                                       \
        if (_pp && ((_p = *_pp) != _obj)) {            \
            *_pp = _obj;                               \
            nm_g_object_unref(_p);                     \
            _changed = TRUE;                           \
        } else                                         \
            nm_g_object_unref(_obj);                   \
        _changed;                                      \
    })

/* basically, replaces
 *   g_clear_pointer (&location, g_free)
 * with
 *   nm_clear_g_free (&location)
 *
 * Another advantage is that by using a macro and typeof(), it is more
 * typesafe and gives you for example a compiler warning when pp is a const
 * pointer or points to a const-pointer.
 */
#define nm_clear_g_free(pp) nm_clear_pointer(pp, g_free)

/* Our nm_clear_pointer() is more typesafe than g_clear_pointer() and
 * should be preferred.
 *
 * For g_clear_object() that is not the case (because g_object_unref()
 * anyway takes a void pointer). So using g_clear_object() is fine.
 *
 * Still have a nm_clear_g_object() because that returns a boolean
 * indication whether anything was cleared. */
#define nm_clear_g_object(pp) nm_clear_pointer(pp, g_object_unref)

/**
 * nm_clear_error:
 * @err: a pointer to pointer to a #GError.
 *
 * This is like g_clear_error(). The only difference is
 * that this is an inline function.
 */
static inline void
nm_clear_error(GError **err)
{
    if (err && *err) {
        g_error_free(*err);
        *err = NULL;
    }
}

/* Patch g_clear_error() to use nm_clear_error(), which is inlineable
 * and visible to the compiler. For example gs_free_error attribute only
 * frees the error after checking that it's not %NULL. So, in many cases
 * the compiler knows that gs_free_error has no effect and can optimize
 * the call away. By making g_clear_error() inlineable, we give the compiler
 * more chance to detect that the function actually has no effect. */
#define g_clear_error(ptr) nm_clear_error(ptr)

static inline gboolean
nm_clear_g_source(guint *id)
{
    guint v;

    if (id && (v = *id)) {
        *id = 0;
        g_source_remove(v);
        return TRUE;
    }
    return FALSE;
}

static inline gboolean
nm_clear_g_signal_handler(gpointer self, gulong *id)
{
    gulong v;

    if (id && (v = *id)) {
        *id = 0;
        g_signal_handler_disconnect(self, v);
        return TRUE;
    }
    return FALSE;
}

static inline gboolean
nm_clear_g_variant(GVariant **variant)
{
    GVariant *v;

    if (variant && (v = *variant)) {
        *variant = NULL;
        g_variant_unref(v);
        return TRUE;
    }
    return FALSE;
}

static inline gboolean
nm_clear_g_string(GString **ptr)
{
    GString *s;

    if (ptr && (s = *ptr)) {
        *ptr = NULL;
        g_string_free(s, TRUE);
    };
    return FALSE;
}

static inline gboolean
nm_clear_g_cancellable(GCancellable **cancellable)
{
    GCancellable *v;

    if (cancellable && (v = *cancellable)) {
        *cancellable = NULL;
        g_cancellable_cancel(v);
        g_object_unref(v);
        return TRUE;
    }
    return FALSE;
}

/* If @cancellable_id is not 0, clear it and call g_cancellable_disconnect().
 * @cancellable may be %NULL, if there is nothing to disconnect.
 *
 * It's like nm_clear_g_signal_handler(), except that it uses g_cancellable_disconnect()
 * instead of g_signal_handler_disconnect().
 *
 * Note the warning in glib documentation about dead-lock and what g_cancellable_disconnect()
 * actually does. */
static inline gboolean
nm_clear_g_cancellable_disconnect(GCancellable *cancellable, gulong *cancellable_id)
{
    gulong id;

    if (cancellable_id && (id = *cancellable_id) != 0) {
        *cancellable_id = 0;
        g_cancellable_disconnect(cancellable, id);
        return TRUE;
    }
    return FALSE;
}

/*****************************************************************************/

static inline const char *
nm_dbus_path_not_empty(const char *str)
{
    nm_assert(!str || str[0] == '/');
    return !str || (str[0] == '/' && str[1] == '\0') ? NULL : str;
}

/*****************************************************************************/

/* GVariantType is basically a C string. But G_VARIANT_TYPE() is not suitable
 * to initialize a static variable (because it evaluates a function check that
 * the string is valid). Add an alternative macro that does the plain cast.
 *
 * Here you loose the assertion check that G_VARIANT_TYPE() to ensure the
 * string is valid. */
#define NM_G_VARIANT_TYPE(fmt) ((const GVariantType *) ("" fmt ""))

static inline GVariant *
nm_g_variant_ref(GVariant *v)
{
    if (v)
        g_variant_ref(v);
    return v;
}

static inline GVariant *
nm_g_variant_ref_sink(GVariant *v)
{
    if (v)
        g_variant_ref_sink(v);
    return v;
}

static inline void
nm_g_variant_unref(GVariant *v)
{
    if (v)
        g_variant_unref(v);
}

static inline GVariant *
nm_g_variant_take_ref(GVariant *v)
{
    if (v)
        g_variant_take_ref(v);
    return v;
}

/*****************************************************************************/

#define NM_DIV_ROUND_UP(x, y)     \
    ({                            \
        const typeof(x) _x = (x); \
        const typeof(y) _y = (y); \
                                  \
        (_x / _y + !!(_x % _y));  \
    })

/*****************************************************************************/

#define NM_UTILS_LOOKUP_DEFAULT(v)      return (v)
#define NM_UTILS_LOOKUP_DEFAULT_WARN(v) g_return_val_if_reached(v)
#define NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT(v) \
    {                                        \
        nm_assert_not_reached();             \
        return (v);                          \
    }
#define NM_UTILS_LOOKUP_ITEM(v, n) \
    (void) 0;                      \
case v:                            \
    return (n);                    \
    (void) 0
#define NM_UTILS_LOOKUP_STR_ITEM(v, n) NM_UTILS_LOOKUP_ITEM(v, "" n "")
#define NM_UTILS_LOOKUP_ITEM_IGNORE(v) \
    (void) 0;                          \
case v:                                \
    break;                             \
    (void) 0
#define NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER() \
    (void) 0;                               \
default:                                    \
    break;                                  \
    (void) 0

#define NM_UTILS_LOOKUP_DEFINE(fcn_name, lookup_type, result_type, unknown_val, ...) \
    result_type fcn_name(lookup_type val)                                            \
    {                                                                                \
        switch (val) {                                                               \
            (void) 0, __VA_ARGS__(void) 0;                                           \
        };                                                                           \
        {                                                                            \
            unknown_val;                                                             \
        }                                                                            \
    }                                                                                \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_UTILS_LOOKUP_STR_DEFINE(fcn_name, lookup_type, unknown_val, ...) \
    NM_UTILS_LOOKUP_DEFINE(fcn_name, lookup_type, const char *, unknown_val, __VA_ARGS__)

/* Call the string-lookup-table function @fcn_name. If the function returns
 * %NULL, the numeric index is converted to string using a alloca() buffer.
 * Beware: this macro uses alloca(). */
#define NM_UTILS_LOOKUP_STR_A(fcn_name, idx)                         \
    ({                                                               \
        typeof(idx) _idx = (idx);                                    \
        const char *_s;                                              \
                                                                     \
        _s = fcn_name(_idx);                                         \
        if (!_s) {                                                   \
            _s = g_alloca(30);                                       \
                                                                     \
            g_snprintf((char *) _s, 30, "(%lld)", (long long) _idx); \
        }                                                            \
        _s;                                                          \
    })

/*****************************************************************************/

/* check if @flags has exactly one flag (@check) set. You should call this
 * only with @check being a compile time constant and a power of two. */
#define NM_FLAGS_HAS(flags, check)                                       \
    (G_STATIC_ASSERT_EXPR((check) > 0 && ((check) & ((check) -1)) == 0), \
     NM_FLAGS_ANY((flags), (check)))

#define NM_FLAGS_ANY(flags, check) ((((flags) & (check)) != 0) ? TRUE : FALSE)
#define NM_FLAGS_ALL(flags, check) ((((flags) & (check)) == (check)) ? TRUE : FALSE)

#define NM_FLAGS_SET(flags, val)              \
    ({                                        \
        const typeof(flags) _flags = (flags); \
        const typeof(flags) _val   = (val);   \
                                              \
        _flags | _val;                        \
    })

#define NM_FLAGS_UNSET(flags, val)            \
    ({                                        \
        const typeof(flags) _flags = (flags); \
        const typeof(flags) _val   = (val);   \
                                              \
        _flags &(~_val);                      \
    })

#define NM_FLAGS_ASSIGN(flags, val, assign)           \
    ({                                                \
        const typeof(flags) _flags = (flags);         \
        const typeof(flags) _val   = (val);           \
                                                      \
        (assign) ? _flags | (_val) : _flags &(~_val); \
    })

#define NM_FLAGS_ASSIGN_MASK(flags, mask, val) \
    ({                                         \
        const typeof(flags) _flags = (flags);  \
        const typeof(flags) _mask  = (mask);   \
        const typeof(flags) _val   = (val);    \
                                               \
        ((_flags & ~_mask) | (_mask & _val));  \
    })

/*****************************************************************************/

#define _NM_BACKPORT_SYMBOL_IMPL(version,                                                       \
                                 return_type,                                                   \
                                 orig_func,                                                     \
                                 versioned_func,                                                \
                                 args_typed,                                                    \
                                 args)                                                          \
    return_type versioned_func                        args_typed;                               \
    _nm_externally_visible return_type versioned_func args_typed                                \
    {                                                                                           \
        return orig_func args;                                                                  \
    }                                                                                           \
    return_type orig_func args_typed;                                                           \
    __asm__(".symver " G_STRINGIFY(versioned_func) ", " G_STRINGIFY(orig_func) "@" G_STRINGIFY( \
        version))

#define NM_BACKPORT_SYMBOL(version, return_type, func, args_typed, args) \
    _NM_BACKPORT_SYMBOL_IMPL(version, return_type, func, _##func##_##version, args_typed, args)

/*****************************************************************************/

/* mirrors g_ascii_isspace() and what we consider spaces in general. */
#define NM_ASCII_SPACES " \n\t\r\f"

/* Like NM_ASCII_SPACES, but without "\f" (0x0c, Formfeed Page Break).
 * This is what for example systemd calls WHITESPACE and what it uses to tokenize
 * the kernel command line. */
#define NM_ASCII_WHITESPACES " \n\t\r"

#define nm_str_skip_leading_spaces(str)                          \
    ({                                                           \
        typeof(*(str)) *             _str_sls        = (str);    \
        _nm_unused const char *const _str_type_check = _str_sls; \
                                                                 \
        if (_str_sls) {                                          \
            while (g_ascii_isspace(_str_sls[0]))                 \
                _str_sls++;                                      \
        }                                                        \
        _str_sls;                                                \
    })

static inline char *
nm_strstrip(char *str)
{
    /* g_strstrip doesn't like NULL. */
    return str ? g_strstrip(str) : NULL;
}

static inline const char *
nm_strstrip_avoid_copy(const char *str, char **str_free)
{
    gsize l;
    char *s;

    nm_assert(str_free && !*str_free);

    if (!str)
        return NULL;

    str = nm_str_skip_leading_spaces(str);
    l   = strlen(str);
    if (l == 0 || !g_ascii_isspace(str[l - 1]))
        return str;
    while (l > 0 && g_ascii_isspace(str[l - 1]))
        l--;

    s = g_new(char, l + 1);
    memcpy(s, str, l);
    s[l]      = '\0';
    *str_free = s;
    return s;
}

#define nm_strstrip_avoid_copy_a(alloca_maxlen, str, out_str_free)                                \
    ({                                                                                            \
        const char *_str_ssac          = (str);                                                   \
        char **     _out_str_free_ssac = (out_str_free);                                          \
                                                                                                  \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) > 0);                                                \
                                                                                                  \
        nm_assert(_out_str_free_ssac || ((alloca_maxlen) > (str ? strlen(str) : 0u)));            \
        nm_assert(!_out_str_free_ssac || !*_out_str_free_ssac);                                   \
                                                                                                  \
        if (_str_ssac) {                                                                          \
            _str_ssac = nm_str_skip_leading_spaces(_str_ssac);                                    \
            if (_str_ssac[0] != '\0') {                                                           \
                gsize _l = strlen(_str_ssac);                                                     \
                                                                                                  \
                if (g_ascii_isspace(_str_ssac[--_l])) {                                           \
                    while (_l > 0 && g_ascii_isspace(_str_ssac[_l - 1])) {                        \
                        _l--;                                                                     \
                    }                                                                             \
                    _str_ssac = nm_strndup_a((alloca_maxlen), _str_ssac, _l, _out_str_free_ssac); \
                }                                                                                 \
            }                                                                                     \
        }                                                                                         \
                                                                                                  \
        _str_ssac;                                                                                \
    })

static inline gboolean
nm_str_is_stripped(const char *str)
{
    if (str && str[0]) {
        if (g_ascii_isspace(str[0]) || g_ascii_isspace(str[strlen(str) - 1]))
            return FALSE;
    }
    return TRUE;
}

/* g_ptr_array_sort()'s compare function takes pointers to the
 * value. Thus, you cannot use strcmp directly. You can use
 * nm_strcmp_p().
 *
 * Like strcmp(), this function is not forgiving to accept %NULL. */
static inline int
nm_strcmp_p(gconstpointer a, gconstpointer b)
{
    const char *s1 = *((const char **) a);
    const char *s2 = *((const char **) b);

    return strcmp(s1, s2);
}

/*****************************************************************************/

static inline int
_NM_IN_STRSET_ASCII_CASE_op_streq(const char *x, const char *s)
{
    return s && g_ascii_strcasecmp(x, s) == 0;
}

#define NM_IN_STRSET_ASCII_CASE(x, ...)                     \
    _NM_IN_STRSET_EVAL_N(||,                                \
                         _NM_IN_STRSET_ASCII_CASE_op_streq, \
                         x,                                 \
                         NM_NARG(__VA_ARGS__),              \
                         __VA_ARGS__)

#define NM_STR_HAS_SUFFIX_ASCII_CASE(str, suffix)                                               \
    ({                                                                                          \
        const char *const _str_has_suffix = (str);                                              \
        size_t            _l;                                                                   \
                                                                                                \
        nm_assert(strlen(suffix) == NM_STRLEN(suffix));                                         \
                                                                                                \
        (_str_has_suffix && ((_l = strlen(_str_has_suffix)) >= NM_STRLEN(suffix))               \
         && (g_ascii_strcasecmp(&_str_has_suffix[_l - NM_STRLEN(suffix)], "" suffix "") == 0)); \
    })

#define NM_STR_HAS_SUFFIX_ASCII_CASE_WITH_MORE(str, suffix)                                     \
    ({                                                                                          \
        const char *const _str_has_suffix = (str);                                              \
        size_t            _l;                                                                   \
                                                                                                \
        nm_assert(strlen(suffix) == NM_STRLEN(suffix));                                         \
                                                                                                \
        (_str_has_suffix && ((_l = strlen(_str_has_suffix)) > NM_STRLEN(suffix))                \
         && (g_ascii_strcasecmp(&_str_has_suffix[_l - NM_STRLEN(suffix)], "" suffix "") == 0)); \
    })

/*****************************************************************************/

#define nm_g_slice_free(ptr) g_slice_free(typeof(*(ptr)), ptr)

/*****************************************************************************/

/* like g_memdup(). The difference is that the @size argument is of type
 * gsize, while g_memdup() has type guint. Since, the size of container types
 * like GArray is guint as well, this means trying to g_memdup() an
 * array,
 *    g_memdup (array->data, array->len * sizeof (ElementType))
 * will lead to integer overflow, if there are more than G_MAXUINT/sizeof(ElementType)
 * bytes. That seems unnecessarily dangerous to me.
 * nm_memdup() avoids that, because its size argument is always large enough
 * to contain all data that a GArray can hold.
 *
 * Another minor difference to g_memdup() is that the glib version also
 * returns %NULL if @data is %NULL. E.g. g_memdup(NULL, 1)
 * gives %NULL, but nm_memdup(NULL, 1) crashes. I think that
 * is desirable, because @size MUST be correct at all times. @size
 * may be zero, but one must not claim to have non-zero bytes when
 * passing a %NULL @data pointer.
 */
static inline gpointer
nm_memdup(gconstpointer data, gsize size)
{
    gpointer p;

    if (size == 0)
        return NULL;
    p = g_malloc(size);
    memcpy(p, data, size);
    return p;
}

#define nm_malloc_maybe_a(alloca_maxlen, bytes, to_free)  \
    ({                                                    \
        const gsize _bytes       = (bytes);               \
        typeof(to_free) _to_free = (to_free);             \
        typeof(*_to_free) _ptr;                           \
                                                          \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) <= 500u);    \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) > 0u);       \
        nm_assert(_to_free && !*_to_free);                \
                                                          \
        if (G_LIKELY(_bytes <= (alloca_maxlen))) {        \
            _ptr = _bytes > 0u ? g_alloca(_bytes) : NULL; \
        } else {                                          \
            _ptr      = g_malloc(_bytes);                 \
            *_to_free = _ptr;                             \
        };                                                \
                                                          \
        _ptr;                                             \
    })

#define nm_malloc0_maybe_a(alloca_maxlen, bytes, to_free) \
    ({                                                    \
        const gsize _bytes       = (bytes);               \
        typeof(to_free) _to_free = (to_free);             \
        typeof(*_to_free) _ptr;                           \
                                                          \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) <= 500u);    \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) > 0u);       \
        nm_assert(_to_free && !*_to_free);                \
                                                          \
        if (G_LIKELY(_bytes <= (alloca_maxlen))) {        \
            if (_bytes > 0u) {                            \
                _ptr = g_alloca(_bytes);                  \
                memset(_ptr, 0, _bytes);                  \
            } else                                        \
                _ptr = NULL;                              \
        } else {                                          \
            _ptr      = g_malloc0(_bytes);                \
            *_to_free = _ptr;                             \
        };                                                \
                                                          \
        _ptr;                                             \
    })

#define nm_memdup_maybe_a(alloca_maxlen, data, size, to_free)                 \
    ({                                                                        \
        const gsize _size            = (size);                                \
        typeof(to_free) _to_free_md  = (to_free);                             \
        typeof(*_to_free_md) _ptr_md = NULL;                                  \
                                                                              \
        nm_assert(_to_free_md && !*_to_free_md);                              \
                                                                              \
        if (_size > 0u) {                                                     \
            _ptr_md = nm_malloc_maybe_a((alloca_maxlen), _size, _to_free_md); \
            memcpy(_ptr_md, (data), _size);                                   \
        }                                                                     \
                                                                              \
        _ptr_md;                                                              \
    })

static inline char *
_nm_strndup_a_step(char *s, const char *str, gsize len)
{
    NM_PRAGMA_WARNING_DISABLE("-Wstringop-truncation");
    NM_PRAGMA_WARNING_DISABLE("-Wstringop-overflow");
    if (len > 0)
        strncpy(s, str, len);
    s[len] = '\0';
    return s;
    NM_PRAGMA_WARNING_REENABLE;
    NM_PRAGMA_WARNING_REENABLE;
}

/* Similar to g_strndup(), however, if the string (including the terminating
 * NUL char) fits into alloca_maxlen, this will alloca() the memory.
 *
 * It's a mix of strndup() and strndupa(), but deciding based on @alloca_maxlen
 * which one to use.
 *
 * In case malloc() is necessary, @out_str_free will be set (this string
 * must be freed afterwards). It is permissible to pass %NULL as @out_str_free,
 * if you ensure that len < alloca_maxlen.
 *
 * Note that just like g_strndup(), this always returns a buffer with @len + 1
 * bytes, even if strlen(@str) is shorter than that (NUL terminated early). We fill
 * the buffer with strncpy(), which means, that @str is copied up to the first
 * NUL character and then filled with NUL characters. */
#define nm_strndup_a(alloca_maxlen, str, len, out_str_free)        \
    ({                                                             \
        const gsize       _alloca_maxlen_snd = (alloca_maxlen);    \
        const char *const _str_snd           = (str);              \
        const gsize       _len_snd           = (len);              \
        char **const      _out_str_free_snd  = (out_str_free);     \
        char *            _s_snd;                                  \
                                                                   \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) <= 300);              \
                                                                   \
        if (_out_str_free_snd && _len_snd >= _alloca_maxlen_snd) { \
            _s_snd             = g_malloc(_len_snd + 1);           \
            *_out_str_free_snd = _s_snd;                           \
        } else {                                                   \
            g_assert(_len_snd < _alloca_maxlen_snd);               \
            _s_snd = g_alloca(_len_snd + 1);                       \
        }                                                          \
        _nm_strndup_a_step(_s_snd, _str_snd, _len_snd);            \
    })

#define nm_strdup_maybe_a(alloca_maxlen, str, out_str_free)               \
    ({                                                                    \
        const char *const _str_snd = (str);                               \
                                                                          \
        (char *) nm_memdup_maybe_a(alloca_maxlen,                         \
                                   _str_snd,                              \
                                   _str_snd ? strlen(_str_snd) + 1u : 0u, \
                                   out_str_free);                         \
    })

/*****************************************************************************/

/* generic macro to convert an int to a (heap allocated) string.
 *
 * Usually, an inline function nm_strdup_int64() would be enough. However,
 * that cannot be used for guint64. So, we would also need nm_strdup_uint64().
 * This causes subtle error potential, because the caller needs to ensure to
 * use the right one (and compiler isn't going to help as it silently casts).
 *
 * Instead, this generic macro is supposed to handle all integers correctly. */
#if _NM_CC_SUPPORT_GENERIC
    #define nm_strdup_int(val)                                                       \
        _Generic((val), char                                                         \
                 : g_strdup_printf("%d", (int) (val)),                               \
                                                                                     \
                   signed char                                                       \
                 : g_strdup_printf("%d", (signed) (val)), signed short               \
                 : g_strdup_printf("%d", (signed) (val)), signed                     \
                 : g_strdup_printf("%d", (signed) (val)), signed long                \
                 : g_strdup_printf("%ld", (signed long) (val)), signed long long     \
                 : g_strdup_printf("%lld", (signed long long) (val)),                \
                                                                                     \
                   unsigned char                                                     \
                 : g_strdup_printf("%u", (unsigned) (val)), unsigned short           \
                 : g_strdup_printf("%u", (unsigned) (val)), unsigned                 \
                 : g_strdup_printf("%u", (unsigned) (val)), unsigned long            \
                 : g_strdup_printf("%lu", (unsigned long) (val)), unsigned long long \
                 : g_strdup_printf("%llu", (unsigned long long) (val)))
#else
    #define nm_strdup_int(val)                                       \
        ((sizeof(val) == sizeof(guint64) && ((typeof(val)) - 1) > 0) \
             ? g_strdup_printf("%" G_GUINT64_FORMAT, (guint64)(val)) \
             : g_strdup_printf("%" G_GINT64_FORMAT, (gint64)(val)))
#endif

/*****************************************************************************/

static inline guint
nm_encode_version(guint major, guint minor, guint micro)
{
    /* analog to the preprocessor macro NM_ENCODE_VERSION(). */
    return (major << 16) | (minor << 8) | micro;
}

static inline void
nm_decode_version(guint version, guint *major, guint *minor, guint *micro)
{
    *major = (version & 0xFFFF0000u) >> 16;
    *minor = (version & 0x0000FF00u) >> 8;
    *micro = (version & 0x000000FFu);
}

/*****************************************************************************/

/* taken from systemd's DECIMAL_STR_MAX()
 *
 * Returns the number of chars needed to format variables of the
 * specified type as a decimal string. Adds in extra space for a
 * negative '-' prefix (hence works correctly on signed
 * types). Includes space for the trailing NUL. */
#define NM_DECIMAL_STR_MAX(type) \
    (2                           \
     + (sizeof(type) <= 1   ? 3  \
        : sizeof(type) <= 2 ? 5  \
        : sizeof(type) <= 4 ? 10 \
        : sizeof(type) <= 8 ? 20 \
                            : sizeof(int[-2 * (sizeof(type) > 8)])))

/*****************************************************************************/

/* if @str is NULL, return "(null)". Otherwise, allocate a buffer using
 * alloca() of and fill it with @str. @str will be quoted with double quote.
 * If @str is longer then @trunc_at, the string is truncated and the closing
 * quote is instead '^' to indicate truncation.
 *
 * Thus, the maximum stack allocated buffer will be @trunc_at+3. The maximum
 * buffer size must be a constant and not larger than 300. */
#define nm_strquote_a(trunc_at, str)                                     \
    ({                                                                   \
        const char *const _str = (str);                                  \
                                                                         \
        (_str ? ({                                                       \
            const gsize _trunc_at     = (trunc_at);                      \
            const gsize _strlen_trunc = NM_MIN(strlen(_str), _trunc_at); \
            char *      _buf;                                            \
                                                                         \
            G_STATIC_ASSERT_EXPR((trunc_at) <= 300);                     \
                                                                         \
            _buf    = g_alloca(_strlen_trunc + 3);                       \
            _buf[0] = '"';                                               \
            memcpy(&_buf[1], _str, _strlen_trunc);                       \
            _buf[_strlen_trunc + 1] = _str[_strlen_trunc] ? '^' : '"';   \
            _buf[_strlen_trunc + 2] = '\0';                              \
            _buf;                                                        \
        })                                                               \
              : "(null)");                                               \
    })

#define nm_sprintf_buf(buf, format, ...)                                                    \
    ({                                                                                      \
        char *_buf = (buf);                                                                 \
        int   _buf_len;                                                                     \
                                                                                            \
        /* some static assert trying to ensure that the buffer is statically allocated.
         * It disallows a buffer size of sizeof(gpointer) to catch that. */     \
        G_STATIC_ASSERT(G_N_ELEMENTS(buf) == sizeof(buf) && sizeof(buf) != sizeof(char *)); \
        _buf_len = g_snprintf(_buf, sizeof(buf), "" format "", ##__VA_ARGS__);              \
        nm_assert(_buf_len < sizeof(buf));                                                  \
        _buf;                                                                               \
    })

/* it is "unsafe" because @bufsize must not be a constant expression and
 * there is no check at compiletime. Regardless of that, the buffer size
 * must not be larger than 300 bytes, as this gets stack allocated. */
#define nm_sprintf_buf_unsafe_a(bufsize, format, ...)                       \
    ({                                                                      \
        char *_buf;                                                         \
        int   _buf_len;                                                     \
        typeof(bufsize) _bufsize = (bufsize);                               \
                                                                            \
        nm_assert(_bufsize <= 300);                                         \
                                                                            \
        _buf     = g_alloca(_bufsize);                                      \
        _buf_len = g_snprintf(_buf, _bufsize, "" format "", ##__VA_ARGS__); \
        nm_assert(_buf_len >= 0 && _buf_len < _bufsize);                    \
        _buf;                                                               \
    })

#define nm_sprintf_bufa(bufsize, format, ...)                      \
    ({                                                             \
        G_STATIC_ASSERT_EXPR((bufsize) <= 300);                    \
        nm_sprintf_buf_unsafe_a((bufsize), format, ##__VA_ARGS__); \
    })

/* aims to alloca() a buffer and fill it with printf(format, name).
 * Note that format must not contain any format specifier except
 * "%s".
 * If the resulting string would be too large for stack allocation,
 * it allocates a buffer with g_malloc() and assigns it to *p_val_to_free. */
#define nm_construct_name_a(format, name, p_val_to_free)                                   \
    ({                                                                                     \
        const char *const _name          = (name);                                         \
        char **const      _p_val_to_free = (p_val_to_free);                                \
        const gsize       _name_len      = strlen(_name);                                  \
        char *            _buf2;                                                           \
                                                                                           \
        nm_assert(_p_val_to_free && !*_p_val_to_free);                                     \
        if (NM_STRLEN(format) <= 290 && _name_len < (gsize)(290 - NM_STRLEN(format)))      \
            _buf2 = nm_sprintf_buf_unsafe_a(NM_STRLEN(format) + _name_len, format, _name); \
        else {                                                                             \
            _buf2           = g_strdup_printf(format, _name);                              \
            *_p_val_to_free = _buf2;                                                       \
        }                                                                                  \
        (const char *) _buf2;                                                              \
    })

/*****************************************************************************/

#ifdef _G_BOOLEAN_EXPR
    /* g_assert() uses G_LIKELY(), which in turn uses _G_BOOLEAN_EXPR().
 * As glib's implementation uses a local variable _g_boolean_var_,
 * we cannot do
 *   g_assert (some_macro ());
 * where some_macro() itself expands to ({g_assert(); ...}).
 * In other words, you cannot have a g_assert() inside a g_assert()
 * without getting a -Werror=shadow failure.
 *
 * Workaround that by re-defining _G_BOOLEAN_EXPR()
 **/
    #undef _G_BOOLEAN_EXPR
    #define _G_BOOLEAN_EXPR(expr) NM_BOOLEAN_EXPR(expr)
#endif

/*****************************************************************************/

#define NM_PID_T_INVAL ((pid_t) -1)

/*****************************************************************************/

NM_AUTO_DEFINE_FCN_VOID0(GMutex *, _nm_auto_unlock_g_mutex, g_mutex_unlock);

#define nm_auto_unlock_g_mutex nm_auto(_nm_auto_unlock_g_mutex)

#define _NM_G_MUTEX_LOCKED(lock, uniq)                                      \
    _nm_unused nm_auto_unlock_g_mutex GMutex *NM_UNIQ_T(nm_lock, uniq) = ({ \
        GMutex *const _lock = (lock);                                       \
                                                                            \
        g_mutex_lock(_lock);                                                \
        _lock;                                                              \
    })

#define NM_G_MUTEX_LOCKED(lock) _NM_G_MUTEX_LOCKED(lock, NM_UNIQ)

/*****************************************************************************/

#endif /* __NM_MACROS_INTERNAL_H__ */
