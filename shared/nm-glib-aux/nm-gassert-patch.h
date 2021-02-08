/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_GASSERT_PATCH_H__
#define __NM_GASSERT_PATCH_H__

/*****************************************************************************/

#if NM_MORE_ASSERTS == 0

/* glib assertions (g_return_*(), g_assert*()) contain a textual representation
 * of the checked statement. This part of the assertion blows up the size of the
 * binary. Unless we compile a debug-build with NM_MORE_ASSERTS, drop these
 * parts. Note that the failed assertion still prints the file and line where the
 * assertion fails. That shall suffice. */

static inline void
_nm_g_return_if_fail_warning(const char *log_domain, const char *file, int line)
{
    char file_buf[256 + 15];

    g_snprintf(file_buf, sizeof(file_buf), "((%s:%d))", file, line);
    g_return_if_fail_warning(log_domain, file_buf, "<dropped>");
}

    #define g_return_if_fail_warning(log_domain, pretty_function, expression) \
        _nm_g_return_if_fail_warning(log_domain, __FILE__, __LINE__)

    #define g_assertion_message_expr(domain, file, line, func, expr) \
        g_assertion_message_expr(domain, file, line, "<unknown-fcn>", (expr) ? "<dropped>" : NULL)

    #undef g_return_val_if_reached
    #define g_return_val_if_reached(val)                          \
        G_STMT_START                                              \
        {                                                         \
            g_log(G_LOG_DOMAIN,                                   \
                  G_LOG_LEVEL_CRITICAL,                           \
                  "file %s: line %d (%s): should not be reached", \
                  __FILE__,                                       \
                  __LINE__,                                       \
                  "<dropped>");                                   \
            return (val);                                         \
        }                                                         \
        G_STMT_END

    #undef g_return_if_reached
    #define g_return_if_reached()                                 \
        G_STMT_START                                              \
        {                                                         \
            g_log(G_LOG_DOMAIN,                                   \
                  G_LOG_LEVEL_CRITICAL,                           \
                  "file %s: line %d (%s): should not be reached", \
                  __FILE__,                                       \
                  __LINE__,                                       \
                  "<dropped>");                                   \
            return;                                               \
        }                                                         \
        G_STMT_END
#endif

/*****************************************************************************/

#if NM_MORE_ASSERTS == 0
    #define NM_ASSERT_G_RETURN_EXPR(expr) "<dropped>"
    #define NM_ASSERT_NO_MSG              1

#else
    #define NM_ASSERT_G_RETURN_EXPR(expr) "" expr ""
    #define NM_ASSERT_NO_MSG              0
#endif

/*****************************************************************************/

#endif /* __NM_GASSERT_PATCH_H__ */
