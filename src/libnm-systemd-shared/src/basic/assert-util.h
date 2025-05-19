/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h"
#include "macro.h"

/* Logging for various assertions */

void log_set_assert_return_is_critical(bool b);
bool log_get_assert_return_is_critical(void) _pure_;

#if 0 /* NM_IGNORED */
void log_assert_failed_return(const char *text, const char *file, int line, const char *func);
#else /* NM_IGNORED */
#define log_assert_failed_return(text, file, line, func)                         \
    ({                                                                           \
        log_internal(LOG_DEBUG,                                                  \
                     0,                                                          \
                     file,                                                       \
                     line,                                                       \
                     func,                                                       \
                     "Assertion '%s' failed at %s:%u, function %s(). Ignoring.", \
                     text,                                                       \
                     file,                                                       \
                     line,                                                       \
                     func);                                                      \
        g_return_if_fail_warning(G_LOG_DOMAIN, G_STRFUNC, text);                 \
        (void) 0;                                                                \
    })
#endif /* NM_IGNORED */

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, PROJECT_FILE, __LINE__, __func__), false))

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
