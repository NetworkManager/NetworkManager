/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-logging-base.h"

#include <syslog.h>

#include "nm-time-utils.h"

/*****************************************************************************/

const LogLevelDesc nm_log_level_desc[_LOGL_N] = {
    [LOGL_TRACE] =
        {
            "TRACE",
            "<trace>",
            LOG_DEBUG,
            G_LOG_LEVEL_DEBUG,
        },
    [LOGL_DEBUG] =
        {
            "DEBUG",
            "<debug>",
            LOG_DEBUG,
            G_LOG_LEVEL_DEBUG,
        },
    [LOGL_INFO] =
        {
            "INFO",
            "<info>",
            LOG_INFO,
            G_LOG_LEVEL_INFO,
        },
    [LOGL_WARN] =
        {
            "WARN",
            "<warn>",
            LOG_WARNING,
            G_LOG_LEVEL_MESSAGE,
        },
    [LOGL_ERR] =
        {
            "ERR",
            "<error>",
            LOG_ERR,
            G_LOG_LEVEL_MESSAGE,
        },
    [_LOGL_OFF] =
        {
            "OFF",
            NULL,
            0,
            0,
        },
    [_LOGL_KEEP] =
        {
            "KEEP",
            NULL,
            0,
            0,
        },
};

gboolean
_nm_log_parse_level(const char *level, NMLogLevel *out_level)
{
    int i;

    if (!level)
        return FALSE;

    for (i = 0; i < (int) G_N_ELEMENTS(nm_log_level_desc); i++) {
        if (!g_ascii_strcasecmp(nm_log_level_desc[i].name, level)) {
            NM_SET_OUT(out_level, i);
            return TRUE;
        }
    }

    return FALSE;
}

/*****************************************************************************/

volatile NMLogLevel _nm_logging_enabled_value = LOGL_TRACE;

void
_nm_logging_enabled_init(const char *level_str)
{
    NMLogLevel level;

    if (!_nm_log_parse_level(level_str, &level))
        level = LOGL_WARN;
    else if (level == _LOGL_KEEP)
        level = LOGL_WARN;

    _nm_logging_enabled_value = level;
}

/*****************************************************************************/

void
_nm_log_simple_printf(NMLogLevel level, const char *fmt, ...)
{
    gs_free char *msg_heap = NULL;
    char          msg_stack[700];
    const char   *msg;
    const char   *level_str;
    gint64        ts;

    ts = nm_utils_clock_gettime_nsec(CLOCK_BOOTTIME);

    msg = nm_vsprintf_buf_or_alloc(fmt, fmt, msg_stack, &msg_heap, NULL);

    switch (level) {
    case LOGL_TRACE:
        level_str = "<trace>";
        break;
    case LOGL_DEBUG:
        level_str = "<debug>";
        break;
    case LOGL_INFO:
        level_str = "<info> ";
        break;
    case LOGL_WARN:
        level_str = "<warn> ";
        break;
    default:
        nm_assert(level == LOGL_ERR);
        level_str = "<error>";
        break;
    }

    g_print("[%" G_GINT64_FORMAT ".%05" G_GINT64_FORMAT "] %s %s\n",
            ts / NM_UTILS_NSEC_PER_SEC,
            (ts / (NM_UTILS_NSEC_PER_SEC / 10000)) % 10000,
            level_str,
            msg);
}
