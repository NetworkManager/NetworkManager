/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-logging-base.h"

#include <syslog.h>

/*****************************************************************************/

const LogLevelDesc level_desc[_LOGL_N] = {
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

    for (i = 0; i < (int) G_N_ELEMENTS(level_desc); i++) {
        if (!g_ascii_strcasecmp(level_desc[i].name, level)) {
            NM_SET_OUT(out_level, i);
            return TRUE;
        }
    }

    return FALSE;
}
