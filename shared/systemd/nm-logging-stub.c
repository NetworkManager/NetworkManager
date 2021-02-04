/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "shared/systemd/nm-default-systemd-shared.h"

#include "nm-glib-aux/nm-logging-fwd.h"

/*****************************************************************************/

gboolean
_nm_log_enabled_impl(gboolean mt_require_locking, NMLogLevel level, NMLogDomain domain)
{
    return FALSE;
}

void
_nm_log_impl(const char *file,
             guint       line,
             const char *func,
             gboolean    mt_require_locking,
             NMLogLevel  level,
             NMLogDomain domain,
             int         error,
             const char *ifname,
             const char *con_uuid,
             const char *fmt,
             ...)
{}

void
_nm_utils_monotonic_timestamp_initialized(const struct timespec *tp,
                                          gint64                 offset_sec,
                                          gboolean               is_boottime)
{}
