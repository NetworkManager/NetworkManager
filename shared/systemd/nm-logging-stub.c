/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-glib-aux/nm-logging-fwd.h"

/*****************************************************************************/

gboolean
_nm_log_enabled_impl (gboolean mt_require_locking,
                      NMLogLevel level,
                      NMLogDomain domain)
{
	return FALSE;
}

void
_nm_log_impl (const char *file,
              guint line,
              const char *func,
              gboolean mt_require_locking,
              NMLogLevel level,
              NMLogDomain domain,
              int error,
              const char *ifname,
              const char *con_uuid,
              const char *fmt,
              ...)
{
}
