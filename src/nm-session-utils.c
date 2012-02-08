/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2012 Red Hat, Inc.
 * Author: Dan Williams <dcbw@redhat.com>
 */

#include <pwd.h>
#include <sys/types.h>

#include "nm-session-utils.h"

/********************************************************************/

GQuark
nm_session_monitor_error_quark (void)
{
	static GQuark ret = 0;

	if (G_UNLIKELY (ret == 0))
		ret = g_quark_from_static_string ("nm-session-monitor-error");
	return ret;
}

/********************************************************************/

gboolean
nm_session_uid_to_user (uid_t uid, const char **out_user, GError **error)
{
	struct passwd *pw;

	pw = getpwuid (uid);
	if (!pw) {
		g_set_error (error,
			         NM_SESSION_MONITOR_ERROR,
			         NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
			         "Could not get username for UID %d",
			         uid);
		return FALSE;
	}

	if (out_user)
		*out_user = pw->pw_name;
	return TRUE;
}

gboolean
nm_session_user_to_uid (const char *user, uid_t *out_uid, GError **error)
{
	struct passwd *pw;

	pw = getpwnam (user);
	if (!pw) {
		g_set_error (error,
			         NM_SESSION_MONITOR_ERROR,
			         NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
			         "Could not get UID for username '%s'",
			         user);
		return FALSE;
	}

	/* Ugly, but hey, use ConsoleKit */
	if (out_uid)
		*out_uid = pw->pw_uid;
	return TRUE;
}

