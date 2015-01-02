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
 * (C) Copyright 2008 - 2015 Red Hat, Inc.
 * Author: Dan Williams <dcbw@redhat.com>
 * Author: Pavel Šimerda <psimerda@redhat.com>
 */
#include <pwd.h>
#include <sys/types.h>

#include "nm-session-monitor.h"

/**
 * nm_session_monitor_uid_to_user:
 * @uid: UID.
 * @out_user: Return location for user name.
 *
 * Translates a UID to a user name.
 */
gboolean
nm_session_monitor_uid_to_user (uid_t uid, const char **out_user)
{
	struct passwd *pw = getpwuid (uid);

	g_assert (out_user);

	if (!pw)
		return FALSE;

	*out_user = pw->pw_name;

	return TRUE;
}

/**
 * nm_session_monitor_user_to_uid:
 * @user: User naee.
 * @out_uid: Return location for UID.
 *
 * Translates a user name to a UID.
 */
gboolean
nm_session_monitor_user_to_uid (const char *user, uid_t *out_uid)
{
	struct passwd *pw = getpwnam (user);

	g_assert (out_uid);

	if (!pw)
		return FALSE;

	*out_uid = pw->pw_uid;

	return TRUE;
}

/**
 * nm_session_monitor_session_exists:
 * @uid: A user ID.
 * @active: Ignore inactive sessions.
 *
 * Checks whether the given @uid is logged into an active session. Don't
 * use this feature for security purposes. It is there just to allow you
 * to prefer an agent from an active session over an agent from an
 * inactive one.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @uid is
 * logged into an active session.
 */
gboolean
nm_session_monitor_session_exists (uid_t uid, gboolean active)
{
	if (active)
		return nm_session_monitor_uid_active (nm_session_monitor_get (), uid, NULL);
	else
		return nm_session_monitor_uid_has_session (nm_session_monitor_get (), uid, NULL, NULL);
}
