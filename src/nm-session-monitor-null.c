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
 * (C) Copyright 2008 - 2010 Red Hat, Inc.
 * Author: David Zeuthen <davidz@redhat.com>
 * Author: Dan Williams <dcbw@redhat.com>
 */

#include "config.h"
#include <string.h>
#include "nm-logging.h"

#include "nm-session-utils.h"
#include "nm-session-monitor.h"

/* <internal>
 * SECTION:nm-session-monitor
 * @title: NMSessionMonitor
 * @short_description: Monitor sessions
 *
 * The #NMSessionMonitor class is a utility class to track and monitor sessions.
 */

struct _NMSessionMonitor {
	GObject parent_instance;
};

struct _NMSessionMonitorClass {
	GObjectClass parent_class;

	void (*changed) (NMSessionMonitor *monitor);
};


enum {
	CHANGED,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (NMSessionMonitor, nm_session_monitor, G_TYPE_OBJECT);

/********************************************************************/

static void
nm_session_monitor_init (NMSessionMonitor *self)
{
}

static void
nm_session_monitor_class_init (NMSessionMonitorClass *klass)
{
	/**
	 * NMSessionMonitor::changed:
	 * @monitor: A #NMSessionMonitor
	 *
	 * Emitted when something changes.
	 */
	signals[CHANGED] = g_signal_new (NM_SESSION_MONITOR_CHANGED,
	                                 NM_TYPE_SESSION_MONITOR,
	                                 G_SIGNAL_RUN_LAST,
	                                 0, NULL, NULL,
	                                 g_cclosure_marshal_VOID__VOID,
	                                 G_TYPE_NONE, 0);
}

NMSessionMonitor *
nm_session_monitor_get (void)
{
	static NMSessionMonitor *singleton = NULL;

	if (!singleton)
		singleton = g_object_new (NM_TYPE_SESSION_MONITOR, NULL);
	return singleton;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * nm_session_monitor_user_has_session:
 * @monitor: A #NMSessionMonitor.
 * @username: A username.
 * @error: Return location for error.
 *
 * Checks whether the given @username is logged into a session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @username is
 * currently logged into a session.
 */
gboolean
nm_session_monitor_user_has_session (NMSessionMonitor *monitor,
                                     const char *username,
                                     uid_t *out_uid,
                                     GError **error)
{
	return nm_session_user_to_uid (username, out_uid, error);
}

/**
 * nm_session_monitor_uid_has_session:
 * @monitor: A #NMSessionMonitor.
 * @uid: A user ID.
 * @error: Return location for error.
 *
 * Checks whether the given @uid is logged into a session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @uid is
 * currently logged into a session.
 */
gboolean
nm_session_monitor_uid_has_session (NMSessionMonitor *monitor,
                                    uid_t uid,
                                    const char **out_user,
                                    GError **error)
{
	return nm_session_uid_to_user (uid, out_user, error);
}

/**
 * nm_session_monitor_user_active:
 * @monitor: A #NMSessionMonitor.
 * @username: A username.
 * @error: Return location for error.
 *
 * Checks whether the given @username is logged into a active session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @username is
 * logged into an active session.
 */
gboolean
nm_session_monitor_user_active (NMSessionMonitor *monitor,
                                const char *username,
                                GError **error)
{
	return TRUE;
}

/**
 * nm_session_monitor_uid_active:
 * @monitor: A #NMSessionMonitor.
 * @uid: A user ID.
 * @error: Return location for error.
 *
 * Checks whether the given @uid is logged into a active session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @uid is
 * logged into an active session.
 */
gboolean
nm_session_monitor_uid_active (NMSessionMonitor *monitor,
                               uid_t uid,
                               GError **error)
{
	return TRUE;
}

