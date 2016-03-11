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
 * Author: David Zeuthen <davidz@redhat.com>
 * Author: Dan Williams <dcbw@redhat.com>
 * Author: Matthias Clasen
 * Author: Pavel Šimerda <psimerda@redhat.com>
 */
#include "nm-default.h"

#include <pwd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "nm-session-monitor.h"
#include "NetworkManagerUtils.h"

#ifdef SESSION_TRACKING_SYSTEMD
#include <systemd/sd-login.h>
#endif

/********************************************************************/

/* <internal>
 * SECTION:nm-session-monitor
 * @title: NMSessionMonitor
 * @short_description: Monitor sessions
 *
 * The #NMSessionMonitor class is a utility class to track and monitor sessions.
 */
struct _NMSessionMonitor {
	GObject parent_instance;

#ifdef SESSION_TRACKING_SYSTEMD
	struct {
		sd_login_monitor *monitor;
		guint watch;
	} sd;
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	struct {
		GFileMonitor *monitor;
		GHashTable *cache;
		time_t timestamp;
	} ck;
#endif
};

struct _NMSessionMonitorClass {
	GObjectClass parent_class;

	void (*changed) (NMSessionMonitor *monitor);
};

G_DEFINE_TYPE (NMSessionMonitor, nm_session_monitor, G_TYPE_OBJECT);

enum {
	CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

/********************************************************************/

#ifdef SESSION_TRACKING_SYSTEMD
static gboolean
st_sd_session_exists (NMSessionMonitor *monitor, uid_t uid, gboolean active)
{
	int status;

	if (!monitor->sd.monitor)
		return FALSE;

	status = sd_uid_get_sessions (uid, active, NULL);

	if (status < 0)
		nm_log_err (LOGD_CORE, "Failed to get systemd sessions for uid %d: %d",
		            uid, status);

	return status > 0;
}

static gboolean
st_sd_changed (GIOChannel *stream, GIOCondition condition, gpointer user_data)
{
	NMSessionMonitor *monitor = user_data;

	g_signal_emit (monitor, signals[CHANGED], 0);

	sd_login_monitor_flush (monitor->sd.monitor);

	return TRUE;
}

static void
st_sd_init (NMSessionMonitor *monitor)
{
	int status;
	GIOChannel *stream;

	if (!g_file_test ("/run/systemd/seats/", G_FILE_TEST_EXISTS))
		return;

	if ((status = sd_login_monitor_new (NULL, &monitor->sd.monitor)) < 0) {
		nm_log_err (LOGD_CORE, "Failed to create systemd login monitor: %d", status);
		return;
	}

	stream = g_io_channel_unix_new (sd_login_monitor_get_fd (monitor->sd.monitor));
	monitor->sd.watch = g_io_add_watch (stream, G_IO_IN, st_sd_changed, monitor);

	g_io_channel_unref (stream);
}

static void
st_sd_finalize (NMSessionMonitor *monitor)
{
	g_clear_pointer (&monitor->sd.monitor, sd_login_monitor_unref);
	g_source_remove (monitor->sd.watch);
}
#endif /* SESSION_TRACKING_SYSTEMD */

/********************************************************************/

#ifdef SESSION_TRACKING_CONSOLEKIT
typedef struct {
	gboolean active;
} CkSession;

static gboolean
ck_load_cache (GHashTable *cache)
{
	GKeyFile *keyfile = g_key_file_new ();
	char **groups = NULL;
	GError *error = NULL;
	gsize i, len;
	gboolean finished = FALSE;

	if (!g_key_file_load_from_file (keyfile, CKDB_PATH, G_KEY_FILE_NONE, &error))
		goto out;

	if (!(groups = g_key_file_get_groups (keyfile, &len))) {
		nm_log_err (LOGD_CORE, "Could not load groups from " CKDB_PATH);
		goto out;
	}

	g_hash_table_remove_all (cache);

	for (i = 0; i < len; i++) {
		guint uid = G_MAXUINT;
		CkSession session = { .active = FALSE };

		if (!g_str_has_prefix (groups[i], "CkSession "))
			continue;

		uid = g_key_file_get_integer (keyfile, groups[i], "uid", &error);
		if (error)
			goto out;

		session.active = g_key_file_get_boolean (keyfile, groups[i], "is_active", &error);
		if (error)
			goto out;

		g_hash_table_insert (cache, GUINT_TO_POINTER (uid), g_memdup (&session, sizeof session));
	}

	finished = TRUE;
out:
	if (error)
		nm_log_err (LOGD_CORE, "ConsoleKit: Failed to load database: %s", error->message);
	g_clear_error (&error);
	g_clear_pointer (&groups, g_strfreev);
	g_clear_pointer (&keyfile, g_key_file_free);

	return finished;
}

static gboolean
ck_update_cache (NMSessionMonitor *monitor)
{
	struct stat statbuf;

	if (!monitor->ck.cache)
		return FALSE;

	/* Check the database file */
	if (stat (CKDB_PATH, &statbuf) != 0) {
		nm_log_err (LOGD_CORE, "Failed to check ConsoleKit timestamp: %s", strerror (errno));
		return FALSE;
	}
	if (statbuf.st_mtime == monitor->ck.timestamp)
		return TRUE;

	/* Update the cache */
	if (!ck_load_cache (monitor->ck.cache))
		return FALSE;

	monitor->ck.timestamp = statbuf.st_mtime;

	return TRUE;
}

static gboolean
ck_session_exists (NMSessionMonitor *monitor, uid_t uid, gboolean active)
{
	CkSession *session;

	if (!ck_update_cache (monitor))
		return FALSE;

	session = g_hash_table_lookup (monitor->ck.cache, GUINT_TO_POINTER (uid));

	if (!session)
		return FALSE;
	if (active && !session->active)
		return FALSE;

	return TRUE;
}

static void
ck_changed (GFileMonitor *    file_monitor,
            GFile *           file,
            GFile *           other_file,
            GFileMonitorEvent event_type,
            gpointer          user_data)
{
	g_signal_emit (user_data, signals[CHANGED], 0);
}

static void
ck_init (NMSessionMonitor *monitor)
{
	GFile *file = g_file_new_for_path (CKDB_PATH);
	GError *error = NULL;

	if (g_file_query_exists (file, NULL)) {
		if ((monitor->ck.monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, &error))) {
			monitor->ck.cache = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);
			g_signal_connect (monitor->ck.monitor,
							  "changed",
							  G_CALLBACK (ck_changed),
							  monitor);
		} else {
			nm_log_err (LOGD_CORE, "Error monitoring " CKDB_PATH ": %s", error->message);
			g_clear_error (&error);
		}
	}

	g_object_unref (file);
}

static void
ck_finalize (NMSessionMonitor *monitor)
{
	g_clear_pointer (&monitor->ck.cache, g_hash_table_unref);
	g_clear_object (&monitor->ck.monitor);
}
#endif /* SESSION_TRACKING_CONSOLEKIT */

/********************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMSessionMonitor, nm_session_monitor_get, NM_TYPE_SESSION_MONITOR);

/**
 * nm_session_monitor_connect:
 * @self: the session monitor
 * @callback: The callback.
 * @user_data: User data for the callback.
 *
 * Connect a callback to the session monitor.
 *
 * Returns: Handler ID to be used with nm_session_monitor_disconnect().
 */
gulong
nm_session_monitor_connect (NMSessionMonitor *self,
                            NMSessionCallback callback,
                            gpointer user_data)
{
	g_return_val_if_fail (NM_IS_SESSION_MONITOR (self), 0);

	return g_signal_connect (self,
                             NM_SESSION_MONITOR_CHANGED,
                             G_CALLBACK (callback),
                             user_data);
}

/**
 * nm_session_monitor_disconnect:
 * @self: the session monitor
 * @handler_id: Handler ID returned by nm_session_monitor-connect().
 *
 * Disconnect callback from the session handler.
 */
void
nm_session_monitor_disconnect (NMSessionMonitor *self,
                               gulong handler_id)
{
	g_return_if_fail (NM_IS_SESSION_MONITOR (self));

	g_signal_handler_disconnect (self, handler_id);
}

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
 * @self: the session monitor
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
nm_session_monitor_session_exists (NMSessionMonitor *self,
                                   uid_t uid,
                                   gboolean active)
{
	g_return_val_if_fail (NM_IS_SESSION_MONITOR (self), FALSE);

#ifdef SESSION_TRACKING_SYSTEMD
	if (st_sd_session_exists (self, uid, active))
		return TRUE;
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	if (ck_session_exists (self, uid, active))
		return TRUE;
#endif

	return FALSE;
}

/********************************************************************/

static void
nm_session_monitor_init (NMSessionMonitor *monitor)
{
#ifdef SESSION_TRACKING_SYSTEMD
	st_sd_init (monitor);
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	ck_init (monitor);
#endif
}

static void
nm_session_monitor_finalize (GObject *object)
{
#ifdef SESSION_TRACKING_SYSTEMD
	st_sd_finalize (NM_SESSION_MONITOR (object));
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	ck_finalize (NM_SESSION_MONITOR (object));
#endif

	if (G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize != NULL)
		G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize (object);
}

static void
nm_session_monitor_class_init (NMSessionMonitorClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->finalize = nm_session_monitor_finalize;

	/**
	 * NMSessionMonitor::changed:
	 * @monitor: A #NMSessionMonitor
	 *
	 * Emitted when something changes.
	 */
	signals[CHANGED] = g_signal_new (NM_SESSION_MONITOR_CHANGED,
	                                        NM_TYPE_SESSION_MONITOR,
	                                        G_SIGNAL_RUN_LAST,
	                                        G_STRUCT_OFFSET (NMSessionMonitorClass, changed),
	                                        NULL,                   /* accumulator      */
	                                        NULL,                   /* accumulator data */
	                                        g_cclosure_marshal_VOID__VOID,
	                                        G_TYPE_NONE,
	                                        0);
}
