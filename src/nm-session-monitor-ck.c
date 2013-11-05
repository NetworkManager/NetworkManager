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
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <gio/gio.h>
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

	GKeyFile *database;
	GFileMonitor *database_monitor;
	time_t database_mtime;
	GHashTable *sessions_by_uid;
	GHashTable *sessions_by_user;
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

typedef struct {
	char *user;
	uid_t uid;
	gboolean local;
	gboolean active;
} Session;

static void
session_free (Session *s)
{
	g_free (s->user);
	memset (s, 0, sizeof (Session));
	g_free (s);
}

static gboolean
check_key (GKeyFile *keyfile, const char *group, const char *key, GError **error)
{
	if (g_key_file_has_key (keyfile, group, key, error))
		return TRUE;

	if (!error) {
		g_set_error (error,
			         NM_SESSION_MONITOR_ERROR,
			         NM_SESSION_MONITOR_ERROR_MALFORMED_DATABASE,
			         "ConsoleKit database " CKDB_PATH " group '%s' had no '%s' key",
			         group, key);
	}
	return FALSE;
}

static Session *
session_new (GKeyFile *keyfile, const char *group, GError **error)
{
	GError *local = NULL;
	Session *s;
	const char *uname = NULL;

	s = g_new0 (Session, 1);
	g_assert (s);

	s->uid = G_MAXUINT; /* paranoia */
	if (!check_key (keyfile, group, "uid", &local))
		goto error;
	s->uid = (uid_t) g_key_file_get_integer (keyfile, group, "uid", &local);
	if (local)
		goto error;

	if (!check_key (keyfile, group, "is_active", &local))
		goto error;
	s->active = g_key_file_get_boolean (keyfile, group, "is_active", &local);
	if (local)
		goto error;

	if (!check_key (keyfile, group, "is_local", &local))
		goto error;
	s->local = g_key_file_get_boolean (keyfile, group, "is_local", &local);
	if (local)
		goto error;

	if (!nm_session_uid_to_user (s->uid, &uname, error))
		return FALSE;
	s->user = g_strdup (uname);

	return s;

error:
	session_free (s);
	g_propagate_error (error, local);
	return NULL;
}

static void
session_merge (Session *src, Session *dest)
{
	g_return_if_fail (src != NULL);
	g_return_if_fail (dest != NULL);

	g_warn_if_fail (g_strcmp0 (src->user, dest->user) == 0);
	g_warn_if_fail (src->uid == dest->uid);

	dest->local = (dest->local || src->local);
	dest->active = (dest->active || src->active);
}

/********************************************************************/

static void
free_database (NMSessionMonitor *self)
{
	if (self->database != NULL) {
		g_key_file_free (self->database);
		self->database = NULL;
	}

	g_hash_table_remove_all (self->sessions_by_uid);
	g_hash_table_remove_all (self->sessions_by_user);
}

static gboolean
reload_database (NMSessionMonitor *self, GError **error)
{
	struct stat statbuf;
	char **groups = NULL;
	gsize len = 0, i;
	Session *s;

	free_database (self);

	errno = 0;
	if (stat (CKDB_PATH, &statbuf) != 0) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             errno == ENOENT ? NM_SESSION_MONITOR_ERROR_NO_DATABASE : NM_SESSION_MONITOR_ERROR_IO_ERROR,
		             "Error statting file " CKDB_PATH ": %s",
		             strerror (errno));
		goto error;
	}
	self->database_mtime = statbuf.st_mtime;

	self->database = g_key_file_new ();
	if (!g_key_file_load_from_file (self->database, CKDB_PATH, G_KEY_FILE_NONE, error))
		goto error;

	groups = g_key_file_get_groups (self->database, &len);
	if (!groups) {
		g_set_error_literal (error,
		                     NM_SESSION_MONITOR_ERROR,
		                     NM_SESSION_MONITOR_ERROR_IO_ERROR,
		                     "Could not load groups from " CKDB_PATH "");
		goto error;
	}

	for (i = 0; i < len; i++) {
		Session *found;

		if (!g_str_has_prefix (groups[i], "Session "))
			continue;

		s = session_new (self->database, groups[i], error);
		if (!s)
			goto error;

		found = g_hash_table_lookup (self->sessions_by_user, (gpointer) s->user);
		if (found) {
			session_merge (s, found);
			session_free (s);
		} else {
			/* Entirely new user */
			g_hash_table_insert (self->sessions_by_user, (gpointer) s->user, s);
			g_hash_table_insert (self->sessions_by_uid, GUINT_TO_POINTER (s->uid), s);
		}
	}

	g_strfreev (groups);
	return TRUE;

error:
	if (groups)
		g_strfreev (groups);
	free_database (self);
	return FALSE;
}

static gboolean
ensure_database (NMSessionMonitor *self, GError **error)
{
	gboolean ret = FALSE;

	if (self->database != NULL) {
		struct stat statbuf;

		errno = 0;
		if (stat (CKDB_PATH, &statbuf) != 0) {
			g_set_error (error,
			             NM_SESSION_MONITOR_ERROR,
			             errno == ENOENT ? NM_SESSION_MONITOR_ERROR_NO_DATABASE : NM_SESSION_MONITOR_ERROR_IO_ERROR,
			             "Error statting file " CKDB_PATH " to check timestamp: %s",
			             strerror (errno));
			goto out;
		}

		if (statbuf.st_mtime == self->database_mtime) {
			ret = TRUE;
			goto out;
		}
	}

	ret = reload_database (self, error);

out:
	return ret;
}

static void
on_file_monitor_changed (GFileMonitor *    file_monitor,
                         GFile *           file,
                         GFile *           other_file,
                         GFileMonitorEvent event_type,
                         gpointer          user_data)
{
	NMSessionMonitor *self = NM_SESSION_MONITOR (user_data);

	/* throw away cache */
	free_database (self);

	g_signal_emit (self, signals[CHANGED], 0);
}

static void
nm_session_monitor_init (NMSessionMonitor *self)
{
	GError *error = NULL;
	GFile *file;

	/* Sessions-by-user is responsible for destroying the Session objects */
	self->sessions_by_user = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                                NULL, (GDestroyNotify) session_free);
	self->sessions_by_uid = g_hash_table_new (g_direct_hash, g_direct_equal);


	error = NULL;
	if (!ensure_database (self, &error)) {
		/* Ignore the first error if the CK database isn't found yet */
		if (g_error_matches (error,
		                     NM_SESSION_MONITOR_ERROR,
		                     NM_SESSION_MONITOR_ERROR_NO_DATABASE) == FALSE) {
			nm_log_err (LOGD_CORE, "Error loading " CKDB_PATH ": %s", error->message);
		}
		g_error_free (error);
	}

	error = NULL;
	file = g_file_new_for_path (CKDB_PATH);
	self->database_monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, &error);
	g_object_unref (file);
	if (self->database_monitor == NULL) {
		nm_log_err (LOGD_CORE, "Error monitoring " CKDB_PATH ": %s", error->message);
		g_error_free (error);
	} else {
		g_signal_connect (self->database_monitor,
		                  "changed",
		                  G_CALLBACK (on_file_monitor_changed),
		                  self);
	}
}

static void
finalize (GObject *object)
{
	NMSessionMonitor *self = NM_SESSION_MONITOR (object);

	if (self->database_monitor != NULL)
		g_object_unref (self->database_monitor);

	free_database (self);

	if (G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize != NULL)
		G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize (object);
}

static void
nm_session_monitor_class_init (NMSessionMonitorClass *klass)
{
	GObjectClass *gobject_class;

	gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->finalize = finalize;

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
	                                 G_TYPE_NONE, 0);
}

NMSessionMonitor *
nm_session_monitor_get (void)
{
	static NMSessionMonitor *singleton = NULL;

	if (!singleton)
		singleton = NM_SESSION_MONITOR (g_object_new (NM_TYPE_SESSION_MONITOR, NULL));
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
	Session *s;

	if (!ensure_database (monitor, error))
		return FALSE;

	s = g_hash_table_lookup (monitor->sessions_by_user, (gpointer) username);
	if (!s) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
		             "No session found for user '%s'",
		             username);
		return FALSE;
	}

	if (out_uid)
		*out_uid = s->uid;
	return TRUE;
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
	Session *s;

	if (!ensure_database (monitor, error))
		return FALSE;

	s = g_hash_table_lookup (monitor->sessions_by_uid, GUINT_TO_POINTER (uid));
	if (!s) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
		             "No session found for uid %d",
		             uid);
		return FALSE;
	}

	if (out_user)
		*out_user = s->user;
	return TRUE;
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
	Session *s;

	if (!ensure_database (monitor, error))
		return FALSE;

	s = g_hash_table_lookup (monitor->sessions_by_user, (gpointer) username);
	if (!s) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
		             "No session found for user '%s'",
		             username);
		return FALSE;
	}

	return s->active;
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
	Session *s;

	if (!ensure_database (monitor, error))
		return FALSE;

	s = g_hash_table_lookup (monitor->sessions_by_uid, GUINT_TO_POINTER (uid));
	if (!s) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
		             "No session found for uid '%d'",
		             uid);
		return FALSE;
	}

	return s->active;
}

