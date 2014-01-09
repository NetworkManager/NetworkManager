/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 *
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
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 * Author: Matthias Clasen
 */

#include "config.h"
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <glib/gstdio.h>
#include <systemd/sd-login.h>
#include <stdlib.h>

#include "nm-session-utils.h"
#include "nm-session-monitor.h"
#include "nm-logging.h"

/********************************************************************/

typedef struct {
	GSource source;
	GPollFD pollfd;
	sd_login_monitor *monitor;
} SdSource;

static gboolean
sd_source_prepare (GSource *source, gint *timeout)
{
	*timeout = -1;
	return FALSE;
}

static gboolean
sd_source_check (GSource *source)
{
	SdSource *sd_source = (SdSource *) source;

	return sd_source->pollfd.revents != 0;
}

static gboolean
sd_source_dispatch (GSource     *source,
                    GSourceFunc  callback,
                    gpointer     user_data)

{
	SdSource *sd_source = (SdSource *)source;
	gboolean ret;

	g_warn_if_fail (callback != NULL);
	ret = (*callback) (user_data);
	sd_login_monitor_flush (sd_source->monitor);
	return ret;
}

static void
sd_source_finalize (GSource *source)
{
	SdSource *sd_source = (SdSource*) source;

	sd_login_monitor_unref (sd_source->monitor);
}

static GSourceFuncs sd_source_funcs = {
	sd_source_prepare,
	sd_source_check,
	sd_source_dispatch,
	sd_source_finalize
};

static GSource *
sd_source_new (void)
{
	GSource *source;
	SdSource *sd_source;
	int ret;

	source = g_source_new (&sd_source_funcs, sizeof (SdSource));
	sd_source = (SdSource *)source;

	ret = sd_login_monitor_new (NULL, &sd_source->monitor);
	if (ret < 0)
		g_printerr ("Error getting login monitor: %d", ret);
	else {
		sd_source->pollfd.fd = sd_login_monitor_get_fd (sd_source->monitor);
		sd_source->pollfd.events = G_IO_IN;
		g_source_add_poll (source, &sd_source->pollfd);
	}

	return source;
}

struct _NMSessionMonitor {
	GObject parent_instance;

	GSource *sd_source;
};

struct _NMSessionMonitorClass {
	GObjectClass parent_class;

	void (*changed) (NMSessionMonitor *monitor);
};


enum {
	CHANGED_SIGNAL,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (NMSessionMonitor, nm_session_monitor, G_TYPE_OBJECT);

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
sessions_changed (gpointer user_data)
{
	NMSessionMonitor *monitor = NM_SESSION_MONITOR (user_data);

	g_signal_emit (monitor, signals[CHANGED_SIGNAL], 0);
	return TRUE;
}


static void
nm_session_monitor_init (NMSessionMonitor *monitor)
{
	monitor->sd_source = sd_source_new ();
	g_source_set_callback (monitor->sd_source, sessions_changed, monitor, NULL);
	g_source_attach (monitor->sd_source, NULL);
}

static void
nm_session_monitor_finalize (GObject *object)
{
	NMSessionMonitor *monitor = NM_SESSION_MONITOR (object);

	if (monitor->sd_source != NULL) {
		g_source_destroy (monitor->sd_source);
		g_source_unref (monitor->sd_source);
	}

	if (G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize != NULL)
		G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize (object);
}

static void
nm_session_monitor_class_init (NMSessionMonitorClass *klass)
{
	GObjectClass *gobject_class;

	gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->finalize = nm_session_monitor_finalize;

	/**
	 * NMSessionMonitor::changed:
	 * @monitor: A #NMSessionMonitor
	 *
	 * Emitted when something changes.
	 */
	signals[CHANGED_SIGNAL] = g_signal_new ("changed",
	                                        NM_TYPE_SESSION_MONITOR,
	                                        G_SIGNAL_RUN_LAST,
	                                        G_STRUCT_OFFSET (NMSessionMonitorClass, changed),
	                                        NULL,                   /* accumulator      */
	                                        NULL,                   /* accumulator data */
	                                        g_cclosure_marshal_VOID__VOID,
	                                        G_TYPE_NONE,
	                                        0);
}

NMSessionMonitor *
nm_session_monitor_get (void)
{
	static NMSessionMonitor *singleton = NULL;

	if (!singleton)
		singleton = g_object_new (NM_TYPE_SESSION_MONITOR, NULL);
	return singleton;
}

gboolean
nm_session_monitor_user_has_session (NMSessionMonitor *monitor,
                                     const char *username,
                                     uid_t *out_uid,
                                     GError **error)
{
	uid_t uid;

	if (!nm_session_user_to_uid (username, &uid, error))
		return FALSE;

	if (out_uid)
		*out_uid = uid;

	return nm_session_monitor_uid_has_session (monitor, uid, NULL, error);
}

gboolean
nm_session_monitor_user_active (NMSessionMonitor *monitor,
                                const char *username,
                                GError **error)
{
	uid_t uid;

	if (!nm_session_user_to_uid (username, &uid, error))
		return FALSE;

	return nm_session_monitor_uid_active (monitor, uid, error);
}

gboolean
nm_session_monitor_uid_has_session (NMSessionMonitor *monitor,
                                    uid_t uid,
                                    const char **out_user,
                                    GError **error)
{
	int num_sessions;

	if (!nm_session_uid_to_user (uid, out_user, error))
		return FALSE;

	/* Get all sessions (including inactive ones) for the user */
	num_sessions = sd_uid_get_sessions (uid, 0, NULL);
	if (num_sessions < 0) {
		nm_log_warn (LOGD_CORE, "Failed to get systemd sessions for uid %d: %d",
		             uid, num_sessions);
		return FALSE;
	}
	return num_sessions > 0;
}

gboolean
nm_session_monitor_uid_active (NMSessionMonitor *monitor,
                               uid_t uid,
                               GError **error)
{
	int num_sessions;

	/* Get active sessions for the user */
	num_sessions = sd_uid_get_sessions (uid, 1, NULL);
	if (num_sessions < 0) {
		nm_log_warn (LOGD_CORE, "Failed to get active systemd sessions for uid %d: %d",
		             uid, num_sessions);
		return FALSE;
	}
	return num_sessions > 0;
}
