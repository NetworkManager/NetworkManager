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
 * (C) Copyright 2012 Red Hat, Inc.
 * Author: Matthias Clasen <mclasen@redhat.com>
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#include "nm-logging.h"
#include "nm-dbus-manager.h"

#include "nm-sleep-monitor.h"

#define SD_NAME              "org.freedesktop.login1"
#define SD_PATH              "/org/freedesktop/login1"
#define SD_INTERFACE         "org.freedesktop.login1.Manager"


struct _NMSleepMonitor {
	GObject parent_instance;

	GDBusProxy *sd_proxy;
	gint inhibit_fd;
};

struct _NMSleepMonitorClass {
	GObjectClass parent_class;

	void (*sleeping) (NMSleepMonitor *monitor);
	void (*resuming) (NMSleepMonitor *monitor);
};


enum {
	SLEEPING,
	RESUMING,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (NMSleepMonitor, nm_sleep_monitor, G_TYPE_OBJECT);

/********************************************************************/

static gboolean
drop_inhibitor (NMSleepMonitor *self)
{
	if (self->inhibit_fd >= 0) {
		nm_log_dbg (LOGD_SUSPEND, "Dropping systemd sleep inhibitor");
		close (self->inhibit_fd);
		self->inhibit_fd = -1;
		return TRUE;
	}
	return FALSE;
}

static void
inhibit_done (GObject      *source,
              GAsyncResult *result,
              gpointer      user_data)
{
	GDBusProxy *sd_proxy = G_DBUS_PROXY (source);
	NMSleepMonitor *self = user_data;
	GError *error = NULL;
	GVariant *res;
	GUnixFDList *fd_list;

	res = g_dbus_proxy_call_with_unix_fd_list_finish (sd_proxy, &fd_list, result, &error);
	if (!res) {
		nm_log_warn (LOGD_SUSPEND, "Inhibit failed: %s", error->message);
		g_error_free (error);
	} else {
		if (!fd_list || g_unix_fd_list_get_length (fd_list) != 1)
			nm_log_warn (LOGD_SUSPEND, "Didn't get a single fd back");

		self->inhibit_fd = g_unix_fd_list_get (fd_list, 0, NULL);

		nm_log_dbg (LOGD_SUSPEND, "Inhibitor fd is %d", self->inhibit_fd);
		g_object_unref (fd_list);
		g_variant_unref (res);
	}
}

static void
take_inhibitor (NMSleepMonitor *self)
{
	g_assert (self->inhibit_fd == -1);

	nm_log_dbg (LOGD_SUSPEND, "Taking systemd sleep inhibitor");
	g_dbus_proxy_call_with_unix_fd_list (self->sd_proxy,
	                                     "Inhibit",
	                                     g_variant_new ("(ssss)",
	                                                    "sleep",
	                                                    "NetworkManager",
	                                                    _("NetworkManager needs to turn off networks"),
	                                                    "delay"),
	                                     0,
	                                     G_MAXINT,
	                                     NULL,
	                                     NULL,
	                                     inhibit_done,
	                                     self);
}

static void
signal_cb (GDBusProxy  *proxy,
           const gchar *sendername,
           const gchar *signalname,
           GVariant    *args,
           gpointer     data)
{
	NMSleepMonitor *self = data;
	gboolean is_about_to_suspend;

	if (strcmp (signalname, "PrepareForSleep") != 0)
		return;

	g_variant_get (args, "(b)", &is_about_to_suspend);
	nm_log_dbg (LOGD_SUSPEND, "Received PrepareForSleep signal: %d", is_about_to_suspend);

	if (is_about_to_suspend) {
		g_signal_emit (self, signals[SLEEPING], 0);
		drop_inhibitor (self);
	} else {
		take_inhibitor (self);
		g_signal_emit (self, signals[RESUMING], 0);
	}
}

static void
sleep_setup (NMSleepMonitor *self)
{
	GDBusConnection *bus;

	bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, NULL);
	self->sd_proxy = g_dbus_proxy_new_sync (bus, 0, NULL,
	                                        SD_NAME, SD_PATH, SD_INTERFACE,
	                                        NULL, NULL);
	g_object_unref (bus);
	g_signal_connect (self->sd_proxy, "g-signal", G_CALLBACK (signal_cb), self);
}

static void
nm_sleep_monitor_init (NMSleepMonitor *self)
{
	self->inhibit_fd = -1;
	sleep_setup (self);
	take_inhibitor (self);
}

static void
finalize (GObject *object)
{
	NMSleepMonitor *self = NM_SLEEP_MONITOR (object);

	drop_inhibitor (self);
	if (self->sd_proxy)
		g_object_unref (self->sd_proxy);

	if (G_OBJECT_CLASS (nm_sleep_monitor_parent_class)->finalize != NULL)
		G_OBJECT_CLASS (nm_sleep_monitor_parent_class)->finalize (object);
}

static void
nm_sleep_monitor_class_init (NMSleepMonitorClass *klass)
{
	GObjectClass *gobject_class;

	gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->finalize = finalize;

	signals[SLEEPING] = g_signal_new (NM_SLEEP_MONITOR_SLEEPING,
	                                  NM_TYPE_SLEEP_MONITOR,
	                                  G_SIGNAL_RUN_LAST,
	                                  G_STRUCT_OFFSET (NMSleepMonitorClass, sleeping),
	                                  NULL,                   /* accumulator      */
	                                  NULL,                   /* accumulator data */
	                                  g_cclosure_marshal_VOID__VOID,
	                                  G_TYPE_NONE, 0);
	signals[RESUMING] = g_signal_new (NM_SLEEP_MONITOR_RESUMING,
	                                  NM_TYPE_SLEEP_MONITOR,
	                                  G_SIGNAL_RUN_LAST,
	                                  G_STRUCT_OFFSET (NMSleepMonitorClass, resuming),
	                                  NULL,                   /* accumulator      */
	                                  NULL,                   /* accumulator data */
	                                  g_cclosure_marshal_VOID__VOID,
	                                  G_TYPE_NONE, 0);
}

NMSleepMonitor *
nm_sleep_monitor_get (void)
{
	static NMSleepMonitor *singleton = NULL;

	if (singleton)
		return g_object_ref (singleton);

	singleton = NM_SLEEP_MONITOR (g_object_new (NM_TYPE_SLEEP_MONITOR, NULL));
	return singleton;
}

/* ---------------------------------------------------------------------------------------------------- */
