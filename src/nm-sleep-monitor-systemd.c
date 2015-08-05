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
#include <gio/gunixfdlist.h>

#include "nm-default.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

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
		g_dbus_error_strip_remote_error (error);
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
prepare_for_sleep_cb (GDBusProxy  *proxy,
                      gboolean     is_about_to_suspend,
                      gpointer     data)
{
	NMSleepMonitor *self = data;

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
name_owner_cb (GObject    *object,
               GParamSpec *pspec,
               gpointer    user_data)
{
	GDBusProxy *proxy = G_DBUS_PROXY (object);
	NMSleepMonitor *self = NM_SLEEP_MONITOR (user_data);
	char *owner;

	g_assert (proxy == self->sd_proxy);

	owner = g_dbus_proxy_get_name_owner (proxy);
	if (owner)
		take_inhibitor (self);
	else
		drop_inhibitor (self);
	g_free (owner);
}

static void
on_proxy_acquired (GObject *object,
                   GAsyncResult *res,
                   NMSleepMonitor *self)
{
	GError *error = NULL;
	char *owner;

	self->sd_proxy = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (!self->sd_proxy) {
		nm_log_warn (LOGD_SUSPEND, "Failed to acquire logind proxy: %s", error->message);
		g_clear_error (&error);
		return;
	}

	g_signal_connect (self->sd_proxy, "notify::g-name-owner", G_CALLBACK (name_owner_cb), self);
	_nm_dbus_signal_connect (self->sd_proxy, "PrepareForSleep", G_VARIANT_TYPE ("(b)"),
	                         G_CALLBACK (prepare_for_sleep_cb), self);

	owner = g_dbus_proxy_get_name_owner (self->sd_proxy);
	if (owner)
		take_inhibitor (self);
	g_free (owner);
}

static void
nm_sleep_monitor_init (NMSleepMonitor *self)
{
	self->inhibit_fd = -1;
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START |
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          SD_NAME, SD_PATH, SD_INTERFACE,
	                          NULL,
	                          (GAsyncReadyCallback) on_proxy_acquired, self);
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

NM_DEFINE_SINGLETON_GETTER (NMSleepMonitor, nm_sleep_monitor_get, NM_TYPE_SLEEP_MONITOR);

/* ---------------------------------------------------------------------------------------------------- */
