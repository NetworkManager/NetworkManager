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
#include "nm-default.h"
#include "nm-core-internal.h"

#include "nm-sleep-monitor.h"

#define UPOWER_DBUS_SERVICE "org.freedesktop.UPower"

struct _NMSleepMonitor {
	GObject parent_instance;

	GDBusProxy *upower_proxy;
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

static void
upower_sleeping_cb (GDBusProxy *proxy, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received UPower sleeping signal");
	g_signal_emit (user_data, signals[SLEEPING], 0);
}

static void
upower_resuming_cb (GDBusProxy *proxy, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received UPower resuming signal");
	g_signal_emit (user_data, signals[RESUMING], 0);
}

static void
nm_sleep_monitor_init (NMSleepMonitor *self)
{
	GError *error = NULL;

	self->upower_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                                    G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START |
	                                                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                                    NULL,
	                                                    UPOWER_DBUS_SERVICE,
	                                                    "/org/freedesktop/UPower",
	                                                    "org.freedesktop.UPower",
	                                                    NULL, &error);
	if (self->upower_proxy) {
		_nm_dbus_signal_connect (self->upower_proxy, "Sleeping", NULL,
		                         G_CALLBACK (upower_sleeping_cb), self);
		_nm_dbus_signal_connect (self->upower_proxy, "Resuming", NULL,
		                         G_CALLBACK (upower_resuming_cb), self);
	} else {
		nm_log_warn (LOGD_SUSPEND, "could not initialize UPower D-Bus proxy: %s", error->message);
		g_error_free (error);
	}
}

static void
finalize (GObject *object)
{
	NMSleepMonitor *self = NM_SLEEP_MONITOR (object);

	g_clear_object (&self->upower_proxy);

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
