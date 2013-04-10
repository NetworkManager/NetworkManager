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
#include <dbus/dbus-glib.h>
#include <gio/gio.h>
#include "nm-logging.h"
#include "nm-dbus-manager.h"

#include "nm-sleep-monitor.h"

#define UPOWER_DBUS_SERVICE "org.freedesktop.UPower"

struct _NMSleepMonitor {
        GObject parent_instance;

        DBusGProxy *upower_proxy;
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
upower_sleeping_cb (DBusGProxy *proxy, gpointer user_data)
{
        nm_log_dbg (LOGD_SUSPEND, "Received UPower sleeping signal");
        g_signal_emit (user_data, signals[SLEEPING], 0);
}

static void
upower_resuming_cb (DBusGProxy *proxy, gpointer user_data)
{
        nm_log_dbg (LOGD_SUSPEND, "Received UPower resuming signal");
        g_signal_emit (user_data, signals[RESUMING], 0);
}

static void
nm_sleep_monitor_init (NMSleepMonitor *self)
{
        DBusGConnection *bus;

        bus = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
        self->upower_proxy = dbus_g_proxy_new_for_name (bus,
                                                        UPOWER_DBUS_SERVICE,
                                                        "/org/freedesktop/UPower",
                                                        "org.freedesktop.UPower");
        if (self->upower_proxy) {
                dbus_g_proxy_add_signal (self->upower_proxy, "Sleeping", G_TYPE_INVALID);
                dbus_g_proxy_connect_signal (self->upower_proxy, "Sleeping",
                                             G_CALLBACK (upower_sleeping_cb),
                                             self, NULL);

                dbus_g_proxy_add_signal (self->upower_proxy, "Resuming", G_TYPE_INVALID);
                dbus_g_proxy_connect_signal (self->upower_proxy, "Resuming",
                                             G_CALLBACK (upower_resuming_cb),
                                             self, NULL);
        } else
                nm_log_warn (LOGD_SUSPEND, "could not initialize UPower D-Bus proxy");
}

static void
finalize (GObject *object)
{
        NMSleepMonitor *self = NM_SLEEP_MONITOR (object);

        if (self->upower_proxy)
                g_object_unref (self->upower_proxy);

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
