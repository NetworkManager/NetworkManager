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

#include "nm-default.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <gio/gunixfdlist.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "nm-sleep-monitor.h"

#if defined (SUSPEND_RESUME_SYSTEMD) == defined (SUSPEND_RESUME_CONSOLEKIT)
#error either define SUSPEND_RESUME_SYSTEMD or SUSPEND_RESUME_CONSOLEKIT
#endif

#ifdef SUSPEND_RESUME_SYSTEMD

#define SUSPEND_DBUS_NAME               "org.freedesktop.login1"
#define SUSPEND_DBUS_PATH               "/org/freedesktop/login1"
#define SUSPEND_DBUS_INTERFACE          "org.freedesktop.login1.Manager"

#else

/* ConsoleKit2 has added the same suspend/resume DBUS API that Systemd
 * uses. http://consolekit2.github.io/ConsoleKit2/#Manager.Inhibit
 */

#define SUSPEND_DBUS_NAME               "org.freedesktop.ConsoleKit"
#define SUSPEND_DBUS_PATH               "/org/freedesktop/ConsoleKit/Manager"
#define SUSPEND_DBUS_INTERFACE          "org.freedesktop.ConsoleKit.Manager"

#endif

struct _NMSleepMonitor {
	GObject parent_instance;

	GDBusProxy *proxy;

	/* used both during construction of proxy and during Inhibit call. */
	GCancellable *cancellable;

	gint inhibit_fd;

	gulong sig_id_1;
	gulong sig_id_2;
};

struct _NMSleepMonitorClass {
	GObjectClass parent_class;
};

enum {
	SLEEPING,
	RESUMING,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (NMSleepMonitor, nm_sleep_monitor, G_TYPE_OBJECT);

NM_DEFINE_SINGLETON_GETTER (NMSleepMonitor, nm_sleep_monitor_get, NM_TYPE_SLEEP_MONITOR);

/*****************************************************************************/

#ifdef SUSPEND_RESUME_SYSTEMD
#define _NMLOG_PREFIX_NAME                "sleep-monitor-sd"
#else
#define _NMLOG_PREFIX_NAME                "sleep-monitor-ck"
#endif

#define _NMLOG_DOMAIN                     LOGD_SUSPEND
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[20]; \
            const NMSleepMonitor *const __self = (self); \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     (!__self || __self == singleton_instance \
                        ? "" \
                        : nm_sprintf_buf (__prefix, "[%p]", __self)) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void
drop_inhibitor (NMSleepMonitor *self)
{
	if (self->inhibit_fd >= 0) {
		_LOGD ("Dropping systemd sleep inhibitor %d", self->inhibit_fd);
		close (self->inhibit_fd);
		self->inhibit_fd = -1;
	}

	nm_clear_g_cancellable (&self->cancellable);
}

static void
inhibit_done (GObject      *source,
              GAsyncResult *result,
              gpointer      user_data)
{
	GDBusProxy *proxy = G_DBUS_PROXY (source);
	NMSleepMonitor *self = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *res = NULL;
	gs_unref_object GUnixFDList *fd_list = NULL;

	res = g_dbus_proxy_call_with_unix_fd_list_finish (proxy, &fd_list, result, &error);
	if (!res) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			g_clear_object (&self->cancellable);
			_LOGW ("Inhibit failed: %s", error->message);
		}
		return;
	}

	g_clear_object (&self->cancellable);

	if (!fd_list || g_unix_fd_list_get_length (fd_list) != 1) {
		_LOGW ("Didn't get a single fd back");
		return;
	}

	self->inhibit_fd = g_unix_fd_list_get (fd_list, 0, NULL);
	_LOGD ("Inhibitor fd is %d", self->inhibit_fd);
}

static void
take_inhibitor (NMSleepMonitor *self)
{
	g_return_if_fail (NM_IS_SLEEP_MONITOR (self));
	g_return_if_fail (G_IS_DBUS_PROXY (self->proxy));

	drop_inhibitor (self);

	_LOGD ("Taking systemd sleep inhibitor");
	self->cancellable = g_cancellable_new ();
	g_dbus_proxy_call_with_unix_fd_list (self->proxy,
	                                     "Inhibit",
	                                     g_variant_new ("(ssss)",
	                                                    "sleep",
	                                                    "NetworkManager",
	                                                    "NetworkManager needs to turn off networks",
	                                                    "delay"),
	                                     0,
	                                     G_MAXINT,
	                                     NULL,
	                                     self->cancellable,
	                                     inhibit_done,
	                                     self);
}

static void
prepare_for_sleep_cb (GDBusProxy  *proxy,
                      gboolean     is_about_to_suspend,
                      gpointer     data)
{
	NMSleepMonitor *self = data;

	_LOGD ("Received PrepareForSleep signal: %d", is_about_to_suspend);

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

	g_assert (proxy == self->proxy);

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
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (!proxy) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			_LOGW ("Failed to acquire logind proxy: %s", error->message);
		g_clear_error (&error);
		return;
	}
	self->proxy = proxy;
	g_clear_object (&self->cancellable);

	self->sig_id_1 = g_signal_connect (self->proxy, "notify::g-name-owner",
	                                   G_CALLBACK (name_owner_cb), self);
	self->sig_id_2 = _nm_dbus_signal_connect (self->proxy, "PrepareForSleep",
	                                          G_VARIANT_TYPE ("(b)"),
	                                          G_CALLBACK (prepare_for_sleep_cb), self);

	owner = g_dbus_proxy_get_name_owner (self->proxy);
	if (owner)
		take_inhibitor (self);
	g_free (owner);
}

static void
nm_sleep_monitor_init (NMSleepMonitor *self)
{
	self->inhibit_fd = -1;
	self->cancellable = g_cancellable_new ();
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START |
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          SUSPEND_DBUS_NAME, SUSPEND_DBUS_PATH, SUSPEND_DBUS_INTERFACE,
	                          self->cancellable,
	                          (GAsyncReadyCallback) on_proxy_acquired, self);
}

static void
dispose (GObject *object)
{
	NMSleepMonitor *self = NM_SLEEP_MONITOR (object);

	/* drop_inhibitor() also clears our "cancellable" */
	drop_inhibitor (self);

	if (self->proxy) {
		nm_clear_g_signal_handler (self->proxy, &self->sig_id_1);
		nm_clear_g_signal_handler (self->proxy, &self->sig_id_2);
		g_clear_object (&self->proxy);
	}

	G_OBJECT_CLASS (nm_sleep_monitor_parent_class)->dispose (object);
}

static void
nm_sleep_monitor_class_init (NMSleepMonitorClass *klass)
{
	GObjectClass *gobject_class;

	gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->dispose = dispose;

	signals[SLEEPING] = g_signal_new (NM_SLEEP_MONITOR_SLEEPING,
	                                  NM_TYPE_SLEEP_MONITOR,
	                                  G_SIGNAL_RUN_LAST,
	                                  0, NULL, NULL,
	                                  g_cclosure_marshal_VOID__VOID,
	                                  G_TYPE_NONE, 0);
	signals[RESUMING] = g_signal_new (NM_SLEEP_MONITOR_RESUMING,
	                                  NM_TYPE_SLEEP_MONITOR,
	                                  G_SIGNAL_RUN_LAST,
	                                  0, NULL, NULL,
	                                  g_cclosure_marshal_VOID__VOID,
	                                  G_TYPE_NONE, 0);
}

