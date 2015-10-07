/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright 2014 Red Hat, Inc.
 *
 */

#include "config.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "nm-default.h"
#include "nm-dhcp-listener.h"
#include "nm-core-internal.h"
#include "nm-bus-manager.h"
#include "NetworkManagerUtils.h"

#define NM_DHCP_CLIENT_DBUS_IFACE "org.freedesktop.nm_dhcp_client"
#define PRIV_SOCK_PATH            NMRUNDIR "/private-dhcp"
#define PRIV_SOCK_TAG             "dhcp"

typedef struct {
	NMBusManager *      dbus_mgr;
	guint               new_conn_id;
	guint               dis_conn_id;
	GHashTable *        signal_handlers;
} NMDhcpListenerPrivate;

#define NM_DHCP_LISTENER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_LISTENER, NMDhcpListenerPrivate))

G_DEFINE_TYPE (NMDhcpListener, nm_dhcp_listener, G_TYPE_OBJECT)

enum {
	EVENT,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/***************************************************/

static char *
get_option (GVariant *options, const char *key)
{
	GVariant *value;
	const guchar *bytes, *s;
	gsize len;
	char *converted, *d;

	if (!g_variant_lookup (options, key, "@ay", &value))
		return NULL;

	bytes = g_variant_get_fixed_array (value, &len, 1);

	/* Since the DHCP options come through environment variables, they should
	 * already be UTF-8 safe, but just make sure.
	 */
	converted = g_malloc (len + 1);
	for (s = bytes, d = converted; s < bytes + len; s++, d++) {
		/* Convert NULLs to spaces and non-ASCII characters to ? */
		if (*s == '\0')
			*d = ' ';
		else if (*s > 127)
			*d = '?';
		else
			*d = *s;
	}
	*d = '\0';
	g_variant_unref (value);

	return converted;
}

static void
handle_event (GDBusConnection  *connection,
              const char       *sender_name,
              const char       *object_path,
              const char       *interface_name,
              const char       *signal_name,
              GVariant         *parameters,
              gpointer          user_data)
{
	NMDhcpListener *self = NM_DHCP_LISTENER (user_data);
	char *iface = NULL;
	char *pid_str = NULL;
	char *reason = NULL;
	gint pid;
	gboolean handled = FALSE;
	GVariant *options;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})")))
		return;

	g_variant_get (parameters, "(@a{sv})", &options);

	iface = get_option (options, "interface");
	if (iface == NULL) {
		nm_log_warn (LOGD_DHCP, "DHCP event: didn't have associated interface.");
		goto out;
	}

	pid_str = get_option (options, "pid");
	pid = _nm_utils_ascii_str_to_int64 (pid_str, 10, 0, G_MAXINT32, -1);
	if (pid == -1) {
		nm_log_warn (LOGD_DHCP, "DHCP event: couldn't convert PID '%s' to an integer", pid_str ? pid_str : "(null)");
		goto out;
	}

	reason = get_option (options, "reason");
	if (reason == NULL) {
		nm_log_warn (LOGD_DHCP, "(pid %d) DHCP event didn't have a reason", pid);
		goto out;
	}

	g_signal_emit (self, signals[EVENT], 0, iface, pid, options, reason, &handled);
	if (!handled) {
		if (g_ascii_strcasecmp (reason, "RELEASE") == 0) {
			/* Ignore event when the dhcp client gets killed and we receive its last message */
			nm_log_dbg (LOGD_DHCP, "(pid %d) unhandled RELEASE DHCP event for interface %s", pid, iface);
		} else
			nm_log_warn (LOGD_DHCP, "(pid %d) unhandled DHCP event for interface %s", pid, iface);
	}

out:
	g_free (iface);
	g_free (pid_str);
	g_free (reason);
	g_variant_unref (options);
}

static void
new_connection_cb (NMBusManager *mgr,
                   GDBusConnection *connection,
                   NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);
	guint id;

	id = g_dbus_connection_signal_subscribe (connection,
	                                         NULL,
	                                         NM_DHCP_CLIENT_DBUS_IFACE,
	                                         "Event",
	                                         NULL,
	                                         NULL,
	                                         G_DBUS_SIGNAL_FLAGS_NONE,
	                                         handle_event, self, NULL);
	g_hash_table_insert (priv->signal_handlers, connection, GUINT_TO_POINTER (id));
}

static void
dis_connection_cb (NMBusManager *mgr,
                   GDBusConnection *connection,
                   NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);
	guint id;

	id = GPOINTER_TO_UINT (g_hash_table_lookup (priv->signal_handlers, connection));
	if (id) {
		g_dbus_connection_signal_unsubscribe (connection, id);
		g_hash_table_remove (priv->signal_handlers, connection);
	}
}

/***************************************************/

NM_DEFINE_SINGLETON_GETTER (NMDhcpListener, nm_dhcp_listener_get, NM_TYPE_DHCP_LISTENER);

static void
nm_dhcp_listener_init (NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);

	/* Maps GDBusConnection :: GDBusProxy */
	priv->signal_handlers = g_hash_table_new (NULL, NULL);

	priv->dbus_mgr = nm_bus_manager_get ();

	/* Register the socket our DHCP clients will return lease info on */
	nm_bus_manager_private_server_register (priv->dbus_mgr, PRIV_SOCK_PATH, PRIV_SOCK_TAG);
	priv->new_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_BUS_MANAGER_PRIVATE_CONNECTION_NEW "::" PRIV_SOCK_TAG,
	                                      G_CALLBACK (new_connection_cb),
	                                      self);
	priv->dis_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_BUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED "::" PRIV_SOCK_TAG,
	                                      G_CALLBACK (dis_connection_cb),
	                                      self);
}

static void
dispose (GObject *object)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (object);

	if (priv->new_conn_id) {
		g_signal_handler_disconnect (priv->dbus_mgr, priv->new_conn_id);
		priv->new_conn_id = 0;
	}
	if (priv->dis_conn_id) {
		g_signal_handler_disconnect (priv->dbus_mgr, priv->dis_conn_id);
		priv->dis_conn_id = 0;
	}
	priv->dbus_mgr = NULL;

	g_clear_pointer (&priv->signal_handlers, g_hash_table_destroy);

	G_OBJECT_CLASS (nm_dhcp_listener_parent_class)->dispose (object);
}

static void
nm_dhcp_listener_class_init (NMDhcpListenerClass *listener_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (listener_class);

	g_type_class_add_private (listener_class, sizeof (NMDhcpListenerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* signals */
	signals[EVENT] =
		g_signal_new (NM_DHCP_LISTENER_EVENT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST, 0,
		              g_signal_accumulator_true_handled,
		              NULL, NULL,
		              G_TYPE_BOOLEAN,     /* listeners return TRUE if handled */
		              4,
		              G_TYPE_STRING,      /* iface */
		              G_TYPE_INT,         /* pid */
		              G_TYPE_VARIANT,     /* options */
		              G_TYPE_STRING);     /* reason */
}
