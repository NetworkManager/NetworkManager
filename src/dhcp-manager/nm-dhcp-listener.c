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

#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "nm-glib.h"
#include "nm-dhcp-listener.h"
#include "nm-core-internal.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"
#include "NetworkManagerUtils.h"

#define NM_DHCP_CLIENT_DBUS_IFACE "org.freedesktop.nm_dhcp_client"
#define PRIV_SOCK_PATH            NMRUNDIR "/private-dhcp"
#define PRIV_SOCK_TAG             "dhcp"

typedef struct {
	NMDBusManager *     dbus_mgr;
	guint               new_conn_id;
	guint               dis_conn_id;
	GHashTable *        proxies;
	DBusGProxy *        proxy;
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
garray_to_string (GArray *array, const char *key)
{
	GString *str;
	int i;
	unsigned char c;
	char *converted = NULL;

	g_return_val_if_fail (array != NULL, NULL);

	/* Since the DHCP options come through environment variables, they should
	 * already be UTF-8 safe, but just make sure.
	 */
	str = g_string_sized_new (array->len);
	for (i = 0; i < array->len; i++) {
		c = array->data[i];

		/* Convert NULLs to spaces and non-ASCII characters to ? */
		if (c == '\0')
			c = ' ';
		else if (c > 127)
			c = '?';
		str = g_string_append_c (str, c);
	}
	str = g_string_append_c (str, '\0');

	converted = str->str;
	if (!g_utf8_validate (converted, -1, NULL))
		nm_log_warn (LOGD_DHCP, "DHCP option '%s' couldn't be converted to UTF-8", key);
	g_string_free (str, FALSE);
	return converted;
}

static char *
get_option (GHashTable *hash, const char *key)
{
	GValue *value;

	value = g_hash_table_lookup (hash, key);
	if (value == NULL)
		return NULL;

	if (G_VALUE_TYPE (value) != DBUS_TYPE_G_UCHAR_ARRAY) {
		nm_log_warn (LOGD_DHCP, "unexpected key %s value type was not "
		             "DBUS_TYPE_G_UCHAR_ARRAY",
		             (char *) key);
		return NULL;
	}

	return garray_to_string ((GArray *) g_value_get_boxed (value), key);
}

static void
handle_event (DBusGProxy *proxy,
              GHashTable *options,
              gpointer user_data)
{
	NMDhcpListener *self = NM_DHCP_LISTENER (user_data);
	char *iface = NULL;
	char *pid_str = NULL;
	char *reason = NULL;
	gint pid;
	gboolean handled = FALSE;

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
}

#if HAVE_DBUS_GLIB_100
static void
new_connection_cb (NMDBusManager *mgr,
                   DBusGConnection *connection,
                   NMDhcpListener *self)
{
	DBusGProxy *proxy;

	/* Create a new proxy for the client */
	proxy = dbus_g_proxy_new_for_peer (connection, "/", NM_DHCP_CLIENT_DBUS_IFACE);
	dbus_g_proxy_add_signal (proxy, "Event", DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, "Event", G_CALLBACK (handle_event), self, NULL);

	g_hash_table_insert (NM_DHCP_LISTENER_GET_PRIVATE (self)->proxies, connection, proxy);
}

static void
dis_connection_cb (NMDBusManager *mgr,
                   DBusGConnection *connection,
                   NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);
	DBusGProxy *proxy;

	proxy = g_hash_table_lookup (priv->proxies, connection);
	if (proxy) {
		dbus_g_proxy_disconnect_signal (proxy, "Event", G_CALLBACK (handle_event), self);
		g_hash_table_remove (priv->proxies, connection);
	}
}
#endif

/***************************************************/

NM_DEFINE_SINGLETON_GETTER (NMDhcpListener, nm_dhcp_listener_get, NM_TYPE_DHCP_LISTENER);

static void
nm_dhcp_listener_init (NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);
#if !HAVE_DBUS_GLIB_100
	DBusGConnection *g_connection;
#endif

	/* Maps DBusGConnection :: DBusGProxy */
	priv->proxies = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);

	priv->dbus_mgr = nm_dbus_manager_get ();

#if HAVE_DBUS_GLIB_100
	/* Register the socket our DHCP clients will return lease info on */
	nm_dbus_manager_private_server_register (priv->dbus_mgr, PRIV_SOCK_PATH, PRIV_SOCK_TAG);
	priv->new_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW "::" PRIV_SOCK_TAG,
	                                      G_CALLBACK (new_connection_cb),
	                                      self);
	priv->dis_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED "::" PRIV_SOCK_TAG,
	                                      G_CALLBACK (dis_connection_cb),
	                                      self);
#else
	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (g_connection,
	                                         "org.freedesktop.nm_dhcp_client",
	                                         "/",
	                                         NM_DHCP_CLIENT_DBUS_IFACE);
	g_assert (priv->proxy);
	dbus_g_proxy_add_signal (priv->proxy, "Event", DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Event", G_CALLBACK (handle_event), self, NULL);
#endif
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

	if (priv->proxies) {
		g_hash_table_destroy (priv->proxies);
		priv->proxies = NULL;
	}
	g_clear_object (&priv->proxy);

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
		              G_TYPE_HASH_TABLE,  /* options */
		              G_TYPE_STRING);     /* reason */
}
