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
 * Copyright 2014 - 2016 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include "nm-dhcp-listener.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "nm-dhcp-helper-api.h"
#include "nm-dhcp-client.h"
#include "nm-dhcp-manager.h"
#include "nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerUtils.h"

#define PRIV_SOCK_PATH            NMRUNDIR "/private-dhcp"
#define PRIV_SOCK_TAG             "dhcp"

/*****************************************************************************/

const NMDhcpClientFactory *const _nm_dhcp_manager_factories[4] = {
	/* the order here matters, as we will try the plugins in this order to find
	 * the first available plugin. */

#if WITH_DHCPCANON
	&_nm_dhcp_client_factory_dhcpcanon,
#endif
#if WITH_DHCLIENT
	&_nm_dhcp_client_factory_dhclient,
#endif
#if WITH_DHCPCD
	&_nm_dhcp_client_factory_dhcpcd,
#endif
	&_nm_dhcp_client_factory_internal,
};

/*****************************************************************************/

typedef struct {
	NMDBusManager *      dbus_mgr;
	gulong              new_conn_id;
	gulong              dis_conn_id;
	GHashTable *        connections;
} NMDhcpListenerPrivate;

struct _NMDhcpListener {
	GObject parent;
	NMDhcpListenerPrivate _priv;
};

struct _NMDhcpListenerClass {
	GObjectClass parent;
};

enum {
	EVENT,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (NMDhcpListener, nm_dhcp_listener, G_TYPE_OBJECT)

#define NM_DHCP_LISTENER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDhcpListener, NM_IS_DHCP_LISTENER)

NM_DEFINE_SINGLETON_GETTER (NMDhcpListener, nm_dhcp_listener_get, NM_TYPE_DHCP_LISTENER);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME    "dhcp-listener"
#define _NMLOG_DOMAIN         LOGD_DHCP
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMDhcpListener *_self = (self); \
        char _prefix[64]; \
        \
        nm_log ((level), (_NMLOG_DOMAIN), NULL, NULL, \
                "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                (_self != singleton_instance \
                    ? nm_sprintf_buf (_prefix, "%s[%p]", _NMLOG_PREFIX_NAME, _self) \
                    : _NMLOG_PREFIX_NAME )\
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

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
_method_call_handle (NMDhcpListener *self,
                     GVariant *parameters)
{
	gs_free char *iface = NULL;
	gs_free char *pid_str = NULL;
	gs_free char *reason = NULL;
	gs_unref_variant GVariant *options = NULL;
	int pid;
	gboolean handled = FALSE;

	g_variant_get (parameters, "(@a{sv})", &options);

	iface = get_option (options, "interface");
	if (iface == NULL) {
		_LOGW ("dhcp-event: didn't have associated interface.");
		return;
	}

	pid_str = get_option (options, "pid");
	pid = _nm_utils_ascii_str_to_int64 (pid_str, 10, 0, G_MAXINT32, -1);
	if (pid == -1) {
		_LOGW ("dhcp-event: couldn't convert PID '%s' to an integer", pid_str ?: "(null)");
		return;
	}

	reason = get_option (options, "reason");
	if (reason == NULL) {
		_LOGW ("dhcp-event: (pid %d) DHCP event didn't have a reason", pid);
		return;
	}

	g_signal_emit (self, signals[EVENT], 0, iface, pid, options, reason, &handled);
	if (!handled) {
		if (g_ascii_strcasecmp (reason, "RELEASE") == 0) {
			/* Ignore event when the dhcp client gets killed and we receive its last message */
			_LOGD ("dhcp-event: (pid %d) unhandled RELEASE DHCP event for interface %s", pid, iface);
		} else
			_LOGW ("dhcp-event: (pid %d) unhandled DHCP event for interface %s", pid, iface);
	}
}

static void
_method_call (GDBusConnection *connection,
              const char *sender,
              const char *object_path,
              const char *interface_name,
              const char *method_name,
              GVariant *parameters,
              GDBusMethodInvocation *invocation,
              gpointer user_data)
{
	NMDhcpListener *self = NM_DHCP_LISTENER (user_data);

	if (   !nm_streq (interface_name, NM_DHCP_HELPER_SERVER_INTERFACE_NAME)
	    || !nm_streq (method_name, NM_DHCP_HELPER_SERVER_METHOD_NOTIFY)) {
		g_dbus_method_invocation_return_error (invocation,
		                                       G_DBUS_ERROR,
		                                       G_DBUS_ERROR_UNKNOWN_METHOD,
		                                       "Unknown method %s",
		                                       method_name);
		return;
	}

	_method_call_handle (self, parameters);
	g_dbus_method_invocation_return_value (invocation, NULL);
}

static GDBusInterfaceInfo *const interface_info = NM_DEFINE_GDBUS_INTERFACE_INFO (
	NM_DHCP_HELPER_SERVER_INTERFACE_NAME,
	.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
		NM_DEFINE_GDBUS_METHOD_INFO (
			NM_DHCP_HELPER_SERVER_METHOD_NOTIFY,
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("data", "a{sv}"),
			),
		),
	),
);

static guint
_dbus_connection_register_object (NMDhcpListener *self,
                                  GDBusConnection *connection,
                                  GError **error)
{
	static const GDBusInterfaceVTable interface_vtable = {
		.method_call = _method_call,
	};

	return g_dbus_connection_register_object (connection,
	                                          NM_DHCP_HELPER_SERVER_OBJECT_PATH,
	                                          interface_info,
	                                          NM_UNCONST_PTR (GDBusInterfaceVTable, &interface_vtable),
	                                          self,
	                                          NULL,
	                                          error);
}

static void
new_connection_cb (NMDBusManager *mgr,
                   GDBusConnection *connection,
                   GDBusObjectManager *manager,
                   NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);
	guint registration_id;
	GError *error = NULL;

	/* it is important to register the object during the new-connection signal,
	 * as this avoids races with the connecting object. */
	registration_id = _dbus_connection_register_object (self, connection, &error);
	if (!registration_id) {
		_LOGE ("failure to register %s for connection %p: %s",
		       NM_DHCP_HELPER_SERVER_OBJECT_PATH, connection, error->message);
		g_error_free (error);
		return;
	}

	g_hash_table_insert (priv->connections, connection, GUINT_TO_POINTER (registration_id));
}

static void
dis_connection_cb (NMDBusManager *mgr,
                   GDBusConnection *connection,
                   NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);
	guint id;

	id = GPOINTER_TO_UINT (g_hash_table_lookup (priv->connections, connection));
	if (id) {
		g_dbus_connection_unregister_object (connection, id);
		g_hash_table_remove (priv->connections, connection);
	}
}

/*****************************************************************************/

static void
nm_dhcp_listener_init (NMDhcpListener *self)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE (self);

	/* Maps GDBusConnection :: signal-id */
	priv->connections = g_hash_table_new (nm_direct_hash, NULL);

	priv->dbus_mgr = nm_dbus_manager_get ();

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
}

static void
dispose (GObject *object)
{
	NMDhcpListenerPrivate *priv = NM_DHCP_LISTENER_GET_PRIVATE ((NMDhcpListener *) object);

	nm_clear_g_signal_handler (priv->dbus_mgr, &priv->new_conn_id);
	nm_clear_g_signal_handler (priv->dbus_mgr, &priv->dis_conn_id);
	priv->dbus_mgr = NULL;

	g_clear_pointer (&priv->connections, g_hash_table_destroy);

	G_OBJECT_CLASS (nm_dhcp_listener_parent_class)->dispose (object);
}

static void
nm_dhcp_listener_class_init (NMDhcpListenerClass *listener_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (listener_class);

	object_class->dispose = dispose;

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
