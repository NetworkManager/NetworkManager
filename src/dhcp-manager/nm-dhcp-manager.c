/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 *
 */

#include "config.h"
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "nm-dhcp-manager.h"
#include "nm-dhcp-dhclient.h"
#include "nm-dhcp-dhcpcd.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-config.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "NetworkManagerUtils.h"

GQuark
nm_dhcp_manager_error_quark (void)
{
    static GQuark ret = 0;

    if (ret == 0)
        ret = g_quark_from_static_string ("nm_dhcp_manager_error");

    return ret;
}

#define NM_DHCP_CLIENT_DBUS_IFACE   "org.freedesktop.nm_dhcp_client"

#define DHCP_TIMEOUT 45 /* default DHCP timeout, in seconds */

#define PRIV_SOCK_PATH NMRUNDIR "/private-dhcp"
#define PRIV_SOCK_TAG  "dhcp"

/* default to installed helper, but can be modified for testing */
const char *nm_dhcp_helper_path = LIBEXECDIR "/nm-dhcp-helper";

typedef GSList * (*GetLeaseConfigFunc) (const char *iface, const char *uuid, gboolean ipv6);

typedef struct {
	GType               client_type;
	GetLeaseConfigFunc  get_lease_ip_configs_func;

	NMDBusManager *     dbus_mgr;
	guint               new_conn_id;
	guint               dis_conn_id;
	GHashTable *        proxies;

	GHashTable *        clients;
	DBusGProxy *        proxy;
	char *              default_hostname;
} NMDHCPManagerPrivate;


#define NM_DHCP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_MANAGER, NMDHCPManagerPrivate))

G_DEFINE_TYPE (NMDHCPManager, nm_dhcp_manager, G_TYPE_OBJECT)

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

static NMDHCPClient *
get_client_for_pid (NMDHCPManager *manager, GPid pid)
{
	NMDHCPManagerPrivate *priv;
	GHashTableIter iter;
	gpointer value;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	g_hash_table_iter_init (&iter, priv->clients);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMDHCPClient *candidate = NM_DHCP_CLIENT (value);

		if (nm_dhcp_client_get_pid (candidate) == pid)
			return candidate;
	}

	return NULL;
}

static NMDHCPClient *
get_client_for_iface (NMDHCPManager *manager,
                      const char *iface,
                      gboolean ip6)
{
	NMDHCPManagerPrivate *priv;
	GHashTableIter iter;
	gpointer value;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);
	g_return_val_if_fail (iface, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	g_hash_table_iter_init (&iter, priv->clients);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMDHCPClient *candidate = NM_DHCP_CLIENT (value);

		if (   !strcmp (iface, nm_dhcp_client_get_iface (candidate))
		    && (nm_dhcp_client_get_ipv6 (candidate) == ip6))
			return candidate;
	}

	return NULL;
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
nm_dhcp_manager_handle_event (DBusGProxy *proxy,
                              GHashTable *options,
                              gpointer user_data)
{
	NMDHCPManager *manager = NM_DHCP_MANAGER (user_data);
	NMDHCPClient *client;
	char *iface = NULL;
	char *pid_str = NULL;
	char *reason = NULL;
	long pid;

	iface = get_option (options, "interface");
	if (iface == NULL) {
		nm_log_warn (LOGD_DHCP, "DHCP event: didn't have associated interface.");
		goto out;
	}

	pid_str = get_option (options, "pid");
	pid = nm_utils_ascii_str_to_int64 (pid_str, 10, 0, LONG_MAX, -1);
	if (pid == -1 || pid != (GPid)pid) {
		nm_log_warn (LOGD_DHCP, "DHCP event: couldn't convert PID '%s' to an integer", pid_str ? pid_str : "(null)");
		goto out;
	}

	reason = get_option (options, "reason");
	client = get_client_for_pid (manager, (GPid) pid);
	if (client == NULL) {
		if (reason && g_ascii_strcasecmp (reason, "RELEASE") == 0) {
			/* This happens regularly, when the dhcp client gets killed and we receive its last message.
			 * Don't log a warning in this case. */
			nm_log_dbg (LOGD_DHCP, "(pid %ld) unhandled RELEASE DHCP event for interface %s", pid, iface);
		} else
			nm_log_warn (LOGD_DHCP, "(pid %ld) unhandled DHCP event for interface %s", pid, iface);
		goto out;
	}

	if (strcmp (iface, nm_dhcp_client_get_iface (client))) {
		nm_log_warn (LOGD_DHCP, "(pid %ld) received DHCP event from unexpected interface '%s' (expected '%s')",
		             pid, iface, nm_dhcp_client_get_iface (client));
		goto out;
	}

	if (reason == NULL) {
		nm_log_warn (LOGD_DHCP, "(pid %ld) DHCP event didn't have a reason", pid);
		goto out;
	}

	nm_dhcp_client_new_options (client, options, reason);

out:
	g_free (iface);
	g_free (pid_str);
	g_free (reason);
}

#if HAVE_DBUS_GLIB_100
static void
new_connection_cb (NMDBusManager *mgr,
                   DBusGConnection *connection,
                   NMDHCPManager *self)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	DBusGProxy *proxy;

	/* Create a new proxy for the client */
	proxy = dbus_g_proxy_new_for_peer (connection, "/", NM_DHCP_CLIENT_DBUS_IFACE);
	dbus_g_proxy_add_signal (proxy,
	                         "Event",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
	                             "Event",
	                             G_CALLBACK (nm_dhcp_manager_handle_event),
	                             self,
	                             NULL);
	g_hash_table_insert (priv->proxies, connection, proxy);
}

static void
dis_connection_cb (NMDBusManager *mgr,
                   DBusGConnection *connection,
                   NMDHCPManager *self)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	DBusGProxy *proxy;

	proxy = g_hash_table_lookup (priv->proxies, connection);
	if (proxy) {
		dbus_g_proxy_disconnect_signal (proxy,
		                                "Event",
		                                G_CALLBACK (nm_dhcp_manager_handle_event),
		                                self);
		g_hash_table_remove (priv->proxies, connection);
	}
}
#endif

static GType
get_client_type (const char *client, GError **error)
{
	const char *dhclient_path = NULL;
	const char *dhcpcd_path = NULL;

	/* If a client was disabled at build-time, its *_PATH define will be
	 * an empty string.
	 */
	/* coverity[array_null] */
	if (DHCLIENT_PATH && strlen (DHCLIENT_PATH))
		dhclient_path = nm_dhcp_dhclient_get_path (DHCLIENT_PATH);
	/* coverity[array_null] */
	if (DHCPCD_PATH && strlen (DHCPCD_PATH))
		dhcpcd_path = nm_dhcp_dhcpcd_get_path (DHCPCD_PATH);

	if (!client) {
		if (dhclient_path)
			return NM_TYPE_DHCP_DHCLIENT;
		else if (dhcpcd_path)
			return NM_TYPE_DHCP_DHCPCD;
		else {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("no usable DHCP client could be found."));
			return G_TYPE_INVALID;
		}
	}

	if (!strcmp (client, "dhclient")) {
		if (!dhclient_path) {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("'dhclient' could be found."));
			return G_TYPE_INVALID;
		}
		return NM_TYPE_DHCP_DHCLIENT;
	}

	if (!strcmp (client, "dhcpcd")) {
		if (!dhcpcd_path) {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("'dhcpcd' could be found."));
			return G_TYPE_INVALID;
		}
		return NM_TYPE_DHCP_DHCPCD;
	}

	g_set_error (error,
	             NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
	             _("unsupported DHCP client '%s'"), client);
	return G_TYPE_INVALID;
}

#define REMOVE_ID_TAG "remove-id"
#define TIMEOUT_ID_TAG "timeout-id"

static void
remove_client (NMDHCPManager *self, NMDHCPClient *client)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	guint id;

	id = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (client), REMOVE_ID_TAG));
	if (id)
		g_signal_handler_disconnect (client, id);

	id = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (client), TIMEOUT_ID_TAG));
	if (id)
		g_signal_handler_disconnect (client, id);

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */

	g_hash_table_remove (priv->clients, client);
}

static void
add_client (NMDHCPManager *self, NMDHCPClient *client)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	guint id;

	id = g_signal_connect_swapped (client, NM_DHCP_CLIENT_SIGNAL_REMOVE, G_CALLBACK (remove_client), self);
	g_object_set_data (G_OBJECT (client), REMOVE_ID_TAG, GUINT_TO_POINTER (id));

	id = g_signal_connect_swapped (client, NM_DHCP_CLIENT_SIGNAL_TIMEOUT, G_CALLBACK (remove_client), self);
	g_object_set_data (G_OBJECT (client), TIMEOUT_ID_TAG, GUINT_TO_POINTER (id));

	g_hash_table_insert (priv->clients, client, g_object_ref (client));
}

static NMDHCPClient *
client_start (NMDHCPManager *self,
              const char *iface,
              const GByteArray *hwaddr,
              const char *uuid,
              guint priority,
              gboolean ipv6,
              const char *dhcp_client_id,
              guint32 timeout,
              GByteArray *dhcp_anycast_addr,
              const char *hostname,
              gboolean info_only)
{
	NMDHCPManagerPrivate *priv;
	NMDHCPClient *client;
	gboolean success = FALSE;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	/* Ensure we have a usable DHCP client */
	g_return_val_if_fail (priv->client_type != 0, NULL);

	/* Kill any old client instance */
	client = get_client_for_iface (self, iface, ipv6);
	if (client) {
		nm_dhcp_client_stop (client, FALSE);
		remove_client (self, client);
	}

	/* And make a new one */
	client = g_object_new (priv->client_type,
	                       NM_DHCP_CLIENT_INTERFACE, iface,
	                       NM_DHCP_CLIENT_HWADDR, hwaddr,
	                       NM_DHCP_CLIENT_IPV6, ipv6,
	                       NM_DHCP_CLIENT_UUID, uuid,
	                       NM_DHCP_CLIENT_PRIORITY, priority,
	                       NM_DHCP_CLIENT_TIMEOUT, timeout ? timeout : DHCP_TIMEOUT,
	                       NULL);
	g_return_val_if_fail (client != NULL, NULL);
	add_client (self, client);

	if (ipv6)
		success = nm_dhcp_client_start_ip6 (client, dhcp_anycast_addr, hostname, info_only);
	else
		success = nm_dhcp_client_start_ip4 (client, dhcp_client_id, dhcp_anycast_addr, hostname);

	if (!success) {
		remove_client (self, client);
		g_object_unref (client);
		client = NULL;
	}

	return client;
}

static const char *
get_send_hostname (NMDHCPManager *self, const char *setting_hostname)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	/* Always prefer the explicit dhcp-send-hostname if given */
	return setting_hostname ? setting_hostname : priv->default_hostname;
}

/* Caller owns a reference to the NMDHCPClient on return */
NMDHCPClient *
nm_dhcp_manager_start_ip4 (NMDHCPManager *self,
                           const char *iface,
                           const GByteArray *hwaddr,
                           const char *uuid,
                           guint priority,
                           NMSettingIP4Config *s_ip4,
                           guint32 timeout,
                           GByteArray *dhcp_anycast_addr)
{
	const char *hostname = NULL, *method;
	gboolean send_hostname;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	method = nm_setting_ip4_config_get_method (s_ip4);
	g_return_val_if_fail (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0, NULL);

	send_hostname = nm_setting_ip4_config_get_dhcp_send_hostname (s_ip4);
	if (send_hostname)
		hostname = get_send_hostname (self, nm_setting_ip4_config_get_dhcp_hostname (s_ip4));

	return client_start (self, iface, hwaddr, uuid, priority, FALSE,
	                     nm_setting_ip4_config_get_dhcp_client_id (s_ip4),
	                     timeout, dhcp_anycast_addr, hostname, FALSE);
}

/* Caller owns a reference to the NMDHCPClient on return */
NMDHCPClient *
nm_dhcp_manager_start_ip6 (NMDHCPManager *self,
                           const char *iface,
                           const GByteArray *hwaddr,
                           const char *uuid,
                           guint priority,
                           NMSettingIP6Config *s_ip6,
                           guint32 timeout,
                           GByteArray *dhcp_anycast_addr,
                           gboolean info_only)
{
	const char *hostname;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	hostname = get_send_hostname (self, nm_setting_ip6_config_get_dhcp_hostname (s_ip6));

	return client_start (self, iface, hwaddr, uuid, priority, TRUE,
	                     NULL, timeout, dhcp_anycast_addr, hostname, info_only);
}

void
nm_dhcp_manager_set_default_hostname (NMDHCPManager *manager, const char *hostname)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	g_clear_pointer (&priv->default_hostname, g_free);

	/* Never send 'localhost'-type names to the DHCP server */
	if (g_strcmp0 (hostname, "localhost.localdomain") == 0 ||
	    g_strcmp0 (hostname, "localhost6.localdomain6") == 0)
		return;

	priv->default_hostname = g_strdup (hostname);
}

GSList *
nm_dhcp_manager_get_lease_ip_configs (NMDHCPManager *self,
                                      const char *iface,
                                      const char *uuid,
                                      gboolean ipv6)
{
	NMDHCPManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (priv->get_lease_ip_configs_func)
		return priv->get_lease_ip_configs_func (iface, uuid, ipv6);
	return NULL;
}

NMIP4Config *
nm_dhcp_manager_test_ip4_options_to_config (const char *dhcp_client,
                                            const char *iface,
                                            GHashTable *options,
                                            const char *reason)
{
	NMDHCPClient *client;
	NMIP4Config *config;
	GType client_type;
	GError *error = NULL;

	client_type = get_client_type (dhcp_client, &error);
	if (!client_type) {
		nm_log_err (LOGD_DHCP4, "error: %s", error ? error->message : "(unknown)");
		g_clear_error (&error);
		return NULL;
	}

	client = (NMDHCPClient *) g_object_new (client_type,
	                                        NM_DHCP_CLIENT_INTERFACE, iface,
	                                        NULL);
	g_return_val_if_fail (client != NULL, NULL);
	nm_dhcp_client_new_options (client, options, reason);
	config = nm_dhcp_client_get_ip4_config (client, TRUE);
	g_object_unref (client);

	return config;
}

/***************************************************/

NMDHCPManager *
nm_dhcp_manager_get (void)
{
	static NMDHCPManager *singleton = NULL;

	if (G_UNLIKELY (singleton == NULL))
		singleton = g_object_new (NM_TYPE_DHCP_MANAGER, NULL);
	g_assert (singleton);
	return singleton;
}

static void
nm_dhcp_manager_init (NMDHCPManager *self)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	const char *client;
	GError *error = NULL;
#if !HAVE_DBUS_GLIB_100
	DBusGConnection *g_connection;
#endif

	/* Maps DBusGConnection :: DBusGProxy */
	priv->proxies = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);

	/* Client-specific setup */
	client = nm_config_get_dhcp_client (nm_config_get ());
	priv->client_type = get_client_type (client, &error);

	if (priv->client_type == NM_TYPE_DHCP_DHCLIENT)
		priv->get_lease_ip_configs_func = nm_dhcp_dhclient_get_lease_ip_configs;
	else if (priv->client_type == G_TYPE_INVALID) {
		nm_log_warn (LOGD_DHCP, "No usable DHCP client found (%s)! DHCP configurations will fail.",
		             error->message);
	}
	g_clear_error (&error);

	priv->clients = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                       NULL,
	                                       (GDestroyNotify) g_object_unref);
	g_assert (priv->clients);

	priv->dbus_mgr = nm_dbus_manager_get ();

#if HAVE_DBUS_GLIB_100
	/* Register the socket our DHCP clients will return lease info on */
	nm_dbus_manager_private_server_register (priv->dbus_mgr, PRIV_SOCK_PATH, PRIV_SOCK_TAG);
	priv->new_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW "::" PRIV_SOCK_TAG,
	                                      (GCallback) new_connection_cb,
	                                      self);
	priv->dis_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED "::" PRIV_SOCK_TAG,
	                                      (GCallback) dis_connection_cb,
	                                      self);
#else
	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (g_connection,
	                                         "org.freedesktop.nm_dhcp_client",
	                                         "/",
	                                         NM_DHCP_CLIENT_DBUS_IFACE);
	g_assert (priv->proxy);
	dbus_g_proxy_add_signal (priv->proxy, "Event", DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Event",
	                             G_CALLBACK (nm_dhcp_manager_handle_event),
	                             self,
	                             NULL);
#endif
}

static void
dispose (GObject *object)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);
	GList *values, *iter;

	if (priv->clients) {
		values = g_hash_table_get_values (priv->clients);
		for (iter = values; iter; iter = g_list_next (iter))
			remove_client (NM_DHCP_MANAGER (object), NM_DHCP_CLIENT (iter->data));
		g_list_free (values);
	}

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
	if (priv->proxy)
		g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);

	g_free (priv->default_hostname);

	if (priv->clients)
		g_hash_table_destroy (priv->clients);

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->finalize (object);
}

static void
nm_dhcp_manager_class_init (NMDHCPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMDHCPManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->dispose = dispose;
}
