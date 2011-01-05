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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 *
 */


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
#include "nm-marshal.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-hostname-provider.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GQuark
nm_dhcp_manager_error_quark (void)
{
    static GQuark ret = 0;

    if (ret == 0)
        ret = g_quark_from_static_string ("nm_dhcp_manager_error");

    return ret;
}

GType
nm_dhcp_manager_error_get_type (void)
{
    static GType etype = 0;

    if (etype == 0) {
        static const GEnumValue values[] = {
            ENUM_ENTRY (NM_DHCP_MANAGER_ERROR_BAD_CLIENT, "BadClient"),
            ENUM_ENTRY (NM_DHCP_MANAGER_ERROR_INTERNAL,   "InternalError"),
            { 0, 0, 0 }
        };
        etype = g_enum_register_static ("NMDhcpManagerError", values);
    }
    return etype;
}

#define NM_DHCP_CLIENT_DBUS_SERVICE "org.freedesktop.nm_dhcp_client"
#define NM_DHCP_CLIENT_DBUS_IFACE   "org.freedesktop.nm_dhcp_client"

#define DHCP_TIMEOUT 45 /* default DHCP timeout, in seconds */

static NMDHCPManager *singleton = NULL;

typedef GSList * (*GetLeaseConfigFunc) (const char *iface, const char *uuid);

typedef struct {
	GType               client_type;
	GetLeaseConfigFunc  get_lease_config_func;

	NMDBusManager *     dbus_mgr;
	GHashTable *        clients;
	DBusGProxy *        proxy;
	NMHostnameProvider *hostname_provider;
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

	g_return_val_if_fail (manager != NULL, NULL);
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

	g_return_val_if_fail (manager != NULL, NULL);
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
	NMDHCPManager *manager;
	NMDHCPManagerPrivate *priv;
	NMDHCPClient *client;
	char *iface = NULL;
	char *pid_str = NULL;
	char *reason = NULL;
	unsigned long temp;

	manager = NM_DHCP_MANAGER (user_data);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	iface = get_option (options, "interface");
	if (iface == NULL) {
		nm_log_warn (LOGD_DHCP, "DHCP event didn't have associated interface.");
		goto out;
	}

	pid_str = get_option (options, "pid");
	if (pid_str == NULL) {
		nm_log_warn (LOGD_DHCP, "DHCP event didn't have associated PID.");
		goto out;
	}

	temp = strtoul (pid_str, NULL, 10);
	if ((temp == ULONG_MAX) && (errno == ERANGE)) {
		nm_log_warn (LOGD_DHCP, "couldn't convert PID");
		goto out;
	}

	client = get_client_for_pid (manager, (GPid) temp);
	if (client == NULL) {
		nm_log_warn (LOGD_DHCP, "(pid %d) unhandled DHCP event for interface %s", temp, iface);
		goto out;
	}

	if (strcmp (iface, nm_dhcp_client_get_iface (client))) {
		nm_log_warn (LOGD_DHCP, "(pid %d) received DHCP event from unexpected interface '%s' (expected '%s')",
		             temp, iface, nm_dhcp_client_get_iface (client));
		goto out;
	}

	reason = get_option (options, "reason");
	if (reason == NULL) {
		nm_log_warn (LOGD_DHCP, "(pid %d) DHCP event didn't have a reason", temp);
		goto out;
	}

	nm_dhcp_client_new_options (client, options, reason);

out:
	g_free (iface);
	g_free (pid_str);
	g_free (reason);
}

static GType
get_client_type (const char *client, GError **error)
{
	const char *dhclient_path = NULL;
	const char *dhcpcd_path = NULL;

	/* If a client was disabled at build-time, its *_PATH define will be
	 * an empty string.
	 */
	if (DHCLIENT_PATH && strlen (DHCLIENT_PATH))
		dhclient_path = nm_dhcp_dhclient_get_path (DHCLIENT_PATH);
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
			return 0;
		}
	}

	if (!strcmp (client, "dhclient")) {
		if (!dhclient_path) {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("'dhclient' could be found."));
			return 0;
		}
		return NM_TYPE_DHCP_DHCLIENT;
	}

	if (!strcmp (client, "dhcpcd")) {
		if (!dhcpcd_path) {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("'dhcpcd' could be found."));
			return 0;
		}
		return NM_TYPE_DHCP_DHCPCD;
	}

	g_set_error (error,
	             NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
	             _("unsupported DHCP client '%s'"), client);
	return 0;
}

NMDHCPManager *
nm_dhcp_manager_new (const char *client, GError **error)
{
	NMDHCPManagerPrivate *priv;
	DBusGConnection *g_connection;
	GType client_type;

	client_type = get_client_type (client, error);
	if (!client_type)
		return NULL;

	g_warn_if_fail (singleton == NULL);

	singleton = g_object_new (NM_TYPE_DHCP_MANAGER, NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (singleton);

	/* Client-specific setup */
	priv->client_type = client_type;
	if (priv->client_type == NM_TYPE_DHCP_DHCLIENT)
		priv->get_lease_config_func = nm_dhcp_dhclient_get_lease_config;
	else if (priv->client_type == NM_TYPE_DHCP_DHCPCD)
		priv->get_lease_config_func = nm_dhcp_dhcpcd_get_lease_config;
	else
		g_assert_not_reached ();

	priv->clients = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                       NULL,
	                                       (GDestroyNotify) g_object_unref);
	g_assert (priv->clients);

	priv->dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (g_connection,
	                                         NM_DHCP_CLIENT_DBUS_SERVICE,
	                                         "/",
	                                         NM_DHCP_CLIENT_DBUS_IFACE);
	g_assert (priv->proxy);

	dbus_g_proxy_add_signal (priv->proxy,
	                         "Event",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);

	dbus_g_proxy_connect_signal (priv->proxy, "Event",
	                             G_CALLBACK (nm_dhcp_manager_handle_event),
	                             singleton,
	                             NULL);

	return singleton;
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

	id = g_signal_connect_swapped (client, "remove", G_CALLBACK (remove_client), self);
	g_object_set_data (G_OBJECT (client), REMOVE_ID_TAG, GUINT_TO_POINTER (id));

	id = g_signal_connect_swapped (client, "timeout", G_CALLBACK (remove_client), self);
	g_object_set_data (G_OBJECT (client), TIMEOUT_ID_TAG, GUINT_TO_POINTER (id));

	g_hash_table_insert (priv->clients, client, g_object_ref (client));
}

static NMDHCPClient *
client_start (NMDHCPManager *self,
              const char *iface,
              const char *uuid,
              gboolean ipv6,
              NMSettingIP4Config *s_ip4,
              NMSettingIP6Config *s_ip6,
              guint32 timeout,
              guint8 *dhcp_anycast_addr,
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

	/* Kill any old client instance */
	client = get_client_for_iface (self, iface, ipv6);
	if (client) {
		nm_dhcp_client_stop (client);
		remove_client (self, client);
	}

	/* And make a new one */
	client = g_object_new (priv->client_type,
	                       NM_DHCP_CLIENT_INTERFACE, iface,
	                       NM_DHCP_CLIENT_IPV6, ipv6,
	                       NM_DHCP_CLIENT_UUID, uuid,
	                       NM_DHCP_CLIENT_TIMEOUT, timeout ? timeout : DHCP_TIMEOUT,
	                       NULL);
	g_return_val_if_fail (client != NULL, NULL);
	add_client (self, client);

	if (ipv6)
		success = nm_dhcp_client_start_ip6 (client, s_ip6, dhcp_anycast_addr, hostname, info_only);
	else
		success = nm_dhcp_client_start_ip4 (client, s_ip4, dhcp_anycast_addr, hostname);

	if (!success) {
		remove_client (self, client);
		g_object_unref (client);
		client = NULL;
	}

	return client;
}

/* Caller owns a reference to the NMDHCPClient on return */
NMDHCPClient *
nm_dhcp_manager_start_ip4 (NMDHCPManager *self,
                           const char *iface,
                           const char *uuid,
                           NMSettingIP4Config *s_ip4,
                           guint32 timeout,
                           guint8 *dhcp_anycast_addr)
{
	NMDHCPManagerPrivate *priv;
	NMDHCPClient *client = NULL;
	const char *hostname = NULL;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (s_ip4) {
		const char *method = nm_setting_ip4_config_get_method (s_ip4);

		if (method) {
			/* Method must be 'auto' */
			g_return_val_if_fail (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0, NULL);
		}

		/* If we're asked to send the hostname to DHCP server, and the hostname
		 * isn't specified, and a hostname provider is registered: use that
		 */
		if (nm_setting_ip4_config_get_dhcp_send_hostname (s_ip4)) {
			hostname = nm_setting_ip4_config_get_dhcp_hostname (s_ip4);

			/* If we're supposed to send the hostname to the DHCP server but
			 * the user didn't specify one, use the persistent hostname.
			 */
			if (!hostname && priv->hostname_provider) {
				hostname = nm_hostname_provider_get_hostname (priv->hostname_provider);
				if (   hostname
				    && (!strcmp (hostname, "localhost.localdomain") ||
				        !strcmp (hostname, "localhost6.localdomain6")))
					hostname = NULL;
			}
		}
	}

	client = client_start (self, iface, uuid, FALSE, s_ip4, NULL, timeout, dhcp_anycast_addr, hostname, FALSE);

	return client;
}

/* Caller owns a reference to the NMDHCPClient on return */
NMDHCPClient *
nm_dhcp_manager_start_ip6 (NMDHCPManager *self,
                           const char *iface,
                           const char *uuid,
                           NMSettingIP6Config *s_ip6,
                           guint32 timeout,
                           guint8 *dhcp_anycast_addr,
                           gboolean info_only)
{
	return client_start (self, iface, uuid, TRUE, NULL, s_ip6, timeout, dhcp_anycast_addr, NULL, info_only);
}

static void
hostname_provider_destroyed (gpointer data, GObject *destroyed_object)
{
	NM_DHCP_MANAGER_GET_PRIVATE (data)->hostname_provider = NULL;
}

void
nm_dhcp_manager_set_hostname_provider (NMDHCPManager *manager,
									   NMHostnameProvider *provider)
{
	NMDHCPManagerPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_MANAGER (manager));

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	if (priv->hostname_provider) {
		g_object_weak_unref (G_OBJECT (priv->hostname_provider), hostname_provider_destroyed, manager);
		priv->hostname_provider = NULL;
	}

	if (provider) {
		priv->hostname_provider = provider;
		g_object_weak_ref (G_OBJECT (provider), hostname_provider_destroyed, manager);
	}
}

GSList *
nm_dhcp_manager_get_lease_config (NMDHCPManager *self,
                                  const char *iface,
                                  const char *uuid)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	return NM_DHCP_MANAGER_GET_PRIVATE (self)->get_lease_config_func (iface, uuid);
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
	g_warn_if_fail (singleton != NULL);
	return g_object_ref (singleton);
}

static void
nm_dhcp_manager_init (NMDHCPManager *manager)
{
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

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);

	if (priv->hostname_provider) {
		g_object_weak_unref (G_OBJECT (priv->hostname_provider), hostname_provider_destroyed, object);
		priv->hostname_provider = NULL;
	}

	if (priv->clients)
		g_hash_table_destroy (priv->clients);
	if (priv->proxy)
		g_object_unref (priv->proxy);
	if (priv->dbus_mgr)
		g_object_unref (priv->dbus_mgr);

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

