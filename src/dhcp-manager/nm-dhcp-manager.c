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
#include "nm-dhcp-systemd.h"
#include "nm-logging.h"
#include "nm-config.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "NetworkManagerUtils.h"

#define DHCP_TIMEOUT 45 /* default DHCP timeout, in seconds */

/* default to installed helper, but can be modified for testing */
const char *nm_dhcp_helper_path = LIBEXECDIR "/nm-dhcp-helper";

typedef GSList * (*GetLeaseConfigFunc) (const char *iface, const char *uuid, gboolean ipv6);

typedef struct {
	GType               client_type;
	GetLeaseConfigFunc  get_lease_ip_configs_func;
	GHashTable *        clients;
	char *              default_hostname;
} NMDhcpManagerPrivate;

#define NM_DHCP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_MANAGER, NMDhcpManagerPrivate))

G_DEFINE_TYPE (NMDhcpManager, nm_dhcp_manager, G_TYPE_OBJECT)

/***************************************************/

static NMDhcpClient *
get_client_for_ifindex (NMDhcpManager *manager, int ifindex, gboolean ip6)
{
	NMDhcpManagerPrivate *priv;
	GHashTableIter iter;
	gpointer value;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);
	g_return_val_if_fail (ifindex > 0, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	g_hash_table_iter_init (&iter, priv->clients);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMDhcpClient *candidate = NM_DHCP_CLIENT (value);

		if (   nm_dhcp_client_get_ifindex (candidate) == ifindex
		    && nm_dhcp_client_get_ipv6 (candidate) == ip6)
			return candidate;
	}

	return NULL;
}

static GType
get_client_type (const char *client, GError **error)
{
	gboolean use_dhclient, use_dhcpcd;

	/* If a client was disabled at build-time, these will return FALSE */
	use_dhclient = !!nm_dhcp_dhclient_get_path ();
	use_dhcpcd = !!nm_dhcp_dhcpcd_get_path ();

	if (!client) {
		if (use_dhclient)
			return NM_TYPE_DHCP_DHCLIENT;
		else if (use_dhcpcd)
			return NM_TYPE_DHCP_DHCPCD;
		else {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
			                     _("no usable DHCP client could be found."));
			return G_TYPE_INVALID;
		}
	}

	if (!strcmp (client, "dhclient")) {
		if (!use_dhclient) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
			                     _("'dhclient' could not be found or was disabled."));
			return G_TYPE_INVALID;
		}
		return NM_TYPE_DHCP_DHCLIENT;
	}

	if (!strcmp (client, "dhcpcd")) {
		if (!use_dhcpcd) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
			                     _("'dhcpcd' could not be found or was disabled."));
			return G_TYPE_INVALID;
		}
		return NM_TYPE_DHCP_DHCPCD;
	}

	if (!strcmp (client, "internal"))
		return NM_TYPE_DHCP_SYSTEMD;

	g_set_error (error,
	             NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
	             _("unsupported DHCP client '%s'"), client);
	return G_TYPE_INVALID;
}

static void client_state_changed (NMDhcpClient *client,
                                  NMDhcpState state,
                                  GObject *ip_config,
                                  GHashTable *options,
                                  NMDhcpManager *self);

static void
remove_client (NMDhcpManager *self, NMDhcpClient *client)
{
	g_signal_handlers_disconnect_by_func (client, client_state_changed, self);

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */

	g_hash_table_remove (NM_DHCP_MANAGER_GET_PRIVATE (self)->clients, client);
}

static void
client_state_changed (NMDhcpClient *client,
                      NMDhcpState state,
                      GObject *ip_config,
                      GHashTable *options,
                      NMDhcpManager *self)
{
	if (state >= NM_DHCP_STATE_TIMEOUT)
		remove_client (self, client);
}

static NMDhcpClient *
client_start (NMDhcpManager *self,
              const char *iface,
              int ifindex,
              const GByteArray *hwaddr,
              const char *uuid,
              guint32 priority,
              gboolean ipv6,
              const char *dhcp_client_id,
              guint32 timeout,
              const char *dhcp_anycast_addr,
              const char *hostname,
              gboolean info_only,
              NMSettingIP6ConfigPrivacy privacy)
{
	NMDhcpManagerPrivate *priv;
	NMDhcpClient *client;
	gboolean success = FALSE;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	/* Ensure we have a usable DHCP client */
	g_return_val_if_fail (priv->client_type != 0, NULL);

	/* Kill any old client instance */
	client = get_client_for_ifindex (self, ifindex, ipv6);
	if (client) {
		g_object_ref (client);
		remove_client (self, client);
		nm_dhcp_client_stop (client, FALSE);
		g_object_unref (client);
	}

	/* And make a new one */
	client = g_object_new (priv->client_type,
	                       NM_DHCP_CLIENT_INTERFACE, iface,
	                       NM_DHCP_CLIENT_IFINDEX, ifindex,
	                       NM_DHCP_CLIENT_HWADDR, hwaddr,
	                       NM_DHCP_CLIENT_IPV6, ipv6,
	                       NM_DHCP_CLIENT_UUID, uuid,
	                       NM_DHCP_CLIENT_PRIORITY, priority,
	                       NM_DHCP_CLIENT_TIMEOUT, timeout ? timeout : DHCP_TIMEOUT,
	                       NULL);
	g_hash_table_insert (NM_DHCP_MANAGER_GET_PRIVATE (self)->clients, client, g_object_ref (client));
	g_signal_connect (client, NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED, G_CALLBACK (client_state_changed), self);

	if (ipv6)
		success = nm_dhcp_client_start_ip6 (client, dhcp_anycast_addr, hostname, info_only, privacy);
	else
		success = nm_dhcp_client_start_ip4 (client, dhcp_client_id, dhcp_anycast_addr, hostname);

	if (!success) {
		remove_client (self, client);
		client = NULL;
	}

	return client;
}

static const char *
get_send_hostname (NMDhcpManager *self, const char *setting_hostname)
{
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	/* Always prefer the explicit dhcp-send-hostname if given */
	return setting_hostname ? setting_hostname : priv->default_hostname;
}

/* Caller owns a reference to the NMDhcpClient on return */
NMDhcpClient *
nm_dhcp_manager_start_ip4 (NMDhcpManager *self,
                           const char *iface,
                           int ifindex,
                           const GByteArray *hwaddr,
                           const char *uuid,
                           guint32 priority,
                           gboolean send_hostname,
                           const char *dhcp_hostname,
                           const char *dhcp_client_id,
                           guint32 timeout,
                           const char *dhcp_anycast_addr)
{
	const char *hostname = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	if (send_hostname)
		hostname = get_send_hostname (self, dhcp_hostname);
	return client_start (self, iface, ifindex, hwaddr, uuid, priority, FALSE,
	                     dhcp_client_id, timeout, dhcp_anycast_addr, hostname,
	                     FALSE, 0);
}

/* Caller owns a reference to the NMDhcpClient on return */
NMDhcpClient *
nm_dhcp_manager_start_ip6 (NMDhcpManager *self,
                           const char *iface,
                           int ifindex,
                           const GByteArray *hwaddr,
                           const char *uuid,
                           guint32 priority,
                           gboolean send_hostname,
                           const char *dhcp_hostname,
                           guint32 timeout,
                           const char *dhcp_anycast_addr,
                           gboolean info_only,
                           NMSettingIP6ConfigPrivacy privacy)
{
	const char *hostname = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	if (send_hostname)
		hostname = get_send_hostname (self, dhcp_hostname);
	return client_start (self, iface, ifindex, hwaddr, uuid, priority, TRUE,
	                     NULL, timeout, dhcp_anycast_addr, hostname, info_only,
	                     privacy);
}

void
nm_dhcp_manager_set_default_hostname (NMDhcpManager *manager, const char *hostname)
{
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	g_clear_pointer (&priv->default_hostname, g_free);

	/* Never send 'localhost'-type names to the DHCP server */
	if (!nm_utils_is_specific_hostname (hostname))
		return;

	priv->default_hostname = g_strdup (hostname);
}

GSList *
nm_dhcp_manager_get_lease_ip_configs (NMDhcpManager *self,
                                      const char *iface,
                                      const char *uuid,
                                      gboolean ipv6)
{
	NMDhcpManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (priv->get_lease_ip_configs_func)
		return priv->get_lease_ip_configs_func (iface, uuid, ipv6);
	return NULL;
}

/***************************************************/

NMDhcpManager *
nm_dhcp_manager_get (void)
{
	static NMDhcpManager *singleton = NULL;

	if (G_UNLIKELY (singleton == NULL))
		singleton = g_object_new (NM_TYPE_DHCP_MANAGER, NULL);
	g_assert (singleton);
	return singleton;
}

static void
nm_dhcp_manager_init (NMDhcpManager *self)
{
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	const char *client;
	GError *error = NULL;

	/* Client-specific setup */
	client = nm_config_get_dhcp_client (nm_config_get ());
	priv->client_type = get_client_type (client, &error);

	if (priv->client_type == NM_TYPE_DHCP_DHCLIENT)
		priv->get_lease_ip_configs_func = nm_dhcp_dhclient_get_lease_ip_configs;
	else if (priv->client_type == NM_TYPE_DHCP_SYSTEMD)
		priv->get_lease_ip_configs_func = nm_dhcp_systemd_get_lease_ip_configs;
	else if (priv->client_type == G_TYPE_INVALID) {
		nm_log_warn (LOGD_DHCP, "No usable DHCP client found (%s)! DHCP configurations will fail.",
		             error->message);
	}
	g_clear_error (&error);

	priv->clients = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                       NULL,
	                                       (GDestroyNotify) g_object_unref);
	g_assert (priv->clients);
}

static void
dispose (GObject *object)
{
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);
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
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);

	g_free (priv->default_hostname);

	if (priv->clients)
		g_hash_table_destroy (priv->clients);

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->finalize (object);
}

static void
nm_dhcp_manager_class_init (NMDhcpManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMDhcpManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->dispose = dispose;
}
