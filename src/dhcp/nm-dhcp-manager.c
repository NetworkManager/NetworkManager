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

#include "nm-default.h"

#include "nm-dhcp-manager.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-config.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef struct {
	const NMDhcpClientFactory *client_factory;
	char *default_hostname;
	CList dhcp_client_lst_head;
} NMDhcpManagerPrivate;

struct _NMDhcpManager {
	GObject parent;
	NMDhcpManagerPrivate _priv;
};

struct _NMDhcpManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMDhcpManager, nm_dhcp_manager, G_TYPE_OBJECT)

#define NM_DHCP_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcpManager, NM_IS_DHCP_MANAGER)

/*****************************************************************************/

/* default to installed helper, but can be modified for testing */
const char *nm_dhcp_helper_path = LIBEXECDIR "/nm-dhcp-helper";

/*****************************************************************************/

static const NMDhcpClientFactory *
_client_factory_find_by_name (const char *name)
{
	int i;

	g_return_val_if_fail (name, NULL);

	for (i = 0; i < G_N_ELEMENTS (_nm_dhcp_manager_factories); i++) {
		const NMDhcpClientFactory *f = _nm_dhcp_manager_factories[i];

		if (f && nm_streq (f->name, name))
			return f;
	}
	return NULL;
}

static const NMDhcpClientFactory *
_client_factory_available (const NMDhcpClientFactory *client_factory)
{
	if (   client_factory
	    && (!client_factory->get_path || client_factory->get_path ()))
		return client_factory;
	return NULL;
}

/*****************************************************************************/

static NMDhcpClient *
get_client_for_ifindex (NMDhcpManager *manager, int addr_family, int ifindex)
{
	NMDhcpManagerPrivate *priv;
	NMDhcpClient *client;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);
	g_return_val_if_fail (ifindex > 0, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	c_list_for_each_entry (client, &priv->dhcp_client_lst_head, dhcp_client_lst) {
		if (   nm_dhcp_client_get_ifindex (client) == ifindex
		    && nm_dhcp_client_get_addr_family (client) == addr_family)
			return client;
	}

	return NULL;
}

static void client_state_changed (NMDhcpClient *client,
                                  NMDhcpState state,
                                  GObject *ip_config,
                                  GVariant *options,
                                  const char *event_id,
                                  NMDhcpManager *self);

static void
remove_client (NMDhcpManager *self, NMDhcpClient *client)
{
	g_signal_handlers_disconnect_by_func (client, client_state_changed, self);
	c_list_unlink (&client->dhcp_client_lst);

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */
}

static void
remove_client_unref (NMDhcpManager *self, NMDhcpClient *client)
{
	remove_client (self, client);
	g_object_unref (client);
}

static void
client_state_changed (NMDhcpClient *client,
                      NMDhcpState state,
                      GObject *ip_config,
                      GVariant *options,
                      const char *event_id,
                      NMDhcpManager *self)
{
	if (state >= NM_DHCP_STATE_TIMEOUT)
		remove_client_unref (self, client);
}

static NMDhcpClient *
client_start (NMDhcpManager *self,
              int addr_family,
              NMDedupMultiIndex *multi_idx,
              const char *iface,
              int ifindex,
              GBytes *hwaddr,
              const char *uuid,
              guint32 route_table,
              guint32 route_metric,
              const struct in6_addr *ipv6_ll_addr,
              GBytes *dhcp_client_id,
              gboolean enforce_duid,
              guint32 timeout,
              const char *dhcp_anycast_addr,
              const char *hostname,
              gboolean hostname_use_fqdn,
              gboolean info_only,
              NMSettingIP6ConfigPrivacy privacy,
              const char *last_ip4_address,
              guint needed_prefixes)
{
	NMDhcpManagerPrivate *priv;
	NMDhcpClient *client;
	gboolean success = FALSE;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);
	g_return_val_if_fail (!dhcp_client_id || g_bytes_get_size (dhcp_client_id) >= 2, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (!priv->client_factory)
		return NULL;

	/* Kill any old client instance */
	client = get_client_for_ifindex (self, addr_family, ifindex);
	if (client) {
		remove_client (self, client);
		nm_dhcp_client_stop (client, FALSE);
		g_object_unref (client);
	}

	client = g_object_new (priv->client_factory->get_type (),
	                       NM_DHCP_CLIENT_MULTI_IDX, multi_idx,
	                       NM_DHCP_CLIENT_ADDR_FAMILY, addr_family,
	                       NM_DHCP_CLIENT_INTERFACE, iface,
	                       NM_DHCP_CLIENT_IFINDEX, ifindex,
	                       NM_DHCP_CLIENT_HWADDR, hwaddr,
	                       NM_DHCP_CLIENT_UUID, uuid,
	                       NM_DHCP_CLIENT_ROUTE_TABLE, (guint) route_table,
	                       NM_DHCP_CLIENT_ROUTE_METRIC, (guint) route_metric,
	                       NM_DHCP_CLIENT_TIMEOUT, (guint) timeout,
	                       NM_DHCP_CLIENT_FLAGS, (guint) (0
	                           | (hostname_use_fqdn ? NM_DHCP_CLIENT_FLAGS_USE_FQDN  : 0)
	                           | (info_only         ? NM_DHCP_CLIENT_FLAGS_INFO_ONLY : 0)
	                       ),
	                       NULL);
	nm_assert (client && c_list_is_empty (&client->dhcp_client_lst));
	c_list_link_tail (&priv->dhcp_client_lst_head, &client->dhcp_client_lst);
	g_signal_connect (client, NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED, G_CALLBACK (client_state_changed), self);

	if (addr_family == AF_INET)
		success = nm_dhcp_client_start_ip4 (client, dhcp_client_id, dhcp_anycast_addr, hostname, last_ip4_address);
	else
		success = nm_dhcp_client_start_ip6 (client, dhcp_client_id, enforce_duid, dhcp_anycast_addr, ipv6_ll_addr, hostname, privacy, needed_prefixes);

	if (!success) {
		remove_client_unref (self, client);
		return NULL;
	}

	return g_object_ref (client);
}

/* Caller owns a reference to the NMDhcpClient on return */
NMDhcpClient *
nm_dhcp_manager_start_ip4 (NMDhcpManager *self,
                           NMDedupMultiIndex *multi_idx,
                           const char *iface,
                           int ifindex,
                           GBytes *hwaddr,
                           const char *uuid,
                           guint32 route_table,
                           guint32 route_metric,
                           gboolean send_hostname,
                           const char *dhcp_hostname,
                           const char *dhcp_fqdn,
                           GBytes *dhcp_client_id,
                           guint32 timeout,
                           const char *dhcp_anycast_addr,
                           const char *last_ip_address)
{
	NMDhcpManagerPrivate *priv;
	const char *hostname = NULL;
	gs_free char *hostname_tmp = NULL;
	gboolean use_fqdn = FALSE;
	char *dot;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (send_hostname) {
		/* Use, in order of preference:
		 *  1. FQDN from configuration
		 *  2. hostname from configuration
		 *  3. system hostname (only host part)
		 */
		if (dhcp_fqdn) {
			hostname = dhcp_fqdn;
			use_fqdn = TRUE;
		} else if (dhcp_hostname)
			hostname = dhcp_hostname;
		else {
			hostname = priv->default_hostname;
			if (hostname) {
				hostname_tmp = g_strdup (hostname);
				dot = strchr (hostname_tmp, '.');
				if (dot)
					*dot = '\0';
				hostname = hostname_tmp;
			}
		}
	}

	return client_start (self, AF_INET, multi_idx, iface, ifindex, hwaddr, uuid,
	                     route_table, route_metric, NULL,
	                     dhcp_client_id, 0, timeout, dhcp_anycast_addr, hostname,
	                     use_fqdn, FALSE, 0, last_ip_address, 0);
}

/* Caller owns a reference to the NMDhcpClient on return */
NMDhcpClient *
nm_dhcp_manager_start_ip6 (NMDhcpManager *self,
                           NMDedupMultiIndex *multi_idx,
                           const char *iface,
                           int ifindex,
                           GBytes *hwaddr,
                           const struct in6_addr *ll_addr,
                           const char *uuid,
                           guint32 route_table,
                           guint32 route_metric,
                           gboolean send_hostname,
                           const char *dhcp_hostname,
                           GBytes *duid,
                           gboolean enforce_duid,
                           guint32 timeout,
                           const char *dhcp_anycast_addr,
                           gboolean info_only,
                           NMSettingIP6ConfigPrivacy privacy,
                           guint needed_prefixes)
{
	NMDhcpManagerPrivate *priv;
	const char *hostname = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (send_hostname) {
		/* Always prefer the explicit dhcp-hostname if given */
		hostname = dhcp_hostname ?: priv->default_hostname;
	}
	return client_start (self, AF_INET6, multi_idx, iface, ifindex, hwaddr, uuid,
	                     route_table, route_metric, ll_addr, duid, enforce_duid,
	                     timeout, dhcp_anycast_addr, hostname, TRUE, info_only,
	                     privacy, NULL, needed_prefixes);
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

const char *
nm_dhcp_manager_get_config (NMDhcpManager *self)
{
	const NMDhcpClientFactory *factory;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	factory = NM_DHCP_MANAGER_GET_PRIVATE (self)->client_factory;
	return factory ? factory->name : NULL;
}

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMDhcpManager, nm_dhcp_manager_get, NM_TYPE_DHCP_MANAGER);

static void
nm_dhcp_manager_init (NMDhcpManager *self)
{
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	NMConfig *config = nm_config_get ();
	gs_free char *client_free = NULL;
	const char *client;
	int i;
	const NMDhcpClientFactory *client_factory = NULL;

	c_list_init (&priv->dhcp_client_lst_head);

	for (i = 0; i < G_N_ELEMENTS (_nm_dhcp_manager_factories); i++) {
		const NMDhcpClientFactory *f = _nm_dhcp_manager_factories[i];

		if (!f)
			continue;

		nm_log_dbg (LOGD_DHCP, "dhcp-init: enabled DHCP client '%s' (%s)%s",
		            f->name, g_type_name (f->get_type ()),
		            _client_factory_available (f) ? "" : " (not available)");
	}

	/* Client-specific setup */
	client_free = nm_config_data_get_value (nm_config_get_data_orig (config),
	                                        NM_CONFIG_KEYFILE_GROUP_MAIN,
	                                        NM_CONFIG_KEYFILE_KEY_MAIN_DHCP,
	                                        NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
	client = client_free;
	if (nm_config_get_configure_and_quit (config)) {
		client_factory = &_nm_dhcp_client_factory_internal;
		if (client && !nm_streq (client, client_factory->name))
			nm_log_info (LOGD_DHCP, "dhcp-init: Using internal DHCP client since configure-and-quit is set.");
	} else {
		if (client) {
			client_factory = _client_factory_available (_client_factory_find_by_name (client));
			if (!client_factory)
				nm_log_warn (LOGD_DHCP, "dhcp-init: DHCP client '%s' not available", client);
		}
		if (!client_factory) {
			client_factory = _client_factory_find_by_name (""NM_CONFIG_DEFAULT_MAIN_DHCP);
			if (!client_factory)
				nm_log_err (LOGD_DHCP, "dhcp-init: default DHCP client '%s' is not installed", NM_CONFIG_DEFAULT_MAIN_DHCP);
			else {
				client_factory = _client_factory_available (client_factory);
				if (!client_factory)
					nm_log_info (LOGD_DHCP, "dhcp-init: default DHCP client '%s' is not available", NM_CONFIG_DEFAULT_MAIN_DHCP);
			}
		}
		if (!client_factory) {
			for (i = 0; i < G_N_ELEMENTS (_nm_dhcp_manager_factories); i++) {
				client_factory = _client_factory_available (_nm_dhcp_manager_factories[i]);
				if (client_factory)
					break;
			}
		}
	}

	nm_assert (client_factory);

	nm_log_info (LOGD_DHCP, "dhcp-init: Using DHCP client '%s'", client_factory->name);

	priv->client_factory = client_factory;
}

static void
dispose (GObject *object)
{
	NMDhcpManager *self = NM_DHCP_MANAGER (object);
	NMDhcpManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	NMDhcpClient *client, *client_safe;

	c_list_for_each_entry_safe (client, client_safe, &priv->dhcp_client_lst_head, dhcp_client_lst)
		remove_client_unref (self, client);

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->dispose (object);

	nm_clear_g_free (&priv->default_hostname);
}

static void
nm_dhcp_manager_class_init (NMDhcpManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	object_class->dispose = dispose;
}
