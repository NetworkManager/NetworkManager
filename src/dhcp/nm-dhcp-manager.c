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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "nm-glib-aux/nm-dedup-multi.h"

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

static const NMDhcpClientFactory *
_client_factory_get_effective (const NMDhcpClientFactory *client_factory,
                               int addr_family)
{
	nm_auto_unref_gtypeclass NMDhcpClientClass *klass = NULL;

	nm_assert (client_factory);
	nm_assert_addr_family (addr_family);

	/* currently, the chosen DHCP plugin for IPv4 and IPv6 is configured in NetworkManager.conf
	 * and cannot be reloaded. It would be nice to configure the plugin per address family
	 * or to be able to reload it.
	 *
	 * Note that certain options in NetworkManager.conf depend on the chosen DHCP plugin.
	 * See "dhcp-plugin:" in "Device List Format" (`man NetworkManager.conf`).
	 * Supporting reloading the plugin would also require to re-evalate the decisions from
	 * the "Device List Format". Likewise, having per-address family plugins would make the
	 * "main.dhcp" setting and "dhcp-plugin:" match non-sensical because these configurations
	 * currently are address family independet.
	 *
	 * So actually, we don't want that complexity. We want to phase out all plugins in favor
	 * of the internal plugin.
	 * However, certain existing plugins are well known to not support an address family.
	 * In those cases, we should just silently fallback to the internal plugin.
	 *
	 * This could be a problem with forward compatibility if we ever intended to add IPv6 support
	 * to those plugins. But we don't intend to do so. The internal plugin is the way forward and
	 * not extending other plugins. */

	if (client_factory == &_nm_dhcp_client_factory_internal) {
		/* already using internal plugin. Nothing to do. */
		return client_factory;
	}

	klass = g_type_class_ref (client_factory->get_type ());

	nm_assert (NM_IS_DHCP_CLIENT_CLASS (klass));

	if (addr_family == AF_INET6) {
		return   klass->ip6_start
		       ? client_factory
		       : &_nm_dhcp_client_factory_internal;
	}
	return   klass->ip4_start
	       ? client_factory
	       : &_nm_dhcp_client_factory_internal;
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
              GBytes *bcast_hwaddr,
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
              guint needed_prefixes,
              GError **error)
{
	NMDhcpManagerPrivate *priv;
	NMDhcpClient *client;
	gboolean success = FALSE;
	gsize hwaddr_len;
	const NMDhcpClientFactory *client_factory;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface, NULL);
	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);
	g_return_val_if_fail (!dhcp_client_id || g_bytes_get_size (dhcp_client_id) >= 2, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!hwaddr || !bcast_hwaddr) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "missing %s address",
		                    hwaddr ? "broadcast" : "MAC");
		return NULL;
	}

	hwaddr_len = g_bytes_get_size (hwaddr);
	if (   hwaddr_len == 0
	    || hwaddr_len > NM_UTILS_HWADDR_LEN_MAX) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "invalid MAC address");
		g_return_val_if_reached (NULL) ;
	}

	nm_assert (g_bytes_get_size (hwaddr) == g_bytes_get_size (bcast_hwaddr));

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	client_factory = _client_factory_get_effective (priv->client_factory, addr_family);

	/* Kill any old client instance */
	client = get_client_for_ifindex (self, addr_family, ifindex);
	if (client) {
		/* FIXME: we cannot just call synchronously "stop()" and forget about the client.
		 * We need to wait for the client to be fully stopped because most/all clients
		 * cannot quit right away.
		 *
		 * FIXME(shutdown): also fix this during shutdown, to wait for all DHCP clients
		 * to be fully stopped. */
		remove_client (self, client);
		nm_dhcp_client_stop (client, FALSE);
		g_object_unref (client);
	}

	client = g_object_new (client_factory->get_type (),
	                       NM_DHCP_CLIENT_MULTI_IDX, multi_idx,
	                       NM_DHCP_CLIENT_ADDR_FAMILY, addr_family,
	                       NM_DHCP_CLIENT_INTERFACE, iface,
	                       NM_DHCP_CLIENT_IFINDEX, ifindex,
	                       NM_DHCP_CLIENT_HWADDR, hwaddr,
	                       NM_DHCP_CLIENT_BROADCAST_HWADDR, bcast_hwaddr,
	                       NM_DHCP_CLIENT_UUID, uuid,
	                       NM_DHCP_CLIENT_HOSTNAME, hostname,
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

	/* unfortunately, our implementations work differently per address-family regarding client-id/DUID.
	 *
	 * - for IPv4, the calling code may determine a client-id (from NM's connection profile).
	 *   If present, it is taken. If not present, the DHCP plugin uses a plugin specific default.
	 *     - for "internal" plugin, the default is just "mac".
	 *     - for "dhclient", we try to get the configuration from dhclient's /etc/dhcp or fallback
	 *       to whatever dhclient uses by default.
	 *   We do it this way, because for dhclient the user may configure a default
	 *   outside of NM, and we want to honor that. Worse, dhclient could be a wapper
	 *   script where the wrapper script overwrites the client-id. We need to distinguish
	 *   between: force a particular client-id and leave it unspecified to whatever dhclient
	 *   wants.
	 *
	 * - for IPv6, the calling code always determines a client-id. It also specifies @enforce_duid,
	 *   to determine whether the given client-id must be used.
	 *     - for "internal" plugin @enforce_duid doesn't matter and the given client-id is
	 *       always used.
	 *     - for "dhclient", @enforce_duid FALSE means to first try to load the DUID from the
	 *       lease file, and only otherwise fallback to the given client-id.
	 *     - other plugins don't support DHCPv6.
	 *   It's done this way, so that existing dhclient setups don't change behavior on upgrade.
	 *
	 * This difference is cumbersome and only exists because of "dhclient" which supports hacking the
	 * default outside of NetworkManager API.
	 */

	if (addr_family == AF_INET) {
		success = nm_dhcp_client_start_ip4 (client,
		                                    dhcp_client_id,
		                                    dhcp_anycast_addr,
		                                    last_ip4_address,
		                                    error);
	} else {
		success = nm_dhcp_client_start_ip6 (client,
		                                    dhcp_client_id,
		                                    enforce_duid,
		                                    dhcp_anycast_addr,
		                                    ipv6_ll_addr,
		                                    privacy,
		                                    needed_prefixes,
		                                    error);
	}

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
                           GBytes *bcast_hwaddr,
                           const char *uuid,
                           guint32 route_table,
                           guint32 route_metric,
                           gboolean send_hostname,
                           const char *dhcp_hostname,
                           const char *dhcp_fqdn,
                           GBytes *dhcp_client_id,
                           guint32 timeout,
                           const char *dhcp_anycast_addr,
                           const char *last_ip_address,
                           GError **error)
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

	return client_start (self,
	                     AF_INET,
	                     multi_idx,
	                     iface,
	                     ifindex,
	                     hwaddr,
	                     bcast_hwaddr,
	                     uuid,
	                     route_table,
	                     route_metric,
	                     NULL,
	                     dhcp_client_id,
	                     FALSE,
	                     timeout,
	                     dhcp_anycast_addr,
	                     hostname,
	                     use_fqdn,
	                     FALSE,
	                     0,
	                     last_ip_address,
	                     0,
	                     error);
}

/* Caller owns a reference to the NMDhcpClient on return */
NMDhcpClient *
nm_dhcp_manager_start_ip6 (NMDhcpManager *self,
                           NMDedupMultiIndex *multi_idx,
                           const char *iface,
                           int ifindex,
                           GBytes *hwaddr,
                           GBytes *bcast_hwaddr,
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
                           guint needed_prefixes,
                           GError **error)
{
	NMDhcpManagerPrivate *priv;
	const char *hostname = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (send_hostname) {
		/* Always prefer the explicit dhcp-hostname if given */
		hostname = dhcp_hostname ?: priv->default_hostname;
	}
	return client_start (self,
	                     AF_INET6,
	                     multi_idx,
	                     iface,
	                     ifindex,
	                     hwaddr,
	                     bcast_hwaddr,
	                     uuid,
	                     route_table,
	                     route_metric,
	                     ll_addr,
	                     duid,
	                     enforce_duid,
	                     timeout,
	                     dhcp_anycast_addr,
	                     hostname,
	                     TRUE,
	                     info_only,
	                     privacy,
	                     NULL,
	                     needed_prefixes,
	                     error);
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

void
nmtst_dhcp_manager_unget (gpointer self)
{
	_nmtst_nm_dhcp_manager_get_reset (self);
}

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
	if (nm_config_get_configure_and_quit (config) == NM_CONFIG_CONFIGURE_AND_QUIT_ENABLED) {
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

	g_return_if_fail (client_factory);

	nm_log_info (LOGD_DHCP, "dhcp-init: Using DHCP client '%s'", client_factory->name);

	/* NOTE: currently the DHCP plugin is chosen once at start. It's not
	 * possible to reload that configuration. If that ever becomes possible,
	 * beware that the "dhcp-plugin" device spec made decisions based on
	 * the previous plugin and may need reevaluation. */
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
