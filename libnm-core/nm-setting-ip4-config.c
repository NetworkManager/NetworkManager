/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <glib/gi18n.h>
#include <arpa/inet.h>

#include "nm-setting-ip4-config.h"
#include "nm-utils.h"
#include "nm-glib-compat.h"
#include "nm-setting-private.h"
#include "nm-core-internal.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-ip4-config
 * @short_description: Describes IPv4 addressing, routing, and name service properties
 *
 * The #NMSettingIP4Config object is a #NMSetting subclass that describes
 * properties related to IPv4 addressing, routing, and Domain Name Service
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING,
                         _nm_register_setting (IP4_CONFIG, 4))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_IP4_CONFIG)

#define NM_SETTING_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigPrivate))

typedef struct {
	char *method;
	GSList *dns;        /* list of IP address strings */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMIPAddress */
	GSList *address_labels; /* list of strings */
	GSList *routes;     /* array of NMIPRoute */
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	char *dhcp_client_id;
	gboolean dhcp_send_hostname;
	char *dhcp_hostname;
	gboolean never_default;
	gboolean may_fail;
} NMSettingIP4ConfigPrivate;

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ADDRESS_LABELS,
	PROP_ROUTES,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_DHCP_CLIENT_ID,
	PROP_DHCP_SEND_HOSTNAME,
	PROP_DHCP_HOSTNAME,
	PROP_NEVER_DEFAULT,
	PROP_MAY_FAIL,

	LAST_PROP
};

/**
 * nm_setting_ip4_config_new:
 *
 * Creates a new #NMSettingIP4Config object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIP4Config object
 **/
NMSetting *
nm_setting_ip4_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP4_CONFIG, NULL);
}

/**
 * nm_setting_ip4_config_get_method:
 * @setting: the #NMSettingIP4Config
 *
 * Returns: the #NMSettingIP4Config:method property of the setting
 **/
const char *
nm_setting_ip4_config_get_method (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->method;
}

/**
 * nm_setting_ip4_config_get_num_dns:
 * @setting: the #NMSettingIP4Config
 *
 * Returns: the number of configured DNS servers
 **/
guint32
nm_setting_ip4_config_get_num_dns (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns);
}

/**
 * nm_setting_ip4_config_get_dns:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the DNS server to return
 *
 * Returns: the IPv4 address of the DNS server at index @i
 **/
const char *
nm_setting_ip4_config_get_dns (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->dns), NULL);

	return (const char *) g_slist_nth_data (priv->dns, i);
}

static const char *
canonicalize_ip (const char *ip)
{
	in_addr_t addr;
	int ret;

	ret = inet_pton (AF_INET, ip, &addr);
	g_return_val_if_fail (ret == 1, NULL);
	return nm_utils_inet4_ntop (addr, NULL);
}

/**
 * nm_setting_ip4_config_add_dns:
 * @setting: the #NMSettingIP4Config
 * @dns: the IPv4 address of the DNS server to add
 *
 * Adds a new DNS server to the setting.
 *
 * Returns: %TRUE if the DNS server was added; %FALSE if the server was already
 * known
 **/
gboolean
nm_setting_ip4_config_add_dns (NMSettingIP4Config *setting, const char *dns)
{
	NMSettingIP4ConfigPrivate *priv;
	const char *dns_canonical;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (dns[0] != '\0', FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (dns);
	g_return_val_if_fail (dns_canonical != NULL, FALSE);

	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_canonical, (char *) iter->data))
			return FALSE;
	}

	priv->dns = g_slist_append (priv->dns, g_strdup (dns_canonical));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS);
	return TRUE;
}

/**
 * nm_setting_ip4_config_remove_dns:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the DNS server to remove
 *
 * Removes the DNS server at index @i.
 **/
void
nm_setting_ip4_config_remove_dns (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns = g_slist_delete_link (priv->dns, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS);
}

/**
 * nm_setting_ip4_config_remove_dns_by_value:
 * @setting: the #NMSettingIP4Config
 * @dns: the DNS server to remove
 *
 * Removes the DNS server @dns.
 *
 * Returns: %TRUE if the DNS server was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip4_config_remove_dns_by_value (NMSettingIP4Config *setting, const char *dns)
{
	NMSettingIP4ConfigPrivate *priv;
	const char *dns_canonical;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (dns[0] != '\0', FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (dns);
	g_return_val_if_fail (dns_canonical != NULL, FALSE);

	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_canonical, (char *) iter->data)) {
			priv->dns = g_slist_delete_link (priv->dns, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip4_config_clear_dns:
 * @setting: the #NMSettingIP4Config
 *
 * Removes all configured DNS servers.
 **/
void
nm_setting_ip4_config_clear_dns (NMSettingIP4Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_slist_free_full (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns, g_free);
	NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS);
}

/**
 * nm_setting_ip4_config_get_num_dns_searches:
 * @setting: the #NMSettingIP4Config
 *
 * Returns: the number of configured DNS search domains
 **/
guint32
nm_setting_ip4_config_get_num_dns_searches (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns_search);
}

/**
 * nm_setting_ip4_config_get_dns_search:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the DNS search domain to return
 *
 * Returns: the DNS search domain at index @i
 **/
const char *
nm_setting_ip4_config_get_dns_search (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->dns_search), NULL);

	return (const char *) g_slist_nth_data (priv->dns_search, i);
}

/**
 * nm_setting_ip4_config_add_dns_search:
 * @setting: the #NMSettingIP4Config
 * @dns_search: the search domain to add
 *
 * Adds a new DNS search domain to the setting.
 *
 * Returns: %TRUE if the DNS search domain was added; %FALSE if the search
 * domain was already known
 **/
gboolean
nm_setting_ip4_config_add_dns_search (NMSettingIP4Config *setting,
                                      const char *dns_search)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns_search; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_search, (char *) iter->data))
			return FALSE;
	}

	priv->dns_search = g_slist_append (priv->dns_search, g_strdup (dns_search));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS_SEARCH);
	return TRUE;
}

/**
 * nm_setting_ip4_config_remove_dns_search:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the DNS search domain
 *
 * Removes the DNS search domain at index @i.
 **/
void
nm_setting_ip4_config_remove_dns_search (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns_search, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns_search = g_slist_delete_link (priv->dns_search, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS_SEARCH);
}

/**
 * nm_setting_ip4_config_remove_dns_search_by_value:
 * @setting: the #NMSettingIP4Config
 * @dns_search: the search domain to remove
 *
 * Removes the DNS search domain @dns_search.
 *
 * Returns: %TRUE if the DNS search domain was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip4_config_remove_dns_search_by_value (NMSettingIP4Config *setting,
                                                  const char *dns_search)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns_search; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_search, (char *) iter->data)) {
			priv->dns_search = g_slist_delete_link (priv->dns_search, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS_SEARCH);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip4_config_clear_dns_searches:
 * @setting: the #NMSettingIP4Config
 *
 * Removes all configured DNS search domains.
 **/
void
nm_setting_ip4_config_clear_dns_searches (NMSettingIP4Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_slist_free_full (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns_search, g_free);
	NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns_search = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_DNS_SEARCH);
}

/**
 * nm_setting_ip4_config_get_num_addresses:
 * @setting: the #NMSettingIP4Config
 *
 * Returns: the number of configured addresses
 **/
guint32
nm_setting_ip4_config_get_num_addresses (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->addresses);
}

/**
 * nm_setting_ip4_config_get_address:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the address to return
 *
 * Returns: the address at index @i
 **/
NMIPAddress *
nm_setting_ip4_config_get_address (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->addresses), NULL);

	return (NMIPAddress *) g_slist_nth_data (priv->addresses, i);
}

const char *
_nm_setting_ip4_config_get_address_label (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->address_labels), NULL);

	return (const char *) g_slist_nth_data (priv->address_labels, i);
}

/**
 * nm_setting_ip4_config_add_address:
 * @setting: the #NMSettingIP4Config
 * @address: the new address to add
 *
 * Adds a new IPv4 address and associated information to the setting.  The
 * given address is duplicated internally and is not changed by this function.
 *
 * Returns: %TRUE if the address was added; %FALSE if the address was already
 * known.
 **/
gboolean
nm_setting_ip4_config_add_address (NMSettingIP4Config *setting,
                                   NMIPAddress *address)
{
	return _nm_setting_ip4_config_add_address_with_label (setting, address, "");
}

gboolean
_nm_setting_ip4_config_add_address_with_label (NMSettingIP4Config *setting,
                                               NMIPAddress *address,
                                               const char *label)
{
	NMSettingIP4ConfigPrivate *priv;
	NMIPAddress *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip_address_equal ((NMIPAddress *) iter->data, address))
			return FALSE;
	}

	copy = nm_ip_address_dup (address);
	priv->addresses = g_slist_append (priv->addresses, copy);
	priv->address_labels = g_slist_append (priv->address_labels, g_strdup (label));

	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ADDRESSES);
	return TRUE;
}

/**
 * nm_setting_ip4_config_remove_address:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the address to remove
 *
 * Removes the address at index @i.
 **/
void
nm_setting_ip4_config_remove_address (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *addr, *label;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	addr = g_slist_nth (priv->addresses, i);
	label = g_slist_nth (priv->address_labels, i);
	g_return_if_fail (addr != NULL && label != NULL);

	nm_ip_address_unref ((NMIPAddress *) addr->data);
	priv->addresses = g_slist_delete_link (priv->addresses, addr);
	g_free (label->data);
	priv->address_labels = g_slist_delete_link (priv->address_labels, label);

	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ADDRESSES);
}

/**
 * nm_setting_ip4_config_remove_address_by_value:
 * @setting: the #NMSettingIP4Config
 * @address: the IP address to remove
 *
 * Removes the address @address.
 *
 * Returns: %TRUE if the address was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip4_config_remove_address_by_value (NMSettingIP4Config *setting,
                                               NMIPAddress *address)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip_address_equal ((NMIPAddress *) iter->data, address)) {
			nm_ip_address_unref ((NMIPAddress *) iter->data);
			priv->addresses = g_slist_delete_link (priv->addresses, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ADDRESSES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip4_config_clear_addresses:
 * @setting: the #NMSettingIP4Config
 *
 * Removes all configured addresses.
 **/
void
nm_setting_ip4_config_clear_addresses (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip_address_unref);
	priv->addresses = NULL;
	g_slist_free_full (priv->address_labels, g_free);
	priv->address_labels = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ADDRESSES);
}

/**
 * nm_setting_ip4_config_get_num_routes:
 * @setting: the #NMSettingIP4Config
 *
 * Returns: the number of configured routes
 **/
guint32
nm_setting_ip4_config_get_num_routes (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->routes);
}

/**
 * nm_setting_ip4_config_get_route:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the route to return
 *
 * Returns: the route at index @i
 **/
NMIPRoute *
nm_setting_ip4_config_get_route (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->routes), NULL);

	return (NMIPRoute *) g_slist_nth_data (priv->routes, i);
}

/**
 * nm_setting_ip4_config_add_route:
 * @setting: the #NMSettingIP4Config
 * @route: the route to add
 *
 * Adds a new IPv4 route and associated information to the setting.  The
 * given route is duplicated internally and is not changed by this function.
 *
 * Returns: %TRUE if the route was added; %FALSE if the route was already known.
 **/
gboolean
nm_setting_ip4_config_add_route (NMSettingIP4Config *setting,
                                 NMIPRoute *route)
{
	NMSettingIP4ConfigPrivate *priv;
	NMIPRoute *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip_route_equal (iter->data, route))
			return FALSE;
	}

	copy = nm_ip_route_dup (route);
	priv->routes = g_slist_append (priv->routes, copy);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ROUTES);
	return TRUE;
}

/**
 * nm_setting_ip4_config_remove_route:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the route
 *
 * Removes the route at index @i.
 **/
void
nm_setting_ip4_config_remove_route (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->routes, i);
	g_return_if_fail (elt != NULL);

	nm_ip_route_unref ((NMIPRoute *) elt->data);
	priv->routes = g_slist_delete_link (priv->routes, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ROUTES);
}

/**
 * nm_setting_ip4_config_remove_route_by_value:
 * @setting: the #NMSettingIP4Config
 * @route: the route to remove
 *
 * Removes the route @route.
 *
 * Returns: %TRUE if the route was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip4_config_remove_route_by_value (NMSettingIP4Config *setting,
                                             NMIPRoute *route)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip_route_equal ((NMIPRoute *) iter->data, route)) {
			nm_ip_route_unref ((NMIPRoute *) iter->data);
			priv->routes = g_slist_delete_link (priv->routes, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ROUTES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip4_config_clear_routes:
 * @setting: the #NMSettingIP4Config
 *
 * Removes all configured routes.
 **/
void
nm_setting_ip4_config_clear_routes (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip_route_unref);
	priv->routes = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ROUTES);
}

/**
 * nm_setting_ip4_config_get_ignore_auto_routes:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:ignore-auto-routes
 * property.
 *
 * Returns: %TRUE if automatically configured (ie via DHCP) routes should be
 * ignored.
 **/
gboolean
nm_setting_ip4_config_get_ignore_auto_routes (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->ignore_auto_routes;
}

/**
 * nm_setting_ip4_config_get_ignore_auto_dns:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:ignore-auto-dns
 * property.
 *
 * Returns: %TRUE if automatically configured (ie via DHCP) DNS information
 * should be ignored.
 **/
gboolean
nm_setting_ip4_config_get_ignore_auto_dns (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->ignore_auto_dns;
}

/**
 * nm_setting_ip4_config_get_dhcp_client_id:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:dhcp-client-id
 * property.
 *
 * Returns: the configured Client ID to send to the DHCP server when requesting
 * addresses via DHCP.
 **/
const char *
nm_setting_ip4_config_get_dhcp_client_id (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_client_id;
}

/**
 * nm_setting_ip4_config_get_dhcp_send_hostname:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:dhcp-send-hostname
 * property.
 *
 * Returns: %TRUE if NetworkManager should send the machine hostname to the
 * DHCP server when requesting addresses to allow the server to automatically
 * update DNS information for this machine.
 **/
gboolean
nm_setting_ip4_config_get_dhcp_send_hostname (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_send_hostname;
}

/**
 * nm_setting_ip4_config_get_dhcp_hostname:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:dhcp-hostname
 * property.
 *
 * Returns: the configured hostname to send to the DHCP server
 **/
const char *
nm_setting_ip4_config_get_dhcp_hostname (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_hostname;
}

/**
 * nm_setting_ip4_config_get_never_default:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:never-default
 * property.
 *
 * Returns: %TRUE if this connection should never be the default connection
 * for IPv4 addressing
 **/
gboolean
nm_setting_ip4_config_get_never_default (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->never_default;
}

/**
 * nm_setting_ip4_config_get_may_fail:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:may-fail
 * property.
 *
 * Returns: %TRUE if this connection doesn't require IPv4 addressing to complete
 * for the connection to succeed.
 **/
gboolean
nm_setting_ip4_config_get_may_fail (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->may_fail;
}

static gboolean
verify_label (const char *label)
{
	const char *p;
	char *iface;

	if (!*label)
		return TRUE;

	p = strchr (label, ':');
	if (!p)
		return FALSE;
	iface = g_strndup (label, p - label);
	if (!nm_utils_iface_valid_name (iface)) {
		g_free (iface);
		return FALSE;
	}
	g_free (iface);

	for (p++; *p; p++) {
		if (!g_ascii_isalnum (*p) && *p != '_')
			return FALSE;
	}

	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	GSList *iter;
	int i;

	if (!priv->method) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (!priv->addresses) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("this property cannot be empty for '%s=%s'"),
			             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
	           || !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		if (priv->dns) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DNS);
			return FALSE;
		}

		if (priv->dns_search) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		/* Shared allows IP addresses; link-local and disabled do not */
		if (strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0) {
			if (priv->addresses) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("this property is not allowed for '%s=%s'"),
				             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_ADDRESSES);
				return FALSE;
			}
		}
	} else if (!strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		/* nothing to do */
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_client_id && !strlen (priv->dhcp_client_id)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID);
		return FALSE;
	}

	if (priv->dhcp_hostname && !strlen (priv->dhcp_hostname)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	/* Validate address labels */
	for (iter = priv->address_labels, i = 0; iter; iter = g_slist_next (iter), i++) {
		const char *label = (const char *) iter->data;

		if (!verify_label (label)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. IPv4 address has invalid label '%s'"),
			             i+1, label);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, "address-labels");
			return FALSE;
		}
	}

	if (g_slist_length (priv->addresses) != g_slist_length (priv->address_labels)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("IPv4 address / label count mismatch (%d vs %d)"),
		             g_slist_length (priv->addresses),
		             g_slist_length (priv->address_labels));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, "address-labels");
		return FALSE;
	}

	/* Validate DNS */
	for (iter = priv->dns, i = 0; iter; iter = g_slist_next (iter), i++) {
		const char *dns = (const char *) iter->data;
		in_addr_t addr;

		if (inet_pton (AF_INET, dns, &addr) != 1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. DNS server address is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DNS);
			return FALSE;
		}
	}

	return TRUE;
}


static void
nm_setting_ip4_config_init (NMSettingIP4Config *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (self);

	g_free (priv->method);
	g_free (priv->dhcp_hostname);
	g_free (priv->dhcp_client_id);

	g_slist_free_full (priv->dns, g_free);
	g_slist_free_full (priv->dns_search, g_free);
	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip_address_unref);
	g_slist_free_full (priv->address_labels, g_free);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip_route_unref);

	G_OBJECT_CLASS (nm_setting_ip4_config_parent_class)->finalize (object);
}

static GVariant *
ip4_dns_to_dbus (const GValue *prop_value)
{
	return nm_utils_ip4_dns_to_variant (g_value_get_boxed (prop_value));
}

static void
ip4_dns_from_dbus (GVariant *dbus_value,
                   GValue *prop_value)
{
	g_value_take_boxed (prop_value, nm_utils_ip4_dns_from_variant (dbus_value));
}

static GVariant *
ip4_addresses_to_dbus (const GValue *prop_value)
{
	return nm_utils_ip4_addresses_to_variant (g_value_get_boxed (prop_value));
}

static void
ip4_addresses_from_dbus (GVariant *dbus_value,
                         GValue *prop_value)
{
	g_value_take_boxed (prop_value, nm_utils_ip4_addresses_from_variant (dbus_value));
}

static GVariant *
ip4_routes_to_dbus (const GValue *prop_value)
{
	return nm_utils_ip4_routes_to_variant (g_value_get_boxed (prop_value));
}

static void
ip4_routes_from_dbus (GVariant *dbus_value,
                      GValue *prop_value)
{
	g_value_take_boxed (prop_value, nm_utils_ip4_routes_from_variant (dbus_value));
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	GSList *iter;

	switch (prop_id) {
	case PROP_METHOD:
		g_free (priv->method);
		priv->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		g_slist_free_full (priv->dns, g_free);
		priv->dns = _nm_utils_strv_to_slist (g_value_get_boxed (value));
		break;
	case PROP_DNS_SEARCH:
		g_slist_free_full (priv->dns_search, g_free);
		priv->dns_search = _nm_utils_strv_to_slist (g_value_get_boxed (value));
		break;
	case PROP_ADDRESSES:
		g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip_address_unref);
		priv->addresses = _nm_utils_copy_array_to_slist (g_value_get_boxed (value),
		                                                 (NMUtilsCopyFunc) nm_ip_address_dup);

		if (g_slist_length (priv->addresses) != g_slist_length (priv->address_labels)) {
			g_slist_free_full (priv->address_labels, g_free);
			priv->address_labels = NULL;
			for (iter = priv->addresses; iter; iter = iter->next)
				priv->address_labels = g_slist_prepend (priv->address_labels, g_strdup (""));
		}
		break;
	case PROP_ADDRESS_LABELS:
		g_slist_free_full (priv->address_labels, g_free);
		priv->address_labels = _nm_utils_strv_to_slist (g_value_get_boxed (value));
		break;
	case PROP_ROUTES:
		g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip_route_unref);
		priv->routes = _nm_utils_copy_array_to_slist (g_value_get_boxed (value),
		                                              (NMUtilsCopyFunc) nm_ip_route_dup);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		priv->ignore_auto_routes = g_value_get_boolean (value);
		break;
	case PROP_IGNORE_AUTO_DNS:
		priv->ignore_auto_dns = g_value_get_boolean (value);
		break;
	case PROP_DHCP_CLIENT_ID:
		g_free (priv->dhcp_client_id);
		priv->dhcp_client_id = g_value_dup_string (value);
		break;
	case PROP_DHCP_SEND_HOSTNAME:
		priv->dhcp_send_hostname = g_value_get_boolean (value);
		break;
	case PROP_DHCP_HOSTNAME:
		g_free (priv->dhcp_hostname);
		priv->dhcp_hostname = g_value_dup_string (value);
		break;
	case PROP_NEVER_DEFAULT:
		priv->never_default = g_value_get_boolean (value);
		break;
	case PROP_MAY_FAIL:
		priv->may_fail = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, nm_setting_ip4_config_get_method (setting));
		break;
	case PROP_DNS:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->dns));
		break;
	case PROP_DNS_SEARCH:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->dns_search));
		break;
	case PROP_ADDRESSES:
		g_value_take_boxed (value, _nm_utils_copy_slist_to_array (priv->addresses, (NMUtilsCopyFunc) nm_ip_address_dup, (GDestroyNotify) nm_ip_address_unref));
		break;
	case PROP_ADDRESS_LABELS:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->address_labels));
		break;
	case PROP_ROUTES:
		g_value_take_boxed (value, _nm_utils_copy_slist_to_array (priv->routes, (NMUtilsCopyFunc) nm_ip_route_dup, (GDestroyNotify) nm_ip_route_unref));
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		g_value_set_boolean (value, nm_setting_ip4_config_get_ignore_auto_routes (setting));
		break;
	case PROP_IGNORE_AUTO_DNS:
		g_value_set_boolean (value, nm_setting_ip4_config_get_ignore_auto_dns (setting));
		break;
	case PROP_DHCP_CLIENT_ID:
		g_value_set_string (value, nm_setting_ip4_config_get_dhcp_client_id (setting));
		break;
	case PROP_DHCP_SEND_HOSTNAME:
		g_value_set_boolean (value, nm_setting_ip4_config_get_dhcp_send_hostname (setting));
		break;
	case PROP_DHCP_HOSTNAME:
		g_value_set_string (value, nm_setting_ip4_config_get_dhcp_hostname (setting));
		break;
	case PROP_NEVER_DEFAULT:
		g_value_set_boolean (value, priv->never_default);
		break;
	case PROP_MAY_FAIL:
		g_value_set_boolean (value, priv->may_fail);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip4_config_class_init (NMSettingIP4ConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingIP4ConfigPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify = verify;

	/* Properties */
	/**
	 * NMSettingIP4Config:method:
	 *
	 * IPv4 configuration method.  If "auto" is specified then the appropriate
	 * automatic method (DHCP, PPP, etc) is used for the interface and most
	 * other properties can be left unset.  If "link-local" is specified, then a
	 * link-local address in the 169.254/16 range will be assigned to the
	 * interface.  If "manual" is specified, static IP addressing is used and at
	 * least one IP address must be given in the "addresses" property.  If
	 * "shared" is specified (indicating that this connection will provide
	 * network access to other computers) then the interface is assigned an
	 * address in the 10.42.x.1/24 range and a DHCP and forwarding DNS server
	 * are started, and the interface is NAT-ed to the current default network
	 * connection.  "disabled" means IPv4 will not be used on this connection.
	 * This property must be set.
	 **/
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_METHOD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:dns:
	 *
	 * Array of IPv4 addresses of DNS servers.  For the 'auto' method, these
	 * DNS servers are appended to those (if any) returned by automatic
	 * configuration.  DNS servers cannot be used with the "shared",
	 * "link-local", or "disabled" methods as there is no upstream network.  In
	 * all other methods, these DNS servers are used as the only DNS servers for
	 * this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 g_param_spec_boxed (NM_SETTING_IP4_CONFIG_DNS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_IP4_CONFIG_DNS,
	                                      G_VARIANT_TYPE ("au"),
	                                      ip4_dns_to_dbus,
	                                      ip4_dns_from_dbus);

	/**
	 * NMSettingIP4Config:dns-search:
	 *
	 * List of DNS search domains.  For the "auto" method, these search domains
	 * are appended to those returned by automatic configuration. Search domains
	 * cannot be used with the "shared", "link-local", or "disabled" methods as
	 * there is no upstream network.  In all other methods, these search domains
	 * are used as the only search domains for this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 g_param_spec_boxed (NM_SETTING_IP4_CONFIG_DNS_SEARCH, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:addresses:
	 *
	 * Array of IPv4 addresses.  The gateway may be left as 0 if no gateway exists
	 * for that subnet.  For the 'auto' method, given IP addresses are appended
	 * to those returned by automatic configuration.  Addresses cannot be used
	 * with the "shared", "link-local", or "disabled" methods as addressing is
	 * either automatic or disabled with these methods.
	 *
	 * Element-Type: NMIPAddress
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 g_param_spec_boxed (NM_SETTING_IP4_CONFIG_ADDRESSES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_IP4_CONFIG_ADDRESSES,
	                                      G_VARIANT_TYPE ("aau"),
	                                      ip4_addresses_to_dbus,
	                                      ip4_addresses_from_dbus);

	/**
	 * NMSettingIP4Config:address-labels:
	 *
	 * Internal use only.
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESS_LABELS,
		 g_param_spec_boxed ("address-labels", "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:routes:
	 *
	 * Array of IPv4 routes. For the 'auto' method, given IP routes are appended
	 * to those returned by automatic configuration. Routes cannot be used with
	 * the 'shared', 'link-local', or 'disabled' methods because there is no
	 * upstream network.
	 *
	 * Element-Type: NMIPRoute
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 g_param_spec_boxed (NM_SETTING_IP4_CONFIG_ROUTES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_IP4_CONFIG_ROUTES,
	                                      G_VARIANT_TYPE ("aau"),
	                                      ip4_routes_to_dbus,
	                                      ip4_routes_from_dbus);

	/**
	 * NMSettingIP4Config:ignore-auto-routes:
	 *
	 * When the method is set to "auto" and this property to %TRUE,
	 * automatically configured routes are ignored and only routes specified in
	 * the #NMSettingIP4Config:routes property, if any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_ROUTES,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:ignore-auto-dns:
	 *
	 * When the method is set to "auto" and this property to %TRUE,
	 * automatically configured nameservers and search domains are ignored and
	 * only nameservers and search domains specified in the
	 * #NMSettingIP4Config:dns and #NMSettingIP4Config:dns-search properties, if
	 * any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_DNS,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:dhcp-client-id:
	 *
	 * A string sent to the DHCP server to identify the local machine which the
	 * DHCP server may use to customize the DHCP lease and options.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_CLIENT_ID,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:dhcp-send-hostname:
	 *
	 * If %TRUE, a hostname is sent to the DHCP server when acquiring a lease.
	 * Some DHCP servers use this hostname to update DNS databases, essentially
	 * providing a static hostname for the computer.  If the
	 * #NMSettingIP4Config:dhcp-hostname property is empty and this property is
	 * %TRUE, the current persistent hostname of the computer is sent.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_SEND_HOSTNAME,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:dhcp-hostname:
	 *
	 * If the #NMSettingIP4Config:dhcp-send-hostname property is %TRUE, then the
	 * specified name will be sent to the DHCP server when acquiring a lease.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_HOSTNAME,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:never-default:
	 *
	 * If %TRUE, this connection will never be the default IPv4 connection,
	 * meaning it will never be assigned the default route by NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_NEVER_DEFAULT,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:may-fail:
	 *
	 * If %TRUE, allow overall network configuration to proceed even if IPv4
	 * configuration times out.  Note that at least one IP configuration must
	 * succeed or overall network configuration will still fail.  For example,
	 * in IPv6-only networks, setting this property to %TRUE allows the overall
	 * network configuration to succeed if IPv4 configuration fails but IPv6
	 * configuration completes successfully.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAY_FAIL,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_MAY_FAIL, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));
}
