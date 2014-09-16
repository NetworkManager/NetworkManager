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
 */

#include <string.h>
#include <glib/gi18n.h>

#include "nm-setting-ip6-config.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-glib-compat.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-ip6-config
 * @short_description: Describes IPv6 addressing, routing, and name service properties
 *
 * The #NMSettingIP6Config object is a #NMSetting subclass that describes
 * properties related to IPv6 addressing, routing, and Domain Name Service
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING,
                         _nm_register_setting (IP6_CONFIG, 4))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_IP6_CONFIG)

#define NM_SETTING_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigPrivate))

typedef struct {
	char *method;
	char *dhcp_hostname;
	GSList *dns;        /* array of struct in6_addr */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMIPAddress */
	GSList *routes;     /* array of NMIPRoute */
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	gboolean never_default;
	gboolean may_fail;
	NMSettingIP6ConfigPrivacy ip6_privacy;
} NMSettingIP6ConfigPrivate;


enum {
	PROP_0,
	PROP_METHOD,
	PROP_DHCP_HOSTNAME,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_NEVER_DEFAULT,
	PROP_MAY_FAIL,
	PROP_IP6_PRIVACY,

	LAST_PROP
};

/**
 * nm_setting_ip6_config_new:
 *
 * Creates a new #NMSettingIP6Config object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIP6Config object
 **/
NMSetting *
nm_setting_ip6_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP6_CONFIG, NULL);
}

/**
 * nm_setting_ip6_config_get_method:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: the #NMSettingIP6Config:method property of the setting
 **/
const char *
nm_setting_ip6_config_get_method (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->method;
}

/**
 * nm_setting_ip6_config_get_dhcp_hostname:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:dhcp-hostname
 * property.
 *
 * Returns: the configured hostname to send to the DHCP server
 **/
const char *
nm_setting_ip6_config_get_dhcp_hostname (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dhcp_hostname;
}

/**
 * nm_setting_ip6_config_get_num_dns:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: the number of configured DNS servers
 **/
guint32
nm_setting_ip6_config_get_num_dns (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns);
}

/**
 * nm_setting_ip6_config_get_dns:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the DNS server to return
 *
 * Returns: (transfer none): the IPv6 address of the DNS server at index @i
 **/
const char *
nm_setting_ip6_config_get_dns (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->dns), NULL);

	return (const char *) g_slist_nth_data (priv->dns, i);
}

static const char *
canonicalize_ip (const char *ip)
{
	struct in6_addr addr;
	int ret;

	ret = inet_pton (AF_INET6, ip, &addr);
	g_return_val_if_fail (ret == 1, NULL);
	return nm_utils_inet6_ntop (&addr, NULL);
}

/**
 * nm_setting_ip6_config_add_dns:
 * @setting: the #NMSettingIP6Config
 * @dns: the IPv6 address of the DNS server to add
 *
 * Adds a new DNS server to the setting.
 *
 * Returns: %TRUE if the DNS server was added; %FALSE if the server was already
 * known
 **/
gboolean
nm_setting_ip6_config_add_dns (NMSettingIP6Config *setting, const char *dns)
{
	NMSettingIP6ConfigPrivate *priv;
	const char *dns_canonical;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (dns[0] != '\0', FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (dns);
	g_return_val_if_fail (dns_canonical != NULL, FALSE);

	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_canonical, (char *) iter->data))
			return FALSE;
	}

	priv->dns = g_slist_append (priv->dns, g_strdup (dns_canonical));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS);
	return TRUE;
}

/**
 * nm_setting_ip6_config_remove_dns:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the DNS server to remove
 *
 * Removes the DNS server at index @i.
 **/
void
nm_setting_ip6_config_remove_dns (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns = g_slist_delete_link (priv->dns, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS);
}

/**
 * nm_setting_ip6_config_remove_dns_by_value:
 * @setting: the #NMSettingIP6Config
 * @dns: the IPv6 address of the DNS server to remove
 *
 * Removes the DNS server at index @i.
 *
 * Returns: %TRUE if the DNS server was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip6_config_remove_dns_by_value (NMSettingIP6Config *setting,
                                           const char *dns)
{
	NMSettingIP6ConfigPrivate *priv;
	const char *dns_canonical;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (dns[0] != '\0', FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (dns);
	g_return_val_if_fail (dns_canonical != NULL, FALSE);

	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_canonical, (char *) iter->data)) {
			priv->dns = g_slist_delete_link (priv->dns, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip6_config_clear_dns:
 * @setting: the #NMSettingIP6Config
 *
 * Removes all configured DNS servers.
 **/
void
nm_setting_ip6_config_clear_dns (NMSettingIP6Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	g_slist_free_full (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns, g_free);
	NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS);
}

/**
 * nm_setting_ip6_config_get_num_dns_searches:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: the number of configured DNS search domains
 **/
guint32
nm_setting_ip6_config_get_num_dns_searches (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns_search);
}

/**
 * nm_setting_ip6_config_get_dns_search:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the DNS search domain to return
 *
 * Returns: the DNS search domain at index @i
 **/
const char *
nm_setting_ip6_config_get_dns_search (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->dns_search), NULL);

	return (const char *) g_slist_nth_data (priv->dns_search, i);
}

/**
 * nm_setting_ip6_config_add_dns_search:
 * @setting: the #NMSettingIP6Config
 * @dns_search: the search domain to add
 *
 * Adds a new DNS search domain to the setting.
 *
 * Returns: %TRUE if the DNS search domain was added; %FALSE if the search
 * domain was already known
 **/
gboolean
nm_setting_ip6_config_add_dns_search (NMSettingIP6Config *setting,
                                      const char *dns_search)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns_search; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_search, (char *) iter->data))
			return FALSE;
	}

	priv->dns_search = g_slist_append (priv->dns_search, g_strdup (dns_search));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS_SEARCH);
	return TRUE;
}

/**
 * nm_setting_ip6_config_remove_dns_search:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the DNS search domain
 *
 * Removes the DNS search domain at index @i.
 **/
void
nm_setting_ip6_config_remove_dns_search (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns_search, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns_search = g_slist_delete_link (priv->dns_search, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS_SEARCH);
}

/**
 * nm_setting_ip6_config_remove_dns_search_by_value:
 * @setting: the #NMSettingIP6Config
 * @dns_search: the search domain to remove
 *
 * Removes the DNS search domain @dns_search.
 *
 * Returns: %TRUE if the DNS search domain was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip6_config_remove_dns_search_by_value (NMSettingIP6Config *setting,
                                                  const char *dns_search)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns_search; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_search, (char *) iter->data)) {
			priv->dns_search = g_slist_delete_link (priv->dns_search, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS_SEARCH);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip6_config_clear_dns_searches:
 * @setting: the #NMSettingIP6Config
 *
 * Removes all configured DNS search domains.
 **/
void
nm_setting_ip6_config_clear_dns_searches (NMSettingIP6Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	g_slist_free_full (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns_search, g_free);
	NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns_search = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_DNS_SEARCH);
}

/**
 * nm_setting_ip6_config_get_num_addresses:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: the number of configured addresses
 **/
guint32
nm_setting_ip6_config_get_num_addresses (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->addresses);
}

/**
 * nm_setting_ip6_config_get_address:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the address to return
 *
 * Returns: the address at index @i
 **/
NMIPAddress *
nm_setting_ip6_config_get_address (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->addresses), NULL);

	return (NMIPAddress *) g_slist_nth_data (priv->addresses, i);
}

/**
 * nm_setting_ip6_config_add_address:
 * @setting: the #NMSettingIP6Config
 * @address: the new address to add
 *
 * Adds a new IPv6 address and associated information to the setting.  The
 * given address is duplicated internally and is not changed by this function.
 *
 * Returns: %TRUE if the address was added; %FALSE if the address was already
 * known.
 **/
gboolean
nm_setting_ip6_config_add_address (NMSettingIP6Config *setting,
                                   NMIPAddress *address)
{
	NMSettingIP6ConfigPrivate *priv;
	NMIPAddress *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip_address_equal ((NMIPAddress *) iter->data, address))
			return FALSE;
	}

	copy = nm_ip_address_dup (address);
	priv->addresses = g_slist_append (priv->addresses, copy);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ADDRESSES);
	return TRUE;
}

/**
 * nm_setting_ip6_config_remove_address:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the address to remove
 *
 * Removes the address at index @i.
 **/
void
nm_setting_ip6_config_remove_address (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->addresses, i);
	g_return_if_fail (elt != NULL);

	nm_ip_address_unref ((NMIPAddress *) elt->data);
	priv->addresses = g_slist_delete_link (priv->addresses, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ADDRESSES);
}

/**
 * nm_setting_ip6_config_remove_address_by_value:
 * @setting: the #NMSettingIP6Config
 * @address: the address to remove
 *
 * Removes the address @address.
 *
 * Returns: %TRUE if the address was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip6_config_remove_address_by_value (NMSettingIP6Config *setting,
                                               NMIPAddress *address)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip_address_equal ((NMIPAddress *) iter->data, address)) {
			priv->addresses = g_slist_delete_link (priv->addresses, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ADDRESSES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip6_config_clear_addresses:
 * @setting: the #NMSettingIP6Config
 *
 * Removes all configured addresses.
 **/
void
nm_setting_ip6_config_clear_addresses (NMSettingIP6Config *setting)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip_address_unref);
	priv->addresses = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ADDRESSES);
}

/**
 * nm_setting_ip6_config_get_num_routes:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: the number of configured routes
 **/
guint32
nm_setting_ip6_config_get_num_routes (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->routes);
}

/**
 * nm_setting_ip6_config_get_route:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the route to return
 *
 * Returns: the route at index @i
 **/
NMIPRoute *
nm_setting_ip6_config_get_route (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i < g_slist_length (priv->routes), NULL);

	return (NMIPRoute *) g_slist_nth_data (priv->routes, i);
}

/**
 * nm_setting_ip6_config_add_route:
 * @setting: the #NMSettingIP6Config
 * @route: the route to add
 *
 * Adds a new IPv6 route and associated information to the setting.  The
 * given route is duplicated internally and is not changed by this function.
 *
 * Returns: %TRUE if the route was added; %FALSE if the route was already known.
 **/
gboolean
nm_setting_ip6_config_add_route (NMSettingIP6Config *setting,
                                 NMIPRoute *route)
{
	NMSettingIP6ConfigPrivate *priv;
	NMIPRoute *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip_route_equal ((NMIPRoute *) iter->data, route))
			return FALSE;
	}

	copy = nm_ip_route_dup (route);
	priv->routes = g_slist_append (priv->routes, copy);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ROUTES);
	return TRUE;
}

/**
 * nm_setting_ip6_config_remove_route:
 * @setting: the #NMSettingIP6Config
 * @i: index number of the route
 *
 * Removes the route at index @i.
 **/
void
nm_setting_ip6_config_remove_route (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->routes, i);
	g_return_if_fail (elt != NULL);

	nm_ip_route_unref ((NMIPRoute *) elt->data);
	priv->routes = g_slist_delete_link (priv->routes, elt);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ROUTES);
}

/**
 * nm_setting_ip6_config_remove_route_by_value:
 * @setting: the #NMSettingIP6Config
 * @route: the route to remove
 *
 * Removes the route @route.
 *
 * Returns: %TRUE if the route was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip6_config_remove_route_by_value (NMSettingIP6Config *setting,
                                             NMIPRoute *route)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip_route_equal ((NMIPRoute *) iter->data, route)) {
			nm_ip_route_unref ((NMIPRoute *) iter->data);
			priv->routes = g_slist_delete_link (priv->routes, iter);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ROUTES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip6_config_clear_routes:
 * @setting: the #NMSettingIP6Config
 *
 * Removes all configured routes.
 **/
void
nm_setting_ip6_config_clear_routes (NMSettingIP6Config *setting)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip_route_unref);
	priv->routes = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ROUTES);
}

/**
 * nm_setting_ip6_config_get_ignore_auto_routes:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:ignore-auto-routes
 * property.
 *
 * Returns: %TRUE if automatically configured (ie via DHCP) routes should be
 * ignored.
 **/
gboolean
nm_setting_ip6_config_get_ignore_auto_routes (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->ignore_auto_routes;
}

/**
 * nm_setting_ip6_config_get_ignore_auto_dns:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:ignore-auto-dns
 * property.
 *
 * Returns: %TRUE if automatically configured (ie via DHCP or router
 * advertisements) DNS information should be ignored.
 **/
gboolean
nm_setting_ip6_config_get_ignore_auto_dns (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->ignore_auto_dns;
}

/**
 * nm_setting_ip6_config_get_never_default:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:never-default
 * property.
 *
 * Returns: %TRUE if this connection should never be the default connection
 * for IPv6 addressing
 **/
gboolean
nm_setting_ip6_config_get_never_default (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->never_default;
}

/**
 * nm_setting_ip6_config_get_may_fail:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:may-fail
 * property.
 *
 * Returns: %TRUE if this connection doesn't require IPv6 addressing to complete
 * for the connection to succeed.
 **/
gboolean
nm_setting_ip6_config_get_may_fail (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->may_fail;
}

/**
 * nm_setting_ip6_config_get_ip6_privacy:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:ip6-privacy
 * property.
 *
 * Returns: IPv6 Privacy Extensions configuration value (#NMSettingIP6ConfigPrivacy).
 **/
NMSettingIP6ConfigPrivacy
nm_setting_ip6_config_get_ip6_privacy (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->ip6_privacy;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	GSList *iter;
	int i;

	if (!priv->method) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (!priv->addresses) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("this property cannot be empty for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		if (priv->dns) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' not allowed for %s=%s"),
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DNS);
			return FALSE;
		}

		if (priv->dns_search) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		if (priv->addresses) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		/* nothing to do */
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_hostname && !strlen (priv->dhcp_hostname)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	for (iter = priv->dns, i = 0; iter; iter = g_slist_next (iter), i++) {
		const char *dns = (const char *) iter->data;
		struct in6_addr addr;

		if (inet_pton (AF_INET6, dns, &addr) != 1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. DNS server address is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DNS);
			return FALSE;
		}
	}

	return TRUE;
}


static void
nm_setting_ip6_config_init (NMSettingIP6Config *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	g_free (priv->method);
	g_free (priv->dhcp_hostname);

	g_slist_free_full (priv->dns, g_free);
	g_slist_free_full (priv->dns_search, g_free);
	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip_address_unref);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip_route_unref);

	G_OBJECT_CLASS (nm_setting_ip6_config_parent_class)->finalize (object);
}

static GVariant *
ip6_dns_to_dbus (const GValue *prop_value)
{
	return nm_utils_ip6_dns_to_variant (g_value_get_boxed (prop_value));
}

static void
ip6_dns_from_dbus (GVariant *dbus_value,
                   GValue *prop_value)
{
	g_value_take_boxed (prop_value, nm_utils_ip6_dns_from_variant (dbus_value));
}

static GVariant *
ip6_addresses_to_dbus (const GValue *prop_value)
{
	return nm_utils_ip6_addresses_to_variant (g_value_get_boxed (prop_value));
}

static void
ip6_addresses_from_dbus (GVariant *dbus_value,
                         GValue *prop_value)
{
	g_value_take_boxed (prop_value, nm_utils_ip6_addresses_from_variant (dbus_value));
}

static GVariant *
ip6_routes_to_dbus (const GValue *prop_value)
{
	return nm_utils_ip6_routes_to_variant (g_value_get_boxed (prop_value));
}

static void
ip6_routes_from_dbus (GVariant *dbus_value,
                      GValue *prop_value)
{
	g_value_take_boxed (prop_value, nm_utils_ip6_routes_from_variant (dbus_value));
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

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
		g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip_address_unref);
		priv->addresses = _nm_utils_copy_array_to_slist (g_value_get_boxed (value),
		                                                 (NMUtilsCopyFunc) nm_ip_address_dup);
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
	case PROP_IP6_PRIVACY:
		priv->ip6_privacy = g_value_get_enum (value);
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
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, priv->method);
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
	case PROP_ROUTES:
		g_value_take_boxed (value, _nm_utils_copy_slist_to_array (priv->routes, (NMUtilsCopyFunc) nm_ip_route_dup, (GDestroyNotify) nm_ip_route_unref));
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		g_value_set_boolean (value, priv->ignore_auto_routes);
		break;
	case PROP_IGNORE_AUTO_DNS:
		g_value_set_boolean (value, priv->ignore_auto_dns);
		break;
	case PROP_DHCP_HOSTNAME:
		g_value_set_string (value, priv->dhcp_hostname);
		break;
	case PROP_NEVER_DEFAULT:
		g_value_set_boolean (value, priv->never_default);
		break;
	case PROP_MAY_FAIL:
		g_value_set_boolean (value, priv->may_fail);
		break;
	case PROP_IP6_PRIVACY:
		g_value_set_enum (value, priv->ip6_privacy);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip6_config_class_init (NMSettingIP6ConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingIP6ConfigPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify = verify;

	/* Properties */
	/**
	 * NMSettingIP6Config:method:
	 *
	 * IPv6 configuration method.  If "auto" is specified then the appropriate
	 * automatic method (PPP, router advertisement, etc) is used for the device
	 * and most other properties can be left unset.  To force the use of DHCP
	 * only, specify "dhcp"; this method is only valid for Ethernet- based
	 * hardware.  If "link-local" is specified, then an IPv6 link-local address
	 * will be assigned to the interface.  If "manual" is specified, static IP
	 * addressing is used and at least one IP address must be given in the
	 * "addresses" property.  If "ignore" is specified, IPv6 configuration is
	 * not done. This property must be set.  Note: the "shared" method is not
	 * yet supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP6_CONFIG_METHOD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:dhcp-hostname:
	 *
	 * The specified name will be sent to the DHCP server when acquiring a
	 * lease.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_HOSTNAME,
		 g_param_spec_string (NM_SETTING_IP6_CONFIG_DHCP_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:dns:
	 *
	 * Array of IPv6 addresses of DNS servers.  For the "auto" method, these DNS
	 * servers are appended to those (if any) returned by automatic
	 * configuration.  DNS servers cannot be used with the "shared" or
	 * "link-local" methods as there is no usptream network.  In all other
	 * methods, these DNS servers are used as the only DNS servers for this
	 * connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 g_param_spec_boxed (NM_SETTING_IP6_CONFIG_DNS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_IP6_CONFIG_DNS,
	                                      G_VARIANT_TYPE ("aay"),
	                                      ip6_dns_to_dbus,
	                                      ip6_dns_from_dbus);

	/**
	 * NMSettingIP6Config:dns-search:
	 *
	 * List of DNS search domains.  For the "auto" method, these search domains
	 * are appended to those returned by automatic configuration. Search domains
	 * cannot be used with the "shared" or "link-local" methods as there is no
	 * upstream network.  In all other methods, these search domains are used as
	 * the only search domains for this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 g_param_spec_boxed (NM_SETTING_IP6_CONFIG_DNS_SEARCH, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:addresses:
	 *
	 * Array of IPv6 addresses.  For the 'auto' method, given IP addresses are
	 * appended to those returned by automatic configuration.  Addresses cannot
	 * be used with the 'shared' or 'link-local' methods as the interface is
	 * automatically assigned an address with these methods.
	 *
	 * Element-Type: NMIPAddress
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 g_param_spec_boxed (NM_SETTING_IP6_CONFIG_ADDRESSES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_IP6_CONFIG_ADDRESSES,
	                                      G_VARIANT_TYPE ("a(ayuay)"),
	                                      ip6_addresses_to_dbus,
	                                      ip6_addresses_from_dbus);

	/**
	 * NMSettingIP6Config:routes:
	 *
	 * Array of IPv6 routes. For the 'auto' method, given IP routes are appended
	 * to those returned by automatic configuration. Routes cannot be used with
	 * the 'shared' or 'link-local' methods because there is no upstream network.
	 *
	 * Element-Type: NMIPRoute
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 g_param_spec_boxed (NM_SETTING_IP6_CONFIG_ROUTES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_IP6_CONFIG_ROUTES,
	                                      G_VARIANT_TYPE ("a(ayuayu)"),
	                                      ip6_routes_to_dbus,
	                                      ip6_routes_from_dbus);

	/**
	 * NMSettingIP6Config:ignore-auto-routes:
	 *
	 * When the method is set to "auto" or "dhcp" and this property is set to
	 * %TRUE, automatically configured routes are ignored and only routes
	 * specified in the #NMSettingIP6Config:routes property, if any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_ROUTES,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:ignore-auto-dns:
	 *
	 * When the method is set to "auto" or "dhcp" and this property is set to
	 * %TRUE, automatically configured nameservers and search domains are
	 * ignored and only nameservers and search domains specified in the
	 * #NMSettingIP6Config:dns and #NMSettingIP6Config:dns-search properties, if
	 * any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_DNS,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:never-default:
	 *
	 * If %TRUE, this connection will never be the default IPv6 connection,
	 * meaning it will never be assigned the default IPv6 route by
	 * NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_NEVER_DEFAULT,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_NEVER_DEFAULT, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:may-fail:
	 *
	 * If %TRUE, allow overall network configuration to proceed even if IPv6
	 * configuration times out.  Note that at least one IP configuration must
	 * succeed or overall network configuration will still fail.  For example,
	 * in IPv4-only networks, setting this property to %TRUE allows the overall
	 * network configuration to succeed if IPv6 configuration fails but IPv4
	 * configuration completes successfully.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAY_FAIL,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_MAY_FAIL, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:ip6-privacy:
	 *
	 * Configure IPv6 Privacy Extensions for SLAAC, described in RFC4941.  If
	 * enabled, it makes the kernel generate a temporary IPv6 address in
	 * addition to the public one generated from MAC address via modified
	 * EUI-64.  This enhances privacy, but could cause problems in some
	 * applications, on the other hand.  The permitted values are: 0: disabled,
	 * 1: enabled (prefer public address), 2: enabled (prefer temporary
	 * addresses).
	 **/
	g_object_class_install_property
		(object_class, PROP_IP6_PRIVACY,
		 g_param_spec_enum (NM_SETTING_IP6_CONFIG_IP6_PRIVACY, "", "",
		                    NM_TYPE_SETTING_IP6_CONFIG_PRIVACY,
		                    NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));
}
