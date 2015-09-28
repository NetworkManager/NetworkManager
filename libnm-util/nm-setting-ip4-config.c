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

#include "config.h"

#include <string.h>
#include <dbus/dbus-glib.h>

#include "nm-default.h"
#include "nm-setting-ip4-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ip4-config
 * @short_description: Describes IPv4 addressing, routing, and name service properties
 * @include: nm-setting-ip4-config.h
 *
 * The #NMSettingIP4Config object is a #NMSetting subclass that describes
 * properties related to IPv4 addressing, routing, and Domain Name Service
 **/

/**
 * nm_setting_ip4_config_error_quark:
 *
 * Registers an error quark for #NMSettingIP4Config if necessary.
 *
 * Returns: the error quark used for #NMSettingIP4Config errors.
 **/
GQuark
nm_setting_ip4_config_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ip4-config-error-quark");
	return quark;
}

G_DEFINE_BOXED_TYPE (NMIP4Address, nm_ip4_address, nm_ip4_address_dup, nm_ip4_address_unref)
G_DEFINE_BOXED_TYPE (NMIP4Route, nm_ip4_route, nm_ip4_route_dup, nm_ip4_route_unref)

G_DEFINE_TYPE_WITH_CODE (NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                               g_define_type_id,
                                               4,
                                               NM_SETTING_IP4_CONFIG_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_IP4_CONFIG)

#define NM_SETTING_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigPrivate))

typedef struct {
	char *method;
	GArray *dns;        /* array of guint32; elements in network byte order */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMIP4Address */
	GSList *routes;     /* array of NMIP4Route */
	gint64  route_metric;
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	char *dhcp_client_id;
	gboolean dhcp_send_hostname;
	char *dhcp_hostname;
	int dhcp_timeout;
	gboolean never_default;
	gboolean may_fail;
} NMSettingIP4ConfigPrivate;

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_ROUTE_METRIC,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_DHCP_CLIENT_ID,
	PROP_DHCP_TIMEOUT,
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

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns->len;
}

/**
 * nm_setting_ip4_config_get_dns:
 * @setting: the #NMSettingIP4Config
 * @i: index number of the DNS server to return
 *
 * Returns: the IPv4 address (network byte order) of the DNS server at index
 * @i
 **/
guint32
nm_setting_ip4_config_get_dns (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= priv->dns->len, 0);

	return g_array_index (priv->dns, guint32, i);
}

/**
 * nm_setting_ip4_config_add_dns:
 * @setting: the #NMSettingIP4Config
 * @dns: the IPv4 address (network byte order) of the DNS server to add
 *
 * Adds a new DNS server to the setting.
 *
 * Returns: %TRUE if the DNS server was added; %FALSE if the server was already
 * known
 **/
gboolean
nm_setting_ip4_config_add_dns (NMSettingIP4Config *setting, guint32 dns)
{
	NMSettingIP4ConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns->len; i++) {
		if (dns == g_array_index (priv->dns, guint32, i))
			return FALSE;
	}

	g_array_append_val (priv->dns, dns);
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

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (i <= priv->dns->len);

	g_array_remove_index (priv->dns, i);
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
 * domain was already known
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_ip4_config_remove_dns_by_value (NMSettingIP4Config *setting, guint32 dns)
{
	NMSettingIP4ConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns->len; i++) {
		if (dns == g_array_index (priv->dns, guint32, i)) {
			g_array_remove_index (priv->dns, i);
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
	NMSettingIP4ConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_array_remove_range (priv->dns, 0, priv->dns->len);
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
	g_return_val_if_fail (i <= g_slist_length (priv->dns_search), NULL);

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
 *
 * Since 0.9.10
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
NMIP4Address *
nm_setting_ip4_config_get_address (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->addresses), NULL);

	return (NMIP4Address *) g_slist_nth_data (priv->addresses, i);
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
                                   NMIP4Address *address)
{
	NMSettingIP4ConfigPrivate *priv;
	NMIP4Address *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip4_address_compare ((NMIP4Address *) iter->data, address))
			return FALSE;
	}

	copy = nm_ip4_address_dup (address);
	priv->addresses = g_slist_append (priv->addresses, copy);
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
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->addresses, i);
	g_return_if_fail (elt != NULL);

	nm_ip4_address_unref ((NMIP4Address *) elt->data);
	priv->addresses = g_slist_delete_link (priv->addresses, elt);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_ip4_config_remove_address_by_value (NMSettingIP4Config *setting,
                                               NMIP4Address *address)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip4_address_compare ((NMIP4Address *) iter->data, address)) {
			nm_ip4_address_unref ((NMIP4Address *) iter->data);
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

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	priv->addresses = NULL;
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
NMIP4Route *
nm_setting_ip4_config_get_route (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->routes), NULL);

	return (NMIP4Route *) g_slist_nth_data (priv->routes, i);
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
                                 NMIP4Route *route)
{
	NMSettingIP4ConfigPrivate *priv;
	NMIP4Route *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip4_route_compare ((NMIP4Route *) iter->data, route))
			return FALSE;
	}

	copy = nm_ip4_route_dup (route);
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

	nm_ip4_route_unref ((NMIP4Route *) elt->data);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_ip4_config_remove_route_by_value (NMSettingIP4Config *setting,
                                             NMIP4Route *route)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip4_route_compare ((NMIP4Route *) iter->data, route)) {
			nm_ip4_route_unref ((NMIP4Route *) iter->data);
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

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
	priv->routes = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP4_CONFIG_ROUTES);
}

/**
 * nm_setting_ip4_config_get_route_metric:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:route-metric
 * property.
 *
 * Returns: the route metric that is used for IPv4 routes that don't explicitly
 * specify a metric. See #NMSettingIP4Config:route-metric for more details.
 *
 * Since: 1.0
 **/
gint64
nm_setting_ip4_config_get_route_metric (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), -1);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->route_metric;
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
 * nm_setting_ip4_config_get_dhcp_timeout:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:dhcp-timeout
 * property.
 *
 * Returns: The number of seconds after which unfinished DHCP transaction
 * fails or zero for "default".
 **/
int
nm_setting_ip4_config_get_dhcp_timeout (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_timeout;
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
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	GSList *iter;
	int i;

	if (!priv->method) {
		g_set_error_literal (error,
		                     NM_SETTING_IP4_CONFIG_ERROR,
		                     NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (!priv->addresses) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
			             _("this property cannot be empty for '%s=%s'"),
			             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
	           || !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		if (priv->dns && priv->dns->len) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DNS);
			return FALSE;
		}

		if (g_slist_length (priv->dns_search)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP4_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		/* Shared allows IP addresses; link-local and disabled do not */
		if (strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0) {
			if (g_slist_length (priv->addresses)) {
				g_set_error (error,
				             NM_SETTING_IP4_CONFIG_ERROR,
				             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
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
		                     NM_SETTING_IP4_CONFIG_ERROR,
		                     NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_client_id && !strlen (priv->dhcp_client_id)) {
		g_set_error_literal (error,
		                     NM_SETTING_IP4_CONFIG_ERROR,
		                     NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID);
		return FALSE;
	}

	if (priv->dhcp_hostname && !strlen (priv->dhcp_hostname)) {
		g_set_error_literal (error,
		                     NM_SETTING_IP4_CONFIG_ERROR,
		                     NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	/* Validate addresses */
	for (iter = priv->addresses, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMIP4Address *addr = (NMIP4Address *) iter->data;
		guint32 prefix = nm_ip4_address_get_prefix (addr);

		if (!nm_ip4_address_get_address (addr)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             _("%d. IPv4 address is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}

		if (!prefix || prefix > 32) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             _("%d. IPv4 address has invalid prefix"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	}

	/* Validate routes */
	for (iter = priv->routes, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMIP4Route *route = (NMIP4Route *) iter->data;
		guint32 prefix = nm_ip4_route_get_prefix (route);

		if (!prefix || prefix > 32) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             _("%d. route has invalid prefix"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_ROUTES);
			return FALSE;
		}
	}

	return TRUE;
}


static void
nm_setting_ip4_config_init (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);


	priv->dns = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);
}

static void
finalize (GObject *object)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (self);

	g_free (priv->method);
	g_free (priv->dhcp_hostname);
	g_free (priv->dhcp_client_id);

	g_array_free (priv->dns, TRUE);

	g_slist_free_full (priv->dns_search, g_free);
	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);

	G_OBJECT_CLASS (nm_setting_ip4_config_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_METHOD:
		g_free (priv->method);
		priv->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		g_array_free (priv->dns, TRUE);
		priv->dns = g_value_dup_boxed (value);
		if (!priv->dns)
			priv->dns = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);
		break;
	case PROP_DNS_SEARCH:
		g_slist_free_full (priv->dns_search, g_free);
		priv->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
		priv->addresses = nm_utils_ip4_addresses_from_gvalue (value);
		break;
	case PROP_ROUTES:
		g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
		priv->routes = nm_utils_ip4_routes_from_gvalue (value);
		break;
	case PROP_ROUTE_METRIC:
		priv->route_metric = g_value_get_int64 (value);
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
	case PROP_DHCP_TIMEOUT:
		priv->dhcp_timeout = g_value_get_uint (value);
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
		g_value_set_boxed (value, priv->dns);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, priv->dns_search);
		break;
	case PROP_ADDRESSES:
		nm_utils_ip4_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip4_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_ROUTE_METRIC:
		g_value_set_int64 (value, priv->route_metric);
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
	case PROP_DHCP_TIMEOUT:
		g_value_set_uint (value, nm_setting_ip4_config_get_dhcp_timeout (setting));
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
	parent_class->verify       = verify;

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
	 * List of DNS servers (network byte order).  For the "auto" method, these
	 * DNS servers are appended to those (if any) returned by automatic
	 * configuration.  DNS servers cannot be used with the "shared",
	 * "link-local", or "disabled" methods as there is no upstream network.  In
	 * all other methods, these DNS servers are used as the only DNS servers for
	 * this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS, "", "",
		                             DBUS_TYPE_G_UINT_ARRAY,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

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
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS_SEARCH, "", "",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:addresses:
	 *
	 * Array of IPv4 address structures.  Each IPv4 address structure is
	 * composed of 3 32-bit values; the first being the IPv4 address (network
	 * byte order), the second the prefix (1 - 32), and last the IPv4 gateway
	 * (network byte order). The gateway may be left as 0 if no gateway exists
	 * for that subnet.  For the "auto" method, given IP addresses are appended
	 * to those returned by automatic configuration.  Addresses cannot be used
	 * with the "shared", "link-local", or "disabled" methods as addressing is
	 * either automatic or disabled with these methods.
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ADDRESSES, "", "",
		                             DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_INFERRABLE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:routes:
	 *
	 * Array of IPv4 route structures.  Each IPv4 route structure is composed of
	 * 4 32-bit values; the first being the destination IPv4 network or address
	 * (network byte order), the second the destination network or address
	 * prefix (1 - 32), the third being the next-hop (network byte order) if
	 * any, and the fourth being the route metric. For the "auto" method, given
	 * IP routes are appended to those returned by automatic configuration.
	 * Routes cannot be used with the "shared", "link-local", or "disabled"
	 * methods because there is no upstream network.
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ROUTES, "", "",
		                             DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_INFERRABLE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP4Config:route-metric:
	 *
	 * The default metric for routes that don't explicitly specify a metric.
	 * The default value -1 means that the metric is choosen automatically
	 * based on the device type.
	 * The metric applies to dynamic routes, manual (static) routes that
	 * don't have an explicit metric setting, address prefix routes, and
	 * the default route.
	 * As the linux kernel accepts zero (0) as a valid metric, zero is
	 * a valid value.
	 *
	 * Since: 1.0
	 **/
	g_object_class_install_property
	    (object_class, PROP_ROUTE_METRIC,
	     g_param_spec_int64 (NM_SETTING_IP4_CONFIG_ROUTE_METRIC, "", "",
	                         -1, G_MAXUINT32, -1,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         G_PARAM_STATIC_STRINGS));

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
	 * NMSettingIP4Config:dhcp-timeout:
	 *
	 * Number of seconds after which the unfinished DHCP transaction fails
	 * or zero for default.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_TIMEOUT,
		 g_param_spec_uint (NM_SETTING_IP4_CONFIG_DHCP_TIMEOUT, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
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


struct NMIP4Address {
	guint32 refcount;
	guint32 address;   /* network byte order */
	guint32 prefix;
	guint32 gateway;   /* network byte order */
};

/**
 * nm_ip4_address_new:
 *
 * Creates and returns a new #NMIP4Address object.
 *
 * Returns: (transfer full): the new empty #NMIP4Address object
 **/
NMIP4Address *
nm_ip4_address_new (void)
{
	NMIP4Address *address;

	address = g_malloc0 (sizeof (NMIP4Address));
	address->refcount = 1;
	return address;
}

/**
 * nm_ip4_address_dup:
 * @source: the #NMIP4Address object to copy
 *
 * Copies a given #NMIP4Address object and returns the copy.
 *
 * Returns: (transfer full): the copy of the given #NMIP4Address copy
 **/
NMIP4Address *
nm_ip4_address_dup (NMIP4Address *source)
{
	NMIP4Address *address;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	address = nm_ip4_address_new ();
	address->address = source->address;
	address->prefix = source->prefix;
	address->gateway = source->gateway;

	return address;
}

/**
 * nm_ip4_address_ref:
 * @address: the #NMIP4Address
 *
 * Increases the reference count of the object.
 **/
void
nm_ip4_address_ref (NMIP4Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount++;
}

/**
 * nm_ip4_address_unref:
 * @address: the #NMIP4Address
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 **/
void
nm_ip4_address_unref (NMIP4Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount--;
	if (address->refcount == 0) {
		memset (address, 0, sizeof (NMIP4Address));
		g_free (address);
	}
}

/**
 * nm_ip4_address_compare:
 * @address: the #NMIP4Address
 * @other: the #NMIP4Address to compare @address to.
 *
 * Determines if two #NMIP4Address objects contain the same values.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
gboolean
nm_ip4_address_compare (NMIP4Address *address, NMIP4Address *other)
{
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   address->address != other->address
	    || address->prefix != other->prefix
	    || address->gateway != other->gateway)
		return FALSE;
	return TRUE;
}

/**
 * nm_ip4_address_get_address:
 * @address: the #NMIP4Address
 *
 * Gets the IPv4 address property of this address object.
 *
 * Returns: the IPv4 address in network byte order
 **/
guint32
nm_ip4_address_get_address (NMIP4Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->address;
}

/**
 * nm_ip4_address_set_address:
 * @address: the #NMIP4Address
 * @addr: the IPv4 address in network byte order
 *
 * Sets the IPv4 address property of this object.
 **/
void
nm_ip4_address_set_address (NMIP4Address *address, guint32 addr)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->address = addr;
}

/**
 * nm_ip4_address_get_prefix:
 * @address: the #NMIP4Address
 *
 * Gets the IPv4 address prefix (ie "24" or "30" etc) property of this address
 * object.
 *
 * Returns: the IPv4 address prefix
 **/
guint32
nm_ip4_address_get_prefix (NMIP4Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->prefix;
}

/**
 * nm_ip4_address_set_prefix:
 * @address: the #NMIP4Address
 * @prefix: the address prefix, a number between 1 and 32 inclusive
 *
 * Sets the IPv4 address prefix.
 **/
void
nm_ip4_address_set_prefix (NMIP4Address *address, guint32 prefix)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);
	g_return_if_fail (prefix <= 32);
	g_return_if_fail (prefix > 0);

	address->prefix = prefix;
}

/**
 * nm_ip4_address_get_gateway:
 * @address: the #NMIP4Address
 *
 * Gets the IPv4 default gateway property of this address object.
 *
 * Returns: the IPv4 gateway address in network byte order
 **/
guint32
nm_ip4_address_get_gateway (NMIP4Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->gateway;
}

/**
 * nm_ip4_address_set_gateway:
 * @address: the #NMIP4Address
 * @gateway: the IPv4 default gateway in network byte order
 *
 * Sets the IPv4 default gateway property of this address object.
 **/
void
nm_ip4_address_set_gateway (NMIP4Address *address, guint32 gateway)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->gateway = gateway;
}


struct NMIP4Route {
	guint32 refcount;

	guint32 dest;   /* network byte order */
	guint32 prefix;
	guint32 next_hop;   /* network byte order */
	guint32 metric;    /* lower metric == more preferred */
};

/**
 * nm_ip4_route_new:
 *
 * Creates and returns a new #NMIP4Route object.
 *
 * Returns: (transfer full): the new empty #NMIP4Route object
 **/
NMIP4Route *
nm_ip4_route_new (void)
{
	NMIP4Route *route;

	route = g_malloc0 (sizeof (NMIP4Route));
	route->refcount = 1;
	return route;
}

/**
 * nm_ip4_route_dup:
 * @source: the #NMIP4Route object to copy
 *
 * Copies a given #NMIP4Route object and returns the copy.
 *
 * Returns: (transfer full): the copy of the given #NMIP4Route copy
 **/
NMIP4Route *
nm_ip4_route_dup (NMIP4Route *source)
{
	NMIP4Route *route;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	route = nm_ip4_route_new ();
	route->dest = source->dest;
	route->prefix = source->prefix;
	route->next_hop = source->next_hop;
	route->metric = source->metric;

	return route;
}

/**
 * nm_ip4_route_ref:
 * @route: the #NMIP4Route
 *
 * Increases the reference count of the object.
 **/
void
nm_ip4_route_ref (NMIP4Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount++;
}

/**
 * nm_ip4_route_unref:
 * @route: the #NMIP4Route
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 **/
void
nm_ip4_route_unref (NMIP4Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount--;
	if (route->refcount == 0) {
		memset (route, 0, sizeof (NMIP4Route));
		g_free (route);
	}
}

/**
 * nm_ip4_route_compare:
 * @route: the #NMIP4Route
 * @other: the #NMIP4Route to compare @route to.
 *
 * Determines if two #NMIP4Route objects contain the same values.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
gboolean
nm_ip4_route_compare (NMIP4Route *route, NMIP4Route *other)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   route->dest != other->dest
	    || route->prefix != other->prefix
	    || route->next_hop != other->next_hop
	    || route->metric != other->metric)
		return FALSE;
	return TRUE;
}

/**
 * nm_ip4_route_get_dest:
 * @route: the #NMIP4Route
 *
 * Gets the IPv4 destination address property of this route object.
 *
 * Returns: the IPv4 address in network byte order
 **/
guint32
nm_ip4_route_get_dest (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->dest;
}

/**
 * nm_ip4_route_set_dest:
 * @route: the #NMIP4Route
 * @dest: the destination address in network byte order
 *
 * Sets the IPv4 destination address property of this route object.
 **/
void
nm_ip4_route_set_dest (NMIP4Route *route, guint32 dest)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->dest = dest;
}

/**
 * nm_ip4_route_get_prefix:
 * @route: the #NMIP4Route
 *
 * Gets the IPv4 prefix (ie "24" or "30" etc) of this route.
 *
 * Returns: the IPv4 prefix
 **/
guint32
nm_ip4_route_get_prefix (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->prefix;
}

/**
 * nm_ip4_route_set_prefix:
 * @route: the #NMIP4Route
 * @prefix: the prefix, a number between 1 and 32 inclusive
 *
 * Sets the IPv4 prefix of this route.
 **/
void
nm_ip4_route_set_prefix (NMIP4Route *route, guint32 prefix)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);
	g_return_if_fail (prefix <= 32);
	g_return_if_fail (prefix > 0);

	route->prefix = prefix;
}

/**
 * nm_ip4_route_get_next_hop:
 * @route: the #NMIP4Route
 *
 * Gets the IPv4 address of the next hop of this route.
 *
 * Returns: the IPv4 address in network byte order
 **/
guint32
nm_ip4_route_get_next_hop (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->next_hop;
}

/**
 * nm_ip4_route_set_next_hop:
 * @route: the #NMIP4Route
 * @next_hop: the IPv4 address of the next hop in network byte order
 *
 * Sets the IPv4 address of the next hop of this route.
 **/
void
nm_ip4_route_set_next_hop (NMIP4Route *route, guint32 next_hop)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->next_hop = next_hop;
}

/**
 * nm_ip4_route_get_metric:
 * @route: the #NMIP4Route
 *
 * Gets the route metric property of this route object; lower values indicate
 * "better" or more preferred routes.
 *
 * Returns: the route metric
 **/
guint32
nm_ip4_route_get_metric (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->metric;
}

/**
 * nm_ip4_route_set_metric:
 * @route: the #NMIP4Route
 * @metric: the route metric
 *
 * Sets the route metric property of this route object; lower values indicate
 * "better" or more preferred routes.
 **/
void
nm_ip4_route_set_metric (NMIP4Route *route, guint32 metric)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->metric = metric;
}
