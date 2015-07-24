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

#include "config.h"

#include <string.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n-lib.h>

#include "nm-glib.h"
#include "nm-setting-ip6-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ip6-config
 * @short_description: Describes IPv6 addressing, routing, and name service properties
 * @include: nm-setting-ip6-config.h
 *
 * The #NMSettingIP6Config object is a #NMSetting subclass that describes
 * properties related to IPv6 addressing, routing, and Domain Name Service
 **/

/**
 * nm_setting_ip6_config_error_quark:
 *
 * Registers an error quark for #NMSettingIP6Config if necessary.
 *
 * Returns: the error quark used for #NMSettingIP6Config errors.
 **/
GQuark
nm_setting_ip6_config_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ip6-config-error-quark");
	return quark;
}

G_DEFINE_BOXED_TYPE (NMIP6Address, nm_ip6_address, nm_ip6_address_dup, nm_ip6_address_unref)
G_DEFINE_BOXED_TYPE (NMIP6Route, nm_ip6_route, nm_ip6_route_dup, nm_ip6_route_unref)

G_DEFINE_TYPE_WITH_CODE (NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                               g_define_type_id,
                                               4,
                                               NM_SETTING_IP6_CONFIG_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_IP6_CONFIG)

#define NM_SETTING_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigPrivate))

typedef struct {
	char *method;
	char *dhcp_hostname;
	GSList *dns;        /* array of struct in6_addr */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMIP6Address */
	GSList *routes;     /* array of NMIP6Route */
	gint64  route_metric;
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
	PROP_ROUTE_METRIC,
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
 *
 * Since: 0.9.8
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
const struct in6_addr *
nm_setting_ip6_config_get_dns (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;


	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->dns), NULL);

	return (const struct in6_addr *) g_slist_nth_data (priv->dns, i);
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
nm_setting_ip6_config_add_dns (NMSettingIP6Config *setting, const struct in6_addr *addr)
{
	NMSettingIP6ConfigPrivate *priv;
	struct in6_addr *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!memcmp (addr, (struct in6_addr *) iter->data, sizeof (struct in6_addr)))
			return FALSE;
	}

	copy = g_malloc0 (sizeof (struct in6_addr));
	memcpy (copy, addr, sizeof (struct in6_addr));
	priv->dns = g_slist_append (priv->dns, copy);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_ip6_config_remove_dns_by_value (NMSettingIP6Config *setting,
                                           const struct in6_addr *addr)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!memcmp (addr, (struct in6_addr *) iter->data, sizeof (struct in6_addr))) {
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
	g_return_val_if_fail (i <= g_slist_length (priv->dns_search), NULL);

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
 *
 * Since 0.9.10
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
NMIP6Address *
nm_setting_ip6_config_get_address (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->addresses), NULL);

	return (NMIP6Address *) g_slist_nth_data (priv->addresses, i);
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
                                   NMIP6Address *address)
{
	NMSettingIP6ConfigPrivate *priv;
	NMIP6Address *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip6_address_compare ((NMIP6Address *) iter->data, address))
			return FALSE;
	}

	copy = nm_ip6_address_dup (address);
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

	nm_ip6_address_unref ((NMIP6Address *) elt->data);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_ip6_config_remove_address_by_value (NMSettingIP6Config *setting,
                                               NMIP6Address *address)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip6_address_compare ((NMIP6Address *) iter->data, address)) {
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

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip6_address_unref);
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
NMIP6Route *
nm_setting_ip6_config_get_route (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->routes), NULL);

	return (NMIP6Route *) g_slist_nth_data (priv->routes, i);
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
                                 NMIP6Route *route)
{
	NMSettingIP6ConfigPrivate *priv;
	NMIP6Route *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip6_route_compare ((NMIP6Route *) iter->data, route))
			return FALSE;
	}

	copy = nm_ip6_route_dup (route);
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

	nm_ip6_route_unref ((NMIP6Route *) elt->data);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_ip6_config_remove_route_by_value (NMSettingIP6Config *setting,
                                             NMIP6Route *route)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip6_route_compare ((NMIP6Route *) iter->data, route)) {
			nm_ip6_route_unref ((NMIP6Route *) iter->data);
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

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	priv->routes = NULL;
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP6_CONFIG_ROUTES);
}

/**
 * nm_setting_ip6_config_get_route_metric:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:route-metric
 * property.
 *
 * Returns: the route metric that is used for IPv6 routes that don't explicitly
 * specify a metric. See #NMSettingIP6Config:route-metric for more details.
 *
 * Since: 1.0
 **/
gint64
nm_setting_ip6_config_get_route_metric (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), -1);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->route_metric;
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
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	GSList *iter;
	int i;

	if (!priv->method) {
		g_set_error_literal (error,
		                     NM_SETTING_IP6_CONFIG_ERROR,
		                     NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (!priv->addresses) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
			             _("this property cannot be empty for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		if (g_slist_length (priv->dns)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             _("'%s' not allowed for %s=%s"),
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DNS);
			return FALSE;
		}

		if (g_slist_length (priv->dns_search)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP6_CONFIG_METHOD, priv->method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		if (g_slist_length (priv->addresses)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
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
		                     NM_SETTING_IP6_CONFIG_ERROR,
		                     NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_hostname && !strlen (priv->dhcp_hostname)) {
		g_set_error_literal (error,
		                     NM_SETTING_IP6_CONFIG_ERROR,
		                     NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	/* Validate addresses */
	for (iter = priv->addresses, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMIP6Address *addr = (NMIP6Address *) iter->data;
		guint32 prefix = nm_ip6_address_get_prefix (addr);

		if (IN6_IS_ADDR_UNSPECIFIED (nm_ip6_address_get_address (addr))) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
			             _("%d. IPv6 address is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}

		if (!prefix || prefix > 128) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
			             _("%d. IPv6 address has invalid prefix"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	}

	/* Validate routes */
	for (iter = priv->routes, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMIP6Route *route = (NMIP6Route *) iter->data;
		guint32 prefix = nm_ip6_route_get_prefix (route);

		if (!prefix || prefix > 128) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
			             _("%d. route has invalid prefix"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ROUTES);
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
	g_slist_free_full (priv->addresses, g_free);
	g_slist_free_full (priv->routes, g_free);

	G_OBJECT_CLASS (nm_setting_ip6_config_parent_class)->finalize (object);
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
		priv->dns = nm_utils_ip6_dns_from_gvalue (value);
		break;
	case PROP_DNS_SEARCH:
		g_slist_free_full (priv->dns_search, g_free);
		priv->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		g_slist_free_full (priv->addresses, g_free);
		priv->addresses = nm_utils_ip6_addresses_from_gvalue (value);
		break;
	case PROP_ROUTES:
		g_slist_free_full (priv->routes, g_free);
		priv->routes = nm_utils_ip6_routes_from_gvalue (value);
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
		priv->ip6_privacy = g_value_get_int (value);
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
		nm_utils_ip6_dns_to_gvalue (priv->dns, value);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, priv->dns_search);
		break;
	case PROP_ADDRESSES:
		nm_utils_ip6_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip6_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_ROUTE_METRIC:
		g_value_set_int64 (value, priv->route_metric);
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
		g_value_set_int (value, priv->ip6_privacy);
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
	parent_class->verify       = verify;

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
	 *
	 * Since: 0.9.8
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
	 * Array of DNS servers, where each member of the array is a byte array
	 * containing the IPv6 address of the DNS server (in network byte order).
	 * For the "auto" method, these DNS servers are appended to those (if any)
	 * returned by automatic configuration.  DNS servers cannot be used with the
	 * "shared" or "link-local" methods as there is no usptream network. In all
	 * other methods, these DNS servers are used as the only DNS servers for
	 * this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_DNS, "", "",
		                             DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

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
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_DNS_SEARCH, "", "",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:addresses:
	 *
	 * Array of IPv6 address structures.  Each IPv6 address structure is
	 * composed of 3 members, the first being a byte array containing the IPv6
	 * address (network byte order), the second a 32-bit integer containing the
	 * IPv6 address prefix, and the third a byte array containing the IPv6
	 * address (network byte order) of the gateway associated with this address,
	 * if any.  If no gateway is given, the third element should be given as all
	 * zeros.  For the "auto" method, given IP addresses are appended to those
	 * returned by automatic configuration.  Addresses cannot be used with the
	 * "shared" or "link-local" methods as the interface is automatically
	 * assigned an address with these methods.
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_ADDRESSES, "", "",
		                             DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_INFERRABLE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:routes:
	 *
	 * Array of IPv6 route structures.  Each IPv6 route structure is composed of
	 * 4 members; the first being the destination IPv6 network or address
	 * (network byte order) as a byte array, the second the destination network
	 * or address IPv6 prefix, the third being the next-hop IPv6 address
	 * (network byte order) if any, and the fourth being the route metric. For
	 * the "auto" method, given IP routes are appended to those returned by
	 * automatic configuration.  Routes cannot be used with the "shared" or
	 * "link-local" methods because there is no upstream network.
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_ROUTES, "", "",
		                             DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_INFERRABLE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIP6Config:route-metric:
	 *
	 * The default metric for routes that don't explicitly specify a metric.
	 * The default value -1 means that the metric is choosen automatically
	 * based on the device type.
	 * The metric applies to dynamic routes, manual (static) routes that
	 * don't have an explicit metric setting, address prefix routes, and
	 * the default route.
	 * As the linux kernel replaces zero (0) by 1024 (user-default), setting
	 * this property to 0 means effectively setting it to 1024.
	 *
	 * Since: 1.0
	 **/
	g_object_class_install_property
	    (object_class, PROP_ROUTE_METRIC,
	     g_param_spec_int64 (NM_SETTING_IP6_CONFIG_ROUTE_METRIC, "", "",
	                         -1, G_MAXUINT32, -1,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         G_PARAM_STATIC_STRINGS));

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
		 g_param_spec_int (NM_SETTING_IP6_CONFIG_IP6_PRIVACY, "", "",
		                   NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
		                   NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
		                   NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT |
		                   G_PARAM_STATIC_STRINGS));
}

/********************************************************************/

struct NMIP6Address {
	guint32 refcount;
	struct in6_addr address;
	guint32 prefix;
	struct in6_addr gateway;
};

/**
 * nm_ip6_address_new:
 *
 * Creates and returns a new #NMIP6Address object.
 *
 * Returns: (transfer full): the new empty #NMIP6Address object
 **/
NMIP6Address *
nm_ip6_address_new (void)
{
	NMIP6Address *address;

	address = g_malloc0 (sizeof (NMIP6Address));
	address->refcount = 1;
	return address;
}

/**
 * nm_ip6_address_dup:
 * @source: the #NMIP6Address object to copy
 *
 * Copies a given #NMIP6Address object and returns the copy.
 *
 * Returns: (transfer full): the copy of the given #NMIP6Address copy
 **/
NMIP6Address *
nm_ip6_address_dup (NMIP6Address *source)
{
	NMIP6Address *address;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	address = nm_ip6_address_new ();
	address->prefix = source->prefix;
	memcpy (&address->address, &source->address, sizeof (struct in6_addr));
	memcpy (&address->gateway, &source->gateway, sizeof (struct in6_addr));

	return address;
}

/**
 * nm_ip6_address_ref:
 * @address: the #NMIP6Address
 *
 * Increases the reference count of the object.
 **/
void
nm_ip6_address_ref (NMIP6Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount++;
}

/**
 * nm_ip6_address_unref:
 * @address: the #NMIP6Address
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 **/
void
nm_ip6_address_unref (NMIP6Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount--;
	if (address->refcount == 0) {
		memset (address, 0, sizeof (NMIP6Address));
		g_free (address);
	}
}

/**
 * nm_ip6_address_compare:
 * @address: the #NMIP6Address
 * @other: the #NMIP6Address to compare @address to.
 *
 * Determines if two #NMIP6Address objects contain the same values.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
gboolean
nm_ip6_address_compare (NMIP6Address *address, NMIP6Address *other)
{
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   memcmp (&address->address, &other->address, sizeof (struct in6_addr))
	    || address->prefix != other->prefix
	    || memcmp (&address->gateway, &other->gateway, sizeof (struct in6_addr)))
		return FALSE;
	return TRUE;
}

/**
 * nm_ip6_address_get_address:
 * @address: the #NMIP6Address
 *
 * Gets the IPv6 address property of this address object.
 *
 * Returns: (array fixed-size=16) (element-type guint8) (transfer none):
 *          the IPv6 address
 **/
const struct in6_addr *
nm_ip6_address_get_address (NMIP6Address *address)
{
	g_return_val_if_fail (address != NULL, NULL);
	g_return_val_if_fail (address->refcount > 0, NULL);

	return &address->address;
}

/**
 * nm_ip6_address_set_address:
 * @address: the #NMIP6Address
 * @addr: the IPv6 address
 *
 * Sets the IPv6 address property of this object.
 **/
void
nm_ip6_address_set_address (NMIP6Address *address, const struct in6_addr *addr)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);
	g_return_if_fail (addr != NULL);

	memcpy (&address->address, addr, sizeof (struct in6_addr));
}

/**
 * nm_ip6_address_get_prefix:
 * @address: the #NMIP6Address
 *
 * Gets the IPv6 address prefix property of this address object.
 *
 * Returns: the IPv6 address prefix
 **/
guint32
nm_ip6_address_get_prefix (NMIP6Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->prefix;
}

/**
 * nm_ip6_address_set_prefix:
 * @address: the #NMIP6Address
 * @prefix: the address prefix, a number between 0 and 128 inclusive
 *
 * Sets the IPv6 address prefix.
 **/
void
nm_ip6_address_set_prefix (NMIP6Address *address, guint32 prefix)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);
	g_return_if_fail (prefix <= 128);
	g_return_if_fail (prefix > 0);

	address->prefix = prefix;
}

/**
 * nm_ip6_address_get_gateway:
 * @address: the #NMIP6Address
 *
 * Gets the IPv6 default gateway property of this address object.
 *
 * Returns: (array fixed-size=16) (element-type guint8) (transfer none):
 *          the IPv6 gateway address
 **/
const struct in6_addr *
nm_ip6_address_get_gateway (NMIP6Address *address)
{
	g_return_val_if_fail (address != NULL, NULL);
	g_return_val_if_fail (address->refcount > 0, NULL);

	return &address->gateway;
}

/**
 * nm_ip6_address_set_gateway:
 * @address: the #NMIP6Address
 * @gateway: the IPv6 default gateway
 *
 * Sets the IPv6 default gateway property of this address object.
 **/
void
nm_ip6_address_set_gateway (NMIP6Address *address, const struct in6_addr *gateway)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);
	g_return_if_fail (gateway != NULL);

	memcpy (&address->gateway, gateway, sizeof (struct in6_addr));
}

/********************************************************************/

struct NMIP6Route {
	guint32 refcount;

	struct in6_addr dest;
	guint32 prefix;
	struct in6_addr next_hop;
	guint32 metric;    /* lower metric == more preferred */
};

/**
 * nm_ip6_route_new:
 *
 * Creates and returns a new #NMIP6Route object.
 *
 * Returns: (transfer full): the new empty #NMIP6Route object
 **/
NMIP6Route *
nm_ip6_route_new (void)
{
	NMIP6Route *route;

	route = g_malloc0 (sizeof (NMIP6Route));
	route->refcount = 1;
	return route;
}

/**
 * nm_ip6_route_dup:
 * @source: the #NMIP6Route object to copy
 *
 * Copies a given #NMIP6Route object and returns the copy.
 *
 * Returns: (transfer full): the copy of the given #NMIP6Route copy
 **/
NMIP6Route *
nm_ip6_route_dup (NMIP6Route *source)
{
	NMIP6Route *route;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	route = nm_ip6_route_new ();
	route->prefix = source->prefix;
	route->metric = source->metric;
	memcpy (&route->dest, &source->dest, sizeof (struct in6_addr));
	memcpy (&route->next_hop, &source->next_hop, sizeof (struct in6_addr));

	return route;
}

/**
 * nm_ip6_route_ref:
 * @route: the #NMIP6Route
 *
 * Increases the reference count of the object.
 **/
void
nm_ip6_route_ref (NMIP6Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount++;
}

/**
 * nm_ip6_route_unref:
 * @route: the #NMIP6Route
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 **/
void
nm_ip6_route_unref (NMIP6Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount--;
	if (route->refcount == 0) {
		memset (route, 0, sizeof (NMIP6Route));
		g_free (route);
	}
}

/**
 * nm_ip6_route_compare:
 * @route: the #NMIP6Route
 * @other: the #NMIP6Route to compare @route to.
 *
 * Determines if two #NMIP6Route objects contain the same values.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
gboolean
nm_ip6_route_compare (NMIP6Route *route, NMIP6Route *other)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   memcmp (&route->dest, &other->dest, sizeof (struct in6_addr))
	    || route->prefix != other->prefix
	    || memcmp (&route->next_hop, &other->next_hop, sizeof (struct in6_addr))
	    || route->metric != other->metric)
		return FALSE;
	return TRUE;
}

/**
 * nm_ip6_route_get_dest:
 * @route: the #NMIP6Route
 *
 * Gets the IPv6 destination address property of this route object.
 *
 * Returns: (array fixed-size=16) (element-type guint8) (transfer none):
 *          the IPv6 address of destination
 **/
const struct in6_addr *
nm_ip6_route_get_dest (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, NULL);
	g_return_val_if_fail (route->refcount > 0, NULL);

	return &route->dest;
}

/**
 * nm_ip6_route_set_dest:
 * @route: the #NMIP6Route
 * @dest: the destination address
 *
 * Sets the IPv6 destination address property of this route object.
 **/
void
nm_ip6_route_set_dest (NMIP6Route *route, const struct in6_addr *dest)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);
	g_return_if_fail (dest != NULL);

	memcpy (&route->dest, dest, sizeof (struct in6_addr));
}

/**
 * nm_ip6_route_get_prefix:
 * @route: the #NMIP6Route
 *
 * Gets the IPv6 prefix (ie "32" or "64" etc) of this route.
 *
 * Returns: the IPv6 prefix
 **/
guint32
nm_ip6_route_get_prefix (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->prefix;
}

/**
 * nm_ip6_route_set_prefix:
 * @route: the #NMIP6Route
 * @prefix: the prefix, a number between 1 and 128 inclusive
 *
 * Sets the IPv6 prefix of this route.
 **/
void
nm_ip6_route_set_prefix (NMIP6Route *route, guint32 prefix)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);
	g_return_if_fail (prefix <= 128);
	g_return_if_fail (prefix > 0);

	route->prefix = prefix;
}

/**
 * nm_ip6_route_get_next_hop:
 * @route: the #NMIP6Route
 *
 * Gets the IPv6 address of the next hop of this route.
 *
 * Returns: (array fixed-size=16) (element-type guint8) (transfer none):
 *          the IPv6 address of next hop
 **/
const struct in6_addr *
nm_ip6_route_get_next_hop (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, NULL);
	g_return_val_if_fail (route->refcount > 0, NULL);

	return &route->next_hop;
}

/**
 * nm_ip6_route_set_next_hop:
 * @route: the #NMIP6Route
 * @next_hop: the IPv6 address of the next hop
 *
 * Sets the IPv6 address of the next hop of this route.
 **/
void
nm_ip6_route_set_next_hop (NMIP6Route *route, const struct in6_addr *next_hop)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);
	g_return_if_fail (next_hop != NULL);

	memcpy (&route->next_hop, next_hop, sizeof (struct in6_addr));
}

/**
 * nm_ip6_route_get_metric:
 * @route: the #NMIP6Route
 *
 * Gets the route metric property of this route object; lower values indicate
 * "better" or more preferred routes.
 *
 * Returns: the route metric
 **/
guint32
nm_ip6_route_get_metric (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->metric;
}

/**
 * nm_ip6_route_set_metric:
 * @route: the #NMIP6Route
 * @metric: the route metric
 *
 * Sets the route metric property of this route object; lower values indicate
 * "better" or more preferred routes.
 **/
void
nm_ip6_route_set_metric (NMIP6Route *route, guint32 metric)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->metric = metric;
}
