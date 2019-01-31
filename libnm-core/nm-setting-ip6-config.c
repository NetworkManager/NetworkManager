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

#include "nm-default.h"

#include "nm-setting-ip6-config.h"

#include <arpa/inet.h>

#include "nm-setting-private.h"
#include "nm-core-enum-types.h"
#include "nm-core-internal.h"

/**
 * SECTION:nm-setting-ip6-config
 * @short_description: Describes IPv6 addressing, routing, and name service properties
 *
 * The #NMSettingIP6Config object is a #NMSetting subclass that describes
 * properties related to IPv6 addressing, routing, and Domain Name Service
 *
 * #NMSettingIP6Config has few properties or methods of its own; it inherits
 * almost everything from #NMSettingIPConfig.
 *
 * NetworkManager supports 6 values for the #NMSettingIPConfig:method property
 * for IPv6.  If "auto" is specified then the appropriate automatic method (PPP,
 * router advertisement, etc) is used for the device and most other properties
 * can be left unset.  To force the use of DHCP only, specify "dhcp"; this
 * method is only valid for Ethernet- based hardware.  If "link-local" is
 * specified, then an IPv6 link-local address will be assigned to the interface.
 * If "manual" is specified, static IP addressing is used and at least one IP
 * address must be given in the "addresses" property.  If "ignore" is specified,
 * IPv6 configuration is not done. Note: the "shared" method is not yet
 * supported.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_IP6_PRIVACY,
	PROP_ADDR_GEN_MODE,
	PROP_TOKEN,
	PROP_DHCP_DUID,
);

typedef struct {
	NMSettingIP6ConfigPrivacy ip6_privacy;
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;
	char *token;
	char *dhcp_duid;
} NMSettingIP6ConfigPrivate;

G_DEFINE_TYPE (NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING_IP_CONFIG)

#define NM_SETTING_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigPrivate))

/*****************************************************************************/

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

/**
 * nm_setting_ip6_config_get_addr_gen_mode:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:addr-gen-mode
 * property.
 *
 * Returns: IPv6 Address Generation Mode.
 *
 * Since: 1.2
 **/
NMSettingIP6ConfigAddrGenMode
nm_setting_ip6_config_get_addr_gen_mode (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting),
	                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->addr_gen_mode;
}

/**
 * nm_setting_ip6_config_get_token:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:token
 * property.
 *
 * Returns: A string.
 *
 * Since: 1.4
 **/
const char *
nm_setting_ip6_config_get_token (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->token;
}

/**
 * nm_setting_ip6_config_get_dhcp_duid:
 * @setting: the #NMSettingIP6Config
 *
 * Returns the value contained in the #NMSettingIP6Config:dhcp-duid
 * property.
 *
 * Returns: The configured DUID value to be included in the DHCPv6 requests
 * sent to the DHCPv6 servers.
 *
 * Since: 1.12
 **/
const char *
nm_setting_ip6_config_get_dhcp_duid (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dhcp_duid;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	NMSettingVerifyResult ret;
	const char *method;
	gboolean token_needs_normalization = FALSE;

	ret = NM_SETTING_CLASS (nm_setting_ip6_config_parent_class)->verify (setting, connection, error);
	if (ret != NM_SETTING_VERIFY_SUCCESS)
		return ret;

	method = nm_setting_ip_config_get_method (s_ip);
	/* Base class already checked that it exists */
	g_assert (method);

	if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (nm_setting_ip_config_get_num_addresses (s_ip) == 0) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("this property cannot be empty for '%s=%s'"),
			             NM_SETTING_IP_CONFIG_METHOD, method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)
	           || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {

		/* Shared allows IP addresses and DNS; link-local and disabled do not */
		if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_SHARED) != 0) {
			if (nm_setting_ip_config_get_num_dns (s_ip) > 0) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("this property is not allowed for '%s=%s'"),
				             NM_SETTING_IP_CONFIG_METHOD, method);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_DNS);
				return FALSE;
			}

			if (nm_setting_ip_config_get_num_dns_searches (s_ip) > 0) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("this property is not allowed for '%s=%s'"),
				             NM_SETTING_IP_CONFIG_METHOD, method);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_DNS_SEARCH);
				return FALSE;
			}

			if (nm_setting_ip_config_get_num_addresses (s_ip) > 0) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("this property is not allowed for '%s=%s'"),
				             NM_SETTING_IP_CONFIG_METHOD, method);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_ADDRESSES);
				return FALSE;
			}
		}
	} else if (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
	           || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		/* nothing to do */
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_METHOD);
		return FALSE;
	}

	if (!NM_IN_SET (priv->addr_gen_mode,
	                NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	                NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                      _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE);
		return FALSE;
	}

	if (priv->token) {
		if (priv->addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64) {
			struct in6_addr i6_token;
			char s_token[NM_UTILS_INET_ADDRSTRLEN];

			if (   inet_pton (AF_INET6, priv->token, &i6_token) != 1
			    || !_nm_utils_inet6_is_token (&i6_token)) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                      _("value is not a valid token"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_TOKEN);
				return FALSE;
			}

			if (g_strcmp0 (priv->token, nm_utils_inet6_ntop (&i6_token, s_token)))
				token_needs_normalization = TRUE;
		} else {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                      _("only makes sense with EUI64 address generation mode"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_TOKEN);
			return FALSE;
		}
	}

	if (priv->dhcp_duid) {
		if (!_nm_utils_dhcp_duid_valid (priv->dhcp_duid, NULL)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid DUID"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_DHCP_DUID);
			return FALSE;
		}
	}

	/* Failures from here on, are NORMALIZABLE_ERROR... */

	if (token_needs_normalization) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("token is not in canonical form"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP6_CONFIG_TOKEN);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	/* Failures from here on are NORMALIZABLE... */

	if (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)
	    && !nm_setting_ip_config_get_may_fail (s_ip)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property should be TRUE when method is set to ignore"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_MAY_FAIL);
		return NM_SETTING_VERIFY_NORMALIZABLE;
	}

	return TRUE;
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
ip6_addresses_get (NMSetting  *setting,
                   const char *property)
{
	GPtrArray *addrs;
	const char *gateway;
	GVariant *ret;

	g_object_get (setting, property, &addrs, NULL);
	gateway = nm_setting_ip_config_get_gateway (NM_SETTING_IP_CONFIG (setting));
	ret = nm_utils_ip6_addresses_to_variant (addrs, gateway);
	g_ptr_array_unref (addrs);

	return ret;
}

static gboolean
ip6_addresses_set (NMSetting  *setting,
                   GVariant   *connection_dict,
                   const char *property,
                   GVariant   *value,
                   NMSettingParseFlags parse_flags,
                   GError    **error)
{
	GPtrArray *addrs;
	char *gateway = NULL;

	/* FIXME: properly handle errors */

	if (!_nm_setting_use_legacy_property (setting, connection_dict, "addresses", "address-data"))
		return TRUE;

	addrs = nm_utils_ip6_addresses_from_variant (value, &gateway);

	g_object_set (setting,
	              NM_SETTING_IP_CONFIG_ADDRESSES, addrs,
	              NM_SETTING_IP_CONFIG_GATEWAY, gateway,
	              NULL);
	g_ptr_array_unref (addrs);
	g_free (gateway);
	return TRUE;
}

static GVariant *
ip6_address_data_get (const NMSettInfoSetting *sett_info,
                      guint property_idx,
                      NMConnection *connection,
                      NMSetting *setting,
                      NMConnectionSerializationFlags flags)
{
	gs_unref_ptrarray GPtrArray *addrs = NULL;

	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
	return nm_utils_ip_addresses_to_variant (addrs);
}

static gboolean
ip6_address_data_set (NMSetting  *setting,
                      GVariant   *connection_dict,
                      const char *property,
                      GVariant   *value,
                      NMSettingParseFlags parse_flags,
                      GError    **error)
{
	GPtrArray *addrs;

	/* FIXME: properly handle errors */

	/* Ignore 'address-data' if we're going to process 'addresses' */
	if (_nm_setting_use_legacy_property (setting, connection_dict, "addresses", "address-data"))
		return TRUE;

	addrs = nm_utils_ip_addresses_from_variant (value, AF_INET6);
	g_object_set (setting, NM_SETTING_IP_CONFIG_ADDRESSES, addrs, NULL);
	g_ptr_array_unref (addrs);
	return TRUE;
}

static GVariant *
ip6_routes_get (NMSetting  *setting,
                const char *property)
{
	GPtrArray *routes;
	GVariant *ret;

	g_object_get (setting, property, &routes, NULL);
	ret = nm_utils_ip6_routes_to_variant (routes);
	g_ptr_array_unref (routes);

	return ret;
}

static gboolean
ip6_routes_set (NMSetting  *setting,
                GVariant   *connection_dict,
                const char *property,
                GVariant   *value,
                NMSettingParseFlags parse_flags,
                GError    **error)
{
	GPtrArray *routes;

	/* FIXME: properly handle errors */

	if (!_nm_setting_use_legacy_property (setting, connection_dict, "routes", "route-data"))
		return TRUE;

	routes = nm_utils_ip6_routes_from_variant (value);
	g_object_set (setting, property, routes, NULL);
	g_ptr_array_unref (routes);
	return TRUE;
}

static GVariant *
ip6_route_data_get (const NMSettInfoSetting *sett_info,
                    guint property_idx,
                    NMConnection *connection,
                    NMSetting *setting,
                    NMConnectionSerializationFlags flags)
{
	gs_unref_ptrarray GPtrArray *routes = NULL;

	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
	return nm_utils_ip_routes_to_variant (routes);
}

static gboolean
ip6_route_data_set (NMSetting  *setting,
                    GVariant   *connection_dict,
                    const char *property,
                    GVariant   *value,
                    NMSettingParseFlags parse_flags,
                    GError    **error)
{
	GPtrArray *routes;

	/* FIXME: properly handle errors */

	/* Ignore 'route-data' if we're going to process 'routes' */
	if (_nm_setting_use_legacy_property (setting, connection_dict, "routes", "route-data"))
		return TRUE;

	routes = nm_utils_ip_routes_from_variant (value, AF_INET6);
	g_object_set (setting, NM_SETTING_IP_CONFIG_ROUTES, routes, NULL);
	g_ptr_array_unref (routes);
	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IP6_PRIVACY:
		g_value_set_enum (value, priv->ip6_privacy);
		break;
	case PROP_ADDR_GEN_MODE:
		g_value_set_int (value, priv->addr_gen_mode);
		break;
	case PROP_TOKEN:
		g_value_set_string (value, priv->token);
		break;
	case PROP_DHCP_DUID:
		g_value_set_string (value, priv->dhcp_duid);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IP6_PRIVACY:
		priv->ip6_privacy = g_value_get_enum (value);
		break;
	case PROP_ADDR_GEN_MODE:
		priv->addr_gen_mode = g_value_get_int (value);
		break;
	case PROP_TOKEN:
		g_free (priv->token);
		priv->token = g_value_dup_string (value);
		break;
	case PROP_DHCP_DUID:
		g_free (priv->dhcp_duid);
		priv->dhcp_duid = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ip6_config_init (NMSettingIP6Config *setting)
{
}

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

static void
finalize (GObject *object)
{
	NMSettingIP6Config *self = NM_SETTING_IP6_CONFIG (object);
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (self);

	g_free (priv->token);
	g_free (priv->dhcp_duid);

	G_OBJECT_CLASS (nm_setting_ip6_config_parent_class)->finalize (object);
}

static void
nm_setting_ip6_config_class_init (NMSettingIP6ConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array_ip_config ();

	g_type_class_add_private (klass, sizeof (NMSettingIP6ConfigPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/* ---ifcfg-rh---
	 * property: method
	 * variable: IPV6INIT, IPV6FORWARDING, IPV6_AUTOCONF, DHCPV6C
	 * default:  IPV6INIT=yes; IPV6FORWARDING=no; IPV6_AUTOCONF=!IPV6FORWARDING, DHCPV6=no
	 * description: Method used for IPv6 protocol configuration.
	 *   ignore ~ IPV6INIT=no; auto ~ IPV6_AUTOCONF=yes; dhcp ~ IPV6_AUTOCONF=no and DHCPV6C=yes
	 * ---end---
	 */

	/* ---keyfile---
	 * property: dns
	 * format: list of DNS IP addresses
	 * description: List of DNS servers.
	 * example: dns=2001:4860:4860::8888;2001:4860:4860::8844;
	 * ---end---
	 * ---ifcfg-rh---
	 * property: dns
	 * variable: DNS1, DNS2, ...
	 * format:   string
	 * description: List of DNS servers. NetworkManager uses the variables both
	 *   for IPv4 and IPv6.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dns-search
	 * variable: IPV6_DOMAIN(+)
	 * format:   string (space-separated domains)
	 * description: List of DNS search domains.
	 * ---end---
	 */

	/* ---keyfile---
	 * property: addresses
	 * variable: address1, address2, ...
	 * format: address/plen
	 * description: List of static IP addresses.
	 * example: address1=abbe::cafe/96 address2=2001::1234
	 * ---end---
	 * ---ifcfg-rh---
	 * property: addresses
	 * variable: IPV6ADDR, IPV6ADDR_SECONDARIES
	 * description: List of static IP addresses.
	 * example: IPV6ADDR=ab12:9876::1
	 *   IPV6ADDR_SECONDARIES="ab12:9876::2 ab12:9876::3"
	 * ---end---
	 */

	/* ---keyfile---
	 * property: gateway
	 * variable: gateway
	 * format: string
	 * description: Gateway IP addresses as a string.
	 * example: gateway=abbe::1
	 * ---end---
	 * ---ifcfg-rh---
	 * property: gateway
	 * variable: IPV6_DEFAULTGW
	 * description: Gateway IP address.
	 * example: IPV6_DEFAULTGW=abbe::1
	 * ---end---
	 */

	/* ---keyfile---
	 * property: routes
	 * variable: route1, route2, ...
	 * format: route/plen[,gateway,metric]
	 * description: List of IP routes.
	 * example: route1=2001:4860:4860::/64,2620:52:0:2219:222:68ff:fe11:5403
	 * ---end---
	 * ---ifcfg-rh---
	 * property: routes
	 * variable: (none)
	 * description: List of static routes. They are not stored in ifcfg-* file,
	 *   but in route6-* file instead in the form of command line for 'ip route add'.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: ignore-auto-routes
	 * variable: IPV6_PEERROUTES(+)
	 * default: yes
	 * description: IPV6_PEERROUTES has the opposite meaning as 'ignore-auto-routes' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: ignore-auto-dns
	 * variable: IPV6_PEERDNS(+)
	 * default: yes
	 * description: IPV6_PEERDNS has the opposite meaning as 'ignore-auto-dns' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dhcp-hostname
	 * variable: DHCP_HOSTNAME
	 * description: Hostname to send the DHCP server.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: never-default
	 * variable: IPV6_DEFROUTE(+), (and IPV6_DEFAULTGW, IPV6_DEFAULTDEV in /etc/sysconfig/network)
	 * default: IPV6_DEFROUTE=yes (when no variable specified)
	 * description: IPV6_DEFROUTE=no tells NetworkManager that this connection
	 *   should not be assigned the default IPv6 route. IPV6_DEFROUTE has the opposite
	 *   meaning as 'never-default' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: may-fail
	 * variable: IPV6_FAILURE_FATAL(+)
	 * default: no
	 * description: IPV6_FAILURE_FATAL has the opposite meaning as 'may-fail' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: route-metric
	 * variable: IPV6_ROUTE_METRIC(+)
	 * default: -1
	 * description: IPV6_ROUTE_METRIC is the default IPv6 metric for routes on this connection.
	 *   If set to -1, a default metric based on the device type is used.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: route-table
	 * variable: IPV6_ROUTE_TABLE(+)
	 * default: 0
	 * description: IPV6_ROUTE_TABLE enables policy-routing and sets the default routing table.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dns-priority
	 * variable: IPV6_DNS_PRIORITY(+)
	 * description: The priority for DNS servers of this connection. Lower values have higher priority.
	 *    If zero, the default value will be used (50 for VPNs, 100 for other connections).
	 *    A negative value prevents DNS from other connections with greater values to be used.
	 * default: 0
	 * example: IPV6_DNS_PRIORITY=20
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dns-options
	 * variable: IPV6_RES_OPTIONS(+)
	 * description: List of DNS options to be added to /etc/resolv.conf
	 * example: IPV6_RES_OPTIONS=ndots:2 timeout:3
	 * ---end---
	 */

	/**
	 * NMSettingIP6Config:ip6-privacy:
	 *
	 * Configure IPv6 Privacy Extensions for SLAAC, described in RFC4941.  If
	 * enabled, it makes the kernel generate a temporary IPv6 address in
	 * addition to the public one generated from MAC address via modified
	 * EUI-64.  This enhances privacy, but could cause problems in some
	 * applications, on the other hand.  The permitted values are: -1: unknown,
	 * 0: disabled, 1: enabled (prefer public address), 2: enabled (prefer temporary
	 * addresses).
	 *
	 * Having a per-connection setting set to "-1" (unknown) means fallback to
	 * global configuration "ipv6.ip6-privacy".
	 *
	 * If also global configuration is unspecified or set to "-1", fallback to read
	 * "/proc/sys/net/ipv6/conf/default/use_tempaddr".
	 *
	 * Note that this setting is distinct from the Stable Privacy addresses
	 * that can be enabled with the "addr-gen-mode" property's "stable-privacy"
	 * setting as another way of avoiding host tracking with IPv6 addresses.
	 **/
	/* ---ifcfg-rh---
	 * property: ip6-privacy
	 * variable: IPV6_PRIVACY, IPV6_PRIVACY_PREFER_PUBLIC_IP(+)
	 * values: IPV6_PRIVACY: no, yes (rfc3041 or rfc4941);
	 *   IPV6_PRIVACY_PREFER_PUBLIC_IP: yes, no
	 * default: no
	 * description: Configure IPv6 Privacy Extensions for SLAAC (RFC4941).
	 * example: IPV6_PRIVACY=rfc3041 IPV6_PRIVACY_PREFER_PUBLIC_IP=yes
	 * ---end---
	 */
	obj_properties[PROP_IP6_PRIVACY] =
	    g_param_spec_enum (NM_SETTING_IP6_CONFIG_IP6_PRIVACY, "", "",
	                       NM_TYPE_SETTING_IP6_CONFIG_PRIVACY,
	                       NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIP6Config:addr-gen-mode:
	 *
	 * Configure method for creating the address for use with RFC4862 IPv6
	 * Stateless Address Autoconfiguration. The permitted values are:
	 * %NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64 or
	 * %NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY.
	 *
	 * If the property is set to EUI64, the addresses will be generated
	 * using the interface tokens derived from hardware address. This makes
	 * the host part of the address to stay constant, making it possible
	 * to track host's presence when it changes networks. The address changes
	 * when the interface hardware is replaced.
	 *
	 * The value of stable-privacy enables use of cryptographically
	 * secure hash of a secret host-specific key along with the connection's
	 * stable-id and the network address as specified by RFC7217.
	 * This makes it impossible to use the address track host's presence,
	 * and makes the address stable when the network interface hardware is
	 * replaced.
	 *
	 * On D-Bus, the absence of an addr-gen-mode setting equals enabling
	 * stable-privacy. For keyfile plugin, the absence of the setting
	 * on disk means EUI64 so that the property doesn't change on upgrade
	 * from older versions.
	 *
	 * Note that this setting is distinct from the Privacy Extensions as
	 * configured by "ip6-privacy" property and it does not affect the
	 * temporary addresses configured with this option.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: addr-gen-mode
	 * variable: IPV6_ADDR_GEN_MODE
	 * values: IPV6_ADDR_GEN_MODE: eui64, stable-privacy
	 * default: eui64
	 * description: Configure IPv6 Stable Privacy addressing for SLAAC (RFC7217).
	 * example: IPV6_ADDR_GEN_MODE=stable-privacy
	 * ---end---
	 */
	obj_properties[PROP_ADDR_GEN_MODE] =
	    g_param_spec_int (NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, "", "",
	                      G_MININT, G_MAXINT,
	                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIP6Config:token:
	 *
	 * Configure the token for draft-chown-6man-tokenised-ipv6-identifiers-02
	 * IPv6 tokenized interface identifiers. Useful with eui64 addr-gen-mode.
	 *
	 * Since: 1.4
	 **/
	/* ---ifcfg-rh---
	 * property: token
	 * variable: IPV6_TOKEN
	 * description: The IPv6 tokenized interface identifier token
	 * example: IPV6_TOKEN=::53
	 * ---end---
	 */
	obj_properties[PROP_TOKEN] =
	    g_param_spec_string (NM_SETTING_IP6_CONFIG_TOKEN, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIP6Config:dhcp-duid:
	 *
	 * A string containing the DHCPv6 Unique Identifier (DUID) used by the dhcp
	 * client to identify itself to DHCPv6 servers (RFC 3315). The DUID is carried
	 * in the Client Identifier option.
	 * If the property is a hex string ('aa:bb:cc') it is interpreted as a binary
	 * DUID and filled as an opaque value in the Client Identifier option.
	 *
	 * The special value "lease" will retrieve the DUID previously used from the
	 * lease file belonging to the connection. If no DUID is found and "dhclient"
	 * is the configured dhcp client, the DUID is searched in the system-wide
	 * dhclient lease file. If still no DUID is found, or another dhcp client is
	 * used, a global and permanent DUID-UUID (RFC 6355) will be generated based
	 * on the machine-id.
	 *
	 * The special values "llt" and "ll" will generate a DUID of type LLT or LL
	 * (see RFC 3315) based on the current MAC address of the device. In order to
	 * try providing a stable DUID-LLT, the time field will contain a constant
	 * timestamp that is used globally (for all profiles) and persisted to disk.
	 *
	 * The special values "stable-llt", "stable-ll" and "stable-uuid" will generate
	 * a DUID of the corresponding type, derived from the connection's stable-id and
	 * a per-host unique key. You may want to include the "${DEVICE}" or "${MAC}" specifier
	 * in the stable-id, in case this profile gets activated on multiple devices.
	 * So, the link-layer address of "stable-ll" and "stable-llt" will be a generated
	 * address derived from the stable id. The DUID-LLT time value in the "stable-llt"
	 * option will be picked among a static timespan of three years (the upper bound
	 * of the interval is the same constant timestamp used in "llt").
	 *
	 * When the property is unset, the global value provided for "ipv6.dhcp-duid" is
	 * used. If no global value is provided, the default "lease" value is assumed.
	 *
	 * Since: 1.12
	 **/
	/* ---ifcfg-rh---
	 * property: dhcp-duid
	 * variable: DHCPV6_DUID(+)
	 * description: A string sent to the DHCPv6 server to identify the local machine.
	 *   Apart from the special values "lease", "stable-llt", "stable-ll", "stable-uuid",
	 *   "llt" and "ll" a binary value in hex format is expected. An hex string where
	 *   each octet is separated by a colon is also accepted.
	 * example: DHCPV6_DUID=LL; DHCPV6_DUID=0301deadbeef0001; DHCPV6_DUID=03:01:de:ad:be:ef:00:01
	 * ---end---
	 */
	obj_properties[PROP_DHCP_DUID] =
	    g_param_spec_string (NM_SETTING_IP6_CONFIG_DHCP_DUID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/* IP6-specific property overrides */

	/* ---dbus---
	 * property: dns
	 * format: array of byte array
	 * description: Array of IP addresses of DNS servers (in network byte order)
	 * ---end---
	 */
	_properties_override_add_transform (properties_override,
	                                    g_object_class_find_property (G_OBJECT_CLASS (setting_class),
	                                                                  NM_SETTING_IP_CONFIG_DNS),
	                                    G_VARIANT_TYPE ("aay"),
	                                    ip6_dns_to_dbus,
	                                    ip6_dns_from_dbus);

	/* ---dbus---
	 * property: addresses
	 * format: array of legacy IPv6 address struct (a(ayuay))
	 * description: Deprecated in favor of the 'address-data' and 'gateway'
	 *   properties, but this can be used for backward-compatibility with older
	 *   daemons. Note that if you send this property the daemon will ignore
	 *   'address-data' and 'gateway'.
	 *
	 *   Array of IPv6 address structures.  Each IPv6 address structure is
	 *   composed of an IPv6 address, a prefix length (1 - 128), and an IPv6
	 *   gateway address. The gateway may be zeroed out if no gateway exists for
	 *   that subnet.
	 * ---end---
	 */
	_properties_override_add_override (properties_override,
	                                   g_object_class_find_property (G_OBJECT_CLASS (setting_class),
	                                                                 NM_SETTING_IP_CONFIG_ADDRESSES),
	                                   G_VARIANT_TYPE ("a(ayuay)"),
	                                   ip6_addresses_get,
	                                   ip6_addresses_set,
	                                   NULL);

	/* ---dbus---
	 * property: address-data
	 * format: array of vardict
	 * description: Array of IPv6 addresses. Each address dictionary contains at
	 *   least 'address' and 'prefix' entries, containing the IP address as a
	 *   string, and the prefix length as a uint32. Additional attributes may
	 *   also exist on some addresses.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    "address-data",
	                                    G_VARIANT_TYPE ("aa{sv}"),
	                                    ip6_address_data_get,
	                                    ip6_address_data_set);

	/* ---dbus---
	 * property: routes
	 * format: array of legacy IPv6 route struct (a(ayuayu))
	 * description: Deprecated in favor of the 'route-data' property, but this
	 *   can be used for backward-compatibility with older daemons. Note that if
	 *   you send this property the daemon will ignore 'route-data'.
	 *
	 *   Array of IPv6 route structures.  Each IPv6 route structure is
	 *   composed of an IPv6 address, a prefix length (1 - 128), an IPv6
	 *   next hop address (which may be zeroed out if there is no next hop),
	 *   and a metric. If the metric is 0, NM will choose an appropriate
	 *   default metric for the device.
	 * ---end---
	 */
	_properties_override_add_override (properties_override,
	                                   g_object_class_find_property (G_OBJECT_CLASS (setting_class),
	                                                                 NM_SETTING_IP_CONFIG_ROUTES),
	                                   G_VARIANT_TYPE ("a(ayuayu)"),
	                                   ip6_routes_get,
	                                   ip6_routes_set,
	                                   NULL);

	/* ---dbus---
	 * property: route-data
	 * format: array of vardict
	 * description: Array of IPv6 routes. Each route dictionary contains at
	 *   least 'dest' and 'prefix' entries, containing the destination IP
	 *   address as a string, and the prefix length as a uint32. Most routes
	 *   will also have a 'next-hop' entry, containing the next hop IP address as
	 *   a string. If the route has a 'metric' entry (containing a uint32), that
	 *   will be used as the metric for the route (otherwise NM will pick a
	 *   default value appropriate to the device). Additional attributes may
	 *   also exist on some routes.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    "route-data",
	                                    G_VARIANT_TYPE ("aa{sv}"),
	                                    ip6_route_data_get,
	                                    ip6_route_data_set);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_IP6_CONFIG,
	                               NULL, properties_override);
}
