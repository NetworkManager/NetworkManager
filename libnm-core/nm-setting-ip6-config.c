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

#include "nm-setting-ip6-config.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

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

G_DEFINE_TYPE_WITH_CODE (NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING_IP_CONFIG,
                         _nm_register_setting (IP6_CONFIG, 4))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_IP6_CONFIG)

#define NM_SETTING_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigPrivate))

typedef struct {
	NMSettingIP6ConfigPrivacy ip6_privacy;
} NMSettingIP6ConfigPrivate;


enum {
	PROP_0,
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
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	NMSettingVerifyResult ret;
	const char *method;

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

	return TRUE;
}


static void
nm_setting_ip6_config_init (NMSettingIP6Config *setting)
{
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

static void
ip6_addresses_set (NMSetting  *setting,
                   GVariant   *connection_dict,
                   const char *property,
                   GVariant   *value)
{
	GPtrArray *addrs;
	char *gateway = NULL;

	if (!_nm_setting_use_legacy_property (setting, connection_dict, "addresses", "address-data"))
		return;

	addrs = nm_utils_ip6_addresses_from_variant (value, &gateway);

	g_object_set (setting,
	              NM_SETTING_IP_CONFIG_ADDRESSES, addrs,
	              NM_SETTING_IP_CONFIG_GATEWAY, gateway,
	              NULL);
	g_ptr_array_unref (addrs);
	g_free (gateway);
}

static GVariant *
ip6_address_data_get (NMSetting    *setting,
                      NMConnection *connection,
                      const char   *property)
{
	GPtrArray *addrs;
	GVariant *ret;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
	ret = nm_utils_ip_addresses_to_variant (addrs);
	g_ptr_array_unref (addrs);

	return ret;
}

static void
ip6_address_data_set (NMSetting  *setting,
                      GVariant   *connection_dict,
                      const char *property,
                      GVariant   *value)
{
	GPtrArray *addrs;

	/* Ignore 'address-data' if we're going to process 'addresses' */
	if (_nm_setting_use_legacy_property (setting, connection_dict, "addresses", "address-data"))
		return;

	addrs = nm_utils_ip_addresses_from_variant (value, AF_INET6);
	g_object_set (setting, NM_SETTING_IP_CONFIG_ADDRESSES, addrs, NULL);
	g_ptr_array_unref (addrs);
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

static void
ip6_routes_set (NMSetting  *setting,
                GVariant   *connection_dict,
                const char *property,
                GVariant   *value)
{
	GPtrArray *routes;

	if (!_nm_setting_use_legacy_property (setting, connection_dict, "routes", "route-data"))
		return;

	routes = nm_utils_ip6_routes_from_variant (value);
	g_object_set (setting, property, routes, NULL);
	g_ptr_array_unref (routes);
}

static GVariant *
ip6_route_data_get (NMSetting    *setting,
                    NMConnection *connection,
                    const char   *property)
{
	GPtrArray *routes;
	GVariant *ret;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
	ret = nm_utils_ip_routes_to_variant (routes);
	g_ptr_array_unref (routes);

	return ret;
}

static void
ip6_route_data_set (NMSetting  *setting,
                    GVariant   *connection_dict,
                    const char *property,
                    GVariant   *value)
{
	GPtrArray *routes;

	/* Ignore 'route-data' if we're going to process 'routes' */
	if (_nm_setting_use_legacy_property (setting, connection_dict, "routes", "route-data"))
		return;

	routes = nm_utils_ip_routes_from_variant (value, AF_INET6);
	g_object_set (setting, NM_SETTING_IP_CONFIG_ROUTES, routes, NULL);
	g_ptr_array_unref (routes);
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
	case PROP_IP6_PRIVACY:
		g_value_set_enum (value, priv->ip6_privacy);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip6_config_class_init (NMSettingIP6ConfigClass *ip6_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ip6_class);
	NMSettingClass *setting_class = NM_SETTING_CLASS (ip6_class);

	g_type_class_add_private (ip6_class, sizeof (NMSettingIP6ConfigPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	setting_class->verify = verify;

	/* Properties */

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
	 * variable: DOMAIN
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
	g_object_class_install_property
		(object_class, PROP_IP6_PRIVACY,
		 g_param_spec_enum (NM_SETTING_IP6_CONFIG_IP6_PRIVACY, "", "",
		                    NM_TYPE_SETTING_IP6_CONFIG_PRIVACY,
		                    NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));

	/* IP6-specific property overrides */

	/* ---dbus---
	 * property: dns
	 * format: array of byte array
	 * description: Array of IP addresses of DNS servers (in network byte order)
	 * ---end---
	 */
	_nm_setting_class_transform_property (setting_class,
	                                      NM_SETTING_IP_CONFIG_DNS,
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
	_nm_setting_class_override_property (setting_class,
	                                     NM_SETTING_IP_CONFIG_ADDRESSES,
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
	_nm_setting_class_add_dbus_only_property (setting_class,
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
	_nm_setting_class_override_property (setting_class,
	                                     NM_SETTING_IP_CONFIG_ROUTES,
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
	_nm_setting_class_add_dbus_only_property (setting_class,
	                                          "route-data",
	                                          G_VARIANT_TYPE ("aa{sv}"),
	                                          ip6_route_data_get,
	                                          ip6_route_data_set);
}
