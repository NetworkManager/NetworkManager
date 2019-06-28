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
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-ip4-config.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ip4-config
 * @short_description: Describes IPv4 addressing, routing, and name service properties
 *
 * The #NMSettingIP4Config object is a #NMSetting subclass that describes
 * properties related to IPv4 addressing, routing, and Domain Name Service.
 *
 * #NMSettingIP4Config has few properties or methods of its own; it inherits
 * almost everything from #NMSettingIPConfig.
 *
 * NetworkManager supports 5 values for the #NMSettingIPConfig:method property
 * for IPv4.  If "auto" is specified then the appropriate automatic method
 * (DHCP, PPP, etc) is used for the interface and most other properties can be
 * left unset.  If "link-local" is specified, then a link-local address in the
 * 169.254/16 range will be assigned to the interface.  If "manual" is
 * specified, static IP addressing is used and at least one IP address must be
 * given in the "addresses" property.  If "shared" is specified (indicating that
 * this connection will provide network access to other computers) then the
 * interface is assigned an address in the 10.42.x.1/24 range and a DHCP and
 * forwarding DNS server are started, and the interface is NAT-ed to the current
 * default network connection.  "disabled" means IPv4 will not be used on this
 * connection.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_DHCP_CLIENT_ID,
	PROP_DHCP_FQDN,
);

typedef struct {
	char *dhcp_client_id;
	char *dhcp_fqdn;
} NMSettingIP4ConfigPrivate;

G_DEFINE_TYPE (NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING_IP_CONFIG)

#define NM_SETTING_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigPrivate))

/*****************************************************************************/

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
 * nm_setting_ip4_config_get_dhcp_fqdn:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:dhcp-fqdn
 * property.
 *
 * Returns: the configured FQDN to send to the DHCP server
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip4_config_get_dhcp_fqdn (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_fqdn;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	NMSettingVerifyResult ret;
	const char *method;

	ret = NM_SETTING_CLASS (nm_setting_ip4_config_parent_class)->verify (setting, connection, error);
	if (ret != NM_SETTING_VERIFY_SUCCESS)
		return ret;

	method = nm_setting_ip_config_get_method (s_ip);
	/* Base class already checked that it exists */
	g_assert (method);

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (nm_setting_ip_config_get_num_addresses (s_ip) == 0) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("this property cannot be empty for '%s=%s'"),
			             NM_SETTING_IP_CONFIG_METHOD, method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
	           || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		if (nm_setting_ip_config_get_num_dns (s_ip) > 0) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP_CONFIG_METHOD, method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_DNS);
			return FALSE;
		}

		if (nm_setting_ip_config_get_num_dns_searches (s_ip) > 0) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for '%s=%s'"),
			             NM_SETTING_IP_CONFIG_METHOD, method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		/* Shared allows IP addresses; link-local and disabled do not */
		if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0) {
			if (nm_setting_ip_config_get_num_addresses (s_ip) > 0) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("this property is not allowed for '%s=%s'"),
				             NM_SETTING_IP_CONFIG_METHOD, method);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_ADDRESSES);
				return FALSE;
			}
		}
	} else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		/* nothing to do */
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_client_id && !priv->dhcp_client_id[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID);
		return FALSE;
	}

	if (priv->dhcp_fqdn && !*priv->dhcp_fqdn) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_FQDN);
		return FALSE;
	}

	if (priv->dhcp_fqdn && !strchr (priv->dhcp_fqdn, '.')) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid FQDN"), priv->dhcp_fqdn);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_FQDN);
		return FALSE;
	}

	if (priv->dhcp_fqdn && nm_setting_ip_config_get_dhcp_hostname (s_ip)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property cannot be set when dhcp-hostname is also set"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP4_CONFIG_DHCP_FQDN);
		return FALSE;
	}

	/* Failures from here on are NORMALIZABLE_ERROR... */

	if (   nm_streq (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
	    && nm_setting_ip_config_get_num_addresses (s_ip) > 1) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("multiple addresses are not allowed for '%s=%s'"),
		             NM_SETTING_IP_CONFIG_METHOD,
		             NM_SETTING_IP4_CONFIG_METHOD_SHARED);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_ADDRESSES);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	/* Failures from here on are NORMALIZABLE... */

	if (   !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)
	    && !nm_setting_ip_config_get_may_fail (s_ip)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property should be TRUE when method is set to disabled"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_MAY_FAIL);
		return NM_SETTING_VERIFY_NORMALIZABLE;
	}

	return TRUE;
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
ip4_addresses_get (const NMSettInfoSetting *sett_info,
                   guint property_idx,
                   NMConnection *connection,
                   NMSetting *setting,
                   NMConnectionSerializationFlags flags,
                   const NMConnectionSerializationOptions *options)
{
	gs_unref_ptrarray GPtrArray *addrs = NULL;
	const char *gateway;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
	gateway = nm_setting_ip_config_get_gateway (NM_SETTING_IP_CONFIG (setting));
	return nm_utils_ip4_addresses_to_variant (addrs, gateway);
}

static gboolean
ip4_addresses_set (NMSetting  *setting,
                   GVariant   *connection_dict,
                   const char *property,
                   GVariant   *value,
                   NMSettingParseFlags parse_flags,
                   GError    **error)
{
	GPtrArray *addrs;
	GVariant *s_ip4;
	char **labels, *gateway = NULL;
	int i;

	/* FIXME: properly handle errors */

	if (!_nm_setting_use_legacy_property (setting, connection_dict, "addresses", "address-data"))
		return TRUE;

	addrs = nm_utils_ip4_addresses_from_variant (value, &gateway);

	s_ip4 = g_variant_lookup_value (connection_dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	if (g_variant_lookup (s_ip4, "address-labels", "^as", &labels)) {
		for (i = 0; i < addrs->len && labels[i]; i++)
			if (*labels[i])
				nm_ip_address_set_attribute (addrs->pdata[i], NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string (labels[i]));
		g_strfreev (labels);
	}
	g_variant_unref (s_ip4);

	g_object_set (setting,
	              NM_SETTING_IP_CONFIG_ADDRESSES, addrs,
	              NM_SETTING_IP_CONFIG_GATEWAY, gateway,
	              NULL);
	g_ptr_array_unref (addrs);
	g_free (gateway);
	return TRUE;
}

static GVariant *
ip4_address_labels_get (const NMSettInfoSetting *sett_info,
                        guint property_idx,
                        NMConnection *connection,
                        NMSetting *setting,
                        NMConnectionSerializationFlags flags,
                        const NMConnectionSerializationOptions *options)
{
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	gboolean have_labels = FALSE;
	GPtrArray *labels;
	GVariant *ret;
	int num_addrs, i;

	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	num_addrs = nm_setting_ip_config_get_num_addresses (s_ip);
	for (i = 0; i < num_addrs; i++) {
		NMIPAddress *addr = nm_setting_ip_config_get_address (s_ip, i);
		GVariant *label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);

		if (label) {
			have_labels = TRUE;
			break;
		}
	}
	if (!have_labels)
		return NULL;

	labels = g_ptr_array_sized_new (num_addrs);
	for (i = 0; i < num_addrs; i++) {
		NMIPAddress *addr = nm_setting_ip_config_get_address (s_ip, i);
		GVariant *label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);

		g_ptr_array_add (labels, (char *) (label ? g_variant_get_string (label, NULL) : ""));
	}

	ret = g_variant_new_strv ((const char * const *) labels->pdata, labels->len);
	g_ptr_array_unref (labels);

	return ret;
}

static GVariant *
ip4_address_data_get (const NMSettInfoSetting *sett_info,
                      guint property_idx,
                      NMConnection *connection,
                      NMSetting *setting,
                      NMConnectionSerializationFlags flags,
                      const NMConnectionSerializationOptions *options)
{
	gs_unref_ptrarray GPtrArray *addrs = NULL;

	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
	return nm_utils_ip_addresses_to_variant (addrs);
}

static gboolean
ip4_address_data_set (NMSetting  *setting,
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

	addrs = nm_utils_ip_addresses_from_variant (value, AF_INET);
	g_object_set (setting, NM_SETTING_IP_CONFIG_ADDRESSES, addrs, NULL);
	g_ptr_array_unref (addrs);
	return TRUE;
}

static GVariant *
ip4_routes_get (const NMSettInfoSetting *sett_info,
                guint property_idx,
                NMConnection *connection,
                NMSetting *setting,
                NMConnectionSerializationFlags flags,
                const NMConnectionSerializationOptions *options)
{
	gs_unref_ptrarray GPtrArray *routes = NULL;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
	return nm_utils_ip4_routes_to_variant (routes);
}

static gboolean
ip4_routes_set (NMSetting  *setting,
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

	routes = nm_utils_ip4_routes_from_variant (value);
	g_object_set (setting, property, routes, NULL);
	g_ptr_array_unref (routes);
	return TRUE;
}

static GVariant *
ip4_route_data_get (const NMSettInfoSetting *sett_info,
                    guint property_idx,
                    NMConnection *connection,
                    NMSetting *setting,
                    NMConnectionSerializationFlags flags,
                    const NMConnectionSerializationOptions *options)
{
	gs_unref_ptrarray GPtrArray *routes = NULL;

	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	g_object_get (setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
	return nm_utils_ip_routes_to_variant (routes);
}

static gboolean
ip4_route_data_set (NMSetting  *setting,
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

	routes = nm_utils_ip_routes_from_variant (value, AF_INET);
	g_object_set (setting, NM_SETTING_IP_CONFIG_ROUTES, routes, NULL);
	g_ptr_array_unref (routes);
	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *s_ip4 = NM_SETTING_IP4_CONFIG (object);

	switch (prop_id) {
	case PROP_DHCP_CLIENT_ID:
		g_value_set_string (value, nm_setting_ip4_config_get_dhcp_client_id (s_ip4));
		break;
	case PROP_DHCP_FQDN:
		g_value_set_string (value, nm_setting_ip4_config_get_dhcp_fqdn (s_ip4));
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
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DHCP_CLIENT_ID:
		g_free (priv->dhcp_client_id);
		priv->dhcp_client_id = g_value_dup_string (value);
		break;
	case PROP_DHCP_FQDN:
		g_free (priv->dhcp_fqdn);
		priv->dhcp_fqdn = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ip4_config_init (NMSettingIP4Config *setting)
{
}

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

static void
finalize (GObject *object)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (object);

	g_free (priv->dhcp_client_id);
	g_free (priv->dhcp_fqdn);

	G_OBJECT_CLASS (nm_setting_ip4_config_parent_class)->finalize (object);
}

static void
nm_setting_ip4_config_class_init (NMSettingIP4ConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array_ip_config ();

	g_type_class_add_private (setting_class, sizeof (NMSettingIP4ConfigPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/* ---ifcfg-rh---
	 * property: method
	 * variable: BOOTPROTO
	 * format:   string
	 * values:   none, dhcp (bootp), static, ibft, autoip, shared
	 * default:  none
	 * description: Method used for IPv4 protocol configuration.
	 * ---end---
	 */

	/* ---keyfile---
	 * property: dns
	 * format: list of DNS IP addresses
	 * description: List of DNS servers.
	 * example: dns=1.2.3.4;8.8.8.8;8.8.4.4;
	 * ---end---
	 * ---ifcfg-rh---
	 * property: dns
	 * variable: DNS1, DNS2, ...
	 * format:   string
	 * description: List of DNS servers. Even if NetworkManager supports many DNS
	 *   servers, initscripts and resolver only care about the first three, usually.
	 * example: DNS1=1.2.3.4 DNS2=10.0.0.254 DNS3=8.8.8.8
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
	 * example: address1=192.168.100.100/24 address2=10.1.1.5/24
	 * ---end---
	 * ---ifcfg-rh---
	 * property: addresses
	 * variable: IPADDR, PREFIX, IPADDR1, PREFIX1, ...
	 * description: List of static IP addresses.
	 * example: IPADDR=10.5.5.23 PREFIX=24 IPADDR1=1.1.1.2 PREFIX1=16
	 * ---end---
	 */

	/* ---keyfile---
	 * property: gateway
	 * variable: gateway
	 * format: string
	 * description: Gateway IP addresses as a string.
	 * example: gateway=192.168.100.1
	 * ---end---
	 * ---ifcfg-rh---
	 * property: gateway
	 * variable: GATEWAY
	 * description: Gateway IP address.
	 * example: GATEWAY=10.5.5.1
	 * ---end---
	 */

	/* ---keyfile---
	 * property: routes
	 * variable: route1, route2, ...
	 * format: route/plen[,gateway,metric]
	 * description: List of IP routes.
	 * example: route1=8.8.8.0/24,10.1.1.1,77
	 *   route2=7.7.0.0/16
	 * ---end---
	 * ---ifcfg-rh---
	 * property: routes
	 * variable: ADDRESS1, NETMASK1, GATEWAY1, METRIC1, OPTIONS1, ...
	 * description: List of static routes. They are not stored in ifcfg-* file,
	 *   but in route-* file instead.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: ignore-auto-routes
	 * variable: PEERROUTES(+)
	 * default: yes
	 * description: PEERROUTES has the opposite meaning as 'ignore-auto-routes' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: ignore-auto-dns
	 * variable: PEERDNS
	 * default: yes
	 * description: PEERDNS has the opposite meaning as 'ignore-auto-dns' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dhcp-send-hostname
	 * variable: DHCP_SEND_HOSTNAME(+)
	 * default: yes
	 * description: Whether DHCP_HOSTNAME should be sent to the DHCP server.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dhcp-hostname
	 * variable: DHCP_HOSTNAME
	 * description: Hostname to send to the DHCP server. When both DHCP_HOSTNAME and
	 *    DHCP_FQDN are specified only the latter is used.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: never-default
	 * variable: DEFROUTE (GATEWAYDEV in /etc/sysconfig/network)
	 * default: yes
	 * description: DEFROUTE=no tells NetworkManager that this connection
	 *   should not be assigned the default route. DEFROUTE has the opposite
	 *   meaning as 'never-default' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: may-fail
	 * variable: IPV4_FAILURE_FATAL(+)
	 * default: no
	 * description: IPV4_FAILURE_FATAL has the opposite meaning as 'may-fail' property.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: route-metric
	 * variable: IPV4_ROUTE_METRIC(+)
	 * default: -1
	 * description: IPV4_ROUTE_METRIC is the default IPv4 metric for routes on this connection.
	 *   If set to -1, a default metric based on the device type is used.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: route-table
	 * variable: IPV4_ROUTE_TABLE(+)
	 * default: 0
	 * description: IPV4_ROUTE_TABLE enables policy-routing and sets the default routing table.
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dns-options
	 * variable: RES_OPTIONS(+)
	 * description: List of DNS options to be added to /etc/resolv.conf
	 * example: RES_OPTIONS=ndots:2 timeout:3
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dns-priority
	 * variable: IPV4_DNS_PRIORITY(+)
	 * description: The priority for DNS servers of this connection. Lower values have higher priority.
	 *    If zero, the default value will be used (50 for VPNs, 100 for other connections).
	 *    A negative value prevents DNS from other connections with greater values to be used.
	 * default: 0
	 * example: IPV4_DNS_PRIORITY=20
	 * ---end---
	 */

	/**
	 * NMSettingIP4Config:dhcp-client-id:
	 *
	 * A string sent to the DHCP server to identify the local machine which the
	 * DHCP server may use to customize the DHCP lease and options.
	 * When the property is a hex string ('aa:bb:cc') it is interpreted as a
	 * binary client ID, in which case the first byte is assumed to be the
	 * 'type' field as per RFC 2132 section 9.14 and the remaining bytes may be
	 * an hardware address (e.g. '01:xx:xx:xx:xx:xx:xx' where 1 is the Ethernet
	 * ARP type and the rest is a MAC address).
	 * If the property is not a hex string it is considered as a
	 * non-hardware-address client ID and the 'type' field is set to 0.
	 *
	 * The special values "mac" and "perm-mac" are supported, which use the
	 * current or permanent MAC address of the device to generate a client identifier
	 * with type ethernet (01). Currently, these options only work for ethernet
	 * type of links.
	 *
	 * The special value "duid" generates a RFC4361-compliant client identifier based
	 * on a hash of the interface name as IAID and /etc/machine-id.
	 *
	 * The special value "stable" is supported to generate a type 0 client identifier based
	 * on the stable-id (see connection.stable-id) and a per-host key. If you set the
	 * stable-id, you may want to include the "${DEVICE}" or "${MAC}" specifier to get a
	 * per-device key.
	 *
	 * If unset, a globally configured default is used. If still unset, the default
	 * depends on the DHCP plugin.
	 **/
	/* ---ifcfg-rh---
	 * property: dhcp-client-id
	 * variable: DHCP_CLIENT_ID(+)
	 * description: A string sent to the DHCP server to identify the local machine.
	 *    A binary value can be specified using hex notation ('aa:bb:cc').
	 * example: DHCP_CLIENT_ID=ax-srv-1; DHCP_CLIENT_ID=01:44:44:44:44:44:44
	 * ---end---
	 */
	obj_properties[PROP_DHCP_CLIENT_ID] =
	    g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/* ---ifcfg-rh---
	 * property: dad-timeout
	 * variable: ACD_TIMEOUT(+), ARPING_WAIT
	 * default: missing variable means global default (config override or zero)
	 * description: Timeout (in milliseconds for ACD_TIMEOUT or in seconds
	 *   for ARPING_WAIT) for address conflict detection before configuring
	 *   IPv4 addresses. 0 turns off the ACD completely, -1 means default value.
	 * example: ACD_TIMEOUT=2000 or ARPING_WAIT=2
	 * ---end---
	 */

	/* ---ifcfg-rh---
	 * property: dhcp-timeout
	 * variable: IPV4_DHCP_TIMEOUT(+)
	 * description: A timeout after which the DHCP transaction fails in case of no response.
	 * example: IPV4_DHCP_TIMEOUT=10
	 * ---end---
	 */

	/**
	 * NMSettingIP4Config:dhcp-fqdn:
	 *
	 * If the #NMSettingIPConfig:dhcp-send-hostname property is %TRUE, then the
	 * specified FQDN will be sent to the DHCP server when acquiring a lease. This
	 * property and #NMSettingIPConfig:dhcp-hostname are mutually exclusive and
	 * cannot be set at the same time.
	 *
	 * Since: 1.2
	 */
	/* ---ifcfg-rh---
	 * property: dhcp-fqdn
	 * variable: DHCP_FQDN
	 * description: FQDN to send to the DHCP server. When both DHCP_HOSTNAME and
	 *    DHCP_FQDN are specified only the latter is used.
	 * example: DHCP_FQDN=foo.bar.com
	 * ---end---
	 */
	obj_properties[PROP_DHCP_FQDN] =
	    g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_FQDN, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/* IP4-specific property overrides */

	/* ---dbus---
	 * property: dns
	 * format: array of uint32
	 * description: Array of IP addresses of DNS servers (as network-byte-order
	 *   integers)
	 * ---end---
	 */
	_properties_override_add_transform (properties_override,
	                                    g_object_class_find_property (G_OBJECT_CLASS (setting_class),
	                                                                  NM_SETTING_IP_CONFIG_DNS),
	                                    G_VARIANT_TYPE ("au"),
	                                    ip4_dns_to_dbus,
	                                    ip4_dns_from_dbus);

	/* ---dbus---
	 * property: addresses
	 * format: array of array of uint32
	 * description: Deprecated in favor of the 'address-data' and 'gateway'
	 *   properties, but this can be used for backward-compatibility with older
	 *   daemons. Note that if you send this property the daemon will ignore
	 *   'address-data' and 'gateway'.
	 *
	 *   Array of IPv4 address structures.  Each IPv4 address structure is
	 *   composed of 3 32-bit values; the first being the IPv4 address (network
	 *   byte order), the second the prefix (1 - 32), and last the IPv4 gateway
	 *   (network byte order). The gateway may be left as 0 if no gateway exists
	 *   for that subnet.
	 * ---end---
	 */
	_properties_override_add_override (properties_override,
	                                   g_object_class_find_property (G_OBJECT_CLASS (setting_class),
	                                                                 NM_SETTING_IP_CONFIG_ADDRESSES),
	                                   G_VARIANT_TYPE ("aau"),
	                                   ip4_addresses_get,
	                                   ip4_addresses_set,
	                                   NULL);

	_properties_override_add_dbus_only (properties_override,
	                                    "address-labels",
	                                    G_VARIANT_TYPE_STRING_ARRAY,
	                                    ip4_address_labels_get,
	                                    NULL);

	/* ---dbus---
	 * property: address-data
	 * format: array of vardict
	 * description: Array of IPv4 addresses. Each address dictionary contains at
	 *   least 'address' and 'prefix' entries, containing the IP address as a
	 *   string, and the prefix length as a uint32. Additional attributes may
	 *   also exist on some addresses.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    "address-data",
	                                    G_VARIANT_TYPE ("aa{sv}"),
	                                    ip4_address_data_get,
	                                    ip4_address_data_set);

	/* ---dbus---
	 * property: routes
	 * format: array of array of uint32
	 * description: Deprecated in favor of the 'route-data' property, but this
	 *   can be used for backward-compatibility with older daemons. Note that if
	 *   you send this property the daemon will ignore 'route-data'.
	 *
	 *   Array of IPv4 route structures.  Each IPv4 route structure is composed
	 *   of 4 32-bit values; the first being the destination IPv4 network or
	 *   address (network byte order), the second the destination network or
	 *   address prefix (1 - 32), the third being the next-hop (network byte
	 *   order) if any, and the fourth being the route metric. If the metric is
	 *   0, NM will choose an appropriate default metric for the device. (There
	 *   is no way to explicitly specify an actual metric of 0 with this
	 *   property.)
	 * ---end---
	 */
	_properties_override_add_override (properties_override,
	                                   g_object_class_find_property (G_OBJECT_CLASS (setting_class),
	                                                                 NM_SETTING_IP_CONFIG_ROUTES),
	                                   G_VARIANT_TYPE ("aau"),
	                                   ip4_routes_get,
	                                   ip4_routes_set,
	                                   NULL);

	/* ---dbus---
	 * property: route-data
	 * format: array of vardict
	 * description: Array of IPv4 routes. Each route dictionary contains at
	 *   least 'dest' and 'prefix' entries, containing the destination IP
	 *   address as a string, and the prefix length as a uint32. Most routes
	 *   will also have a 'gateway' entry, containing the gateway IP address as
	 *   a string. If the route has a 'metric' entry (containing a uint32), that
	 *   will be used as the metric for the route (otherwise NM will pick a
	 *   default value appropriate to the device). Additional attributes may
	 *   also exist on some routes.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    "route-data",
	                                    G_VARIANT_TYPE ("aa{sv}"),
	                                    ip4_route_data_get,
	                                    ip4_route_data_set);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_IP4_CONFIG,
	                               NULL, properties_override);
}
