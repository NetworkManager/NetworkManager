/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ip6-config.h"

#include <arpa/inet.h>

#include "nm-setting-private.h"
#include "nm-utils-private.h"
#include "nm-core-enum-types.h"
#include "libnm-core-intern/nm-core-internal.h"

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
 * NetworkManager supports 7 values for the #NMSettingIPConfig:method property
 * for IPv6.  If "auto" is specified then the appropriate automatic method (PPP,
 * router advertisement, etc) is used for the device and most other properties
 * can be left unset.  To force the use of DHCP only, specify "dhcp"; this
 * method is only valid for Ethernet- based hardware.  If "link-local" is
 * specified, then an IPv6 link-local address will be assigned to the interface.
 * If "manual" is specified, static IP addressing is used and at least one IP
 * address must be given in the "addresses" property.  If "ignore" is specified,
 * IPv6 configuration is not done. Note: the "shared" method is not yet
 * supported. If "disabled" is specified, IPv6 is disabled completely for the
 * interface.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_IP6_PRIVACY,
                                  PROP_ADDR_GEN_MODE,
                                  PROP_TOKEN,
                                  PROP_DHCP_DUID,
                                  PROP_RA_TIMEOUT,
                                  PROP_MTU, );

typedef struct {
    NMSettingIPConfigPrivate parent;

    char   *token;
    char   *dhcp_duid;
    int     ip6_privacy;
    gint32  addr_gen_mode;
    gint32  ra_timeout;
    guint32 mtu;
} NMSettingIP6ConfigPrivate;

/**
 * NMSettingIP6Config:
 *
 * IPv6 Settings
 */
struct _NMSettingIP6Config {
    NMSettingIPConfig parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingIP6ConfigClass {
    NMSettingIPConfigClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING_IP_CONFIG)

#define NM_SETTING_IP6_CONFIG_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigPrivate))

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
nm_setting_ip6_config_get_ip6_privacy(NMSettingIP6Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP6_CONFIG(setting), NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

    return NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting)->ip6_privacy;
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
nm_setting_ip6_config_get_addr_gen_mode(NMSettingIP6Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP6_CONFIG(setting),
                         NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT);

    return NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting)->addr_gen_mode;
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
nm_setting_ip6_config_get_token(NMSettingIP6Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP6_CONFIG(setting), NULL);

    return NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting)->token;
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
nm_setting_ip6_config_get_dhcp_duid(NMSettingIP6Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP6_CONFIG(setting), NULL);

    return NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting)->dhcp_duid;
}

/**
 * nm_setting_ip6_config_get_ra_timeout:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: The configured %NM_SETTING_IP6_CONFIG_RA_TIMEOUT value with the
 * timeout for router advertisements in seconds.
 *
 * Since: 1.24
 **/
gint32
nm_setting_ip6_config_get_ra_timeout(NMSettingIP6Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP6_CONFIG(setting), 0);

    return NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting)->ra_timeout;
}

/**
 * nm_setting_ip6_config_get_mtu:
 * @setting: the #NMSettingIP6Config
 *
 * Returns: The configured %NM_SETTING_IP6_CONFIG_MTU value for the maximum
 * transmission unit.
 *
 * Since: 1.40
 **/
guint32
nm_setting_ip6_config_get_mtu(NMSettingIP6Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP6_CONFIG(setting), 0);

    return NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting)->mtu;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting);
    NMSettingIPConfig         *s_ip = NM_SETTING_IP_CONFIG(setting);
    NMSettingVerifyResult      ret;
    const char                *method;
    gboolean                   token_needs_normalization = FALSE;

    ret = NM_SETTING_CLASS(nm_setting_ip6_config_parent_class)->verify(setting, connection, error);
    if (ret != NM_SETTING_VERIFY_SUCCESS)
        return ret;

    method = nm_setting_ip_config_get_method(s_ip);
    /* Base class already checked that it exists */
    g_assert(method);

    if (nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
        if (nm_setting_ip_config_get_num_addresses(s_ip) == 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_PROPERTY,
                        _("this property cannot be empty for '%s=%s'"),
                        NM_SETTING_IP_CONFIG_METHOD,
                        method);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
                           NM_SETTING_IP_CONFIG_ADDRESSES);
            return FALSE;
        }
    } else if (NM_IN_STRSET(method,
                            NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                            NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
                            NM_SETTING_IP6_CONFIG_METHOD_SHARED,
                            NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
        /* Shared allows IP addresses and DNS; other methods do not */
        if (!nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
            if (nm_setting_ip_config_get_num_dns(s_ip) > 0) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("this property is not allowed for '%s=%s'"),
                            NM_SETTING_IP_CONFIG_METHOD,
                            method);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP6_CONFIG_SETTING_NAME,
                               NM_SETTING_IP_CONFIG_DNS);
                return FALSE;
            }

            if (nm_setting_ip_config_get_num_dns_searches(s_ip) > 0) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("this property is not allowed for '%s=%s'"),
                            NM_SETTING_IP_CONFIG_METHOD,
                            method);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP6_CONFIG_SETTING_NAME,
                               NM_SETTING_IP_CONFIG_DNS_SEARCH);
                return FALSE;
            }

            if (nm_setting_ip_config_get_num_addresses(s_ip) > 0) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("this property is not allowed for '%s=%s'"),
                            NM_SETTING_IP_CONFIG_METHOD,
                            method);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP6_CONFIG_SETTING_NAME,
                               NM_SETTING_IP_CONFIG_ADDRESSES);
                return FALSE;
            }
        }
    } else if (NM_IN_STRSET(method,
                            NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                            NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
        /* nothing to do */
    } else {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP6_CONFIG_SETTING_NAME,
                       NM_SETTING_IP_CONFIG_METHOD);
        return FALSE;
    }

    if (!NM_IN_SET(priv->addr_gen_mode,
                   NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                   NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY,
                   NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64,
                   NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP6_CONFIG_SETTING_NAME,
                       NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE);
        return FALSE;
    }

    if (priv->token) {
        if (priv->addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64) {
            struct in6_addr i6_token;
            char            s_token[NM_INET_ADDRSTRLEN];

            if (inet_pton(AF_INET6, priv->token, &i6_token) != 1
                || !_nm_utils_inet6_is_token(&i6_token)) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("value is not a valid token"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP6_CONFIG_SETTING_NAME,
                               NM_SETTING_IP6_CONFIG_TOKEN);
                return FALSE;
            }

            if (g_strcmp0(priv->token, nm_inet6_ntop(&i6_token, s_token)))
                token_needs_normalization = TRUE;
        } else {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("only makes sense with EUI64 address generation mode"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
                           NM_SETTING_IP6_CONFIG_TOKEN);
            return FALSE;
        }
    }

    if (priv->dhcp_duid) {
        if (!_nm_utils_dhcp_duid_valid(priv->dhcp_duid, NULL)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("invalid DUID"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
                           NM_SETTING_IP6_CONFIG_DHCP_DUID);
            return FALSE;
        }
    }

    /* Failures from here on, are NORMALIZABLE_ERROR... */

    if (token_needs_normalization) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("token is not in canonical form"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP6_CONFIG_SETTING_NAME,
                       NM_SETTING_IP6_CONFIG_TOKEN);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    /* Failures from here on are NORMALIZABLE... */

    if (NM_IN_STRSET(method,
                     NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                     NM_SETTING_IP6_CONFIG_METHOD_DISABLED)
        && !nm_setting_ip_config_get_may_fail(s_ip)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property should be TRUE when method is set to ignore or disabled"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP6_CONFIG_SETTING_NAME,
                       NM_SETTING_IP_CONFIG_MAY_FAIL);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

static GVariant *
ip6_dns_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    GPtrArray *dns;

    dns = _nm_setting_ip_config_get_dns_array(NM_SETTING_IP_CONFIG(setting));
    if (nm_g_ptr_array_len(dns) == 0)
        return NULL;

    return nm_utils_dns_to_variant(AF_INET6, (const char *const *) dns->pdata, dns->len);
}

static gboolean
ip6_dns_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_strfreev char **strv = NULL;

    if (!_nm_setting_use_legacy_property(setting, connection_dict, "dns", "dns-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    strv = nm_utils_ip6_dns_from_variant(value);
    g_object_set(setting, NM_SETTING_IP_CONFIG_DNS, strv, NULL);
    return TRUE;
}

static GVariant *
ip6_addresses_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;
    const char                  *gateway;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
    gateway = nm_setting_ip_config_get_gateway(NM_SETTING_IP_CONFIG(setting));
    return nm_utils_ip6_addresses_to_variant(addrs, gateway);
}

static gboolean
ip6_addresses_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs   = NULL;
    gs_free char                *gateway = NULL;

    if (!_nm_setting_use_legacy_property(setting, connection_dict, "addresses", "address-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    addrs = nm_utils_ip6_addresses_from_variant(value, &gateway);

    g_object_set(setting,
                 NM_SETTING_IP_CONFIG_ADDRESSES,
                 addrs,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 gateway,
                 NULL);
    return TRUE;
}

static GVariant *
ip6_address_data_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;

    if (!_nm_connection_serialize_non_secret(flags))
        return NULL;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
    return nm_utils_ip_addresses_to_variant(addrs);
}

static gboolean
ip6_address_data_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;

    /* Ignore 'address-data' if we're going to process 'addresses' */
    if (_nm_setting_use_legacy_property(setting, connection_dict, "addresses", "address-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    addrs = nm_utils_ip_addresses_from_variant(value, AF_INET6);
    g_object_set(setting, NM_SETTING_IP_CONFIG_ADDRESSES, addrs, NULL);
    return TRUE;
}

static GVariant *
ip6_routes_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
    return nm_utils_ip6_routes_to_variant(routes);
}

static gboolean
ip6_routes_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    if (!_nm_setting_use_legacy_property(setting, connection_dict, "routes", "route-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    routes = nm_utils_ip6_routes_from_variant(value);
    g_object_set(setting, property_info->name, routes, NULL);
    return TRUE;
}

static GVariant *
ip6_route_data_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    if (!_nm_connection_serialize_non_secret(flags))
        return NULL;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
    return nm_utils_ip_routes_to_variant(routes);
}

static gboolean
ip6_route_data_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    /* Ignore 'route-data' if we're going to process 'routes' */
    if (_nm_setting_use_legacy_property(setting, connection_dict, "routes", "route-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    routes = nm_utils_ip_routes_from_variant(value, AF_INET6);
    g_object_set(setting, NM_SETTING_IP_CONFIG_ROUTES, routes, NULL);
    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ip6_config_init(NMSettingIP6Config *setting)
{
    NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE(setting);

    _nm_setting_ip_config_private_init(setting, &priv->parent);
}

/**
 * nm_setting_ip6_config_new:
 *
 * Creates a new #NMSettingIP6Config object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIP6Config object
 **/
NMSetting *
nm_setting_ip6_config_new(void)
{
    return g_object_new(NM_TYPE_SETTING_IP6_CONFIG, NULL);
}

static void
nm_setting_ip6_config_class_init(NMSettingIP6ConfigClass *klass)
{
    GObjectClass           *object_class            = G_OBJECT_CLASS(klass);
    NMSettingClass         *setting_class           = NM_SETTING_CLASS(klass);
    NMSettingIPConfigClass *setting_ip_config_class = NM_SETTING_IP_CONFIG_CLASS(klass);
    GArray *properties_override = _nm_sett_info_property_override_create_array_ip_config(AF_INET6);

    g_type_class_add_private(klass, sizeof(NMSettingIP6ConfigPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    setting_ip_config_class->private_offset = g_type_class_get_instance_private_offset(klass);
    setting_ip_config_class->is_ipv4        = FALSE;
    setting_ip_config_class->addr_family    = AF_INET6;

    /* ---ifcfg-rh---
     * property: method
     * variable: IPV6INIT, IPV6FORWARDING, IPV6_AUTOCONF, DHCPV6C, IPV6_DISABLED
     * default: IPV6INIT=yes; IPV6FORWARDING=no; IPV6_AUTOCONF=!IPV6FORWARDING, DHCPV6=no
     * description: Method used for IPv6 protocol configuration.
     *   ignore ~ IPV6INIT=no; auto ~ IPV6_AUTOCONF=yes; dhcp ~ IPV6_AUTOCONF=no and DHCPV6C=yes;
     *   disabled ~ IPV6_DISABLED=yes
     * ---end---
     */

    /* ---keyfile---
     * property: dns
     * format: list of DNS IP addresses
     * description: List of DNS servers.
     * example: dns=2001:4860:4860::8888;2001:4860:4860::8844;
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: dns
     * variable: DNS1, DNS2, ...
     * format: string
     * description: List of DNS servers. NetworkManager uses the variables both
     *   for IPv4 and IPv6.
     * ---end---
     */

    /* ---ifcfg-rh---
     * property: dns-search
     * variable: IPV6_DOMAIN(+)
     * format: string (space-separated domains)
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
     */
    /* ---ifcfg-rh---
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
     */
    /* ---ifcfg-rh---
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
     */
    /* ---ifcfg-rh---
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
     * variable: DHCPV6_HOSTNAME
     * description: Hostname to send the DHCP server.
     * ---end---
     */

    /* ---ifcfg-rh---
     * property: dhcp-timeout
     * variable: IPV6_DHCP_TIMEOUT(+)
     * description: A timeout after which the DHCP transaction fails in case of no response.
     * example: IPV6_DHCP_TIMEOUT=10
     * ---end---
     */

    /* ---ifcfg-rh---
     * property: dhcp-hostname-flags
     * variable: DHCPV6_HOSTNAME_FLAGS
     * description: flags for the DHCP hostname property
     * example: DHCPV6_HOSTNAME_FLAGS=5
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

    /* ---ifcfg-rh---
     * property: auto-route-ext-gw
     * variable: IPV6_AUTO_ROUTE_EXT_GW(+)
     * default: yes
     * description: VPN connections will default to add the route automatically unless this
     *     setting is set to %FALSE.
     *     For other connection types, adding such an automatic route is currently
     *     not supported and setting this to %TRUE has no effect.
     * ---end---
     */

    /* ---ifcfg-rh---
     * property: replace-local-rule
     * variable: IPV6_REPLACE_LOCAL_RULE(+)
     * default: no
     * description: Connections will default to keep the autogenerated priority
     *     0 local rule unless this setting is set to %TRUE.
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
    _nm_setting_property_define_direct_enum(properties_override,
                                            obj_properties,
                                            NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
                                            PROP_IP6_PRIVACY,
                                            NM_TYPE_SETTING_IP6_CONFIG_PRIVACY,
                                            NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
                                            NM_SETTING_PARAM_NONE,
                                            NMSettingIP6ConfigPrivate,
                                            ip6_privacy);

    /**
     * NMSettingIP6Config:addr-gen-mode:
     *
     * Configure method for creating the address for use with RFC4862 IPv6
     * Stateless Address Autoconfiguration. The permitted values are:
     * %NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
     * %NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY.
     * %NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64
     * or %NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT.
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
     * The special values "default" and "default-or-eui64" will fallback to the global
     * connection default in as documented in NetworkManager.conf(5) manual. If the
     * global default is not specified, the fallback value is "stable-privacy"
     * or "eui64", respectively.
     *
     * For libnm, the property defaults to "default" since 1.40.
     * Previously it defaulted to "stable-privacy".
     * On D-Bus, the absence of an addr-gen-mode setting equals
     * "default". For keyfile plugin, the absence of the setting
     * on disk means "default-or-eui64" so that the property doesn't change on upgrade
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
     * values: IPV6_ADDR_GEN_MODE: default, default-or-eui64, eui64, stable-privacy
     * default: "default-or-eui64"
     * description: Configure IPv6 Stable Privacy addressing for SLAAC (RFC7217).
     * example: IPV6_ADDR_GEN_MODE=stable-privacy
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
                                             PROP_ADDR_GEN_MODE,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingIP6ConfigPrivate,
                                             addr_gen_mode);

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
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP6_CONFIG_TOKEN,
                                              PROP_TOKEN,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIP6ConfigPrivate,
                                              token);

    /**
     * NMSettingIP6Config:ra-timeout:
     *
     * A timeout for waiting Router Advertisements in seconds. If zero (the default), a
     * globally configured default is used. If still unspecified, the timeout depends on the
     * sysctl settings of the device.
     *
     * Set to 2147483647 (MAXINT32) for infinity.
     *
     * Since: 1.24
     **/
    /* ---ifcfg-rh---
     * property: ra-timeout
     * variable: IPV6_RA_TIMEOUT(+)
     * description: A timeout for waiting Router Advertisements in seconds.
     * example: IPV6_RA_TIMEOUT=10
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_IP6_CONFIG_RA_TIMEOUT,
                                             PROP_RA_TIMEOUT,
                                             0,
                                             G_MAXINT32,
                                             0,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingIP6ConfigPrivate,
                                             ra_timeout);

    /**
     * NMSettingIP6Config:mtu:
     *
     * Maximum transmission unit size, in bytes. If zero (the default), the MTU
     * is set automatically from router advertisements or is left equal to the
     * link-layer MTU. If greater than the link-layer MTU, or greater than zero
     * but less than the minimum IPv6 MTU of 1280, this value has no effect.
     *
     * Since: 1.40
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP6_CONFIG_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingIP6ConfigPrivate,
                                              mtu);

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
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP6_CONFIG_DHCP_DUID,
                                              PROP_DHCP_DUID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingIP6ConfigPrivate,
                                              dhcp_duid);

    /* IP6-specific property overrides */

    /* ---dbus---
     * property: dns
     * format: array of byte array
     * description: Array of IP addresses of DNS servers (in network byte order)
     * ---end---
     */
    _nm_properties_override_gobj(
        properties_override,
        g_object_class_find_property(G_OBJECT_CLASS(setting_class), NM_SETTING_IP_CONFIG_DNS),
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aay"),
                                       .compare_fcn   = _nm_setting_ip_config_compare_fcn_dns,
                                       .to_dbus_fcn   = ip6_dns_to_dbus,
                                       .from_dbus_fcn = ip6_dns_from_dbus, ),
        .to_dbus_only_in_manager_process = TRUE,
        .dbus_deprecated                 = TRUE);

    /* ---dbus---
     * property: addresses
     * format: array of legacy IPv6 address struct (a(ayuay))
     * description: Deprecated in favor of the 'address-data' and 'gateway'
     *   properties, but this can be used for backward-compatibility with older
     *   daemons. Note that if you send this property the daemon will ignore
     *   'address-data' and 'gateway'.
     *
     *   Array of IPv6 address structures.  Each IPv6 address structure is
     *   composed of an IPv6 address, a prefix length (0 - 128), and an IPv6
     *   gateway address. The gateway may be zeroed out if no gateway exists for
     *   that subnet.
     * ---end---
     */
    /* ---nmcli---
     * property: addresses
     * format: a comma separated list of addresses
     * description: A list of IPv6 addresses and their prefix length. Multiple addresses
     * can be separated by comma. For example "2001:db8:85a3::8a2e:370:7334/64, 2001:db8:85a3::5/64".
     * The addresses are listed in decreasing priority, meaning the first address will
     * be the primary address. This can make a difference with IPv6 source address selection
     * (RFC 6724, section 5).
     * ---end---
     */
    _nm_properties_override_gobj(
        properties_override,
        g_object_class_find_property(G_OBJECT_CLASS(setting_class), NM_SETTING_IP_CONFIG_ADDRESSES),
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("a(ayuay)"),
                                       .to_dbus_fcn   = ip6_addresses_to_dbus,
                                       .compare_fcn   = _nm_setting_ip_config_compare_fcn_addresses,
                                       .from_dbus_fcn = ip6_addresses_from_dbus, ),
        .to_dbus_only_in_manager_process = TRUE,
        .dbus_deprecated                 = TRUE, );

    /* ---dbus---
     * property: address-data
     * format: array of vardict
     * description: Array of IPv6 addresses. Each address dictionary contains at
     *   least 'address' and 'prefix' entries, containing the IP address as a
     *   string, and the prefix length as a uint32. Additional attributes may
     *   also exist on some addresses.
     * ---end---
     */
    _nm_properties_override_dbus(
        properties_override,
        "address-data",
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aa{sv}"),
                                       .to_dbus_fcn   = ip6_address_data_to_dbus,
                                       .compare_fcn   = _nm_setting_property_compare_fcn_ignore,
                                       .from_dbus_fcn = ip6_address_data_from_dbus, ));

    /* ---dbus---
     * property: routes
     * format: array of legacy IPv6 route struct (a(ayuayu))
     * description: Deprecated in favor of the 'route-data' property, but this
     *   can be used for backward-compatibility with older daemons. Note that if
     *   you send this property the daemon will ignore 'route-data'.
     *
     *   Array of IPv6 route structures.  Each IPv6 route structure is
     *   composed of an IPv6 address, a prefix length (0 - 128), an IPv6
     *   next hop address (which may be zeroed out if there is no next hop),
     *   and a metric. If the metric is 0, NM will choose an appropriate
     *   default metric for the device.
     * ---end---
     */
    /* ---nmcli---
     * property: routes
     * format: a comma separated list of routes
     * description-docbook:
     *   <para>
     *     A list of IPv6 destination addresses, prefix length, optional IPv6
     *     next hop addresses, optional route metric, optional attribute. The valid syntax is:
     *     "ip[/prefix] [next-hop] [metric] [attribute=val]...[,ip[/prefix]...]".
     *   </para>
     *   <para>
     *     Various attributes are supported:
     *     <itemizedlist>
     *      <listitem>
     *        <para><literal>"advmss"</literal> - an unsigned 32 bit integer.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"cwnd"</literal> - an unsigned 32 bit integer.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"from"</literal> - an IPv6 address with optional prefix. IPv6 only.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"initcwnd"</literal> - an unsigned 32 bit integer.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"initrwnd"</literal> - an unsigned 32 bit integer.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"lock-advmss"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"lock-cwnd"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"lock-initcwnd"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"lock-initrwnd"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"lock-mtu"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"lock-window"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"mtu"</literal> - an unsigned 32 bit integer.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"onlink"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"quickack"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"rto_min"</literal> - an unsigned 32 bit integer.
     *        The value is in milliseconds.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"src"</literal> - an IPv6 address.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"table"</literal> - an unsigned 32 bit integer. The default depends on ipv6.route-table.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"type"</literal> - one of <literal>unicast</literal>, <literal>local</literal>, <literal>blackhole</literal>,
     *          <literal>unreachable</literal>, <literal>prohibit</literal>, <literal>throw</literal>.
     *          The default is <literal>unicast</literal>.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"window"</literal> - an unsigned 32 bit integer.</para>
     *      </listitem>
     *     </itemizedlist>
     *   </para>
     *   <para>
     *   For details see also `man ip-route`.
     *   </para>
     * ---end---
     */
    _nm_properties_override_gobj(
        properties_override,
        g_object_class_find_property(G_OBJECT_CLASS(setting_class), NM_SETTING_IP_CONFIG_ROUTES),
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("a(ayuayu)"),
                                       .to_dbus_fcn   = ip6_routes_to_dbus,
                                       .compare_fcn   = _nm_setting_ip_config_compare_fcn_routes,
                                       .from_dbus_fcn = ip6_routes_from_dbus, ),
        .to_dbus_only_in_manager_process = TRUE,
        .dbus_deprecated                 = TRUE, );

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
    _nm_properties_override_dbus(
        properties_override,
        "route-data",
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aa{sv}"),
                                       .to_dbus_fcn   = ip6_route_data_to_dbus,
                                       .compare_fcn   = _nm_setting_property_compare_fcn_ignore,
                                       .from_dbus_fcn = ip6_route_data_from_dbus, ));

    /* ---nmcli---
     * property: routing-rules
     * format: a comma separated list of routing rules
     * description: A comma separated list of routing rules for policy routing.
     * description-docbook:
     *   <para>
     *   A comma separated list of routing rules for policy routing. The format
     *   is based on <command>ip rule add</command> syntax and mostly compatible.
     *   One difference is that routing rules in NetworkManager always need a
     *   fixed priority.
     *   </para>
     *   <para>
     *   Example: <literal>priority 5 from 1:2:3::5/128 table 45</literal>
     *   </para>
     * ---end---
     */

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_IP6_CONFIG,
                             NULL,
                             properties_override,
                             setting_ip_config_class->private_offset);
}
