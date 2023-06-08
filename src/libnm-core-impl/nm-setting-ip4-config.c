/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ip4-config.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"

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

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_DHCP_CLIENT_ID,
                                  PROP_DHCP_FQDN,
                                  PROP_DHCP_VENDOR_CLASS_IDENTIFIER,
                                  PROP_LINK_LOCAL, );

typedef struct {
    NMSettingIPConfigPrivate parent;

    char  *dhcp_client_id;
    char  *dhcp_fqdn;
    char  *dhcp_vendor_class_identifier;
    gint32 link_local;
} NMSettingIP4ConfigPrivate;

/**
 * NMSettingIP4Config:
 *
 * IPv4 Settings
 */
struct _NMSettingIP4Config {
    NMSettingIPConfig parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingIP4ConfigClass {
    NMSettingIPConfigClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING_IP_CONFIG)

#define NM_SETTING_IP4_CONFIG_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigPrivate))

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
nm_setting_ip4_config_get_dhcp_client_id(NMSettingIP4Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP4_CONFIG(setting), NULL);

    return NM_SETTING_IP4_CONFIG_GET_PRIVATE(setting)->dhcp_client_id;
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
nm_setting_ip4_config_get_dhcp_fqdn(NMSettingIP4Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP4_CONFIG(setting), NULL);

    return NM_SETTING_IP4_CONFIG_GET_PRIVATE(setting)->dhcp_fqdn;
}

/**
 * nm_setting_ip4_config_get_dhcp_vendor_class_identifier:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:dhcp_vendor_class_identifier
 * property.
 *
 * Returns: the vendor class identifier option to send to the DHCP server
 *
 * Since: 1.28
 **/
const char *
nm_setting_ip4_config_get_dhcp_vendor_class_identifier(NMSettingIP4Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP4_CONFIG(setting), NULL);

    return NM_SETTING_IP4_CONFIG_GET_PRIVATE(setting)->dhcp_vendor_class_identifier;
}

/**
 * nm_setting_ip4_config_get_link_local:
 * @setting: the #NMSettingIP4Config
 *
 * Returns the value contained in the #NMSettingIP4Config:link_local
 * property.
 *
 * Returns: the link-local configuration
 *
 * Since: 1.42
 **/
NMSettingIP4LinkLocal
nm_setting_ip4_config_get_link_local(NMSettingIP4Config *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP4_CONFIG(setting), NM_SETTING_IP4_LL_DEFAULT);

    return NM_SETTING_IP4_CONFIG_GET_PRIVATE(setting)->link_local;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE(setting);
    NMSettingIPConfig         *s_ip = NM_SETTING_IP_CONFIG(setting);
    NMSettingVerifyResult      ret;
    const char                *method;

    ret = NM_SETTING_CLASS(nm_setting_ip4_config_parent_class)->verify(setting, connection, error);
    if (ret != NM_SETTING_VERIFY_SUCCESS)
        return ret;

    method = nm_setting_ip_config_get_method(s_ip);
    /* Base class already checked that it exists */
    g_assert(method);

    if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
        if (nm_setting_ip_config_get_num_addresses(s_ip) == 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_PROPERTY,
                        _("this property cannot be empty for '%s=%s'"),
                        NM_SETTING_IP_CONFIG_METHOD,
                        method);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
                           NM_SETTING_IP_CONFIG_ADDRESSES);
            return FALSE;
        }
    } else if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
               || !strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
               || !strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
        if (nm_setting_ip_config_get_num_dns(s_ip) > 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("this property is not allowed for '%s=%s'"),
                        NM_SETTING_IP_CONFIG_METHOD,
                        method);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
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
                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
                           NM_SETTING_IP_CONFIG_DNS_SEARCH);
            return FALSE;
        }

        /* Shared allows IP addresses; link-local and disabled do not */
        if (strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0) {
            if (nm_setting_ip_config_get_num_addresses(s_ip) > 0) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("this property is not allowed for '%s=%s'"),
                            NM_SETTING_IP_CONFIG_METHOD,
                            method);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP4_CONFIG_SETTING_NAME,
                               NM_SETTING_IP_CONFIG_ADDRESSES);
                return FALSE;
            }
        }
    } else if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
        /* nothing to do */
    } else {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP_CONFIG_METHOD);
        return FALSE;
    }

    if (!NM_IN_SET(priv->link_local,
                   NM_SETTING_IP4_LL_AUTO,
                   NM_SETTING_IP4_LL_DEFAULT,
                   NM_SETTING_IP4_LL_DISABLED,
                   NM_SETTING_IP4_LL_ENABLED)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_LINK_LOCAL);
        return FALSE;
    }
    if (priv->link_local == NM_SETTING_IP4_LL_ENABLED
        && nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("cannot enable ipv4.link-local with ipv4.method=disabled"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_LINK_LOCAL);
        return FALSE;
    }
    if (priv->link_local == NM_SETTING_IP4_LL_DISABLED
        && nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("cannot disable ipv4.link-local with ipv4.method=link-local"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_LINK_LOCAL);
        return FALSE;
    }

    if (priv->dhcp_client_id && !priv->dhcp_client_id[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID);
        return FALSE;
    }

    if (priv->dhcp_fqdn && !*priv->dhcp_fqdn) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_FQDN);
        return FALSE;
    }

    if (priv->dhcp_fqdn && !strchr(priv->dhcp_fqdn, '.')) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid FQDN"),
                    priv->dhcp_fqdn);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_FQDN);
        return FALSE;
    }

    if (priv->dhcp_fqdn && nm_setting_ip_config_get_dhcp_hostname(s_ip)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property cannot be set when dhcp-hostname is also set"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_FQDN);
        return FALSE;
    }

    if (NM_FLAGS_ANY(nm_setting_ip_config_get_dhcp_hostname_flags(s_ip),
                     NM_DHCP_HOSTNAME_FLAGS_FQDN_MASK)
        && !priv->dhcp_fqdn) {
        /* Currently, we send a FQDN option only when ipv4.dhcp-fqdn is set */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("FQDN flags requires a FQDN set"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP_CONFIG_DHCP_HOSTNAME_FLAGS);
        return FALSE;
    }

    if (priv->dhcp_vendor_class_identifier
        && !nm_utils_validate_dhcp4_vendor_class_id(priv->dhcp_vendor_class_identifier, error))
        return FALSE;

    /* Failures from here on are NORMALIZABLE_ERROR... */

    if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
        && nm_setting_ip_config_get_num_addresses(s_ip) > 1) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("multiple addresses are not allowed for '%s=%s'"),
                    NM_SETTING_IP_CONFIG_METHOD,
                    NM_SETTING_IP4_CONFIG_METHOD_SHARED);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP_CONFIG_ADDRESSES);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    /* Failures from here on are NORMALIZABLE... */

    if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)
        && !nm_setting_ip_config_get_may_fail(s_ip)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property should be TRUE when method is set to disabled"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP_CONFIG_MAY_FAIL);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

static GVariant *
ip4_dns_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    GPtrArray *dns;

    dns = _nm_setting_ip_config_get_dns_array(NM_SETTING_IP_CONFIG(setting));
    if (nm_g_ptr_array_len(dns) == 0)
        return NULL;

    return nm_utils_dns_to_variant(AF_INET, (const char *const *) dns->pdata, dns->len);
}

static gboolean
ip4_dns_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_strfreev char **strv = NULL;

    if (!_nm_setting_use_legacy_property(setting, connection_dict, "dns", "dns-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    strv = nm_utils_ip4_dns_from_variant(value);
    g_object_set(setting, NM_SETTING_IP_CONFIG_DNS, strv, NULL);
    return TRUE;
}

static GVariant *
ip4_addresses_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;
    const char                  *gateway;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
    gateway = nm_setting_ip_config_get_gateway(NM_SETTING_IP_CONFIG(setting));
    return nm_utils_ip4_addresses_to_variant(addrs, gateway);
}

static gboolean
ip4_addresses_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs   = NULL;
    gs_unref_variant GVariant   *s_ip4   = NULL;
    gs_free const char         **labels  = NULL;
    gs_free char                *gateway = NULL;
    guint                        i;

    /* FIXME: properly handle errors */

    if (!_nm_setting_use_legacy_property(setting, connection_dict, "addresses", "address-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    addrs = nm_utils_ip4_addresses_from_variant(value, &gateway);

    s_ip4 = g_variant_lookup_value(connection_dict,
                                   NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                   NM_VARIANT_TYPE_SETTING);
    if (g_variant_lookup(s_ip4, "address-labels", "^a&s", &labels)) {
        for (i = 0; i < addrs->len && labels[i]; i++) {
            if (*labels[i]) {
                nm_ip_address_set_attribute(addrs->pdata[i],
                                            NM_IP_ADDRESS_ATTRIBUTE_LABEL,
                                            g_variant_new_string(labels[i]));
            }
        }
    }

    g_object_set(setting,
                 NM_SETTING_IP_CONFIG_ADDRESSES,
                 addrs,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 gateway,
                 NULL);
    return TRUE;
}

static GVariant *
ip4_address_labels_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    NMSettingIPConfig *s_ip        = NM_SETTING_IP_CONFIG(setting);
    gboolean           have_labels = FALSE;
    gs_free GVariant **labels_free = NULL;
    GVariant          *s_empty;
    GVariant         **labels;
    guint              num_addrs;
    guint              i;

    if (!_nm_connection_serialize_non_secret(flags))
        return NULL;

    num_addrs = nm_setting_ip_config_get_num_addresses(s_ip);
    if (num_addrs == 0)
        return NULL;

    labels = nm_malloc_maybe_a(500, sizeof(gpointer) * num_addrs, &labels_free);

    s_empty = nm_g_variant_singleton_s_empty();

    for (i = 0; i < num_addrs; i++) {
        NMIPAddress *addr  = nm_setting_ip_config_get_address(s_ip, i);
        GVariant    *label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);

        if (label) {
            have_labels = TRUE;
            labels[i]   = label;
        } else
            labels[i] = s_empty;
    }

    if (!have_labels)
        return NULL;

    return g_variant_new_array(G_VARIANT_TYPE_STRING, labels, num_addrs);
}

static GVariant *
ip4_address_data_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;

    if (!_nm_connection_serialize_non_secret(flags))
        return NULL;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);
    return nm_utils_ip_addresses_to_variant(addrs);
}

static gboolean
ip4_address_data_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;

    /* FIXME: properly handle errors */

    /* Ignore 'address-data' if we're going to process 'addresses' */
    if (_nm_setting_use_legacy_property(setting, connection_dict, "addresses", "address-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    addrs = nm_utils_ip_addresses_from_variant(value, AF_INET);
    g_object_set(setting, NM_SETTING_IP_CONFIG_ADDRESSES, addrs, NULL);
    return TRUE;
}

static GVariant *
ip4_routes_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
    return nm_utils_ip4_routes_to_variant(routes);
}

static gboolean
ip4_routes_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    /* FIXME: properly handle errors */

    if (!_nm_setting_use_legacy_property(setting, connection_dict, "routes", "route-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    routes = nm_utils_ip4_routes_from_variant(value);
    g_object_set(setting, property_info->name, routes, NULL);
    return TRUE;
}

static GVariant *
ip4_route_data_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    if (!_nm_connection_serialize_non_secret(flags))
        return NULL;

    g_object_get(setting, NM_SETTING_IP_CONFIG_ROUTES, &routes, NULL);
    return nm_utils_ip_routes_to_variant(routes);
}

static gboolean
ip4_route_data_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gs_unref_ptrarray GPtrArray *routes = NULL;

    /* FIXME: properly handle errors */

    /* Ignore 'route-data' if we're going to process 'routes' */
    if (_nm_setting_use_legacy_property(setting, connection_dict, "routes", "route-data")) {
        *out_is_modified = FALSE;
        return TRUE;
    }

    routes = nm_utils_ip_routes_from_variant(value, AF_INET);
    g_object_set(setting, NM_SETTING_IP_CONFIG_ROUTES, routes, NULL);
    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ip4_config_init(NMSettingIP4Config *setting)
{
    NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE(setting);

    _nm_setting_ip_config_private_init(setting, &priv->parent);
}

/**
 * nm_setting_ip4_config_new:
 *
 * Creates a new #NMSettingIP4Config object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIP4Config object
 **/
NMSetting *
nm_setting_ip4_config_new(void)
{
    return g_object_new(NM_TYPE_SETTING_IP4_CONFIG, NULL);
}

static void
nm_setting_ip4_config_class_init(NMSettingIP4ConfigClass *klass)
{
    GObjectClass           *object_class            = G_OBJECT_CLASS(klass);
    NMSettingClass         *setting_class           = NM_SETTING_CLASS(klass);
    NMSettingIPConfigClass *setting_ip_config_class = NM_SETTING_IP_CONFIG_CLASS(klass);
    GArray *properties_override = _nm_sett_info_property_override_create_array_ip_config(AF_INET);

    g_type_class_add_private(klass, sizeof(NMSettingIP4ConfigPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    setting_ip_config_class->private_offset = g_type_class_get_instance_private_offset(klass);
    setting_ip_config_class->is_ipv4        = TRUE;
    setting_ip_config_class->addr_family    = AF_INET;

    /* ---ifcfg-rh---
     * property: method
     * variable: BOOTPROTO
     * format: string
     * values: none, dhcp (bootp), static, ibft, autoip, shared
     * default: none
     * description: Method used for IPv4 protocol configuration.
     * ---end---
     */

    /* ---keyfile---
     * property: dns
     * format: list of DNS IP addresses
     * description: List of DNS servers.
     * example: dns=1.2.3.4;8.8.8.8;8.8.4.4;
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: dns
     * variable: DNS1, DNS2, ...
     * format: string
     * description: List of DNS servers. Even if NetworkManager supports many DNS
     *   servers, initscripts and resolver only care about the first three, usually.
     * example: DNS1=1.2.3.4 DNS2=10.0.0.254 DNS3=8.8.8.8
     * ---end---
     */

    /* ---ifcfg-rh---
     * property: dns-search
     * variable: DOMAIN
     * format: string (space-separated domains)
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
     */
    /* ---ifcfg-rh---
     * property: addresses
     * variable: IPADDR, PREFIX (NETMASK), IPADDR1, PREFIX1 (NETMASK1), ...
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
     */
    /* ---ifcfg-rh---
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
     */
    /* ---ifcfg-rh---
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

    /* ---nmcli---
     * property: dns-options
     * format: a comma separated list of DNS options
     * description:
     *   DNS options for /etc/resolv.conf as described in resolv.conf(5) manual.
     *
     *   The currently supported options are "attempts", "debug", "edns0",
     *   "ndots", "no-aaaa", "no-check-names", "no-reload", "no-tld-query",
     *   "rotate", "single-request", "single-request-reopen", "timeout",
     *   "trust-ad", "use-vc". See the resolv.conf(5) manual.
     *
     *   Note that there is a distinction between an unset (default) list
     *   and an empty list. In nmcli, to unset the list set the value to
     *   "". To set an empty list, set it to " ". Currently, an unset list
     *   has the same meaning as an empty list. That might change in the future.
     *
     *   The "trust-ad" setting is only honored if the profile contributes
     *   name servers to resolv.conf, and if all contributing profiles have
     *   "trust-ad" enabled.
     *
     *   When using a caching DNS plugin (dnsmasq or systemd-resolved in
     *   NetworkManager.conf) then "edns0" and "trust-ad" are automatically
     *   added.
     *
     *   The valid "ipv4.dns-options" and "ipv6.dns-options" get merged together.
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

    /* ---ifcfg-rh---
     * property: auto-route-ext-gw
     * variable: IPV4_AUTO_ROUTE_EXT_GW(+)
     * default: yes
     * description: VPN connections will default to add the route automatically unless this
     *     setting is set to %FALSE.
     *     For other connection types, adding such an automatic route is currently
     *     not supported and setting this to %TRUE has no effect.
     * ---end---
     */

    /* ---ifcfg-rh---
     * property: replace-local-rule
     * variable: IPV4_REPLACE_LOCAL_RULE(+)
     * default: no
     * description: Connections will default to keep the autogenerated priority
     *     0 local rule unless this setting is set to %TRUE.
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
     * The special value "ipv6-duid" uses the DUID from "ipv6.dhcp-duid" property as
     * an RFC4361-compliant client identifier. As IAID it uses "ipv4.dhcp-iaid"
     * and falls back to "ipv6.dhcp-iaid" if unset.
     *
     * The special value "duid" generates a RFC4361-compliant client identifier based
     * on "ipv4.dhcp-iaid" and uses a DUID generated by hashing /etc/machine-id.
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
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,
                                              PROP_DHCP_CLIENT_ID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingIP4ConfigPrivate,
                                              dhcp_client_id);

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

    /* ---ifcfg-rh---
     * property: dhcp-hostname-flags
     * variable: DHCP_HOSTNAME_FLAGS
     * description: flags for the DHCP hostname and FQDN properties
     * example: DHCP_HOSTNAME_FLAGS=5
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
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP4_CONFIG_DHCP_FQDN,
                                              PROP_DHCP_FQDN,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingIP4ConfigPrivate,
                                              dhcp_fqdn);

    /**
     * NMSettingIP4Config:dhcp-vendor-class-identifier:
     *
     * The Vendor Class Identifier DHCP option (60).
     * Special characters in the data string may be escaped using C-style escapes,
     * nevertheless this property cannot contain nul bytes.
     * If the per-profile value is unspecified (the default),
     * a global connection default gets consulted.
     * If still unspecified, the DHCP option is not sent to the server.
     *
     * Since: 1.28
     */
    /* ---ifcfg-rh---
     * property: dhcp-vendor-class-identifier
     * variable: DHCP_VENDOR_CLASS_IDENTIFIER(+)
     * description: The Vendor Class Identifier DHCP option (60).
     * example: DHCP_VENDOR_CLASS_IDENTIFIER=foo
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER,
                                              PROP_DHCP_VENDOR_CLASS_IDENTIFIER,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingIP4ConfigPrivate,
                                              dhcp_vendor_class_identifier);

    /**
     * NMSettingIP4Config:link-local:
     *
     * Enable and disable the IPv4 link-local configuration independently of the
     * ipv4.method configuration. This allows a link-local address (169.254.x.y/16)
     * to be obtained in addition to other addresses, such as those manually
     * configured or obtained from a DHCP server.
     *
     * When set to "auto", the value is dependent on "ipv4.method".
     * When set to "default", it honors the global connection default, before
     * falling back to "auto". Note that if "ipv4.method" is "disabled", then
     * link local addressing is always disabled too. The default is "default".
     *
     * Since: 1.40
     */
    /* ---ifcfg-rh---
     * property: link-local
     * variable: IPV4_LINK_LOCAL(+)
     * description: Configure link-local IP address in interaction with method
     * example: IPV4_LINK_LOCAL=auto
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_IP4_CONFIG_LINK_LOCAL,
                                             PROP_LINK_LOCAL,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_IP4_LL_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingIP4ConfigPrivate,
                                             link_local);

    /* IP4-specific property overrides */

    /* ---dbus---
     * property: dns
     * format: array of uint32
     * description: Array of IP addresses of DNS servers (as network-byte-order
     *   integers)
     * ---end---
     */
    _nm_properties_override_gobj(
        properties_override,
        g_object_class_find_property(G_OBJECT_CLASS(setting_class), NM_SETTING_IP_CONFIG_DNS),
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("au"),
                                       .compare_fcn   = _nm_setting_ip_config_compare_fcn_dns,
                                       .to_dbus_fcn   = ip4_dns_to_dbus,
                                       .from_dbus_fcn = ip4_dns_from_dbus, ),
        .to_dbus_only_in_manager_process = TRUE,
        .dbus_deprecated                 = TRUE, );

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
    /* ---nmcli---
     * property: addresses
     * format: a comma separated list of addresses
     * description: A list of IPv4 addresses and their prefix length. Multiple addresses
     * can be separated by comma. For example "192.168.1.5/24, 10.1.0.5/24".
     * The addresses are listed in decreasing priority, meaning the first address will
     * be the primary address.
     * ---end---
     */
    _nm_properties_override_gobj(
        properties_override,
        g_object_class_find_property(G_OBJECT_CLASS(setting_class), NM_SETTING_IP_CONFIG_ADDRESSES),
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aau"),
                                       .to_dbus_fcn   = ip4_addresses_to_dbus,
                                       .compare_fcn   = _nm_setting_ip_config_compare_fcn_addresses,
                                       .from_dbus_fcn = ip4_addresses_from_dbus, ),
        .to_dbus_only_in_manager_process = TRUE,
        .dbus_deprecated                 = TRUE, );
    _nm_properties_override_dbus(
        properties_override,
        "address-labels",
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING_ARRAY,
                                       .to_dbus_fcn = ip4_address_labels_to_dbus,
                                       .compare_fcn = _nm_setting_property_compare_fcn_ignore,
                                       /* from_dbus() is handled by ip4_addresses_from_dbus(). */),
        .dbus_deprecated = TRUE, );

    /* ---dbus---
     * property: address-data
     * format: array of vardict
     * description: Array of IPv4 addresses. Each address dictionary contains at
     *   least 'address' and 'prefix' entries, containing the IP address as a
     *   string, and the prefix length as a uint32. Additional attributes may
     *   also exist on some addresses.
     * ---end---
     */
    _nm_properties_override_dbus(
        properties_override,
        "address-data",
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aa{sv}"),
                                       .to_dbus_fcn   = ip4_address_data_to_dbus,
                                       .compare_fcn   = _nm_setting_property_compare_fcn_ignore,
                                       .from_dbus_fcn = ip4_address_data_from_dbus, ));

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
    /* ---nmcli---
     * property: routes
     * format: a comma separated list of routes
     * description: A list of IPv4 destination addresses, prefix length, optional IPv4
     *   next hop addresses, optional route metric, optional attribute. The valid syntax is:
     *   "ip[/prefix] [next-hop] [metric] [attribute=val]...[,ip[/prefix]...]". For example
     *   "192.0.2.0/24 10.1.1.1 77, 198.51.100.0/24".
     * description-docbook:
     *   <para>
     *     A list of IPv4 destination addresses, prefix length, optional IPv4
     *     next hop addresses, optional route metric, optional attribute. The valid syntax is:
     *     "ip[/prefix] [next-hop] [metric] [attribute=val]...[,ip[/prefix]...]".
     *     For example "192.0.2.0/24 10.1.1.1 77, 198.51.100.0/24".
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
     *        <para><literal>"onlink"</literal> - a boolean value. The onlink flag
     *          is ignored for IPv4 routes without a gateway. That also means,
     *          with a positive "weight" the route cannot merge with ECMP routes
     *          which are onlink and have a gateway.
     *        </para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"quickack"</literal> - a boolean value.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"rto_min"</literal> - an unsigned 32 bit integer.
     *        The value is in milliseconds.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"scope"</literal> - an unsigned 8 bit integer. IPv4 only.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"src"</literal> - an IPv4 address.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"table"</literal> - an unsigned 32 bit integer. The default depends on ipv4.route-table.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"tos"</literal> - an unsigned 8 bit integer. IPv4 only.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"type"</literal> - one of <literal>unicast</literal>, <literal>local</literal>, <literal>blackhole</literal>,
     *          <literal>unreachable</literal>, <literal>prohibit</literal>, <literal>throw</literal>.
     *          The default is <literal>unicast</literal>.</para>
     *      </listitem>
     *      <listitem>
     *        <para><literal>"weight"</literal> - an unsigned 32 bit integer
     *        ranging from 0 to 256. A non-zero weight indicates that the IPv4
     *        route is an ECMP IPv4 route.  NetworkManager will automatically
     *        merge compatible ECMP routes into multi-hop routes.  Setting to
     *        zero or omitting the attribute configures single hop routes that
     *        won't get merged. If the route finds no merge partner, it is
     *        configured as single hop route.</para> <para>Note that in
     *        NetworkManager, currently all nexthops of a ECMP route must share
     *        the same "onlink" flag in order to be mergable.</para>
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
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aau"),
                                       .to_dbus_fcn   = ip4_routes_to_dbus,
                                       .compare_fcn   = _nm_setting_ip_config_compare_fcn_routes,
                                       .from_dbus_fcn = ip4_routes_from_dbus, ),
        .to_dbus_only_in_manager_process = TRUE,
        .dbus_deprecated                 = TRUE, );

    /* ---dbus---
     * property: route-data
     * format: array of vardict
     * description: Array of IPv4 routes. Each route dictionary contains at
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
                                       .to_dbus_fcn   = ip4_route_data_to_dbus,
                                       .compare_fcn   = _nm_setting_property_compare_fcn_ignore,
                                       .from_dbus_fcn = ip4_route_data_from_dbus, ));

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
     *   Example: <literal>priority 5 from 192.167.4.0/24 table 45</literal>
     *   </para>
     * ---end---
     */

    /* ---nmcli---
     * property: method
     * format: string
     * description: The IPv4 connection method.
     * description-docbook:
     *   <para>
     *     Sets the IPv4 connection method. You can set one of the following values:
     *   </para>
     *   <para>
     *     <itemizedlist>
     *        <listitem>
     *          <para><literal>"auto"</literal> - Enables automatic IPv4 address assignment from DHCP, PPP, or similar services.</para>
     *        </listitem>
     *        <listitem>
     *          <para><literal>"manual"</literal> - Enables the configuration of static IPv4 addresses on the interface. Note that you must set at least one IP address and subnet mask in the "ipv4.addresses" property.</para>
     *        </listitem>
     *        <listitem>
     *          <para><literal>"disabled"</literal> - Disables the IPv4 protocol in this connection profile.</para>
     *        </listitem>
     *        <listitem>
     *          <para><literal>"shared"</literal> - Provides network access to other computers. If you do not specify an IP address and subnet mask in "ipv4.addresses", NetworkManager assigns 10.42.x.1/24 to the interface. Additionally, NetworkManager starts a DHCP server and DNS forwarder. Hosts that connect to this interface will then receive an IP address from the configured range, and NetworkManager configures NAT to map client addresses to the one of the current default network connection.</para>
     *        </listitem>
     *        <listitem>
     *          <para><literal>"link-local"</literal> - Enables link-local addresses according to RFC 3927. NetworkManager assigns a random link-local address from the 169.254.0.0/16 subnet to the interface.</para>
     *        </listitem>
     *     </itemizedlist>
     *   </para>
     * ---end---
     */

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_IP4_CONFIG,
                             NULL,
                             properties_override,
                             setting_ip_config_class->private_offset);
}
