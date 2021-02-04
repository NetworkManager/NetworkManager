/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2020 Red Hat, Inc.
 */

#include "libnm-core/nm-default-libnm-core.h"

#include "nm-setting-hostname.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-hostname
 * @short_description: Contains properties related to the hostname
 * @include: nm-setting-hostname.h
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingHostname,
                             PROP_PRIORITY,
                             PROP_FROM_DHCP,
                             PROP_FROM_DNS_LOOKUP,
                             PROP_ONLY_FROM_DEFAULT, );

/**
 * NMSettingHostname:
 *
 * Hostname settings
 *
 * Since: 1.30
 */
struct _NMSettingHostname {
    NMSetting parent;
    int       priority;
    NMTernary from_dhcp;
    NMTernary from_dns_lookup;
    NMTernary only_from_default;
};

struct _NMSettingHostnameClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingHostname, nm_setting_hostname, NM_TYPE_SETTING)

/**
 * nm_setting_hostname_get_priority:
 * @setting: the #NMSettingHostname
 *
 * Returns the value contained in the #NMSettingHostname:priority
 * property.
 *
 * Returns: the 'priority' property value
 *
 * Since: 1.30
 **/
int
nm_setting_hostname_get_priority(NMSettingHostname *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_HOSTNAME(setting), 0);

    return setting->priority;
}

/**
 * nm_setting_hostname_get_from_dhcp:
 * @setting: the #NMSettingHostname
 *
 * Returns the value contained in the #NMSettingHostname:from-dhcp
 * property.
 *
 * Returns: the 'from-dhcp' property value
 *
 * Since: 1.30
 **/
NMTernary
nm_setting_hostname_get_from_dhcp(NMSettingHostname *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_HOSTNAME(setting), NM_TERNARY_DEFAULT);

    return setting->from_dhcp;
}

/**
 * nm_setting_hostname_get_from_dns_lookup:
 * @setting: the #NMSettingHostname
 *
 * Returns the value contained in the #NMSettingHostname:from-dns-lookup
 * property.
 *
 * Returns: the 'from-dns-lookup' property value
 *
 * Since: 1.30
 **/
NMTernary
nm_setting_hostname_get_from_dns_lookup(NMSettingHostname *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_HOSTNAME(setting), NM_TERNARY_DEFAULT);

    return setting->from_dns_lookup;
}

/**
 * nm_setting_hostname_get_only_from_default:
 * @setting: the #NMSettingHostname
 *
 * Returns the value contained in the #NMSettingHostname:only-from-default
 * property.
 *
 * Returns: the 'only-from-default' property value
 *
 * Since: 1.30
 **/
NMTernary
nm_setting_hostname_get_only_from_default(NMSettingHostname *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_HOSTNAME(setting), NM_TERNARY_DEFAULT);

    return setting->only_from_default;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingHostname *self = NM_SETTING_HOSTNAME(object);

    switch (prop_id) {
    case PROP_PRIORITY:
        g_value_set_int(value, self->priority);
        break;
    case PROP_FROM_DHCP:
        g_value_set_enum(value, self->from_dhcp);
        break;
    case PROP_FROM_DNS_LOOKUP:
        g_value_set_enum(value, self->from_dns_lookup);
        break;
    case PROP_ONLY_FROM_DEFAULT:
        g_value_set_enum(value, self->only_from_default);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingHostname *self = NM_SETTING_HOSTNAME(object);

    switch (prop_id) {
    case PROP_PRIORITY:
        self->priority = g_value_get_int(value);
        break;
    case PROP_FROM_DHCP:
        self->from_dhcp = g_value_get_enum(value);
        break;
    case PROP_FROM_DNS_LOOKUP:
        self->from_dns_lookup = g_value_get_enum(value);
        break;
    case PROP_ONLY_FROM_DEFAULT:
        self->only_from_default = g_value_get_enum(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_hostname_init(NMSettingHostname *setting)
{
    setting->from_dhcp         = NM_TERNARY_DEFAULT;
    setting->from_dns_lookup   = NM_TERNARY_DEFAULT;
    setting->only_from_default = NM_TERNARY_DEFAULT;
}

/**
 * nm_setting_hostname_new:
 *
 * Creates a new #NMSettingHostname object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingHostname object
 *
 * Since: 1.30
 **/
NMSetting *
nm_setting_hostname_new(void)
{
    return g_object_new(NM_TYPE_SETTING_HOSTNAME, NULL);
}

static void
nm_setting_hostname_class_init(NMSettingHostnameClass *klass)
{
    GObjectClass *  object_class  = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class = NM_SETTING_CLASS(klass);

    object_class->get_property = get_property;
    object_class->set_property = set_property;

    /**
     * NMSettingHostname:priority
     *
     * The relative priority of this connection to determine the
     * system hostname. A lower numerical value is better (higher
     * priority).  A connection with higher priority is considered
     * before connections with lower priority.
     *
     * If the value is zero, it can be overridden by a global value
     * from NetworkManager configuration. If the property doesn't have
     * a value in the global configuration, the value is assumed to be
     * 100.
     *
     * Negative values have the special effect of excluding other
     * connections with a greater numerical priority value; so in
     * presence of at least one negative priority, only connections
     * with the lowest priority value will be used to determine the
     * hostname.
     *
     * Since: 1.30
     **/
    /* ---ifcfg-rh---
     * property: priority
     * variable: HOSTNAME_PRIORITY(+)
     * default: missing variable means global value or 100
     * description: hostname priority
     * example: HOSTNAME_PRIORITY=50
     * ---end---
     */
    obj_properties[PROP_PRIORITY] = g_param_spec_int(NM_SETTING_HOSTNAME_PRIORITY,
                                                     "",
                                                     "",
                                                     G_MININT32,
                                                     G_MAXINT32,
                                                     0,
                                                     G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingHostname:from-dhcp
     *
     * Whether the system hostname can be determined from DHCP on
     * this connection.
     *
     * When set to %NM_TERNARY_DEFAULT, the value from global configuration
     * is used. If the property doesn't have a value in the global
     * configuration, NetworkManager assumes the value to be %NM_TERNARY_TRUE.
     *
     * Since: 1.30
     **/
    /* ---ifcfg-rh---
     * property: from-dhcp
     * variable: HOSTNAME_FROM_DHCP(+)
     * default: missing variable means global default or 1
     * description: whether the system hostname can be determined from DHCP
     * example: HOSTNAME_FROM_DHCP=0,1
     * ---end---
     */
    obj_properties[PROP_FROM_DHCP] = g_param_spec_enum(
        NM_SETTING_HOSTNAME_FROM_DHCP,
        "",
        "",
        NM_TYPE_TERNARY,
        NM_TERNARY_DEFAULT,
        NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingHostname:from-dns-lookup
     *
     * Whether the system hostname can be determined from reverse
     * DNS lookup of addresses on this device.
     *
     * When set to %NM_TERNARY_DEFAULT, the value from global configuration
     * is used. If the property doesn't have a value in the global
     * configuration, NetworkManager assumes the value to be %NM_TERNARY_TRUE.
     *
     * Since: 1.30
     **/
    /* ---ifcfg-rh---
     * property: from-dhcp
     * variable: HOSTNAME_FROM_DNS_LOOKUP(+)
     * default: missing variable means global default or 1
     * description: whether the system hostname can be determined from reverse
     *    DNS lookup
     * example: HOSTNAME_FROM_DNS_LOOKUP=0,1
     * ---end---
     */
    obj_properties[PROP_FROM_DNS_LOOKUP] = g_param_spec_enum(
        NM_SETTING_HOSTNAME_FROM_DNS_LOOKUP,
        "",
        "",
        NM_TYPE_TERNARY,
        NM_TERNARY_DEFAULT,
        NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingHostname:only-from-default
     *
     * If set to %NM_TERNARY_TRUE, NetworkManager attempts to get
     * the hostname via DHCPv4/DHCPv6 or reverse DNS lookup on this
     * device only when the device has the default route for the given
     * address family (IPv4/IPv6).
     *
     * If set to %NM_TERNARY_FALSE, the hostname can be set from this
     * device even if it doesn't have the default route.
     *
     * When set to %NM_TERNARY_DEFAULT, the value from global configuration
     * is used. If the property doesn't have a value in the global
     * configuration, NetworkManager assumes the value to be %NM_TERNARY_FALSE.
     *
     * Since: 1.30
     **/
    /* ---ifcfg-rh---
     * property: only-best-device
     * variable: HOSTNAME_ONLY_FROM_DEFAULT(+)
     * default: missing variable means global default or 1
     * description: whether the hostname can be determined only from
     *    devices with the default route
     * example: HOSTNAME_ONLY_FROM_DEFAULT=0,1
     * ---end---
     */
    obj_properties[PROP_ONLY_FROM_DEFAULT] = g_param_spec_enum(
        NM_SETTING_HOSTNAME_ONLY_FROM_DEFAULT,
        "",
        "",
        NM_TYPE_TERNARY,
        NM_TERNARY_DEFAULT,
        NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class, NM_META_SETTING_TYPE_HOSTNAME);
}
