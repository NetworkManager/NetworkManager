/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-dhcp-config.h"

#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-utils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDhcpConfig, PROP_FAMILY, PROP_OPTIONS, );

typedef struct _NMDhcpConfigPrivate {
    GHashTable *options;
} NMDhcpConfigPrivate;

G_DEFINE_ABSTRACT_TYPE(NMDhcpConfig, nm_dhcp_config, NM_TYPE_OBJECT)

#define NM_DHCP_CONFIG_GET_PRIVATE(self) \
    _NM_GET_PRIVATE_PTR(self, NMDhcpConfig, NM_IS_DHCP_CONFIG, NMObject)

/*****************************************************************************/

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_options(NMClient               *client,
                            NMLDBusObject          *dbobj,
                            const NMLDBusMetaIface *meta_iface,
                            guint                   dbus_property_idx,
                            GVariant               *value)
{
    NMDhcpConfig        *self = NM_DHCP_CONFIG(dbobj->nmobj);
    NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE(self);

    g_hash_table_remove_all(priv->options);

    if (value) {
        GVariantIter iter;
        const char  *key;
        GVariant    *opt;

        g_variant_iter_init(&iter, value);
        while (g_variant_iter_next(&iter, "{&sv}", &key, &opt)) {
            if (g_variant_is_of_type(opt, G_VARIANT_TYPE_STRING))
                g_hash_table_insert(priv->options, g_strdup(key), g_variant_dup_string(opt, NULL));
            g_variant_unref(opt);
        }
    }

    return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/*****************************************************************************/

static void
nm_dhcp_config_init(NMDhcpConfig *self)
{
    NMDhcpConfigPrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_DHCP_CONFIG, NMDhcpConfigPrivate);

    self->_priv = priv;

    priv->options = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
}

static void
finalize(GObject *object)
{
    NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE(object);

    g_hash_table_destroy(priv->options);

    G_OBJECT_CLASS(nm_dhcp_config_parent_class)->finalize(object);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDhcpConfig *self = NM_DHCP_CONFIG(object);

    switch (prop_id) {
    case PROP_FAMILY:
        g_value_set_int(value, nm_dhcp_config_get_family(self));
        break;
    case PROP_OPTIONS:
        g_value_set_boxed(value, nm_dhcp_config_get_options(self));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_dhcp4config = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DHCP4_CONFIG,
    nm_dhcp4_config_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_FCN("Options",
                                        PROP_OPTIONS,
                                        "a{sv}",
                                        _notify_update_prop_options), ),
    .base_struct_offset = G_STRUCT_OFFSET(NMDhcpConfig, _priv), );

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_dhcp6config = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DHCP6_CONFIG,
    nm_dhcp6_config_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_FCN("Options",
                                        PROP_OPTIONS,
                                        "a{sv}",
                                        _notify_update_prop_options), ),
    .base_struct_offset = G_STRUCT_OFFSET(NMDhcpConfig, _priv), );

static void
nm_dhcp_config_class_init(NMDhcpConfigClass *config_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(config_class);

    g_type_class_add_private(config_class, sizeof(NMDhcpConfigPrivate));

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    /**
     * NMDhcpConfig:family:
     *
     * The IP address family of the configuration; either
     * <literal>AF_INET</literal> or <literal>AF_INET6</literal>.
     **/
    obj_properties[PROP_FAMILY] = g_param_spec_int(NM_DHCP_CONFIG_FAMILY,
                                                   "",
                                                   "",
                                                   0,
                                                   255,
                                                   AF_UNSPEC,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDhcpConfig:options: (type GHashTable(utf8,utf8))
     *
     * The #GHashTable containing options of the configuration.
     **/
    obj_properties[PROP_OPTIONS] = g_param_spec_boxed(NM_DHCP_CONFIG_OPTIONS,
                                                      "",
                                                      "",
                                                      G_TYPE_HASH_TABLE,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class,
                                              &_nml_dbus_meta_iface_nm_dhcp4config,
                                              &_nml_dbus_meta_iface_nm_dhcp6config);
}

/**
 * nm_dhcp_config_get_family:
 * @config: a #NMDhcpConfig
 *
 * Gets the IP address family of the configuration
 *
 * Returns: the IP address family; either <literal>AF_INET</literal> or
 *   <literal>AF_INET6</literal>
 **/
int
nm_dhcp_config_get_family(NMDhcpConfig *config)
{
    g_return_val_if_fail(NM_IS_DHCP_CONFIG(config), AF_UNSPEC);

    return NM_IS_DHCP4_CONFIG(config) ? AF_INET : AF_INET6;
}

/**
 * nm_dhcp_config_get_options:
 * @config: a #NMDhcpConfig
 *
 * Gets all the options contained in the configuration.
 *
 * Returns: (transfer none) (element-type utf8 utf8): the #GHashTable containing
 * strings for keys and values.  This is the internal copy used by the
 * configuration, and must not be modified.
 **/
GHashTable *
nm_dhcp_config_get_options(NMDhcpConfig *config)
{
    g_return_val_if_fail(NM_IS_DHCP_CONFIG(config), NULL);

    return NM_DHCP_CONFIG_GET_PRIVATE(config)->options;
}

/**
 * nm_dhcp_config_get_one_option:
 * @config: a #NMDhcpConfig
 * @option: the option to retrieve
 *
 * Gets one option by option name.
 *
 * Returns: the configuration option's value. This is the internal string used by the
 * configuration, and must not be modified.
 **/
const char *
nm_dhcp_config_get_one_option(NMDhcpConfig *config, const char *option)
{
    g_return_val_if_fail(NM_IS_DHCP_CONFIG(config), NULL);

    return g_hash_table_lookup(nm_dhcp_config_get_options(config), option);
}
