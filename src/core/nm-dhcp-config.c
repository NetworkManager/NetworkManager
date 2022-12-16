/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dhcp-config.h"

#include "nm-dbus-interface.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-dbus-object.h"
#include "nm-core-utils.h"
#include "nm-l3-config-data.h"

/*****************************************************************************/

#define NM_TYPE_DHCP4_CONFIG (nm_dhcp4_config_get_type())
#define NM_DHCP4_CONFIG(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4Config))
#define NM_DHCP4_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))
#define NM_IS_DHCP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP4_CONFIG))
#define NM_IS_DHCP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP4_CONFIG))
#define NM_DHCP4_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))

typedef struct _NMDhcp4Config      NMDhcp4Config;
typedef struct _NMDhcp4ConfigClass NMDhcp4ConfigClass;

static GType nm_dhcp4_config_get_type(void);

#define NM_TYPE_DHCP6_CONFIG (nm_dhcp6_config_get_type())
#define NM_DHCP6_CONFIG(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP6_CONFIG, NMDhcp6Config))
#define NM_DHCP6_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigClass))
#define NM_IS_DHCP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP6_CONFIG))
#define NM_IS_DHCP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP6_CONFIG))
#define NM_DHCP6_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigClass))

typedef struct _NMDhcp6Config      NMDhcp6Config;
typedef struct _NMDhcp6ConfigClass NMDhcp6ConfigClass;

static GType nm_dhcp6_config_get_type(void);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDhcpConfig, PROP_L3CD, PROP_OPTIONS, );

typedef struct {
    const NML3ConfigData *l3cd;
    GVariant             *options;
} NMDhcpConfigPrivate;

struct _NMDhcpConfig {
    NMDBusObject        parent;
    NMDhcpConfigPrivate _priv;
};

struct _NMDhcpConfigClass {
    NMDBusObjectClass parent;
    int               addr_family;
};

G_DEFINE_ABSTRACT_TYPE(NMDhcpConfig, nm_dhcp_config, NM_TYPE_DBUS_OBJECT)

#define NM_DHCP_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDhcpConfig, NM_IS_DHCP_CONFIG)

/*****************************************************************************/

int
nm_dhcp_config_get_addr_family(NMDhcpConfig *self)
{
    return NM_DHCP_CONFIG_GET_CLASS(self)->addr_family;
}

/*****************************************************************************/

static GVariant *
_l3cd_to_options(const NML3ConfigData *l3cd, int addr_family)
{
    GVariant *options;

    options = NULL;
    if (l3cd) {
        NMDhcpLease *lease;

        lease = nm_l3_config_data_get_dhcp_lease(l3cd, addr_family);
        if (lease)
            options = nm_strdict_to_variant_asv(nm_dhcp_lease_get_options(lease));
    }
    if (!options)
        options = nm_g_variant_singleton_aLsvI();
    return g_variant_ref_sink(options);
}

void
nm_dhcp_config_set_lease(NMDhcpConfig *self, const NML3ConfigData *l3cd)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old = NULL;
    gs_unref_variant GVariant               *options2 = NULL;
    NMDhcpConfigPrivate                     *priv;

    g_return_if_fail(NM_IS_DHCP_CONFIG(self));

    priv = NM_DHCP_CONFIG_GET_PRIVATE(self);

    if (priv->l3cd == l3cd)
        return;

    l3cd_old = g_steal_pointer(&priv->l3cd);
    if (l3cd)
        priv->l3cd = nm_l3_config_data_ref_and_seal(l3cd);

    options2 = _l3cd_to_options(priv->l3cd, nm_dhcp_config_get_addr_family(self));

    if (g_variant_equal(priv->options, options2))
        return;

    NM_SWAP(&priv->options, &options2);

    _notify(self, PROP_OPTIONS);
}

NMUtilsNamedValue *
nm_dhcp_config_get_option_values(NMDhcpConfig *self, guint *num)
{
    NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE(self);
    NMDhcpLease         *lease;
    NMUtilsNamedValue   *buffer = NULL;

    if (!priv->l3cd) {
        NM_SET_OUT(num, 0);
        return NULL;
    }

    lease = nm_l3_config_data_get_dhcp_lease(priv->l3cd, nm_dhcp_config_get_addr_family(self));
    nm_utils_named_values_from_strdict_full(nm_dhcp_lease_get_options(lease),
                                            num,
                                            nm_strcmp_p_with_data,
                                            NULL,
                                            NULL,
                                            0,
                                            &buffer);
    return buffer;
}

const char *
nm_dhcp_config_get_option(NMDhcpConfig *self, const char *key)
{
    NMDhcpConfigPrivate *priv;
    NMDhcpLease         *lease;

    g_return_val_if_fail(NM_IS_DHCP_CONFIG(self), NULL);
    g_return_val_if_fail(key, NULL);

    priv = NM_DHCP_CONFIG_GET_PRIVATE(self);

    if (!priv->l3cd)
        return NULL;

    lease = nm_l3_config_data_get_dhcp_lease(priv->l3cd, nm_dhcp_config_get_addr_family(self));
    return nm_dhcp_lease_lookup_option(lease, key);
}

/*****************************************************************************/

GVariant *
nm_dhcp_config_get_options(NMDhcpConfig *self)
{
    g_return_val_if_fail(NM_IS_DHCP_CONFIG(self), NULL);

    return NM_DHCP_CONFIG_GET_PRIVATE(self)->options;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_OPTIONS:
        g_value_set_variant(value, priv->options);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMDhcpConfig        *self = NM_DHCP_CONFIG(object);
    NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_L3CD:
        /* construct-only */
        priv->l3cd    = nm_l3_config_data_ref_and_seal(g_value_get_pointer(value));
        priv->options = _l3cd_to_options(priv->l3cd, nm_dhcp_config_get_addr_family(self));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_dhcp_config_init(NMDhcpConfig *self)
{}

NMDhcpConfig *
nm_dhcp_config_new(int addr_family, const NML3ConfigData *l3cd)
{
    return g_object_new(NM_IS_IPv4(addr_family) ? NM_TYPE_DHCP4_CONFIG : NM_TYPE_DHCP6_CONFIG,
                        NM_DHCP_CONFIG_L3CD,
                        l3cd,
                        NULL);
}

static void
finalize(GObject *object)
{
    NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE(object);

    g_variant_unref(priv->options);

    nm_l3_config_data_unref(priv->l3cd);

    G_OBJECT_CLASS(nm_dhcp_config_parent_class)->finalize(object);
}

static void
nm_dhcp_config_class_init(NMDhcpConfigClass *config_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(config_class);

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    obj_properties[PROP_L3CD] =
        g_param_spec_pointer(NM_DHCP_CONFIG_L3CD,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_OPTIONS] = g_param_spec_variant(NM_DHCP_CONFIG_OPTIONS,
                                                        "",
                                                        "",
                                                        G_VARIANT_TYPE("a{sv}"),
                                                        NULL,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

struct _NMDhcp4Config {
    NMDhcpConfig parent;
};

struct _NMDhcp4ConfigClass {
    NMDhcpConfigClass parent;
};

G_DEFINE_TYPE(NMDhcp4Config, nm_dhcp4_config, NM_TYPE_DHCP_CONFIG)

static void
nm_dhcp4_config_init(NMDhcp4Config *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_dhcp4_config = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DHCP4_CONFIG,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Options",
                                                           "a{sv}",
                                                           NM_DHCP_CONFIG_OPTIONS), ), ),
};

static void
nm_dhcp4_config_class_init(NMDhcp4ConfigClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDhcpConfigClass *dhcp_config_class = NM_DHCP_CONFIG_CLASS(klass);

    dbus_object_class->export_path     = NM_DBUS_EXPORT_PATH_NUMBERED(NM_DBUS_PATH "/DHCP4Config");
    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_dhcp4_config);
    dbus_object_class->export_on_construction = TRUE;

    dhcp_config_class->addr_family = AF_INET;
}

/*****************************************************************************/

struct _NMDhcp6Config {
    NMDhcpConfig parent;
};

struct _NMDhcp6ConfigClass {
    NMDhcpConfigClass parent;
};

G_DEFINE_TYPE(NMDhcp6Config, nm_dhcp6_config, NM_TYPE_DHCP_CONFIG)

static void
nm_dhcp6_config_init(NMDhcp6Config *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_dhcp6_config = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DHCP6_CONFIG,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Options",
                                                           "a{sv}",
                                                           NM_DHCP_CONFIG_OPTIONS), ), ),
};

static void
nm_dhcp6_config_class_init(NMDhcp6ConfigClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDhcpConfigClass *dhcp_config_class = NM_DHCP_CONFIG_CLASS(klass);

    dbus_object_class->export_path     = NM_DBUS_EXPORT_PATH_NUMBERED(NM_DBUS_PATH "/DHCP6Config");
    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_dhcp6_config);
    dbus_object_class->export_on_construction = TRUE;

    dhcp_config_class->addr_family = AF_INET6;
}
