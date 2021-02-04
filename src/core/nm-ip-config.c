/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ip-config.h"

#include "nm-l3cfg.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMIPConfig, PROP_L3CFG, PROP_IS_VPN, );

typedef struct _NMIPConfigPrivate {
    NML3Cfg *l3cfg;
    bool     is_vpn : 1;
} NMIPConfigPrivate;

G_DEFINE_ABSTRACT_TYPE(NMIPConfig, nm_ip_config, NM_TYPE_DBUS_OBJECT)

#define NM_IP_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMIPConfig, NM_IS_IP_CONFIG)

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    (void) priv;
    switch (prop_id) {
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_L3CFG:
        /* construct-only */
        priv->l3cfg = nm_g_object_ref(g_value_get_pointer(value));
        nm_assert(!priv->l3cfg || NM_IS_L3CFG(priv->l3cfg));
        break;
    case PROP_IS_VPN:
        /* construct-only */
        priv->is_vpn = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_ip_config_init(NMIPConfig *self)
{
    NMIPConfigPrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_IP_CONFIG, NMIPConfigPrivate);

    self->_priv = priv;
}

NMIPConfig *
nm_ip_config_new(int addr_family, NML3Cfg *l3cfg, gboolean is_vpn)
{
    nm_assert_addr_family(addr_family);
    nm_assert(NM_L3CFG(l3cfg));

    return g_object_new(NM_IS_IPv4(addr_family) ? nm_ip4_config_get_type()
                                                : nm_ip6_config_get_type(),
                        NM_IP_CONFIG_L3CFG,
                        l3cfg,
                        NM_IP_CONFIG_IS_VPN,
                        is_vpn,
                        NULL);
}

static void
finalize(GObject *object)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    nm_g_object_unref(priv->l3cfg);

    G_OBJECT_CLASS(nm_ip_config_parent_class)->finalize(object);
}

static void
nm_ip_config_class_init(NMIPConfigClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    g_type_class_add_private(object_class, sizeof(NMIPConfigPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    obj_properties[PROP_L3CFG] =
        g_param_spec_pointer(NM_IP_CONFIG_L3CFG,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_IS_VPN] =
        g_param_spec_boolean(NM_IP_CONFIG_IS_VPN,
                             "",
                             "",
                             FALSE,
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
