/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-loopback.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-loopback
 * @short_description: Describes connection properties for loopback interfaces
 *
 * The #NMSettingLoopback object is a #NMSetting subclass that describes properties
 * necessary for connection to loopback devices
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingLoopback, PROP_MTU, );

typedef struct {
    guint32 mtu;
} NMSettingLoopbackPrivate;

/**
 * NMSettingLoopback:
 *
 * Loopback Link Settings
 *
 * Since: 1.42
 */
struct _NMSettingLoopback {
    NMSetting                parent;
    NMSettingLoopbackPrivate _priv;
};

struct _NMSettingLoopbackClass {
    NMSettingClass parent;
};

#define NM_SETTING_LOOPBACK_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingLoopback, NM_IS_SETTING_LOOPBACK)

G_DEFINE_TYPE(NMSettingLoopback, nm_setting_loopback, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_loopback_get_mtu:
 * @setting: the #NMSettingLoopback
 *
 * Returns: the #NMSettingLoopback:mtu property of the setting
 *
 * Since: 1.42
 **/
guint32
nm_setting_loopback_get_mtu(NMSettingLoopback *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_LOOPBACK(setting), 0);

    return NM_SETTING_LOOPBACK_GET_PRIVATE(setting)->mtu;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    if (connection) {
        NMSettingIPConfig   *s_ip4;
        NMSettingIPConfig   *s_ip6;
        NMSettingConnection *s_con;
        const char          *method;

        if ((s_ip4 = nm_connection_get_setting_ip4_config(connection))) {
            if ((method = nm_setting_ip_config_get_method(s_ip4))
                && !NM_IN_STRSET(method,
                                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("ipv4 method \"%s\" is not supported for loopback"),
                            method);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP4_CONFIG_SETTING_NAME,
                               NM_SETTING_IP_CONFIG_METHOD);
                return FALSE;
            }
            if (!NM_IN_SET(nm_setting_ip4_config_get_link_local(NM_SETTING_IP4_CONFIG(s_ip4)),
                           NM_SETTING_IP4_LL_DEFAULT,
                           NM_SETTING_IP4_LL_AUTO,
                           NM_SETTING_IP4_LL_DISABLED)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("ipv4.link-local cannot be enabled for loopback"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP4_CONFIG_SETTING_NAME,
                               NM_SETTING_IP4_CONFIG_LINK_LOCAL);
                return FALSE;
            }
        }
        if ((s_ip6 = nm_connection_get_setting_ip6_config(connection))) {
            if ((method = nm_setting_ip_config_get_method(s_ip6))
                && !NM_IN_STRSET(method,
                                 NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                                 NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("ipv6 method \"%s\" is not supported for loopback"),
                            method);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_IP6_CONFIG_SETTING_NAME,
                               NM_SETTING_IP_CONFIG_METHOD);
                return FALSE;
            }
        }

        if ((s_con = nm_connection_get_setting_connection(connection))) {
            if (nm_setting_connection_get_slave_type(s_con)
                || nm_setting_connection_get_master(s_con)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("a loopback profile cannot be a port"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_CONNECTION_SETTING_NAME,
                               nm_setting_connection_get_slave_type(s_con)
                                   ? NM_SETTING_CONNECTION_SLAVE_TYPE
                                   : NM_SETTING_CONNECTION_MASTER);
                return FALSE;
            }
        }
    }
    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_loopback_init(NMSettingLoopback *setting)
{}

/**
 * nm_setting_loopback_new:
 *
 * Creates a new #NMSettingLoopback object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingLoopback object
 *
 * Since: 1.42
 **/
NMSetting *
nm_setting_loopback_new(void)
{
    return g_object_new(NM_TYPE_SETTING_LOOPBACK, NULL);
}

static void
nm_setting_loopback_class_init(NMSettingLoopbackClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingLoopback:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple Ethernet frames.
     *
     * Since: 1.42
     **/
    /* ---ifcfg-rh---
     * property: mtu
     * variable: MTU
     * description: MTU of the interface.
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_LOOPBACK_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingLoopback,
                                              _priv.mtu);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_LOOPBACK,
                             NULL,
                             properties_override,
                             0);
}
