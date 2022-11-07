/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ovs-bridge.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-bridge
 * @short_description: Describes connection properties for Open vSwitch bridges.
 *
 * The #NMSettingOvsBridge object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch bridges.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_FAIL_MODE,
                                  PROP_MCAST_SNOOPING_ENABLE,
                                  PROP_RSTP_ENABLE,
                                  PROP_STP_ENABLE,
                                  PROP_DATAPATH_TYPE, );

/**
 * NMSettingOvsBridge:
 *
 * OvsBridge Link Settings
 */
struct _NMSettingOvsBridge {
    NMSetting parent;

    char *fail_mode;
    char *datapath_type;
    bool  mcast_snooping_enable;
    bool  rstp_enable;
    bool  stp_enable;
};

struct _NMSettingOvsBridgeClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsBridge, nm_setting_ovs_bridge, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_bridge_get_fail_mode:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:fail_mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_bridge_get_fail_mode(NMSettingOvsBridge *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_BRIDGE(self), NULL);

    return self->fail_mode;
}

/**
 * nm_setting_ovs_bridge_get_mcast_snooping_enable:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:mcast_snooping_enable property of the setting
 *
 * Since: 1.10
 **/
gboolean
nm_setting_ovs_bridge_get_mcast_snooping_enable(NMSettingOvsBridge *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_BRIDGE(self), FALSE);

    return self->mcast_snooping_enable;
}

/**
 * nm_setting_ovs_bridge_get_rstp_enable:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:rstp_enable property of the setting
 *
 * Since: 1.10
 **/
gboolean
nm_setting_ovs_bridge_get_rstp_enable(NMSettingOvsBridge *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_BRIDGE(self), FALSE);

    return self->rstp_enable;
}

/**
 * nm_setting_ovs_bridge_get_stp_enable:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:stp_enable property of the setting
 *
 * Since: 1.10
 **/
gboolean
nm_setting_ovs_bridge_get_stp_enable(NMSettingOvsBridge *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_BRIDGE(self), FALSE);

    return self->stp_enable;
}

/**
 * nm_setting_ovs_bridge_get_datapath_type:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:datapath_type property of the setting
 *
 * Since: 1.42
 **/
const char *
nm_setting_ovs_bridge_get_datapath_type(NMSettingOvsBridge *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_BRIDGE(self), NULL);

    return self->datapath_type;
}

/*****************************************************************************/

static int
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingOvsBridge *self = NM_SETTING_OVS_BRIDGE(setting);

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    if (connection) {
        NMSettingConnection *s_con;

        s_con = nm_connection_get_setting_connection(connection);
        if (!s_con) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_SETTING,
                        _("missing setting"));
            g_prefix_error(error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
            return FALSE;
        }

        if (nm_setting_connection_get_master(s_con)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must not have a master."),
                        NM_SETTING_OVS_BRIDGE_SETTING_NAME);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_MASTER);
            return FALSE;
        }
    }

    if (!NM_IN_STRSET(self->fail_mode, "secure", "standalone", NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in fail_mode"),
                    self->fail_mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                       NM_SETTING_OVS_BRIDGE_FAIL_MODE);
        return FALSE;
    }

    if (!NM_IN_STRSET(self->datapath_type, "system", "netdev", NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not valid"),
                    self->datapath_type);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                       NM_SETTING_OVS_BRIDGE_DATAPATH_TYPE);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ovs_bridge_init(NMSettingOvsBridge *self)
{}

/**
 * nm_setting_ovs_bridge_new:
 *
 * Creates a new #NMSettingOvsBridge object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsBridge object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_bridge_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_BRIDGE, NULL);
}

static void
nm_setting_ovs_bridge_class_init(NMSettingOvsBridgeClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingOvsBridge:fail-mode:
     *
     * The bridge failure mode. One of "secure", "standalone" or empty.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_BRIDGE_FAIL_MODE,
                                              PROP_FAIL_MODE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsBridge,
                                              fail_mode);

    /**
     * NMSettingOvsBridge:mcast-snooping-enable:
     *
     * Enable or disable multicast snooping.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_OVS_BRIDGE_MCAST_SNOOPING_ENABLE,
                                               PROP_MCAST_SNOOPING_ENABLE,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingOvsBridge,
                                               mcast_snooping_enable);

    /**
     * NMSettingOvsBridge:rstp-enable:
     *
     * Enable or disable RSTP.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_OVS_BRIDGE_RSTP_ENABLE,
                                               PROP_RSTP_ENABLE,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingOvsBridge,
                                               rstp_enable);

    /**
     * NMSettingOvsBridge:stp-enable:
     *
     * Enable or disable STP.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_OVS_BRIDGE_STP_ENABLE,
                                               PROP_STP_ENABLE,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingOvsBridge,
                                               stp_enable);

    /**
     * NMSettingOvsBridge:datapath-type:
     *
     * The data path type. One of "system", "netdev" or empty.
     *
     * Since: 1.20
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_BRIDGE_DATAPATH_TYPE,
                                              PROP_DATAPATH_TYPE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsBridge,
                                              datapath_type);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OVS_BRIDGE,
                             NULL,
                             properties_override,
                             0);
}
