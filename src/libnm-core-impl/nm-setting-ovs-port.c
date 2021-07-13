/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ovs-port.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-port
 * @short_description: Describes connection properties for Open vSwitch ports.
 *
 * The #NMSettingOvsPort object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch ports.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_VLAN_MODE,
                                  PROP_TAG,
                                  PROP_LACP,
                                  PROP_BOND_MODE,
                                  PROP_BOND_UPDELAY,
                                  PROP_BOND_DOWNDELAY, );

/**
 * NMSettingOvsPort:
 *
 * OvsPort Link Settings
 */
struct _NMSettingOvsPort {
    NMSetting parent;

    char *  vlan_mode;
    char *  lacp;
    char *  bond_mode;
    guint32 tag;
    guint32 bond_updelay;
    guint32 bond_downdelay;
};

struct _NMSettingOvsPortClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsPort, nm_setting_ovs_port, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_port_get_vlan_mode:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:vlan-mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_vlan_mode(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->vlan_mode;
}

/**
 * nm_setting_ovs_port_get_tag:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:tag property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_tag(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->tag;
}

/**
 * nm_setting_ovs_port_get_lacp:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:lacp property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_lacp(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->lacp;
}

/**
 * nm_setting_ovs_port_get_bond_mode:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_bond_mode(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->bond_mode;
}

/**
 * nm_setting_ovs_port_get_bond_updelay:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-updelay property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_bond_updelay(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->bond_updelay;
}

/**
 * nm_setting_ovs_port_get_bond_downdelay:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-downdelay property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_bond_downdelay(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->bond_downdelay;
}

/*****************************************************************************/

static int
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingOvsPort *self = NM_SETTING_OVS_PORT(setting);

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    if (connection) {
        NMSettingConnection *s_con;
        const char *         slave_type;

        s_con = nm_connection_get_setting_connection(connection);
        if (!s_con) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_SETTING,
                        _("missing setting"));
            g_prefix_error(error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
            return FALSE;
        }

        if (!nm_setting_connection_get_master(s_con)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must have a master."),
                        NM_SETTING_OVS_PORT_SETTING_NAME);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_MASTER);
            return FALSE;
        }

        slave_type = nm_setting_connection_get_slave_type(s_con);
        if (slave_type && strcmp(slave_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must have the slave-type set to '%s'. "
                          "Instead it is '%s'"),
                        NM_SETTING_OVS_PORT_SETTING_NAME,
                        NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                        slave_type);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_SLAVE_TYPE);
            return FALSE;
        }
    }

    if (!NM_IN_STRSET(self->vlan_mode,
                      "access",
                      "native-tagged",
                      "native-untagged",
                      "trunk",
                      NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in vlan_mode"),
                    self->vlan_mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_VLAN_MODE);
        return FALSE;
    }

    if (self->tag >= 4095) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("the tag id must be in range 0-4094 but is %u"),
                    self->tag);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_OVS_PORT_SETTING_NAME, NM_SETTING_OVS_PORT_TAG);
        return FALSE;
    }

    if (!NM_IN_STRSET(self->lacp, "active", "off", "passive", NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in lacp"),
                    self->lacp);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_LACP);
        return FALSE;
    }

    if (!NM_IN_STRSET(self->bond_mode, "active-backup", "balance-slb", "balance-tcp", NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in bond_mode"),
                    self->bond_mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_BOND_MODE);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ovs_port_init(NMSettingOvsPort *self)
{}

/**
 * nm_setting_ovs_port_new:
 *
 * Creates a new #NMSettingOvsPort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsPort object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_port_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_PORT, NULL);
}

static void
nm_setting_ovs_port_class_init(NMSettingOvsPortClass *klass)
{
    GObjectClass *  object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray *        properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify          = verify;
    setting_class->finalize_direct = TRUE;

    /**
     * NMSettingOvsPort:vlan-mode:
     *
     * The VLAN mode. One of "access", "native-tagged", "native-untagged",
     * "trunk" or unset.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_VLAN_MODE,
                                              PROP_VLAN_MODE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              vlan_mode);

    /**
     * NMSettingOvsPort:tag:
     *
     * The VLAN tag in the range 0-4095.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_TAG,
                                              PROP_TAG,
                                              0,
                                              4095,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              tag);

    /**
     * NMSettingOvsPort:lacp:
     *
     * LACP mode. One of "active", "off", or "passive".
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_LACP,
                                              PROP_LACP,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              lacp);

    /**
     * NMSettingOvsPort:bond-mode:
     *
     * Bonding mode. One of "active-backup", "balance-slb", or "balance-tcp".
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_BOND_MODE,
                                              PROP_BOND_MODE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              bond_mode);

    /**
     * NMSettingOvsPort:bond-updelay:
     *
     * The time port must be active before it starts forwarding traffic.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_BOND_UPDELAY,
                                              PROP_BOND_UPDELAY,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              bond_updelay);

    /**
     * NMSettingOvsPort:bond-downdelay:
     *
     * The time port must be inactive in order to be considered down.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_BOND_DOWNDELAY,
                                              PROP_BOND_DOWNDELAY,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              bond_downdelay);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OVS_PORT,
                             NULL,
                             properties_override,
                             0);
}
