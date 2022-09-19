/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-connection-private.h"
#include "nm-setting-bond-port.h"
#include "nm-setting-bond.h"
#include "nm-setting-connection.h"
#include "nm-utils-private.h"
#include "nm-utils.h"

/**
 * SECTION:nm-setting-bond-port
 * @short_description: Describes connection properties for bond ports
 *
 * The #NMSettingBondPort object is a #NMSetting subclass that describes
 * optional properties that apply to bond ports.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingBondPort, PROP_QUEUE_ID, );

typedef struct {
    guint32 queue_id;
} NMSettingBondPortPrivate;

/**
 * NMSettingBondPort:
 *
 * Bond Port Settings
 */
struct _NMSettingBondPort {
    NMSetting                parent;
    NMSettingBondPortPrivate _priv;
};

struct _NMSettingBondPortClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingBondPort, nm_setting_bond_port, NM_TYPE_SETTING)

#define NM_SETTING_BOND_PORT_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingBondPort, NM_IS_SETTING_BOND_PORT, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_bond_port_get_queue_id:
 * @setting: the #NMSettingBondPort
 *
 * Returns: the #NMSettingBondPort:queue_id property of the setting
 *
 * Since: 1.34
 **/
guint32
nm_setting_bond_port_get_queue_id(NMSettingBondPort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND_PORT(setting), 0);

    return NM_SETTING_BOND_PORT_GET_PRIVATE(setting)->queue_id;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    if (connection) {
        NMSettingConnection *s_con;
        const char          *slave_type;

        s_con = nm_connection_get_setting_connection(connection);
        if (!s_con) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_SETTING,
                        _("missing setting"));
            g_prefix_error(error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
            return FALSE;
        }

        slave_type = nm_setting_connection_get_slave_type(s_con);
        if (slave_type && !nm_streq(slave_type, NM_SETTING_BOND_SETTING_NAME)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must have the slave-type set to '%s'. "
                          "Instead it is '%s'"),
                        NM_SETTING_BOND_PORT_SETTING_NAME,
                        NM_SETTING_BOND_SETTING_NAME,
                        slave_type);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_SLAVE_TYPE);
            return FALSE;
        }
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_bond_port_init(NMSettingBondPort *setting)
{}

/**
 * nm_setting_bond_port_new:
 *
 * Creates a new #NMSettingBondPort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBondPort object
 *
 * Since: 1.34
 **/
NMSetting *
nm_setting_bond_port_new(void)
{
    return g_object_new(NM_TYPE_SETTING_BOND_PORT, NULL);
}

static void
nm_setting_bond_port_class_init(NMSettingBondPortClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingBondPort:queue-id:
     *
     * The queue ID of this bond port. The maximum value of queue ID is
     * the number of TX queues currently active in device.
     *
     * Since: 1.34
     **/
    /* ---ifcfg-rh---
     * property: queue-id
     * variable: BONDING_OPTS: queue-id=
     * values: 0 - 65535
     * default: 0
     * description: Queue ID.
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_BOND_PORT_QUEUE_ID,
                                              PROP_QUEUE_ID,
                                              0,
                                              G_MAXUINT16,
                                              NM_BOND_PORT_QUEUE_ID_DEF,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingBondPort,
                                              _priv.queue_id);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_BOND_PORT,
                             NULL,
                             properties_override,
                             0);
}
