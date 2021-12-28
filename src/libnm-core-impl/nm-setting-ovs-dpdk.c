/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ovs-dpdk.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-ovs-dpdk
 * @short_description: Describes connection properties for Open vSwitch DPDK interfaces.
 *
 * The #NMSettingOvsDpdk object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch interfaces of type "dpdk".
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_DEVARGS, PROP_N_RXQ, );

/**
 * NMSettingOvsDpdk:
 *
 * OvsDpdk Link Settings
 */
struct _NMSettingOvsDpdk {
    NMSetting parent;

    char   *devargs;
    guint32 n_rxq;
};

struct _NMSettingOvsDpdkClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsDpdk, nm_setting_ovs_dpdk, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_dpdk_get_devargs:
 * @self: the #NMSettingOvsDpdk
 *
 * Returns: the #NMSettingOvsDpdk:devargs property of the setting
 *
 * Since: 1.20
 **/
const char *
nm_setting_ovs_dpdk_get_devargs(NMSettingOvsDpdk *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_DPDK(self), NULL);

    return self->devargs;
}

/**
 * nm_setting_ovs_dpdk_get_n_rxq:
 * @self: the #NMSettingOvsDpdk
 *
 * Returns: the #NMSettingOvsDpdk:n-rxq property of the setting
 *
 * Since: 1.36
 **/
guint32
nm_setting_ovs_dpdk_get_n_rxq(NMSettingOvsDpdk *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_DPDK(self), 0);

    return self->n_rxq;
}

/*****************************************************************************/

static void
nm_setting_ovs_dpdk_init(NMSettingOvsDpdk *self)
{}

/**
 * nm_setting_ovs_dpdk_new:
 *
 * Creates a new #NMSettingOvsDpdk object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsDpdk object
 *
 * Since: 1.20
 **/
NMSetting *
nm_setting_ovs_dpdk_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_DPDK, NULL);
}

static void
nm_setting_ovs_dpdk_class_init(NMSettingOvsDpdkClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    /**
     * NMSettingOvsDpdk:devargs:
     *
     * Open vSwitch DPDK device arguments.
     *
     * Since: 1.20
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_DPDK_DEVARGS,
                                              PROP_DEVARGS,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsDpdk,
                                              devargs);

    /**
     * NMSettingOvsDpdk:n-rxq:
     *
     * Open vSwitch DPDK number of rx queues.
     * Defaults to zero which means to leave the parameter in OVS unspecified
     * and effectively configures one queue.
     *
     * Since: 1.36
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_DPDK_N_RXQ,
                                              PROP_N_RXQ,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsDpdk,
                                              n_rxq);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OVS_DPDK,
                             NULL,
                             properties_override,
                             0);
}
