/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
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
 */
struct _NMSettingLoopback {
    NMSetting parent;
};

struct _NMSettingLoopbackClass {
    NMSettingClass parent;
    gpointer       padding[4];
};

#define NM_SETTING_LOOPBACK_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_LOOPBACK, NMSettingLoopbackPrivate))

G_DEFINE_TYPE(NMSettingLoopback, nm_setting_loopback, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_loopback_get_mtu:
 * @setting: the #NMSettingLoopback
 *
 * Returns: the #NMSettingLoopback:mtu property of the setting
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
    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

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
 * Since: 1.8
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

    g_type_class_add_private(klass, sizeof(NMSettingLoopbackPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingLoopback:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple Ethernet frames.
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
                                              NMSettingLoopbackPrivate,
                                              mtu);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_LOOPBACK,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
