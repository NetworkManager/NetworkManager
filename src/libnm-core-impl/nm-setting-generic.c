/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-generic.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-generic
 * @short_description: Describes connection properties for generic devices
 *
 * The #NMSettingGeneric object is a #NMSetting subclass that describes
 * optional properties that apply to "generic" devices (ie, devices that
 * NetworkManager does not specifically recognize).
 *
 * There are currently no properties on this object; it exists only to be
 * the "connection type" setting on #NMConnections for generic devices.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingGeneric, PROP_DEVICE_HANDLER, );

typedef struct {
    char *device_handler;
} NMSettingGenericPrivate;

/**
 * NMSettingGeneric:
 *
 * Generic Link Settings
 */
struct _NMSettingGeneric {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingGenericClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingGeneric, nm_setting_generic, NM_TYPE_SETTING)

#define NM_SETTING_GENERIC_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_GENERIC, NMSettingGenericPrivate))

/*****************************************************************************/

/**
 * nm_setting_generic_get_device_handler:
 * @setting: the #NMSettingGeneric
 *
 * Returns the #NMSettingGeneric:device-handler property of the connection.
 *
 * Returns: the device handler
 *
 * Since: 1.46
 **/
const char *
nm_setting_generic_get_device_handler(NMSettingGeneric *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENERIC(setting), NULL);

    return NM_SETTING_GENERIC_GET_PRIVATE(setting)->device_handler;
}

/*****************************************************************************/

static void
nm_setting_generic_init(NMSettingGeneric *setting)
{}

/**
 * nm_setting_generic_new:
 *
 * Creates a new #NMSettingGeneric object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingGeneric object
 **/
NMSetting *
nm_setting_generic_new(void)
{
    return g_object_new(NM_TYPE_SETTING_GENERIC, NULL);
}

static void
nm_setting_generic_class_init(NMSettingGenericClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingGenericPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    /**
     * NMSettingGeneric:device-handler:
     *
     * Name of the device handler that will be invoked to add and delete
     * the device for this connection. See the NetworkManager-dispatcher man
     * page for more details about how to write the device handler.
     *
     * By setting this property the generic connection becomes "virtual",
     * meaning that it can be activated without an existing device; the device
     * will be created at the time the connection is started by invoking the
     * device-handler.
     *
     * Since: 1.46
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GENERIC_DEVICE_HANDLER,
                                              PROP_DEVICE_HANDLER,
                                              NM_SETTING_PARAM_FUZZY_IGNORE
                                                  | NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingGenericPrivate,
                                              device_handler);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_GENERIC,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
