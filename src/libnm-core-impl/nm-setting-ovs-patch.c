/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ovs-patch.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-patch
 * @short_description: Describes connection properties for Open vSwitch patch interfaces.
 *
 * The #NMSettingOvsPatch object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch interfaces of type "patch".
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PEER, );

/**
 * NMSettingOvsPatch:
 *
 * OvsPatch Link Settings
 */
struct _NMSettingOvsPatch {
    NMSetting parent;

    char *peer;
};

struct _NMSettingOvsPatchClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsPatch, nm_setting_ovs_patch, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_patch_get_peer:
 * @self: the #NMSettingOvsPatch
 *
 * Returns: the #NMSettingOvsPatch:peer property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_patch_get_peer(NMSettingOvsPatch *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PATCH(self), NULL);

    return self->peer;
}

/*****************************************************************************/

static int
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingOvsPatch *self = NM_SETTING_OVS_PATCH(setting);

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    if (!self->peer) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PATCH_SETTING_NAME,
                       NM_SETTING_OVS_PATCH_PEER);
        return FALSE;
    }

    if (!nm_utils_ifname_valid(self->peer, NMU_IFACE_OVS, error)) {
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PATCH_SETTING_NAME,
                       NM_SETTING_OVS_PATCH_PEER);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ovs_patch_init(NMSettingOvsPatch *self)
{}

/**
 * nm_setting_ovs_patch_new:
 *
 * Creates a new #NMSettingOvsPatch object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsPatch object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_patch_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_PATCH, NULL);
}

static void
nm_setting_ovs_patch_class_init(NMSettingOvsPatchClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingOvsPatch:peer:
     *
     * Specifies the name of the interface for the other side of the patch.
     * The patch on the other side must also set this interface as peer.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PATCH_PEER,
                                              PROP_PEER,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPatch,
                                              peer);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OVS_PATCH,
                             NULL,
                             properties_override,
                             0);
}
