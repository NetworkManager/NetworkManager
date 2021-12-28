/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2020 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-veth.h"

#include <stdlib.h>

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-veth
 * @short_description: Describes connection properties for veth interfaces
 *
 * The #NMSettingVeth object is a #NMSetting subclass that describes properties
 * necessary for connection to veth interfaces.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PEER, );

typedef struct {
    char *peer;
} NMSettingVethPrivate;

/**
 * NMSettingVeth:
 *
 * Veth Settings
 */
struct _NMSettingVeth {
    NMSetting            parent;
    NMSettingVethPrivate _priv;
};

struct _NMSettingVethClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingVeth, nm_setting_veth, NM_TYPE_SETTING)

#define NM_SETTING_VETH_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingVeth, NM_IS_SETTING_VETH, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_veth_get_peer:
 * @setting: the #NMSettingVeth
 *
 * Returns: the #NMSettingVeth:peer property of the setting
 *
 * Since: 1.30
 **/
const char *
nm_setting_veth_get_peer(NMSettingVeth *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VETH(setting), NULL);

    return NM_SETTING_VETH_GET_PRIVATE(setting)->peer;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingVethPrivate *priv = NM_SETTING_VETH_GET_PRIVATE(setting);

    if (!priv->peer) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("property is not specified"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_VETH_SETTING_NAME, NM_SETTING_VETH_PEER);
        return FALSE;
    }

    if (!nm_utils_ifname_valid(priv->peer, NMU_IFACE_KERNEL, NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid interface name"),
                    priv->peer);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_VETH_SETTING_NAME, NM_SETTING_VETH_PEER);
        return FALSE;
    }

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_veth_init(NMSettingVeth *setting)
{}

/**
 * nm_setting_veth_new:
 *
 * Creates a new #NMSettingVeth object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingVeth object
 *
 * Since: 1.30
 **/
NMSetting *
nm_setting_veth_new(void)
{
    return g_object_new(NM_TYPE_SETTING_VETH, NULL);
}

static void
nm_setting_veth_class_init(NMSettingVethClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingVeth:peer:
     *
     * This property specifies the peer interface name of the veth. This
     * property is mandatory.
     *
     * Since: 1.30
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_VETH_PEER,
                                              PROP_PEER,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVeth,
                                              _priv.peer);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_VETH,
                             NULL,
                             properties_override,
                             0);
}
