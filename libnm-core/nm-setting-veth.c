/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2020 Red Hat, Inc.
 */

#include "libnm-core/nm-default-libnm-core.h"

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
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingVeth *       setting = NM_SETTING_VETH(object);
    NMSettingVethPrivate *priv    = NM_SETTING_VETH_GET_PRIVATE(setting);

    switch (prop_id) {
    case PROP_PEER:
        g_value_set_string(value, priv->peer);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingVeth *       setting = NM_SETTING_VETH(object);
    NMSettingVethPrivate *priv    = NM_SETTING_VETH_GET_PRIVATE(setting);

    switch (prop_id) {
    case PROP_PEER:
        g_free(priv->peer);
        priv->peer = g_value_dup_string(value);
        break;
    }
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
finalize(GObject *object)
{
    NMSettingVeth *       setting = NM_SETTING_VETH(object);
    NMSettingVethPrivate *priv    = NM_SETTING_VETH_GET_PRIVATE(setting);

    g_free(priv->peer);

    G_OBJECT_CLASS(nm_setting_veth_parent_class)->finalize(object);
}

static void
nm_setting_veth_class_init(NMSettingVethClass *klass)
{
    GObjectClass *  object_class  = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class = NM_SETTING_CLASS(klass);

    g_type_class_add_private(klass, sizeof(NMSettingVethPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingVeth:peer:
     *
     * This property specifies the peer interface name of the veth. This
     * property is mandatory.
     *
     * Since: 1.30
     **/
    obj_properties[PROP_PEER] = g_param_spec_string(NM_SETTING_VETH_PEER,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE
                                                        | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class, NM_META_SETTING_TYPE_VETH);
}
