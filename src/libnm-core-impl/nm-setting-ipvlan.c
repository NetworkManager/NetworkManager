/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ipvlan.h"

#include "nm-connection-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-ipvlan
 * @short_description: Describes connection properties for IPVLAN interfaces
 *
 * The #NMSettingIpvlan object is a #NMSetting subclass that describes properties
 * necessary for connection to IPVLAN interfaces.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT, PROP_MODE, PROP_PRIVATE, PROP_VEPA, );

typedef struct {
    char   *parent;
    guint32 mode;
    bool    private_flag;
    bool    vepa;
} NMSettingIpvlanPrivate;

/**
 * NMSettingIpvlan:
 *
 * IPVLAN Settings
 */
struct _NMSettingIpvlan {
    NMSetting              parent;
    NMSettingIpvlanPrivate _priv;
};

struct _NMSettingIpvlanClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingIpvlan, nm_setting_ipvlan, NM_TYPE_SETTING)

#define NM_SETTING_IPVLAN_GET_PRIVATE(o) \
    _NM_GET_PRIVATE(o, NMSettingIpvlan, NM_IS_SETTING_IPVLAN, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_ipvlan_get_parent:
 * @setting: the #NMSettingIpvlan
 *
 * Returns: the #NMSettingIpvlan:parent property of the setting
 *
 * Since: 1.52
 **/
const char *
nm_setting_ipvlan_get_parent(NMSettingIpvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IPVLAN(setting), NULL);

    return NM_SETTING_IPVLAN_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_ipvlan_get_mode:
 * @setting: the #NMSettingIpvlan
 *
 * Returns: the #NMSettingIpvlan:mode property of the setting
 *
 * Since: 1.52
 **/
NMSettingIpvlanMode
nm_setting_ipvlan_get_mode(NMSettingIpvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IPVLAN(setting), NM_SETTING_IPVLAN_MODE_UNKNOWN);

    return NM_SETTING_IPVLAN_GET_PRIVATE(setting)->mode;
}

/**
 * nm_setting_ipvlan_get_private:
 * @setting: the #NMSettingIpvlan
 *
 * Returns: the #NMSettingIpvlan:private property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_ipvlan_get_private(NMSettingIpvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IPVLAN(setting), FALSE);

    return NM_SETTING_IPVLAN_GET_PRIVATE(setting)->private_flag;
}

/**
 * nm_setting_ipvlan_get_vepa:
 * @setting: the #NMSettingIpvlan
 *
 * Returns: the #NMSettingIpvlan:vepa property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_ipvlan_get_vepa(NMSettingIpvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IPVLAN(setting), FALSE);

    return NM_SETTING_IPVLAN_GET_PRIVATE(setting)->vepa;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingIpvlanPrivate *priv    = NM_SETTING_IPVLAN_GET_PRIVATE(setting);
    NMSettingWired         *s_wired = NULL;

    if (connection)
        s_wired = nm_connection_get_setting_wired(connection);

    if (priv->parent) {
        if (!nm_utils_is_uuid(priv->parent) && !nm_utils_ifname_valid_kernel(priv->parent, NULL)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is neither an UUID nor an interface name"),
                        priv->parent);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IPVLAN_SETTING_NAME,
                           NM_SETTING_IPVLAN_PARENT);
            return FALSE;
        }
    } else {
        /* If parent is NULL, the parent must be specified via NMSettingWired:mac-address. */
        if (connection && (!s_wired || !nm_setting_wired_get_mac_address(s_wired))) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_PROPERTY,
                        _("property is not specified and neither is '%s:%s'"),
                        NM_SETTING_WIRED_SETTING_NAME,
                        NM_SETTING_WIRED_MAC_ADDRESS);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IPVLAN_SETTING_NAME,
                           NM_SETTING_IPVLAN_PARENT);
            return FALSE;
        }
    }

    if (!NM_IN_SET(priv->mode,
                   NM_SETTING_IPVLAN_MODE_L2,
                   NM_SETTING_IPVLAN_MODE_L3,
                   NM_SETTING_IPVLAN_MODE_L3S)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("unsupported mode %u"),
                    priv->mode);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_IPVLAN_SETTING_NAME, NM_SETTING_IPVLAN_MODE);
        return FALSE;
    }

    if (priv->private_flag && priv->vepa) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("private and VEPA cannot be enabled at the same time"));
        g_prefix_error(error, "%s: ", NM_SETTING_IPVLAN_SETTING_NAME);
        return FALSE;
    }

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ipvlan_init(NMSettingIpvlan *self)
{}

/**
 * nm_setting_ipvlan_new:
 *
 * Creates a new #NMSettingIpvlan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIpvlan object
 *
 * Since: 1.52
 **/
NMSetting *
nm_setting_ipvlan_new(void)
{
    return g_object_new(NM_TYPE_SETTING_IPVLAN, NULL);
}

static void
nm_setting_ipvlan_class_init(NMSettingIpvlanClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingIpvlan:parent:
     *
     * If given, specifies the parent interface name or parent connection UUID
     * from which this IPVLAN interface should be created. If this property is
     * not specified, the connection must contain an #NMSettingWired setting
     * with a #NMSettingWired:mac-address property.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IPVLAN_PARENT,
                                              PROP_PARENT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIpvlanPrivate,
                                              parent,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingIpvlan:mode:
     *
     * The IPVLAN mode. Valid values: %NM_SETTING_IPVLAN_MODE_L2,
     * %NM_SETTING_IPVLAN_MODE_L3 and %NM_SETTING_IPVLAN_MODE_L3S.
     *
     * Since: 1.52
     **/
    /* ---nmcli---
     * property: mode
     * description:
     *   The IPVLAN mode. Valid values: l2 (1), l3 (2), l3s (3)
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IPVLAN_MODE,
                                              PROP_MODE,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_IPVLAN_MODE_UNKNOWN,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIpvlanPrivate,
                                              mode);

    /**
     * NMSettingIpvlan:private:
     *
     * Whether the interface should be put in private mode.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_IPVLAN_PRIVATE,
                                               PROP_PRIVATE,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingIpvlanPrivate,
                                               private_flag);

    /**
     * NMSettingIpvlan:vepa:
     *
     * Whether the interface should be put in VEPA mode.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_IPVLAN_VEPA,
                                               PROP_VEPA,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingIpvlanPrivate,
                                               vepa);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_IPVLAN,
                             NULL,
                             properties_override,
                             G_STRUCT_OFFSET(NMSettingIpvlan, _priv));
}
