/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-macvlan.h"

#include <stdlib.h>

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-setting-wired.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-macvlan
 * @short_description: Describes connection properties for macvlan interfaces
 *
 * The #NMSettingMacvlan object is a #NMSetting subclass that describes properties
 * necessary for connection to macvlan interfaces.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT, PROP_MODE, PROP_PROMISCUOUS, PROP_TAP, );

typedef struct {
    char   *parent;
    guint32 mode;
    bool    promiscuous;
    bool    tap;
} NMSettingMacvlanPrivate;

/**
 * NMSettingMacvlan:
 *
 * MAC VLAN Settings
 */
struct _NMSettingMacvlan {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingMacvlanClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingMacvlan, nm_setting_macvlan, NM_TYPE_SETTING)

#define NM_SETTING_MACVLAN_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_MACVLAN, NMSettingMacvlanPrivate))

/*****************************************************************************/

/**
 * nm_setting_macvlan_get_parent:
 * @setting: the #NMSettingMacvlan
 *
 * Returns: the #NMSettingMacvlan:parent property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_macvlan_get_parent(NMSettingMacvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACVLAN(setting), NULL);

    return NM_SETTING_MACVLAN_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_macvlan_get_mode:
 * @setting: the #NMSettingMacvlan
 *
 * Returns: the #NMSettingMacvlan:mode property of the setting
 *
 * Since: 1.2
 **/
NMSettingMacvlanMode
nm_setting_macvlan_get_mode(NMSettingMacvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACVLAN(setting), NM_SETTING_MACVLAN_MODE_UNKNOWN);

    return NM_SETTING_MACVLAN_GET_PRIVATE(setting)->mode;
}

/**
 * nm_setting_macvlan_get_promiscuous:
 * @setting: the #NMSettingMacvlan
 *
 * Returns: the #NMSettingMacvlan:promiscuous property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_macvlan_get_promiscuous(NMSettingMacvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACVLAN(setting), FALSE);
    return NM_SETTING_MACVLAN_GET_PRIVATE(setting)->promiscuous;
}

/**
 * nm_setting_macvlan_get_tap:
 * @setting: the #NMSettingMacvlan
 *
 * Returns: the #NMSettingMacvlan:tap property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_macvlan_get_tap(NMSettingMacvlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACVLAN(setting), FALSE);
    return NM_SETTING_MACVLAN_GET_PRIVATE(setting)->tap;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingMacvlanPrivate *priv = NM_SETTING_MACVLAN_GET_PRIVATE(setting);
    NMSettingWired          *s_wired;

    if (connection)
        s_wired = nm_connection_get_setting_wired(connection);
    else
        s_wired = NULL;

    if (priv->parent) {
        if (!nm_utils_is_uuid(priv->parent) && !nm_utils_ifname_valid_kernel(priv->parent, NULL)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is neither an UUID nor an interface name"),
                        priv->parent);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_MACVLAN_SETTING_NAME,
                           NM_SETTING_MACVLAN_PARENT);
            return FALSE;
        }
    } else {
        /* If parent is NULL, the parent must be specified via
         * NMSettingWired:mac-address.
         */
        if (connection && (!s_wired || !nm_setting_wired_get_mac_address(s_wired))) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_PROPERTY,
                        _("property is not specified and neither is '%s:%s'"),
                        NM_SETTING_WIRED_SETTING_NAME,
                        NM_SETTING_WIRED_MAC_ADDRESS);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_MACVLAN_SETTING_NAME,
                           NM_SETTING_MACVLAN_PARENT);
            return FALSE;
        }
    }

    if (!priv->promiscuous && priv->mode != NM_SETTING_MACVLAN_MODE_PASSTHRU) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("non promiscuous operation is allowed only in passthru mode"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_MACVLAN_SETTING_NAME,
                       NM_SETTING_MACVLAN_PROMISCUOUS);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_macvlan_init(NMSettingMacvlan *self)
{}

/**
 * nm_setting_macvlan_new:
 *
 * Creates a new #NMSettingMacvlan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingMacvlan object
 *
 * Since: 1.2
 **/
NMSetting *
nm_setting_macvlan_new(void)
{
    return g_object_new(NM_TYPE_SETTING_MACVLAN, NULL);
}

static void
nm_setting_macvlan_class_init(NMSettingMacvlanClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingMacvlanPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingMacvlan:parent:
     *
     * If given, specifies the parent interface name or parent connection UUID
     * from which this MAC-VLAN interface should be created.  If this property is
     * not specified, the connection must contain an #NMSettingWired setting
     * with a #NMSettingWired:mac-address property.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_MACVLAN_PARENT,
                                              PROP_PARENT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingMacvlanPrivate,
                                              parent);

    /**
     * NMSettingMacvlan:mode:
     *
     * The macvlan mode, which specifies the communication mechanism between multiple
     * macvlans on the same lower device.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_MACVLAN_MODE,
                                              PROP_MODE,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_MACVLAN_MODE_UNKNOWN,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingMacvlanPrivate,
                                              mode);

    /**
     * NMSettingMacvlan:promiscuous:
     *
     * Whether the interface should be put in promiscuous mode.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_MACVLAN_PROMISCUOUS,
                                               PROP_PROMISCUOUS,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingMacvlanPrivate,
                                               promiscuous);

    /**
     * NMSettingMacvlan:tap:
     *
     * Whether the interface should be a MACVTAP.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_MACVLAN_TAP,
                                               PROP_TAP,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingMacvlanPrivate,
                                               tap);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_MACVLAN,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
