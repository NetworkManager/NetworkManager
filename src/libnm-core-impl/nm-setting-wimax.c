/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2013 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-wimax.h"

#include <net/ethernet.h>

#include "nm-setting-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-wimax
 * @short_description: Describes 802.16e Mobile WiMAX connection properties
 *
 * The #NMSettingWimax object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.16e Mobile WiMAX networks.
 *
 * NetworkManager no longer supports WiMAX; while this API remains available for
 * backward-compatibility reasons, it serves no real purpose, since WiMAX
 * connections cannot be activated.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_NETWORK_NAME, PROP_MAC_ADDRESS, );

typedef struct {
    char *network_name;
    char *mac_address;
} NMSettingWimaxPrivate;

/**
 * NMSettingWimax:
 *
 * WiMax Settings
 */
struct _NMSettingWimax {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingWimaxClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingWimax, nm_setting_wimax, NM_TYPE_SETTING)

#define NM_SETTING_WIMAX_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_WIMAX, NMSettingWimaxPrivate))

/*****************************************************************************/

/**
 * nm_setting_wimax_get_network_name:
 * @setting: the #NMSettingWimax
 *
 * Returns the WiMAX NSP name (ex "Sprint" or "CLEAR") which identifies the
 * specific WiMAX network this setting describes a connection to.
 *
 * Returns: the WiMAX NSP name
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_setting_wimax_get_network_name(NMSettingWimax *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIMAX(setting), NULL);

    return NM_SETTING_WIMAX_GET_PRIVATE(setting)->network_name;
}

/**
 * nm_setting_wimax_get_mac_address:
 * @setting: the #NMSettingWimax
 *
 * Returns the MAC address of a WiMAX device which this connection is locked
 * to.
 *
 * Returns: the MAC address
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_setting_wimax_get_mac_address(NMSettingWimax *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIMAX(setting), NULL);

    return NM_SETTING_WIMAX_GET_PRIVATE(setting)->mac_address;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE(setting);

    if (nm_str_is_empty(priv->network_name)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            !priv->network_name ? _("property is missing")
                                                : _("property is empty"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIMAX_SETTING_NAME,
                       NM_SETTING_WIMAX_NETWORK_NAME);
        return FALSE;
    }

    if (priv->mac_address && !nm_utils_hwaddr_valid(priv->mac_address, ETH_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIMAX_SETTING_NAME,
                       NM_SETTING_WIMAX_MAC_ADDRESS);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_wimax_init(NMSettingWimax *setting)
{}

/**
 * nm_setting_wimax_new:
 *
 * Creates a new #NMSettingWimax object with default values.
 *
 * Returns: the new empty #NMSettingWimax object
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
NMSetting *
nm_setting_wimax_new(void)
{
    return g_object_new(NM_TYPE_SETTING_WIMAX, NULL);
}

static void
nm_setting_wimax_class_init(NMSettingWimaxClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingWimaxPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingWimax:network-name:
     *
     * Network Service Provider (NSP) name of the WiMAX network this connection
     * should use.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIMAX_NETWORK_NAME,
                                              PROP_NETWORK_NAME,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWimaxPrivate,
                                              network_name,
                                              .is_deprecated = TRUE, );

    /**
     * NMSettingWimax:mac-address:
     *
     * If specified, this connection will only apply to the WiMAX device whose
     * MAC address matches. This property does not change the MAC address of the
     * device (known as MAC spoofing).
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    _nm_setting_property_define_direct_mac_address(properties_override,
                                                   obj_properties,
                                                   NM_SETTING_WIMAX_MAC_ADDRESS,
                                                   PROP_MAC_ADDRESS,
                                                   NM_SETTING_PARAM_NONE,
                                                   NMSettingWimaxPrivate,
                                                   mac_address,
                                                   .direct_set_string_mac_address_len = ETH_ALEN,
                                                   .is_deprecated                     = TRUE, );

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_WIMAX,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
