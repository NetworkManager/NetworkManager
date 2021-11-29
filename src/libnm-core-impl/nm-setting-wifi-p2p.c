/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-wifi-p2p.h"

#include <net/ethernet.h>

#include "nm-utils.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wifi-p2p
 * @short_description: Describes connection properties for 802.11 Wi-Fi P2P networks
 *
 * The #NMSettingWifiP2P object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.11 Wi-Fi P2P networks (aka Wi-Fi Direct).
 **/

/**
 * NMSettingWifiP2P:
 *
 * Wi-Fi P2P Settings
 *
 * Since: 1.16
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PEER, PROP_WPS_METHOD, PROP_WFD_IES, );

typedef struct {
    char   *peer;
    GBytes *wfd_ies;
    guint32 wps_method;
} NMSettingWifiP2PPrivate;

struct _NMSettingWifiP2P {
    NMSetting               parent;
    NMSettingWifiP2PPrivate _priv;
};

struct _NMSettingWifiP2PClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingWifiP2P, nm_setting_wifi_p2p, NM_TYPE_SETTING)

#define NM_SETTING_WIFI_P2P_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingWifiP2P, NM_IS_SETTING_WIFI_P2P, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_wifi_p2p_get_peer:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:peer property of the setting
 *
 * Since: 1.16
 **/
const char *
nm_setting_wifi_p2p_get_peer(NMSettingWifiP2P *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIFI_P2P(setting), NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE(setting)->peer;
}

/**
 * nm_setting_wifi_p2p_get_wps_method:
 * @setting: the #NMSettingWifiP2P
 *
 * Returns: the #NMSettingWifiP2P:wps-method property of the setting
 *
 * Since: 1.16
 **/
NMSettingWirelessSecurityWpsMethod
nm_setting_wifi_p2p_get_wps_method(NMSettingWifiP2P *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIFI_P2P(setting),
                         NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE(setting)->wps_method;
}

/**
 * nm_setting_wifi_p2p_get_wfd_ies:
 * @setting: the #NMSettingWiFiP2P
 *
 * Returns: (transfer none): the #NMSettingWiFiP2P:wfd-ies property of the setting
 *
 * Since: 1.16
 **/
GBytes *
nm_setting_wifi_p2p_get_wfd_ies(NMSettingWifiP2P *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIFI_P2P(setting), NULL);

    return NM_SETTING_WIFI_P2P_GET_PRIVATE(setting)->wfd_ies;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingWifiP2PPrivate *priv = NM_SETTING_WIFI_P2P_GET_PRIVATE(setting);

    if (!priv->peer) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIFI_P2P_SETTING_NAME,
                       NM_SETTING_WIFI_P2P_PEER);
        return FALSE;
    }

    if (!nm_utils_hwaddr_valid(priv->peer, ETH_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIFI_P2P_SETTING_NAME,
                       NM_SETTING_WIFI_P2P_PEER);
        return FALSE;
    }

    if (!_nm_utils_wps_method_validate(priv->wps_method,
                                       NM_SETTING_WIFI_P2P_SETTING_NAME,
                                       NM_SETTING_WIFI_P2P_WPS_METHOD,
                                       TRUE,
                                       error))
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_wifi_p2p_init(NMSettingWifiP2P *setting)
{}

/**
 * nm_setting_wifi_p2p_new:
 *
 * Creates a new #NMSettingWifiP2P object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWifiP2P object
 *
 * Since: 1.16
 **/
NMSetting *
nm_setting_wifi_p2p_new(void)
{
    return g_object_new(NM_TYPE_SETTING_WIFI_P2P, NULL);
}

static void
nm_setting_wifi_p2p_class_init(NMSettingWifiP2PClass *setting_wifi_p2p_class)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(setting_wifi_p2p_class);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(setting_wifi_p2p_class);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingWifiP2P:peer:
     *
     * The P2P device that should be connected to. Currently, this is the only
     * way to create or join a group.
     *
     * Since: 1.16
     */
    /* ---keyfile---
     * property: peer
     * format: usual hex-digits-and-colons notation
     * description: MAC address in traditional hex-digits-and-colons notation
     *   (e.g. 00:22:68:12:79:A2), or semicolon separated list of 6 bytes (obsolete)
     *   (e.g. 0;34;104;18;121;162).
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIFI_P2P_PEER,
                                              PROP_PEER,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWifiP2P,
                                              _priv.peer);

    /**
     * NMSettingWifiP2P:wps-method:
     *
     * Flags indicating which mode of WPS is to be used.
     *
     * There's little point in changing the default setting as NetworkManager will
     * automatically determine the best method to use.
     *
     * Since: 1.16
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIFI_P2P_WPS_METHOD,
                                              PROP_WPS_METHOD,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingWifiP2P,
                                              _priv.wps_method);

    /**
     * NMSettingWifiP2P:wfd-ies:
     *
     * The Wi-Fi Display (WFD) Information Elements (IEs) to set.
     *
     * Wi-Fi Display requires a protocol specific information element to be
     * set in certain Wi-Fi frames. These can be specified here for the
     * purpose of establishing a connection.
     * This setting is only useful when implementing a Wi-Fi Display client.
     *
     * Since: 1.16
     */
    _nm_setting_property_define_direct_bytes(properties_override,
                                             obj_properties,
                                             NM_SETTING_WIFI_P2P_WFD_IES,
                                             PROP_WFD_IES,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingWifiP2P,
                                             _priv.wfd_ies);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_WIFI_P2P,
                             NULL,
                             properties_override,
                             0);
}
