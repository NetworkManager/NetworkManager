/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-p2p-wireless.h"

#include <string.h>
#include <net/ethernet.h>

#include "nm-utils.h"
#include "nm-common-macros.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-p2p-wireless
 * @short_description: Describes connection properties for 802.11 Wi-Fi P2P networks
 *
 * The #NMSettingP2PWireless object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.11 Wi-Fi P2P networks (aka Wi-Fi Direct).
 **/

/**
 * NMSettingP2PWireless:
 *
 * P2P Wi-Fi Settings
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PEER,
	PROP_WPS_METHOD,
#if 0
	PROP_WPS_PIN,
	PROP_WPS_PIN_FLAGS,
#endif
);

typedef struct {
	char *peer_mac_address;

	NMSettingWirelessSecurityWpsMethod wps_method;
} NMSettingP2PWirelessPrivate;

struct _NMSettingP2PWireless {
	NMSetting parent;
	NMSettingP2PWirelessPrivate _priv;
};

struct _NMSettingP2PWirelessClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingP2PWireless, nm_setting_p2p_wireless, NM_TYPE_SETTING)

#define NM_SETTING_P2P_WIRELESS_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettingP2PWireless, NM_IS_SETTING_P2P_WIRELESS, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_p2p_wireless_get_peer:
 * @setting: the #NMSettingP2PWireless
 *
 * Returns: the #NMSettingP2PWireless:peer property of the setting
 *
 * Since: 1.16
 **/
const char *
nm_setting_p2p_wireless_get_peer (NMSettingP2PWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_P2P_WIRELESS (setting), NULL);

	return NM_SETTING_P2P_WIRELESS_GET_PRIVATE (setting)->peer_mac_address;
}

/**
 * nm_setting_p2p_wireless_get_wps_method:
 * @setting: the #NMSettingP2PWireless
 *
 * Returns: the #NMSettingP2PWireless:wps-method property of the setting
 *
 * Since: 1.16
 **/
NMSettingWirelessSecurityWpsMethod
nm_setting_p2p_wireless_get_wps_method (NMSettingP2PWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_P2P_WIRELESS (setting), NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT);

	return NM_SETTING_P2P_WIRELESS_GET_PRIVATE (setting)->wps_method;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingP2PWirelessPrivate *priv = NM_SETTING_P2P_WIRELESS_GET_PRIVATE (setting);

	if (!priv->peer_mac_address || !nm_utils_hwaddr_valid (priv->peer_mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_P2P_WIRELESS_SETTING_NAME, NM_SETTING_P2P_WIRELESS_PEER);
		return FALSE;
	}

	if (priv->wps_method > NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		return FALSE;
	}

	if (priv->wps_method > NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("P2P connections require WPS"));
		return FALSE;
	}

	if (priv->wps_method > NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("P2P connections require WPS"));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingP2PWireless *setting = NM_SETTING_P2P_WIRELESS (object);

	switch (prop_id) {
	case PROP_PEER:
		g_value_set_string (value, nm_setting_p2p_wireless_get_peer (setting));
		break;
	case PROP_WPS_METHOD:
		g_value_set_uint (value, nm_setting_p2p_wireless_get_wps_method (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingP2PWirelessPrivate *priv = NM_SETTING_P2P_WIRELESS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PEER:
		g_free (priv->peer_mac_address);
		priv->peer_mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                                ETH_ALEN);
		break;
	case PROP_WPS_METHOD:
		priv->wps_method = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_p2p_wireless_init (NMSettingP2PWireless *setting)
{
}

/**
 * nm_setting_p2p_wireless_new:
 *
 * Creates a new #NMSettingP2PWireless object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingP2PWireless object
 *
 * Since: 1.16
 **/
NMSetting *
nm_setting_p2p_wireless_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_P2P_WIRELESS, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingP2PWirelessPrivate *priv = NM_SETTING_P2P_WIRELESS_GET_PRIVATE (object);

	g_free (priv->peer_mac_address);

	G_OBJECT_CLASS (nm_setting_p2p_wireless_parent_class)->finalize (object);
}

static void
nm_setting_p2p_wireless_class_init (NMSettingP2PWirelessClass *setting_p2p_wireless_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_p2p_wireless_class);
	NMSettingClass *setting_class = NM_SETTING_CLASS (setting_p2p_wireless_class);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->verify      = verify;

	/**
	 * NMSettingP2PWireless:peer:
	 *
	 * The P2P device that should be connected to. Currently this is the only
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
	obj_properties[PROP_PEER] =
	    g_param_spec_string (NM_SETTING_P2P_WIRELESS_PEER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingP2PWireless:wps-method:
	 *
	 * Flags indicating which mode of WPS is to be used.
	 *
	 * There's little point in changing the default setting as NetworkManager will
	 * automatically determine the best method to use.
	 *
	 * Since: 1.16
	 */
	obj_properties[PROP_WPS_METHOD] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WPS_METHOD, "", "",
	                       0,
	                       G_MAXUINT32,
	                       NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_P2P_WIRELESS);
}
