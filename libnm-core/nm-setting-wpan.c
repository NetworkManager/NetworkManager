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
 * Copyright 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#include "nm-default.h"

#include "nm-setting-wpan.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

/* Ideally we'll be able to get this from a public header. */
#ifndef IEEE802154_ADDR_LEN
#define IEEE802154_ADDR_LEN 8
#endif

enum {
	PROP_0,
	PROP_MAC_ADDRESS,
	PROP_PAN_ID,
	PROP_SHORT_ADDRESS,
};

typedef struct {
	char *mac_address;
	guint16 pan_id;
	guint16 short_address;
} NMSettingWpanPrivate;

/**
 * NMSettingWpan:
 *
 * IEEE 802.15.4 (WPAN) MAC Settings
 */
struct _NMSettingWpan {
        NMSetting parent;
};

struct _NMSettingWpanClass {
        NMSettingClass parent;
};

/**
 * SECTION:nm-setting-wpan
 * @short_description: Describes connection properties for IEEE 802.15.4 (WPAN) MAC
 *
 * The #NMSettingWpan object is a #NMSetting subclass that describes properties
 * necessary for configuring IEEE 802.15.4 (WPAN) MAC layer devices.
 **/

G_DEFINE_TYPE (NMSettingWpan, nm_setting_wpan, NM_TYPE_SETTING)

#define NM_SETTING_WPAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WPAN, NMSettingWpanPrivate))

/**
 * nm_setting_wpan_get_mac_address:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:mac-address property of the setting
 *
 * Since: 1.14
 **/
const char *
nm_setting_wpan_get_mac_address (NMSettingWpan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WPAN (setting), NULL);

	return NM_SETTING_WPAN_GET_PRIVATE (setting)->mac_address;
}

/**
 * nm_setting_wpan_get_pan_id:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:pan-id property of the setting
 *
 * Since: 1.14
 **/
guint16
nm_setting_wpan_get_pan_id (NMSettingWpan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WPAN (setting), G_MAXUINT16);

	return NM_SETTING_WPAN_GET_PRIVATE (setting)->pan_id;
}

/**
 * nm_setting_wpan_get_short_address:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:short-address property of the setting
 *
 * Since: 1.14
 **/
guint16
nm_setting_wpan_get_short_address (NMSettingWpan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WPAN (setting), G_MAXUINT16);

	return NM_SETTING_WPAN_GET_PRIVATE (setting)->short_address;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWpanPrivate *priv = NM_SETTING_WPAN_GET_PRIVATE (setting);

	if (priv->mac_address && !nm_utils_hwaddr_valid (priv->mac_address, IEEE802154_ADDR_LEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WPAN_SETTING_NAME, NM_SETTING_WPAN_MAC_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	NMSettingWpan *setting = NM_SETTING_WPAN (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_wpan_get_mac_address (setting));
		break;
	case PROP_PAN_ID:
		g_value_set_uint (value, nm_setting_wpan_get_pan_id (setting));
		break;
	case PROP_SHORT_ADDRESS:
		g_value_set_uint (value, nm_setting_wpan_get_short_address (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NMSettingWpanPrivate *priv = NM_SETTING_WPAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_free (priv->mac_address);
		priv->mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                           IEEE802154_ADDR_LEN);
		break;
	case PROP_PAN_ID:
		priv->pan_id = g_value_get_uint (value);
		break;
	case PROP_SHORT_ADDRESS:
		priv->short_address = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wpan_init (NMSettingWpan *setting)
{
	NMSettingWpanPrivate *priv = NM_SETTING_WPAN_GET_PRIVATE (setting);

	priv->short_address = G_MAXUINT16;
	priv->pan_id = G_MAXUINT16;
}

/**
 * nm_setting_wpan_new:
 *
 * Creates a new #NMSettingWpan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWpan object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_wpan_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WPAN, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingWpanPrivate *priv = NM_SETTING_WPAN_GET_PRIVATE (object);

	g_free (priv->mac_address);

	G_OBJECT_CLASS (nm_setting_wpan_parent_class)->finalize (object);
}

static void
nm_setting_wpan_class_init (NMSettingWpanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	g_type_class_add_private (setting_class, sizeof (NMSettingWpanPrivate));

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/**
	 * NMSettingWpan:mac-address:
	 *
	 * If specified, this connection will only apply to the IEEE 802.15.4 (WPAN)
	 * MAC layer device whose permanent MAC address matches.
	 **/
	/* ---keyfile---
	 * property: mac-address
	 * format: usual hex-digits-and-colons notation
	 * description: MAC address in hex-digits-and-colons notation
	 *   (e.g. 76:d8:9b:87:66:60:84:ee).
	 * ---end---
	 */
	g_object_class_install_property
	        (object_class, PROP_MAC_ADDRESS,
	         g_param_spec_string (NM_SETTING_WPAN_MAC_ADDRESS, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWpan:pan-id:
	 *
	 * IEEE 802.15.4 Personal Area Network (PAN) identifier.
	 **/
	g_object_class_install_property
	        (object_class, PROP_PAN_ID,
	         g_param_spec_uint (NM_SETTING_WPAN_PAN_ID, "", "",
	                            0, G_MAXUINT16, G_MAXUINT16,
	                            G_PARAM_READWRITE |
	                            G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWpan:short-address:
	 *
	 * Short IEEE 802.15.4 address to be used within a restricted environment.
	 **/
	g_object_class_install_property
	        (object_class, PROP_SHORT_ADDRESS,
	         g_param_spec_uint (NM_SETTING_WPAN_SHORT_ADDRESS, "", "",
	                            0, G_MAXUINT16, G_MAXUINT16,
	                            G_PARAM_READWRITE |
	                            G_PARAM_STATIC_STRINGS));

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_WPAN);
}
