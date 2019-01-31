/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2011 - 2013 Red Hat, Inc.
 * Copyright 2009 Novell, Inc.
 */

#include "nm-default.h"

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

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_NETWORK_NAME,
	PROP_MAC_ADDRESS,
);

typedef struct {
	char *network_name;
	char *mac_address;
} NMSettingWimaxPrivate;

G_DEFINE_TYPE (NMSettingWimax, nm_setting_wimax, NM_TYPE_SETTING)

#define NM_SETTING_WIMAX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIMAX, NMSettingWimaxPrivate))

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
nm_setting_wimax_get_network_name (NMSettingWimax *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIMAX (setting), NULL);

	return NM_SETTING_WIMAX_GET_PRIVATE (setting)->network_name;
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
nm_setting_wimax_get_mac_address (NMSettingWimax *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIMAX (setting), NULL);

	return NM_SETTING_WIMAX_GET_PRIVATE (setting)->mac_address;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE (setting);

	if (!priv->network_name) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIMAX_SETTING_NAME, NM_SETTING_WIMAX_NETWORK_NAME);
		return FALSE;
	}

	if (!strlen (priv->network_name)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIMAX_SETTING_NAME, NM_SETTING_WIMAX_NETWORK_NAME);
		return FALSE;
	}

	if (priv->mac_address && !nm_utils_hwaddr_valid (priv->mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIMAX_SETTING_NAME, NM_SETTING_WIMAX_MAC_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingWimax *setting = NM_SETTING_WIMAX (object);

	switch (prop_id) {
	case PROP_NETWORK_NAME:
		g_value_set_string (value, nm_setting_wimax_get_network_name (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_wimax_get_mac_address (setting));
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
	NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NETWORK_NAME:
		g_free (priv->network_name);
		priv->network_name = g_value_dup_string (value);
		break;
	case PROP_MAC_ADDRESS:
		g_free (priv->mac_address);
		priv->mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                           ETH_ALEN);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_wimax_init (NMSettingWimax *setting)
{
}

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
nm_setting_wimax_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIMAX, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE (object);

	g_free (priv->network_name);
	g_free (priv->mac_address);

	G_OBJECT_CLASS (nm_setting_wimax_parent_class)->finalize (object);
}

static void
nm_setting_wimax_class_init (NMSettingWimaxClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingWimaxPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/**
	 * NMSettingWimax:network-name:
	 *
	 * Network Service Provider (NSP) name of the WiMAX network this connection
	 * should use.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	obj_properties[PROP_NETWORK_NAME] =
	    g_param_spec_string (NM_SETTING_WIMAX_NETWORK_NAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWimax:mac-address:
	 *
	 * If specified, this connection will only apply to the WiMAX device whose
	 * MAC address matches. This property does not change the MAC address of the
	 * device (known as MAC spoofing).
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	obj_properties[PROP_MAC_ADDRESS] =
	    g_param_spec_string (NM_SETTING_WIMAX_MAC_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_MAC_ADDRESS],
	                                    G_VARIANT_TYPE_BYTESTRING,
	                                    _nm_utils_hwaddr_to_dbus,
	                                    _nm_utils_hwaddr_from_dbus);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_WIMAX,
	                               NULL, properties_override);
}
