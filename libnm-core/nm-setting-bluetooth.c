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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <net/ethernet.h>

#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-setting-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-bluetooth
 * @short_description: Describes Bluetooth connection properties
 *
 * The #NMSettingBluetooth object is a #NMSetting subclass that describes
 * properties necessary for connection to devices that provide network
 * connections via the Bluetooth Dial-Up Networking (DUN) and Network Access
 * Point (NAP) profiles.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingBluetooth, nm_setting_bluetooth, NM_TYPE_SETTING,
                         _nm_register_setting (BLUETOOTH, 1))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_BLUETOOTH)

#define NM_SETTING_BLUETOOTH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothPrivate))

typedef struct {
	char *bdaddr;
	char *type;
} NMSettingBluetoothPrivate;

enum {
	PROP_0,
	PROP_BDADDR,
	PROP_TYPE,

	LAST_PROP
};

/**
 * nm_setting_bluetooth_new:
 *
 * Creates a new #NMSettingBluetooth object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBluetooth object
 **/
NMSetting *nm_setting_bluetooth_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BLUETOOTH, NULL);
}

/**
 * nm_setting_bluetooth_get_connection_type:
 * @setting: the #NMSettingBluetooth
 *
 * Returns the connection method for communicating with the remote device (i.e.
 * either DUN to a DUN-capable device or PANU to a NAP-capable device).
 *
 * Returns: the type, either %NM_SETTING_BLUETOOTH_TYPE_PANU or
 * %NM_SETTING_BLUETOOTH_TYPE_DUN
 **/
const char *
nm_setting_bluetooth_get_connection_type (NMSettingBluetooth *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (setting), NULL);

	return NM_SETTING_BLUETOOTH_GET_PRIVATE (setting)->type;
}

/**
 * nm_setting_bluetooth_get_bdaddr:
 * @setting: the #NMSettingBluetooth
 *
 * Gets the Bluetooth address of the remote device which this setting
 * describes a connection to.
 *
 * Returns: the Bluetooth address
 **/
const char *
nm_setting_bluetooth_get_bdaddr (NMSettingBluetooth *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (setting), NULL);

	return NM_SETTING_BLUETOOTH_GET_PRIVATE (setting)->bdaddr;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (setting);

	if (!priv->bdaddr) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_BDADDR);
		return FALSE;
	}

	if (!nm_utils_hwaddr_valid (priv->bdaddr, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_BDADDR);
		return FALSE;
	}

	if (!priv->type) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	} else if (!g_str_equal (priv->type, NM_SETTING_BLUETOOTH_TYPE_DUN) &&
	           !g_str_equal (priv->type, NM_SETTING_BLUETOOTH_TYPE_PANU)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->type);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	}

	/* Make sure the corresponding 'type' setting is present */
	if (   connection
	    && !strcmp (priv->type, NM_SETTING_BLUETOOTH_TYPE_DUN)) {
		gboolean gsm = FALSE, cdma = FALSE;

		gsm = !!nm_connection_get_setting_gsm (connection);
		cdma = !!nm_connection_get_setting_cdma (connection);

		if (!gsm && !cdma) {
			/* We can't return MISSING_SETTING here, because we don't know
			 * whether to prefix the message with NM_SETTING_GSM_SETTING_NAME or
			 * NM_SETTING_CDMA_SETTING_NAME.
			 */
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_SETTING,
			             _("'%s' connection requires '%s' or '%s' setting"),
			             NM_SETTING_BLUETOOTH_TYPE_DUN,
			             NM_SETTING_GSM_SETTING_NAME, NM_SETTING_CDMA_SETTING_NAME);
			g_prefix_error (error, "%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME);
			return FALSE;
		}
	}
	/* PANU doesn't need a 'type' setting since no further configuration
	 * is required at the interface level.
	 */

	return TRUE;
}

static void
nm_setting_bluetooth_init (NMSettingBluetooth *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (object);

	g_free (priv->bdaddr);
	g_free (priv->type);

	G_OBJECT_CLASS (nm_setting_bluetooth_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BDADDR:
		g_free (priv->bdaddr);
		priv->bdaddr = g_value_dup_string (value);
		break;
	case PROP_TYPE:
		g_free (priv->type);
		priv->type = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingBluetooth *setting = NM_SETTING_BLUETOOTH (object);

	switch (prop_id) {
	case PROP_BDADDR:
		g_value_set_string (value, nm_setting_bluetooth_get_bdaddr (setting));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_setting_bluetooth_get_connection_type (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_bluetooth_class_init (NMSettingBluetoothClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingBluetoothPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */

	/**
	 * NMSettingBluetooth:bdaddr:
	 *
	 * The Bluetooth address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_BDADDR,
		 g_param_spec_string (NM_SETTING_BLUETOOTH_BDADDR, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_BLUETOOTH_BDADDR,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingBluetooth:type:
	 *
	 * Either "dun" for Dial-Up Networking connections or "panu" for Personal
	 * Area Networking connections to devices supporting the NAP profile.
	 **/
	g_object_class_install_property
		(object_class, PROP_TYPE,
		 g_param_spec_string (NM_SETTING_BLUETOOTH_TYPE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));
}
