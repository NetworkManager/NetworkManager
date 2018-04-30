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

#include "nm-default.h"

#include <string.h>
#include <net/ethernet.h>

#include "nm-param-spec-specialized.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-bluetooth
 * @short_description: Describes Bluetooth connection properties
 * @include: nm-setting-bluetooth.h
 *
 * The #NMSettingBluetooth object is a #NMSetting subclass that describes
 * properties necessary for connection to devices that provide network
 * connections via the Bluetooth Dial-Up Networking (DUN) and Network Access
 * Point (NAP) profiles.
 **/

/**
 * nm_setting_bluetooth_error_quark:
 *
 * Registers an error quark for #NMSettingBluetooth if necessary.
 *
 * Returns: the error quark used for #NMSettingBluetooth errors.
 **/
GQuark
nm_setting_bluetooth_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-bluetooth-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingBluetooth, nm_setting_bluetooth, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_BLUETOOTH_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_BLUETOOTH_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_BLUETOOTH)

#define NM_SETTING_BLUETOOTH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothPrivate))

typedef struct {
	GByteArray *bdaddr;
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
 *   %NM_SETTING_BLUETOOTH_TYPE_DUN
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
const GByteArray *
nm_setting_bluetooth_get_bdaddr (NMSettingBluetooth *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (setting), NULL);

	return NM_SETTING_BLUETOOTH_GET_PRIVATE (setting)->bdaddr;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (setting);

	if (!priv->bdaddr) {
		g_set_error_literal (error,
		                     NM_SETTING_BLUETOOTH_ERROR,
		                     NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_BDADDR);
		return FALSE;
	}

	if (priv->bdaddr && priv->bdaddr->len != ETH_ALEN) {
		g_set_error_literal (error,
		                     NM_SETTING_BLUETOOTH_ERROR,
		                     NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_BDADDR);
		return FALSE;
	}

	if (!priv->type) {
		g_set_error_literal (error,
		                     NM_SETTING_BLUETOOTH_ERROR,
		                     NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	} else if (!g_str_equal (priv->type, NM_SETTING_BLUETOOTH_TYPE_DUN) &&
	           !g_str_equal (priv->type, NM_SETTING_BLUETOOTH_TYPE_PANU)) {
		g_set_error (error,
		             NM_SETTING_BLUETOOTH_ERROR,
		             NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->type);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	}

	/* Make sure the corresponding 'type' setting is present */
	if (   all_settings
	    && !strcmp (priv->type, NM_SETTING_BLUETOOTH_TYPE_DUN)) {
		gboolean gsm = FALSE, cdma = FALSE;

		gsm = !!nm_setting_find_in_list (all_settings, NM_SETTING_GSM_SETTING_NAME);
		cdma = !!nm_setting_find_in_list (all_settings, NM_SETTING_CDMA_SETTING_NAME);

		if (!gsm && !cdma) {
			g_set_error (error,
			             NM_SETTING_BLUETOOTH_ERROR,
			             NM_SETTING_BLUETOOTH_ERROR_TYPE_SETTING_NOT_FOUND,
			             _("requires '%s' or '%s' setting"),
			             NM_SETTING_GSM_SETTING_NAME, NM_SETTING_CDMA_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
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

	if (priv->bdaddr)
		g_byte_array_free (priv->bdaddr, TRUE);
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
		if (priv->bdaddr)
			g_byte_array_free (priv->bdaddr, TRUE);
		priv->bdaddr = g_value_dup_boxed (value);
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
		g_value_set_boxed (value, nm_setting_bluetooth_get_bdaddr (setting));
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
		 _nm_param_spec_specialized (NM_SETTING_BLUETOOTH_BDADDR, "", "",
		                             DBUS_TYPE_G_UCHAR_ARRAY,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_INFERRABLE |
		                             G_PARAM_STATIC_STRINGS));

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
