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
 * Copyright 2011 - 2012 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-device-modem.h"

#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-object-private.h"
#include "nm-enum-types.h"

G_DEFINE_TYPE (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE)

#define NM_DEVICE_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MODEM, NMDeviceModemPrivate))

typedef struct {
	NMDeviceModemCapabilities caps;
	NMDeviceModemCapabilities current_caps;
	char *device_id;
	char *operator_code;
	char *apn;
} NMDeviceModemPrivate;

enum {
	PROP_0,
	PROP_MODEM_CAPS,
	PROP_CURRENT_CAPS,
	PROP_DEVICE_ID,
	PROP_OPERATOR_CODE,
	PROP_APN,
	LAST_PROP
};

/**
 * nm_device_modem_get_modem_capabilities:
 * @self: a #NMDeviceModem
 *
 * Returns a bitfield of the generic access technology families the modem
 * supports.  Not all capabilities are available concurrently however; some
 * may require a firmware reload or reinitialization.
 *
 * Returns: the generic access technology families the modem supports
 **/
NMDeviceModemCapabilities
nm_device_modem_get_modem_capabilities (NMDeviceModem *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NM_DEVICE_MODEM_CAPABILITY_NONE);

	return NM_DEVICE_MODEM_GET_PRIVATE (self)->caps;
}

/**
 * nm_device_modem_get_current_capabilities:
 * @self: a #NMDeviceModem
 *
 * Returns a bitfield of the generic access technology families the modem
 * supports without a firmware reload or reinitialization.  This value
 * represents the network types the modem can immediately connect to.
 *
 * Returns: the generic access technology families the modem supports without
 * a firmware reload or other reinitialization
 **/
NMDeviceModemCapabilities
nm_device_modem_get_current_capabilities (NMDeviceModem *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NM_DEVICE_MODEM_CAPABILITY_NONE);

	return NM_DEVICE_MODEM_GET_PRIVATE (self)->current_caps;
}

/**
 * nm_device_modem_get_device_id:
 * @self: a #NMDeviceModem
 *
 * An identifier used by the modem backend (ModemManager) that aims to
 * uniquely identify the a device. Can be used to match a connection to a
 * particular device.
 *
 * Returns: a device-id string
 *
 * Since: 1.20
 **/
const char *
nm_device_modem_get_device_id (NMDeviceModem *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NULL);

	return NM_DEVICE_MODEM_GET_PRIVATE (self)->device_id;
}

/**
 * nm_device_modem_get_operator_code:
 * @self: a #NMDeviceModem
 *
 * The MCC and MNC (concatenated) of the network the modem is connected to.
 *
 * Returns: the operator code or %NULL if disconnected or not a 3GPP modem.
 *
 * Since: 1.20
 **/
const char *
nm_device_modem_get_operator_code (NMDeviceModem *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NULL);

	return NM_DEVICE_MODEM_GET_PRIVATE (self)->operator_code;
}

/**
 * nm_device_modem_get_apn:
 * @self: a #NMDeviceModem
 *
 * The access point name the modem is connected to.
 *
 * Returns: the APN name or %NULL if disconnected
 *
 * Since: 1.20
 **/
const char *
nm_device_modem_get_apn (NMDeviceModem *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NULL);

	return NM_DEVICE_MODEM_GET_PRIVATE (self)->apn;
}

static const char *
get_type_description (NMDevice *device)
{
	NMDeviceModemCapabilities caps;

	caps = nm_device_modem_get_current_capabilities (NM_DEVICE_MODEM (device));
	if (caps & NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS)
		return "gsm";
	else if (caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO)
		return "cdma";
	else
		return NULL;
}

#define MODEM_CAPS_3GPP(caps) (caps & (NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS |    \
                                       NM_DEVICE_MODEM_CAPABILITY_LTE))

#define MODEM_CAPS_3GPP2(caps) (caps & (NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO))

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMDeviceModemCapabilities current_caps;

	if (!NM_DEVICE_CLASS (nm_device_modem_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (   !nm_connection_is_type (connection, NM_SETTING_GSM_SETTING_NAME)
	    && !nm_connection_is_type (connection, NM_SETTING_CDMA_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a modem connection."));
		return FALSE;
	}

	s_gsm = nm_connection_get_setting_gsm (connection);
	s_cdma = nm_connection_get_setting_cdma (connection);
	if (!s_cdma && !s_gsm) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     _("The connection was not a valid modem connection."));
		return FALSE;
	}

	current_caps = nm_device_modem_get_current_capabilities (NM_DEVICE_MODEM (device));
	if (!(s_gsm && MODEM_CAPS_3GPP (current_caps)) && !(s_cdma && MODEM_CAPS_3GPP2 (current_caps))) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The device is lacking capabilities required by the connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	NMDeviceModemCapabilities caps;

	caps = nm_device_modem_get_current_capabilities (NM_DEVICE_MODEM (device));
	if (caps & (NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS | NM_DEVICE_MODEM_CAPABILITY_LTE))
		return NM_TYPE_SETTING_GSM;
	else if (caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO)
		return NM_TYPE_SETTING_CDMA;
	else
		return G_TYPE_INVALID;
}

/*****************************************************************************/

static void
nm_device_modem_init (NMDeviceModem *device)
{
}

static void
init_dbus (NMObject *object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_MODEM_MODEM_CAPABILITIES,   &priv->caps },
		{ NM_DEVICE_MODEM_CURRENT_CAPABILITIES, &priv->current_caps },
		{ NM_DEVICE_MODEM_DEVICE_ID,            &priv->device_id },
		{ NM_DEVICE_MODEM_OPERATOR_CODE,        &priv->operator_code },
		{ NM_DEVICE_MODEM_APN,                  &priv->apn },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_modem_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_MODEM,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	g_free (priv->device_id);
	g_free (priv->operator_code);
	g_free (priv->apn);

	G_OBJECT_CLASS (nm_device_modem_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (object);

	switch (prop_id) {
	case PROP_MODEM_CAPS:
		g_value_set_flags (value, nm_device_modem_get_modem_capabilities (self));
		break;
	case PROP_CURRENT_CAPS:
		g_value_set_flags (value, nm_device_modem_get_current_capabilities (self));
		break;
	case PROP_DEVICE_ID:
		g_value_set_string (value, nm_device_modem_get_device_id (self));
		break;
	case PROP_OPERATOR_CODE:
		g_value_set_string (value, nm_device_modem_get_operator_code (self));
		break;
	case PROP_APN:
		g_value_set_string (value, nm_device_modem_get_apn (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_modem_class_init (NMDeviceModemClass *modem_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (modem_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (modem_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (modem_class);

	g_type_class_add_private (modem_class, sizeof (NMDeviceModemPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->get_type_description = get_type_description;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;

	/**
	 * NMDeviceModem:modem-capabilities:
	 *
	 * The generic family of access technologies the modem supports.  Not all
	 * capabilities are available at the same time however; some modems require
	 * a firmware reload or other reinitialization to switch between eg
	 * CDMA/EVDO and GSM/UMTS.
	 **/
	g_object_class_install_property
		(object_class, PROP_MODEM_CAPS,
		 g_param_spec_flags (NM_DEVICE_MODEM_MODEM_CAPABILITIES, "", "",
		                     NM_TYPE_DEVICE_MODEM_CAPABILITIES,
		                     NM_DEVICE_MODEM_CAPABILITY_NONE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceModem:current-capabilities:
	 *
	 * The generic family of access technologies the modem currently supports
	 * without a firmware reload or reinitialization.
	 **/
	g_object_class_install_property
		(object_class, PROP_CURRENT_CAPS,
		 g_param_spec_flags (NM_DEVICE_MODEM_CURRENT_CAPABILITIES, "", "",
		                     NM_TYPE_DEVICE_MODEM_CAPABILITIES,
		                     NM_DEVICE_MODEM_CAPABILITY_NONE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceModem:device-id:
	 *
	 * Since: 1.20
	 **/
	g_object_class_install_property
		(object_class, PROP_CURRENT_CAPS,
		 g_param_spec_string (NM_DEVICE_MODEM_DEVICE_ID, "", "",
		                     NULL,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceModem:operator-code:
	 *
	 * Since: 1.20
	 **/
	g_object_class_install_property
		(object_class, PROP_CURRENT_CAPS,
		 g_param_spec_string (NM_DEVICE_MODEM_OPERATOR_CODE, "", "",
		                     NULL,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceModem:apn:
	 *
	 * Since: 1.20
	 **/
	g_object_class_install_property
		(object_class, PROP_CURRENT_CAPS,
		 g_param_spec_string (NM_DEVICE_MODEM_APN, "", "",
		                     NULL,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}
