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
 * Copyright 2011 - 2012 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"

#include "nm-device-modem.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE)

#define NM_DEVICE_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MODEM, NMDeviceModemPrivate))

typedef struct {
	DBusGProxy *proxy;

	NMDeviceModemCapabilities caps;
	NMDeviceModemCapabilities current_caps;
} NMDeviceModemPrivate;

enum {
	PROP_0,
	PROP_MODEM_CAPS,
	PROP_CURRENT_CAPS,
	LAST_PROP
};

/**
 * nm_device_modem_error_quark:
 *
 * Registers an error quark for #NMDeviceModem if necessary.
 *
 * Returns: the error quark used for #NMDeviceModem errors.
 **/
GQuark
nm_device_modem_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-modem-error-quark");
	return quark;
}

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

	_nm_object_ensure_inited (NM_OBJECT (self));
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

	_nm_object_ensure_inited (NM_OBJECT (self));
	return NM_DEVICE_MODEM_GET_PRIVATE (self)->current_caps;
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
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	const char *ctype;
	NMDeviceModemCapabilities current_caps;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (   strcmp (ctype, NM_SETTING_GSM_SETTING_NAME) != 0
	    && strcmp (ctype, NM_SETTING_CDMA_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_MODEM_ERROR, NM_DEVICE_MODEM_ERROR_NOT_MODEM_CONNECTION,
		             "The connection was not a modem connection.");
		return FALSE;
	}

	s_gsm = nm_connection_get_setting_gsm (connection);
	s_cdma = nm_connection_get_setting_cdma (connection);
	if (!s_cdma && !s_gsm) {
		g_set_error (error, NM_DEVICE_MODEM_ERROR, NM_DEVICE_MODEM_ERROR_INVALID_MODEM_CONNECTION,
		             "The connection was not a valid modem connection.");
		return FALSE;
	}

	current_caps = nm_device_modem_get_current_capabilities (NM_DEVICE_MODEM (device));
	if (!(s_gsm && MODEM_CAPS_3GPP (current_caps)) && !(s_cdma && MODEM_CAPS_3GPP2 (current_caps))) {
		g_set_error (error, NM_DEVICE_MODEM_ERROR, NM_DEVICE_MODEM_ERROR_MISSING_DEVICE_CAPS,
		             "The device missed capabilities required by the GSM/CDMA connection.");
		return FALSE;
	}

	return NM_DEVICE_CLASS (nm_device_modem_parent_class)->connection_compatible (device, connection, error);
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

/*******************************************************************/

static void
nm_device_modem_init (NMDeviceModem *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_MODEM);
}

static void
register_properties (NMDeviceModem *device)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_MODEM_MODEM_CAPABILITIES,   &priv->caps },
		{ NM_DEVICE_MODEM_CURRENT_CAPABILITIES, &priv->current_caps },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_modem_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_MODEM);
	register_properties (NM_DEVICE_MODEM (object));
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_MODEM_CAPS:
		g_value_set_uint (value, nm_device_modem_get_modem_capabilities (self));
		break;
	case PROP_CURRENT_CAPS:
		g_value_set_uint (value, nm_device_modem_get_current_capabilities (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_device_modem_parent_class)->dispose (object);
}

static void
nm_device_modem_class_init (NMDeviceModemClass *modem_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (modem_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (modem_class);

	g_type_class_add_private (modem_class, sizeof (NMDeviceModemPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

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
		 g_param_spec_uint (NM_DEVICE_MODEM_MODEM_CAPABILITIES, "", "",
		                    0, G_MAXUINT32, 0,
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
		 g_param_spec_uint (NM_DEVICE_MODEM_CURRENT_CAPABILITIES, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
}
