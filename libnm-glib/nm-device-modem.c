/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include <config.h>
#include <string.h>

#include <nm-setting-connection.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>

#include "nm-device-modem.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-marshal.h"

G_DEFINE_TYPE (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE)

#define NM_DEVICE_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_DEVICE_MODEM, \
                                        NMDeviceModemPrivate))

typedef struct {
	DBusGProxy *proxy;

	NMDeviceModemCapabilities caps;
	NMDeviceModemCapabilities current_caps;

	gboolean disposed;
} NMDeviceModemPrivate;

enum {
	PROP_0,
	PROP_MODEM_CAPS,
	PROP_CURRENT_CAPS,
	LAST_PROP
};

#define DBUS_PROP_MODEM_CAPS "ModemCapabilities"
#define DBUS_PROP_CURRENT_CAPS "CurrentCapabilities"

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
	NMDeviceModemPrivate *priv;

	g_return_val_if_fail (self != NULL, NM_DEVICE_MODEM_CAPABILITY_NONE);
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NM_DEVICE_MODEM_CAPABILITY_NONE);

	priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	if (!priv->caps) {
		priv->caps = _nm_object_get_uint_property (NM_OBJECT (self),
		                                           NM_DBUS_INTERFACE_DEVICE_MODEM,
		                                           DBUS_PROP_MODEM_CAPS,
		                                           NULL);
	}

	return priv->caps;
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
	NMDeviceModemPrivate *priv;

	g_return_val_if_fail (self != NULL, NM_DEVICE_MODEM_CAPABILITY_NONE);
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NM_DEVICE_MODEM_CAPABILITY_NONE);

	priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	if (!priv->current_caps) {
		priv->current_caps = _nm_object_get_uint_property (NM_OBJECT (self),
		                                                   NM_DBUS_INTERFACE_DEVICE_MODEM,
		                                                   DBUS_PROP_CURRENT_CAPS,
		                                                   NULL);
	}

	return priv->current_caps;
}

static gboolean
connection_valid (NMDevice *device, NMConnection *connection)
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
	    && strcmp (ctype, NM_SETTING_CDMA_SETTING_NAME) != 0)
		return FALSE;

	s_gsm = nm_connection_get_setting_gsm (connection);
	s_cdma = nm_connection_get_setting_cdma (connection);
	if (!s_cdma && !s_gsm)
		return FALSE;

	current_caps = nm_device_modem_get_current_capabilities (NM_DEVICE_MODEM (device));
	if (   !(s_gsm && (current_caps & NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS))
	    && !(s_cdma && (current_caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO))) {
		return FALSE;
	}

	return TRUE;
}

/*******************************************************************/

static void
register_for_property_changed (NMDeviceModem *device)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_MODEM_MODEM_CAPABILITIES,   _nm_object_demarshal_generic, &priv->caps },
		{ NM_DEVICE_MODEM_CURRENT_CAPABILITIES, _nm_object_demarshal_generic, &priv->current_caps },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (device),
	                                      priv->proxy,
	                                      property_changed_info);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceModemPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_modem_parent_class)->constructor (type,
	                                                                     n_construct_params,
	                                                                     construct_params);
	if (object) {
		priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

		priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
		                                         NM_DBUS_SERVICE,
		                                         nm_object_get_path (NM_OBJECT (object)),
		                                         NM_DBUS_INTERFACE_DEVICE_MODEM);

		register_for_property_changed (NM_DEVICE_MODEM (object));
	}

	return object;
}

static void
nm_device_modem_init (NMDeviceModem *device)
{
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

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_modem_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_device_modem_parent_class)->dispose (object);
}

static void
nm_device_modem_class_init (NMDeviceModemClass *modem_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (modem_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (modem_class);

	g_type_class_add_private (modem_class, sizeof (NMDeviceModemPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	device_class->connection_valid = connection_valid;

	/**
	 * NMDeviceModem:modem-capabilities:
	 *
	 * The generic family of access technologies the modem supports.  Not all
	 * capabilities are available at the same time however; some modems require
	 * a firmware reload or other reinitialization to switch between eg
	 * CDMA/EVDO and GSM/UMTS.
	 **/
	g_object_class_install_property (object_class, PROP_MODEM_CAPS,
		g_param_spec_uint (NM_DEVICE_MODEM_MODEM_CAPABILITIES,
		                   "Modem capabilities",
		                   "Modem capabilities",
		                   0, G_MAXUINT32, 0,
		                   G_PARAM_READABLE));

	/**
	 * NMDeviceModem:current-capabilities:
	 *
	 * The generic family of access technologies the modem currently supports
	 * without a firmware reload or reinitialization.
	 **/
	g_object_class_install_property (object_class, PROP_CURRENT_CAPS,
		g_param_spec_uint (NM_DEVICE_MODEM_CURRENT_CAPABILITIES,
		                   "Current capabilities",
		                   "Current capabilities",
		                   0, G_MAXUINT32, 0,
		                   G_PARAM_READABLE));
}

