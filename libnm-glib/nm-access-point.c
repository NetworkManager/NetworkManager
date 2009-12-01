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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <string.h>

#include "nm-access-point.h"
#include "NetworkManager.h"
#include "nm-types-private.h"
#include "nm-object-private.h"

#include "nm-access-point-bindings.h"

G_DEFINE_TYPE (NMAccessPoint, nm_access_point, NM_TYPE_OBJECT)

#define NM_ACCESS_POINT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACCESS_POINT, NMAccessPointPrivate))

typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	guint32 flags;
	guint32 wpa_flags;
	guint32 rsn_flags;
	GByteArray *ssid;
	guint32 frequency;
	char *hw_address;
	NM80211Mode mode;
	guint32 max_bitrate;
	guint8 strength;
} NMAccessPointPrivate;

enum {
	PROP_0,
	PROP_FLAGS,
	PROP_WPA_FLAGS,
	PROP_RSN_FLAGS,
	PROP_SSID,
	PROP_FREQUENCY,
	PROP_HW_ADDRESS,
	PROP_MODE,
	PROP_MAX_BITRATE,
	PROP_STRENGTH,

	LAST_PROP
};

#define DBUS_PROP_FLAGS "Flags"
#define DBUS_PROP_WPA_FLAGS "WpaFlags"
#define DBUS_PROP_RSN_FLAGS "RsnFlags"
#define DBUS_PROP_SSID "Ssid"
#define DBUS_PROP_FREQUENCY "Frequency"
#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_MODE "Mode"
#define DBUS_PROP_MAX_BITRATE "MaxBitrate"
#define DBUS_PROP_STRENGTH "Strength"

/**
 * nm_access_point_new:
 * @connection: the #DBusGConnection
 * @path: the DBusobject path of the access point
 *
 * Creates a new #NMAccessPoint.
 *
 * Returns: a new access point
 **/
GObject *
nm_access_point_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (GObject *) g_object_new (NM_TYPE_ACCESS_POINT,
								    NM_OBJECT_DBUS_CONNECTION, connection,
								    NM_OBJECT_DBUS_PATH, path,
								    NULL);
}

/**
 * nm_access_point_get_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the flags of the access point
 *
 * Returns: the flags
 **/
guint32
nm_access_point_get_flags (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_FLAGS_NONE);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->flags) {
		priv->flags = _nm_object_get_uint_property (NM_OBJECT (ap),
		                                           NM_DBUS_INTERFACE_ACCESS_POINT,
		                                           DBUS_PROP_FLAGS);
	}

	return priv->flags;
}

/**
 * nm_access_point_get_wpa_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the WPA flags of the access point.
 *
 * Returns: the WPA flags
 **/
guint32
nm_access_point_get_wpa_flags (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->wpa_flags) {
		priv->wpa_flags = _nm_object_get_uint_property (NM_OBJECT (ap),
		                                               NM_DBUS_INTERFACE_ACCESS_POINT,
		                                               DBUS_PROP_WPA_FLAGS);
	}

	return priv->wpa_flags;
}

/**
 * nm_access_point_get_rsn_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the RSN flags of the access point.
 *
 * Returns: the RSN flags
 **/
guint32
nm_access_point_get_rsn_flags (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->rsn_flags) {
		priv->rsn_flags = _nm_object_get_uint_property (NM_OBJECT (ap),
		                                               NM_DBUS_INTERFACE_ACCESS_POINT,
		                                               DBUS_PROP_RSN_FLAGS);
	}

	return priv->rsn_flags;
}

/**
 * nm_access_point_get_ssid:
 * @ap: a #NMAccessPoint
 *
 * Gets the SSID of the access point.
 *
 * Returns: the #GByteArray containing the SSID. This is the internal copy used by the
 * access point, and must not be modified.
 **/
const GByteArray *
nm_access_point_get_ssid (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->ssid) {
		priv->ssid = _nm_object_get_byte_array_property (NM_OBJECT (ap),
		                                                NM_DBUS_INTERFACE_ACCESS_POINT,
		                                                DBUS_PROP_SSID);
	}

	return priv->ssid;
}

/**
 * nm_access_point_get_frequency:
 * @ap: a #NMAccessPoint
 *
 * Gets the frequency of the access point.
 *
 * Returns: the frequency
 **/
guint32
nm_access_point_get_frequency (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->frequency) {
		priv->frequency = _nm_object_get_uint_property (NM_OBJECT (ap),
		                                               NM_DBUS_INTERFACE_ACCESS_POINT,
		                                               DBUS_PROP_FREQUENCY);
	}

	return priv->frequency;
}

/**
 * nm_access_point_get_hw_address:
 * @ap: a #NMAccessPoint
 *
 * Gets the hardware (MAC) address of the access point.
 *
 * Returns: the hardware address of the access point. This is the internal string used by the
 * access point and must not be modified.
 **/
const char *
nm_access_point_get_hw_address (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->hw_address) {
		priv->hw_address = _nm_object_get_string_property (NM_OBJECT (ap),
		                                                  NM_DBUS_INTERFACE_ACCESS_POINT,
		                                                  DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
}

/**
 * nm_access_point_get_mode:
 * @ap: a #NMAccessPoint
 *
 * Gets the mode of the access point.
 *
 * Returns: the mode
 **/
NM80211Mode
nm_access_point_get_mode (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->mode) {
		priv->mode = _nm_object_get_uint_property (NM_OBJECT (ap),
		                                          NM_DBUS_INTERFACE_ACCESS_POINT,
		                                          DBUS_PROP_MODE);
	}

	return priv->mode;
}

/**
 * nm_access_point_get_max_bitrate:
 * @ap: a #NMAccessPoint
 *
 * Gets the maximum bit rate of the access point.
 *
 * Returns: the maximum bit rate
 **/
guint32
nm_access_point_get_max_bitrate (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->max_bitrate) {
		priv->max_bitrate = _nm_object_get_uint_property (NM_OBJECT (ap),
		                                              NM_DBUS_INTERFACE_ACCESS_POINT,
		                                              DBUS_PROP_MAX_BITRATE);
	}

	return priv->max_bitrate;
}

/**
 * nm_access_point_get_strength:
 * @ap: a #NMAccessPoint
 *
 * Gets the current signal strength of the access point.
 *
 * Returns: the signal strength
 **/
guint8
nm_access_point_get_strength (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->strength) {
		priv->strength = _nm_object_get_byte_property (NM_OBJECT (ap),
		                                              NM_DBUS_INTERFACE_ACCESS_POINT,
		                                              DBUS_PROP_STRENGTH);
	}

	return priv->strength;
}

/************************************************************/

static void
nm_access_point_init (NMAccessPoint *ap)
{
}

static void
dispose (GObject *object)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_access_point_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_access_point_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);

	if (priv->hw_address)
		g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_access_point_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (object);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_uint (value, nm_access_point_get_flags (ap));
		break;
	case PROP_WPA_FLAGS:
		g_value_set_uint (value, nm_access_point_get_wpa_flags (ap));
		break;
	case PROP_RSN_FLAGS:
		g_value_set_uint (value, nm_access_point_get_rsn_flags (ap));
		break;
	case PROP_SSID:
		g_value_set_boxed (value, nm_access_point_get_ssid (ap));
		break;
	case PROP_FREQUENCY:
		g_value_set_uint (value, nm_access_point_get_frequency (ap));
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_access_point_get_hw_address (ap));
		break;
	case PROP_MODE:
		g_value_set_uint (value, nm_access_point_get_mode (ap));
		break;
	case PROP_MAX_BITRATE:
		g_value_set_uint (value, nm_access_point_get_max_bitrate (ap));
		break;
	case PROP_STRENGTH:
		g_value_set_uchar (value, nm_access_point_get_strength (ap));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
demarshal_ssid (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	if (!_nm_ssid_demarshal (value, (GByteArray **) field))
		return FALSE;

	_nm_object_queue_notify (object, NM_ACCESS_POINT_SSID);
	return TRUE;
}

static void
register_for_property_changed (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_ACCESS_POINT_FLAGS,       _nm_object_demarshal_generic, &priv->flags },
		{ NM_ACCESS_POINT_WPA_FLAGS,   _nm_object_demarshal_generic, &priv->wpa_flags },
		{ NM_ACCESS_POINT_RSN_FLAGS,   _nm_object_demarshal_generic, &priv->rsn_flags },
		{ NM_ACCESS_POINT_SSID,        demarshal_ssid,              &priv->ssid },
		{ NM_ACCESS_POINT_FREQUENCY,   _nm_object_demarshal_generic, &priv->frequency },
		{ NM_ACCESS_POINT_HW_ADDRESS,  _nm_object_demarshal_generic, &priv->hw_address },
		{ NM_ACCESS_POINT_MODE,        _nm_object_demarshal_generic, &priv->mode },
		{ NM_ACCESS_POINT_MAX_BITRATE, _nm_object_demarshal_generic, &priv->max_bitrate },
		{ NM_ACCESS_POINT_STRENGTH,    _nm_object_demarshal_generic, &priv->strength },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (ap),
	                                     priv->proxy,
	                                     property_changed_info);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMAccessPointPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_access_point_parent_class)->constructor (type,
																	  n_construct_params,
																	  construct_params);
	if (!object)
		return NULL;

	priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
									    NM_DBUS_SERVICE,
									    nm_object_get_path (object),
									    NM_DBUS_INTERFACE_ACCESS_POINT);

	register_for_property_changed (NM_ACCESS_POINT (object));

	return G_OBJECT (object);
}


static void
nm_access_point_class_init (NMAccessPointClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMAccessPoint:flags:
	 *
	 * The flags of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_FLAGS,
		                    "Flags",
		                    "Flags",
		                    NM_802_11_AP_FLAGS_NONE,
		                    NM_802_11_AP_FLAGS_PRIVACY,
		                    NM_802_11_AP_FLAGS_NONE,
		                    G_PARAM_READABLE));

	/**
	 * NMAccessPoint:wpa-flags:
	 *
	 * The WPA flags of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_WPA_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_WPA_FLAGS,
		                    "WPA Flags",
		                    "WPA Flags",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	/**
	 * NMAccessPoint:rsn-flags:
	 *
	 * The RSN flags of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_RSN_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_RSN_FLAGS,
		                    "RSN Flags",
		                    "RSN Flags",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	/**
	 * NMAccessPoint:ssid:
	 *
	 * The SSID of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_SSID,
		 g_param_spec_boxed (NM_ACCESS_POINT_SSID,
						 "SSID",
						 "SSID",
						 NM_TYPE_SSID,
						 G_PARAM_READABLE));

	/**
	 * NMAccessPoint:frequency:
	 *
	 * The frequency of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_uint (NM_ACCESS_POINT_FREQUENCY,
						"Frequency",
						"Frequency",
						0, 10000, 0,
						G_PARAM_READABLE));

	/**
	 * NMAccessPoint:hw-address:
	 *
	 * The hardware address of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_ACCESS_POINT_HW_ADDRESS,
						  "MAC Address",
						  "Hardware MAC address",
						  NULL,
						  G_PARAM_READABLE));
	
	/**
	 * NMAccessPoint:mode:
	 *
	 * The mode of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_ACCESS_POINT_MODE,
					    "Mode",
					    "Mode",
					    NM_802_11_MODE_ADHOC, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
					    G_PARAM_READABLE));

	/**
	 * NMAccessPoint:max-bitrate:
	 *
	 * The maximum bit rate of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAX_BITRATE,
		 g_param_spec_uint (NM_ACCESS_POINT_MAX_BITRATE,
						"Max Bitrate",
						"Max Bitrate",
						0, G_MAXUINT32, 0,
						G_PARAM_READABLE));

	/**
	 * NMAccessPoint:strength:
	 *
	 * The current signal strength of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_STRENGTH,
		 g_param_spec_uchar (NM_ACCESS_POINT_STRENGTH,
						"Strength",
						"Strength",
						0, G_MAXUINT8, 0,
						G_PARAM_READABLE));
}
