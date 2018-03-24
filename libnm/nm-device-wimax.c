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
 * Copyright 2009 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-connection.h"
#include "nm-setting-wimax.h"
#include "nm-utils.h"

#include "nm-device-wimax.h"
#include "nm-wimax-nsp.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"

G_DEFINE_TYPE (NMDeviceWimax, nm_device_wimax, NM_TYPE_DEVICE)

#define NM_DEVICE_WIMAX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIMAX, NMDeviceWimaxPrivate))

void _nm_device_wimax_set_wireless_enabled (NMDeviceWimax *wimax, gboolean enabled);
static void state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data);

typedef struct {
	char *hw_address;
	NMWimaxNsp *active_nsp;
	GPtrArray *nsps;

	guint center_freq;
	gint rssi;
	gint cinr;
	gint tx_power;
	char *bsid;
} NMDeviceWimaxPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_ACTIVE_NSP,
	PROP_CENTER_FREQ,
	PROP_RSSI,
	PROP_CINR,
	PROP_TX_POWER,
	PROP_BSID,
	PROP_NSPS,

	LAST_PROP
};

enum {
	NSP_ADDED,
	NSP_REMOVED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_device_wimax_get_hw_address:
 * @wimax: a #NMDeviceWimax
 *
 * Gets the hardware (MAC) address of the #NMDeviceWimax
 *
 * Returns: the hardware address. This is the internal string used by the
 *          device, and must not be modified.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_device_wimax_get_hw_address (NMDeviceWimax *wimax)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (wimax), NULL);

	return nm_str_not_empty (NM_DEVICE_WIMAX_GET_PRIVATE (wimax)->hw_address);
}

/**
 * nm_device_wimax_get_active_nsp:
 * @wimax: a #NMDeviceWimax
 *
 * Gets the active #NMWimaxNsp.
 *
 * Returns: (transfer full): the access point or %NULL if none is active
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
NMWimaxNsp *
nm_device_wimax_get_active_nsp (NMDeviceWimax *wimax)
{
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (wimax), NULL);

	state = nm_device_get_state (NM_DEVICE (wimax));
	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
	case NM_DEVICE_STATE_ACTIVATED:
	case NM_DEVICE_STATE_DEACTIVATING:
		break;
	default:
		return NULL;
		break;
	}

	return NM_DEVICE_WIMAX_GET_PRIVATE (wimax)->active_nsp;
}

/**
 * nm_device_wimax_get_nsps:
 * @wimax: a #NMDeviceWimax
 *
 * Gets all the scanned NSPs of the #NMDeviceWimax.
 *
 * Returns: (element-type NMWimaxNsp): a #GPtrArray containing
 *          all the scanned #NMWimaxNsps.
 * The returned array is owned by the client and should not be modified.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const GPtrArray *
nm_device_wimax_get_nsps (NMDeviceWimax *wimax)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (wimax), NULL);

	return NM_DEVICE_WIMAX_GET_PRIVATE (wimax)->nsps;
}

/**
 * nm_device_wimax_get_nsp_by_path:
 * @wimax: a #NMDeviceWimax
 * @path: the object path of the NSP
 *
 * Gets a #NMWimaxNsp by path.
 *
 * Returns: (transfer none): the access point or %NULL if none is found.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
NMWimaxNsp *
nm_device_wimax_get_nsp_by_path (NMDeviceWimax *wimax,
                                 const char *path)
{
	const GPtrArray *nsps;
	int i;
	NMWimaxNsp *nsp = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (wimax), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	nsps = nm_device_wimax_get_nsps (wimax);
	if (!nsps)
		return NULL;

	for (i = 0; i < nsps->len; i++) {
		NMWimaxNsp *candidate = g_ptr_array_index (nsps, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), path)) {
			nsp = candidate;
			break;
		}
	}

	return nsp;
}

static void
clean_up_nsps (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_WIMAX (self));

	priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->active_nsp) {
		g_object_unref (priv->active_nsp);
		priv->active_nsp = NULL;
	}

	g_clear_pointer (&priv->nsps, g_ptr_array_unref);
}

/**
 * nm_device_wimax_get_center_frequency:
 * @self: a #NMDeviceWimax
 *
 * Gets the center frequency (in KHz) of the radio channel the device is using
 * to communicate with the network when connected.  Has no meaning when the
 * device is not connected.
 *
 * Returns: the center frequency in KHz, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
guint
nm_device_wimax_get_center_frequency (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->center_freq;
}

/**
 * nm_device_wimax_get_rssi:
 * @self: a #NMDeviceWimax
 *
 * Gets the RSSI of the current radio link in dBm.  This value indicates how
 * strong the raw received RF signal from the base station is, but does not
 * indicate the overall quality of the radio link.  Has no meaning when the
 * device is not connected.
 *
 * Returns: the RSSI in dBm, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
gint
nm_device_wimax_get_rssi (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->rssi;
}

/**
 * nm_device_wimax_get_cinr:
 * @self: a #NMDeviceWimax
 *
 * Gets the CINR (Carrier to Interference + Noise Ratio) of the current radio
 * link in dB.  CINR is a more accurate measure of radio link quality.  Has no
 * meaning when the device is not connected.
 *
 * Returns: the CINR in dB, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
gint
nm_device_wimax_get_cinr (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->cinr;
}

/**
 * nm_device_wimax_get_tx_power:
 * @self: a #NMDeviceWimax
 *
 * Average power of the last burst transmitted by the device, in units of
 * 0.5 dBm.  i.e. a TxPower of -11 represents an actual device TX power of
 * -5.5 dBm.  Has no meaning when the device is not connected.
 *
 * Returns: the TX power in dBm, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
gint
nm_device_wimax_get_tx_power (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->tx_power;
}

/**
 * nm_device_wimax_get_bsid:
 * @self: a #NMDeviceWimax
 *
 * Gets the ID of the serving Base Station when the device is connected.
 *
 * Returns: the ID of the serving Base Station, or %NULL
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_device_wimax_get_bsid (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), NULL);

	return nm_str_not_empty (NM_DEVICE_WIMAX_GET_PRIVATE (self)->bsid);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingWimax *s_wimax;
	const char *hwaddr, *setting_hwaddr;

	if (!NM_DEVICE_CLASS (nm_device_wimax_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_WIMAX_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a WiMAX connection."));
		return FALSE;
	}

	/* Check MAC address */
	hwaddr = nm_device_wimax_get_hw_address (NM_DEVICE_WIMAX (device));
	if (hwaddr) {
		if (!nm_utils_hwaddr_valid (hwaddr, ETH_ALEN)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			                     _("Invalid device MAC address."));
			return FALSE;
		}
		s_wimax = nm_connection_get_setting_wimax (connection);
		setting_hwaddr = nm_setting_wimax_get_mac_address (s_wimax);
		if (setting_hwaddr && !nm_utils_hwaddr_matches (setting_hwaddr, -1, hwaddr, -1)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The MACs of the device and the connection didn't match."));
			return FALSE;
		}
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_WIMAX;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_wimax_get_hw_address (NM_DEVICE_WIMAX (device));
}

/*****************************************************************************/

static void
nm_device_wimax_init (NMDeviceWimax *device)
{
	g_signal_connect (device,
	                  "notify::" NM_DEVICE_STATE,
	                  G_CALLBACK (state_changed_cb),
	                  NULL);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_wimax_get_hw_address (self));
		break;
	case PROP_ACTIVE_NSP:
		g_value_set_object (value, nm_device_wimax_get_active_nsp (self));
		break;
	case PROP_CENTER_FREQ:
		g_value_set_uint (value, nm_device_wimax_get_center_frequency (self));
		break;
	case PROP_RSSI:
		g_value_set_int (value, nm_device_wimax_get_rssi (self));
		break;
	case PROP_CINR:
		g_value_set_int (value, nm_device_wimax_get_cinr (self));
		break;
	case PROP_TX_POWER:
		g_value_set_int (value, nm_device_wimax_get_tx_power (self));
		break;
	case PROP_BSID:
		g_value_set_string (value, nm_device_wimax_get_bsid (self));
		break;
	case PROP_NSPS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_wimax_get_nsps (self)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
clear_link_status (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->center_freq) {
		priv->center_freq = 0;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIMAX_CENTER_FREQUENCY);
	}

	if (priv->rssi) {
		priv->rssi = 0;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIMAX_RSSI);
	}

	if (priv->cinr) {
		priv->cinr = 0;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIMAX_CINR);
	}

	if (priv->tx_power) {
		priv->tx_power = 0;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIMAX_TX_POWER);
	}

	if (priv->bsid) {
		g_free (priv->bsid);
		priv->bsid = NULL;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIMAX_BSID);
	}
}

static void
state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMDeviceState state;

	state = nm_device_get_state (device);
	switch (state) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		if (priv->active_nsp) {
			g_object_unref (priv->active_nsp);
			priv->active_nsp = NULL;
		}
		_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_WIMAX_ACTIVE_NSP);
		clear_link_status (self);
		break;
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
		clear_link_status (self);
		break;
	default:
		break;
	}
}

static void
init_dbus (NMObject *object)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_WIMAX_HW_ADDRESS,       &priv->hw_address },
		{ NM_DEVICE_WIMAX_ACTIVE_NSP,       &priv->active_nsp, NULL, NM_TYPE_WIMAX_NSP },
		{ NM_DEVICE_WIMAX_CENTER_FREQUENCY, &priv->center_freq },
		{ NM_DEVICE_WIMAX_RSSI,             &priv->rssi },
		{ NM_DEVICE_WIMAX_CINR,             &priv->cinr },
		{ NM_DEVICE_WIMAX_TX_POWER,         &priv->tx_power },
		{ NM_DEVICE_WIMAX_BSID,             &priv->bsid },
		{ NM_DEVICE_WIMAX_NSPS,             &priv->nsps,       NULL, NM_TYPE_WIMAX_NSP, "nsp" },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_wimax_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_WIMAX,
	                                property_info);
}

static void
nsp_removed (NMDeviceWimax *self, NMWimaxNsp *nsp)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (nsp == priv->active_nsp) {
		g_object_unref (priv->active_nsp);
		priv->active_nsp = NULL;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIMAX_ACTIVE_NSP);
	}
}

static void
dispose (GObject *object)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (object);

	if (priv->hw_address) {
		g_free (priv->hw_address);
		priv->hw_address = NULL;
	}

	if (priv->bsid) {
		g_free (priv->bsid);
		priv->bsid = NULL;
	}

	if (priv->nsps)
		clean_up_nsps (NM_DEVICE_WIMAX (object));

	G_OBJECT_CLASS (nm_device_wimax_parent_class)->dispose (object);
}

static void
nm_device_wimax_class_init (NMDeviceWimaxClass *wimax_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wimax_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (wimax_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wimax_class);

	g_type_class_add_private (wimax_class, sizeof (NMDeviceWimaxPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	wimax_class->nsp_removed = nsp_removed;

	/* properties */

	/**
	 * NMDeviceWimax:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIMAX_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:active-nsp:
	 *
	 * The active #NMWimaxNsp of the device.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_NSP,
		 g_param_spec_object (NM_DEVICE_WIMAX_ACTIVE_NSP, "", "",
		                      NM_TYPE_WIMAX_NSP,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:center-frequency:
	 *
	 * The center frequency (in KHz) of the radio channel the device is using to
	 * communicate with the network when connected.  Has no meaning when the
	 * device is not connected.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_CENTER_FREQ,
		 g_param_spec_uint (NM_DEVICE_WIMAX_CENTER_FREQUENCY, "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:rssi:
	 *
	 * RSSI of the current radio link in dBm.  This value indicates how strong
	 * the raw received RF signal from the base station is, but does not
	 * indicate the overall quality of the radio link.  Has no meaning when the
	 * device is not connected.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_RSSI,
		 g_param_spec_int (NM_DEVICE_WIMAX_RSSI, "", "",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:cinr:
	 *
	 * CINR (Carrier to Interference + Noise Ratio) of the current radio link
	 * in dB.  CINR is a more accurate measure of radio link quality.  Has no
	 * meaning when the device is not connected.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_CINR,
		 g_param_spec_int (NM_DEVICE_WIMAX_CINR, "", "",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:tx-power:
	 *
	 * Average power of the last burst transmitted by the device, in units of
	 * 0.5 dBm.  i.e. a TxPower of -11 represents an actual device TX power of
	 * -5.5 dBm.  Has no meaning when the device is not connected.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_TX_POWER,
		 g_param_spec_int (NM_DEVICE_WIMAX_TX_POWER, "", "",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:bsid:
	 *
	 * The ID of the serving base station as received from the network.  Has
	 * no meaning when the device is not connected.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_BSID,
		 g_param_spec_string (NM_DEVICE_WIMAX_BSID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWimax:nsps: (type GPtrArray(NMWimaxNsp))
	 *
	 * List of all WiMAX Network Service Providers the device can see.
	 **/
	g_object_class_install_property
		(object_class, PROP_NSPS,
		 g_param_spec_boxed (NM_DEVICE_WIMAX_NSPS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMDeviceWimax::nsp-added:
	 * @self: the wimax device that received the signal
	 * @nsp: the new NSP
	 *
	 * Notifies that a #NMWimaxNsp is added to the wimax device.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	signals[NSP_ADDED] =
		g_signal_new ("nsp-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWimaxClass, nsp_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMDeviceWimax::nsp-removed:
	 * @self: the wimax device that received the signal
	 * @nsp: the removed NSP
	 *
	 * Notifies that a #NMWimaxNsp is removed from the wimax device.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	signals[NSP_REMOVED] =
		g_signal_new ("nsp-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWimaxClass, nsp_removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
}
