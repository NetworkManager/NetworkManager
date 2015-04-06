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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <glib/gi18n-lib.h>

#include <nm-setting-connection.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-utils.h>

#include "nm-glib.h"
#include "nm-device-wifi.h"
#include "nm-access-point.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-core-internal.h"
#include "nm-dbus-helpers.h"

#include "nmdbus-device-wifi.h"

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIFI, NMDeviceWifiPrivate))

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);
static void state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data);

typedef struct {
	NMDeviceWifi *device;
	GSimpleAsyncResult *simple;
} RequestScanInfo;

typedef struct {
	NMDBusDeviceWifi *proxy;

	char *hw_address;
	char *perm_hw_address;
	NM80211Mode mode;
	guint32 rate;
	NMAccessPoint *active_ap;
	NMDeviceWifiCapabilities wireless_caps;
	GPtrArray *aps;

	RequestScanInfo *scan_info;
} NMDeviceWifiPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_WIRELESS_CAPABILITIES,
	PROP_ACCESS_POINTS,

	LAST_PROP
};

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_device_wifi_get_hw_address:
 * @device: a #NMDeviceWifi
 *
 * Gets the actual hardware (MAC) address of the #NMDeviceWifi
 *
 * Returns: the actual hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_wifi_get_hw_address (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->hw_address;
}

/**
 * nm_device_wifi_get_permanent_hw_address:
 * @device: a #NMDeviceWifi
 *
 * Gets the permanent hardware (MAC) address of the #NMDeviceWifi
 *
 * Returns: the permanent hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_wifi_get_permanent_hw_address (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->perm_hw_address;
}

/**
 * nm_device_wifi_get_mode:
 * @device: a #NMDeviceWifi
 *
 * Gets the #NMDeviceWifi mode.
 *
 * Returns: the mode
 **/
NM80211Mode
nm_device_wifi_get_mode (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->mode;
}

/**
 * nm_device_wifi_get_bitrate:
 * @device: a #NMDeviceWifi
 *
 * Gets the bit rate of the #NMDeviceWifi in kbit/s.
 *
 * Returns: the bit rate (kbit/s)
 **/
guint32
nm_device_wifi_get_bitrate (NMDeviceWifi *device)
{
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	state = nm_device_get_state (NM_DEVICE (device));
	switch (state) {
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
	case NM_DEVICE_STATE_ACTIVATED:
	case NM_DEVICE_STATE_DEACTIVATING:
		break;
	default:
		return 0;
	}

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->rate;
}

/**
 * nm_device_wifi_get_capabilities:
 * @device: a #NMDeviceWifi
 *
 * Gets the Wi-Fi capabilities of the #NMDeviceWifi.
 *
 * Returns: the capabilities
 **/
NMDeviceWifiCapabilities
nm_device_wifi_get_capabilities (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->wireless_caps;
}

/**
 * nm_device_wifi_get_active_access_point:
 * @device: a #NMDeviceWifi
 *
 * Gets the active #NMAccessPoint.
 *
 * Returns: (transfer none): the access point or %NULL if none is active
 **/
NMAccessPoint *
nm_device_wifi_get_active_access_point (NMDeviceWifi *device)
{
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	state = nm_device_get_state (NM_DEVICE (device));
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

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->active_ap;
}

/**
 * nm_device_wifi_get_access_points:
 * @device: a #NMDeviceWifi
 *
 * Gets all the scanned access points of the #NMDeviceWifi.
 *
 * Returns: (element-type NMAccessPoint): a #GPtrArray containing all the
 * scanned #NMAccessPoints.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_device_wifi_get_access_points (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->aps;
}

/**
 * nm_device_wifi_get_access_point_by_path:
 * @device: a #NMDeviceWifi
 * @path: the object path of the access point
 *
 * Gets a #NMAccessPoint by path.
 *
 * Returns: (transfer none): the access point or %NULL if none is found.
 **/
NMAccessPoint *
nm_device_wifi_get_access_point_by_path (NMDeviceWifi *device,
                                         const char *path)
{
	const GPtrArray *aps;
	int i;
	NMAccessPoint *ap = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	aps = nm_device_wifi_get_access_points (device);
	if (!aps)
		return NULL;

	for (i = 0; i < aps->len; i++) {
		NMAccessPoint *candidate = g_ptr_array_index (aps, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), path)) {
			ap = candidate;
			break;
		}
	}

	return ap;
}

/**
 * nm_device_wifi_request_scan:
 * @device: a #NMDeviceWifi
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Request NM to scan for access points on @device. Note that the function
 * returns immediately after requesting the scan, and it may take some time
 * after that for the scan to complete.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be
 * set.
 **/
gboolean
nm_device_wifi_request_scan (NMDeviceWifi *device,
                             GCancellable *cancellable,
                             GError **error)
{
	gboolean ret;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), FALSE);

	ret = nmdbus_device_wifi_call_request_scan_sync (NM_DEVICE_WIFI_GET_PRIVATE (device)->proxy,
	                                                 g_variant_new_array (G_VARIANT_TYPE ("{sv}"),
	                                                                      NULL, 0),
	                                                 cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
request_scan_cb (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	RequestScanInfo *info = user_data;
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (info->device);
	GError *error = NULL;

	priv->scan_info = NULL;

	if (nmdbus_device_wifi_call_request_scan_finish (NMDBUS_DEVICE_WIFI (source),
	                                                 result, &error))
		g_simple_async_result_set_op_res_gboolean (info->simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (info->simple, error);
	}

	g_simple_async_result_complete (info->simple);
	g_object_unref (info->simple);
	g_slice_free (RequestScanInfo, info);
}

/**
 * nm_device_wifi_request_scan_async:
 * @device: a #NMDeviceWifi
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the scan has been requested
 * @user_data: caller-specific data passed to @callback
 *
 * Request NM to scan for access points on @device. Note that @callback will be
 * called immediately after requesting the scan, and it may take some time after
 * that for the scan to complete.
 **/
void
nm_device_wifi_request_scan_async (NMDeviceWifi *device,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	RequestScanInfo *info;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_DEVICE_WIFI (device));

	simple = g_simple_async_result_new (G_OBJECT (device), callback, user_data,
	                                    nm_device_wifi_request_scan_async);

	/* If a scan is in progress, just return */
	if (priv->scan_info) {
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	info = g_slice_new0 (RequestScanInfo);
	info->device = device;
	info->simple = simple;

	priv->scan_info = info;
	nmdbus_device_wifi_call_request_scan (NM_DEVICE_WIFI_GET_PRIVATE (device)->proxy,
	                                      g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0),
	                                      cancellable, request_scan_cb, info);
}

/**
 * nm_device_wifi_request_scan_finish:
 * @device: a #NMDeviceWifi
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_device_wifi_request_scan_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be
 * set.
 **/
gboolean
nm_device_wifi_request_scan_finish (NMDeviceWifi *device,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (device), nm_device_wifi_request_scan_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

static void
clean_up_aps (NMDeviceWifi *self, gboolean in_dispose)
{
	NMDeviceWifiPrivate *priv;
	GPtrArray *aps;
	int i;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->active_ap) {
		g_object_unref (priv->active_ap);
		priv->active_ap = NULL;
	}

	aps = priv->aps;

	if (in_dispose)
		priv->aps = NULL;
	else {
		priv->aps = g_ptr_array_new ();

		for (i = 0; i < aps->len; i++) {
			NMAccessPoint *ap = NM_ACCESS_POINT (g_ptr_array_index (aps, i));

			g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);
		}
	}

	g_ptr_array_unref (aps);
}

/**
 * _nm_device_wifi_set_wireless_enabled:
 * @device: a #NMDeviceWifi
 * @enabled: %TRUE to enable the device
 *
 * Enables or disables the wireless device.
 **/
void
_nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device,
                                      gboolean enabled)
{
	g_return_if_fail (NM_IS_DEVICE_WIFI (device));

	if (!enabled)
		clean_up_aps (device, FALSE);
}

#define WPA_CAPS (NM_WIFI_DEVICE_CAP_CIPHER_TKIP | \
                  NM_WIFI_DEVICE_CAP_CIPHER_CCMP | \
                  NM_WIFI_DEVICE_CAP_WPA | \
                  NM_WIFI_DEVICE_CAP_RSN)

#define RSN_CAPS (NM_WIFI_DEVICE_CAP_CIPHER_CCMP | NM_WIFI_DEVICE_CAP_RSN)

static gboolean
has_proto (NMSettingWirelessSecurity *s_wsec, const char *proto)
{
	int i;

	for (i = 0; i < nm_setting_wireless_security_get_num_protos (s_wsec); i++) {
		if (g_strcmp0 (proto, nm_setting_wireless_security_get_proto (s_wsec, i)) == 0)
			return TRUE;
	}
	return FALSE;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *hwaddr, *setting_hwaddr;
	NMDeviceWifiCapabilities wifi_caps;
	const char *key_mgmt;

	if (!NM_DEVICE_CLASS (nm_device_wifi_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_WIRELESS_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a Wi-Fi connection."));
		return FALSE;
	}

	/* Check MAC address */
	hwaddr = nm_device_wifi_get_permanent_hw_address (NM_DEVICE_WIFI (device));
	if (hwaddr) {
		if (!nm_utils_hwaddr_valid (hwaddr, ETH_ALEN)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			                     _("Invalid device MAC address."));
			return FALSE;
		}
		s_wifi = nm_connection_get_setting_wireless (connection);
		setting_hwaddr = nm_setting_wireless_get_mac_address (s_wifi);
		if (setting_hwaddr && !nm_utils_hwaddr_matches (setting_hwaddr, -1, hwaddr, -1)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The MACs of the device and the connection didn't match."));
			return FALSE;
		}
	}

	/* Check device capabilities; we assume all devices can do WEP at least */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec) {
		/* Connection has security, verify it against the device's capabilities */
		key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
		if (   !g_strcmp0 (key_mgmt, "wpa-none")
		    || !g_strcmp0 (key_mgmt, "wpa-psk")
		    || !g_strcmp0 (key_mgmt, "wpa-eap")) {

			wifi_caps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));

			/* Is device only WEP capable? */
			if (!(wifi_caps & WPA_CAPS)) {
				g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
				                     _("The device is lacking WPA capabilities required by the connection."));
				return FALSE;
			}

			/* Make sure WPA2/RSN-only connections don't get chosen for WPA-only cards */
			if (has_proto (s_wsec, "rsn") && !has_proto (s_wsec, "wpa") && !(wifi_caps & RSN_CAPS)) {
				g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
				                     _("The device is lacking WPA2/RSN capabilities required by the connection."));
				return FALSE;
			}
		}
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_WIRELESS;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_wifi_get_hw_address (NM_DEVICE_WIFI (device));
}

/**************************************************************/

static void
nm_device_wifi_init (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_WIFI);

	g_signal_connect (device,
	                  "notify::" NM_DEVICE_STATE,
	                  G_CALLBACK (state_changed_cb),
	                  NULL);

	priv->aps = g_ptr_array_new ();
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_wifi_get_hw_address (self));
		break;
	case PROP_PERM_HW_ADDRESS:
		g_value_set_string (value, nm_device_wifi_get_permanent_hw_address (self));
		break;
	case PROP_MODE:
		g_value_set_enum (value, nm_device_wifi_get_mode (self));
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, nm_device_wifi_get_bitrate (self));
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		g_value_set_object (value, nm_device_wifi_get_active_access_point (self));
		break;
	case PROP_WIRELESS_CAPABILITIES:
		g_value_set_flags (value, nm_device_wifi_get_capabilities (self));
		break;
	case PROP_ACCESS_POINTS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_wifi_get_access_points (self)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		/* Just clear active AP; don't clear the AP list unless wireless is disabled completely */
		if (priv->active_ap) {
			g_object_unref (priv->active_ap);
			priv->active_ap = NULL;
		}
		_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);
		priv->rate = 0;
		_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_WIFI_BITRATE);
		break;
	default:
		break;
	}
}

static void
init_dbus (NMObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_WIFI_HW_ADDRESS,           &priv->hw_address },
		{ NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS, &priv->perm_hw_address },
		{ NM_DEVICE_WIFI_MODE,                 &priv->mode },
		{ NM_DEVICE_WIFI_BITRATE,              &priv->rate },
		{ NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT,  &priv->active_ap, NULL, NM_TYPE_ACCESS_POINT },
		{ NM_DEVICE_WIFI_CAPABILITIES,         &priv->wireless_caps },
		{ NM_DEVICE_WIFI_ACCESS_POINTS,        &priv->aps, NULL, NM_TYPE_ACCESS_POINT, "access-point" },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_wifi_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_DEVICE_WIFI (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_DEVICE_WIRELESS));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	                                property_info);
}

static void
access_point_removed (NMDeviceWifi *self, NMAccessPoint *ap)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (ap == priv->active_ap) {
		g_object_unref (priv->active_ap);
		priv->active_ap = NULL;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);

		priv->rate = 0;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
	}
}

static void
dispose (GObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	if (priv->aps)
		clean_up_aps (NM_DEVICE_WIFI (object), TRUE);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_free (priv->perm_hw_address);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->finalize (object);
}

static void
nm_device_wifi_class_init (NMDeviceWifiClass *wifi_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wifi_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (wifi_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wifi_class);

	g_type_class_add_private (wifi_class, sizeof (NMDeviceWifiPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DEVICE_WIRELESS);
	_nm_dbus_register_proxy_type (NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	                              NMDBUS_TYPE_DEVICE_WIFI_PROXY);

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	wifi_class->access_point_removed = access_point_removed;

	/* properties */

	/**
	 * NMDeviceWifi:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIFI_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWifi:perm-hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWifi:mode:
	 *
	 * The mode of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_enum (NM_DEVICE_WIFI_MODE, "", "",
		                    NM_TYPE_802_11_MODE,
		                    NM_802_11_MODE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWifi:bitrate:
	 *
	 * The bit rate of the device in kbit/s.
	 **/
	g_object_class_install_property
		(object_class, PROP_BITRATE,
		 g_param_spec_uint (NM_DEVICE_WIFI_BITRATE, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWifi:active-access-point:
	 *
	 * The active #NMAccessPoint of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_ACCESS_POINT,
		 g_param_spec_object (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT, "", "",
		                      NM_TYPE_ACCESS_POINT,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWifi:wireless-capabilities:
	 *
	 * The wireless capabilities of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_CAPABILITIES,
		 g_param_spec_flags (NM_DEVICE_WIFI_CAPABILITIES, "", "",
		                     NM_TYPE_DEVICE_WIFI_CAPABILITIES,
		                     NM_WIFI_DEVICE_CAP_NONE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceWifi:access-points:
	 *
	 * List of all Wi-Fi access points the device can see.
	 *
	 * Element-type: NMAccessPoint
	 **/
	g_object_class_install_property
		(object_class, PROP_ACCESS_POINTS,
		 g_param_spec_boxed (NM_DEVICE_WIFI_ACCESS_POINTS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMDeviceWifi::access-point-added:
	 * @device: the Wi-Fi device that received the signal
	 * @ap: the new access point
	 *
	 * Notifies that a #NMAccessPoint is added to the Wi-Fi device.
	 **/
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMDeviceWifi::access-point-removed:
	 * @device: the Wi-Fi device that received the signal
	 * @ap: the removed access point
	 *
	 * Notifies that a #NMAccessPoint is removed from the Wi-Fi device.
	 **/
	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
}
