// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-wifi.h"

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-utils.h"
#include "nm-access-point.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"
#include "nm-dbus-helpers.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACCESS_POINTS,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_WIRELESS_CAPABILITIES,
	PROP_LAST_SCAN,
);

typedef struct {
	NMLDBusPropertyAO access_points;
	NMLDBusPropertyO active_access_point;
	char *hw_address;
	char *perm_hw_address;
	gint64 last_scan;
	guint32 mode;
	guint32 bitrate;
	guint32 wireless_capabilities;
} NMDeviceWifiPrivate;

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _NMDeviceWifi {
	NMDevice parent;
	NMDeviceWifiPrivate _priv;
};

struct _NMDeviceWifiClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceWifi, NM_IS_DEVICE_WIFI, NMObject, NMDevice)

/*****************************************************************************/

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

	return _nml_coerce_property_str_not_empty (NM_DEVICE_WIFI_GET_PRIVATE (device)->hw_address);
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

	return _nml_coerce_property_str_not_empty (NM_DEVICE_WIFI_GET_PRIVATE (device)->perm_hw_address);
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

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->bitrate;
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

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->wireless_capabilities;
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
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_WIFI_GET_PRIVATE (device)->active_access_point);
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

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_DEVICE_WIFI_GET_PRIVATE (device)->access_points);
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
 * nm_device_wifi_get_last_scan:
 * @device: a #NMDeviceWifi
 *
 * Returns the timestamp (in CLOCK_BOOTTIME milliseconds) for the last finished
 * network scan. A value of -1 means the device never scanned for access points.
 *
 * Use nm_utils_get_timestamp_msec() to obtain current time value suitable for
 * comparing to this value.
 *
 * Returns: the last scan time in seconds
 *
 * Since: 1.12
 **/
gint64
nm_device_wifi_get_last_scan (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), -1);

	return NM_DEVICE_WIFI_GET_PRIVATE (device)->last_scan;
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
 *
 * Deprecated: 1.22, use nm_device_wifi_request_scan_async() or GDBusConnection
 **/
gboolean
nm_device_wifi_request_scan (NMDeviceWifi *device,
                             GCancellable *cancellable,
                             GError **error)
{
	return nm_device_wifi_request_scan_options (device, NULL, cancellable, error);
}

/**
 * nm_device_wifi_request_scan_options:
 * @device: a #NMDeviceWifi
 * @options: dictionary with options for RequestScan(), or %NULL
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Request NM to scan for access points on @device. Note that the function
 * returns immediately after requesting the scan, and it may take some time
 * after that for the scan to complete.
 * This is the same as @nm_device_wifi_request_scan except it accepts @options
 * for the scanning. The argument is the dictionary passed to RequestScan()
 * D-Bus call. Valid options inside the dictionary are:
 * 'ssids' => array of SSIDs (saay)
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be
 * set.
 *
 * Since: 1.2
 *
 * Deprecated: 1.22, use nm_device_wifi_request_scan_options_async() or GDBusConnection
 **/
gboolean
nm_device_wifi_request_scan_options (NMDeviceWifi *device,
                                     GVariant *options,
                                     GCancellable *cancellable,
                                     GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), FALSE);
	g_return_val_if_fail (!options || g_variant_is_of_type (options, G_VARIANT_TYPE_VARDICT), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!options)
		options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);

	return _nm_client_dbus_call_sync_void (_nm_object_get_client (device),
	                                       cancellable,
	                                       _nm_object_get_path (device),
	                                       NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	                                       "RequestScan",
	                                       g_variant_new ("(@a{sv})", options),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

NM_BACKPORT_SYMBOL (libnm_1_0_6, gboolean, nm_device_wifi_request_scan_options,
  (NMDeviceWifi *device, GVariant *options, GCancellable *cancellable, GError **error),
  (device, options, cancellable, error));

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
	nm_device_wifi_request_scan_options_async (device, NULL, cancellable, callback, user_data);
}

/**
 * nm_device_wifi_request_scan_options_async:
 * @device: a #NMDeviceWifi
 * @options: dictionary with options for RequestScan(), or %NULL
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the scan has been requested
 * @user_data: caller-specific data passed to @callback
 *
 * Request NM to scan for access points on @device. Note that @callback will be
 * called immediately after requesting the scan, and it may take some time after
 * that for the scan to complete.
 * This is the same as @nm_device_wifi_request_scan_async except it accepts @options
 * for the scanning. The argument is the dictionary passed to RequestScan()
 * D-Bus call. Valid options inside the dictionary are:
 * 'ssids' => array of SSIDs (saay)
 *
 * To complete the request call nm_device_wifi_request_scan_finish().
 *
 * Since: 1.2
 **/
void
nm_device_wifi_request_scan_options_async (NMDeviceWifi *device,
                                           GVariant *options,
                                           GCancellable *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
	g_return_if_fail (NM_IS_DEVICE_WIFI (device));
	g_return_if_fail (!options || g_variant_is_of_type (options, G_VARIANT_TYPE_VARDICT));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	if (!options)
		options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);

	_nm_client_dbus_call (_nm_object_get_client (device),
	                      device,
	                      nm_device_wifi_request_scan_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (device),
	                      NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	                      "RequestScan",
	                      g_variant_new ("(@a{sv})", options),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

NM_BACKPORT_SYMBOL (libnm_1_0_6, void, nm_device_wifi_request_scan_options_async,
  (NMDeviceWifi *device, GVariant *options, GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data),
  (device, options, cancellable, callback, user_data));

/**
 * nm_device_wifi_request_scan_finish:
 * @device: a #NMDeviceWifi
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_device_wifi_request_scan_async() and
 * nm_device_wifi_request_scan_options_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be
 * set.
 **/
gboolean
nm_device_wifi_request_scan_finish (NMDeviceWifi *device,
                                    GAsyncResult *result,
                                    GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, device, nm_device_wifi_request_scan_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
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
		if (   !g_strcmp0 (key_mgmt, "wpa-psk")
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

/*****************************************************************************/

static void
_property_ao_notify_changed_access_points_cb (NMLDBusPropertyAO *pr_ao,
                                              NMClient *client,
                                              NMObject *nmobj,
                                              gboolean is_added /* or else removed */)
{
	_nm_client_notify_event_queue_emit_obj_signal (client,
	                                               G_OBJECT (pr_ao->owner_dbobj->nmobj),
	                                               nmobj,
	                                               is_added,
	                                               10,
	                                                 is_added
	                                               ? signals[ACCESS_POINT_ADDED]
	                                               : signals[ACCESS_POINT_REMOVED]);
}

/*****************************************************************************/

static void
nm_device_wifi_init (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

	priv->last_scan = -1;
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
	case PROP_LAST_SCAN:
		g_value_set_int64 (value, nm_device_wifi_get_last_scan (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_free (priv->perm_hw_address);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->finalize (object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_wireless = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	nm_device_wifi_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("AccessPoints",         PROP_ACCESS_POINTS,         NMDeviceWifi, _priv.access_points,       nm_access_point_get_type, .notify_changed_ao = _property_ao_notify_changed_access_points_cb ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("ActiveAccessPoint",    PROP_ACTIVE_ACCESS_POINT,   NMDeviceWifi, _priv.active_access_point, nm_access_point_get_type                                                                    ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Bitrate",              PROP_BITRATE,               NMDeviceWifi, _priv.bitrate                                                                                                          ),
		NML_DBUS_META_PROPERTY_INIT_S       ("HwAddress",            PROP_HW_ADDRESS,            NMDeviceWifi, _priv.hw_address                                                                                                       ),
		NML_DBUS_META_PROPERTY_INIT_X       ("LastScan",             PROP_LAST_SCAN,             NMDeviceWifi, _priv.last_scan                                                                                                        ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Mode",                 PROP_MODE,                  NMDeviceWifi, _priv.mode                                                                                                             ),
		NML_DBUS_META_PROPERTY_INIT_S       ("PermHwAddress",        PROP_PERM_HW_ADDRESS,       NMDeviceWifi, _priv.perm_hw_address                                                                                                  ),
		NML_DBUS_META_PROPERTY_INIT_U       ("WirelessCapabilities", PROP_WIRELESS_CAPABILITIES, NMDeviceWifi, _priv.wireless_capabilities                                                                                            ),
	),
);

static void
nm_device_wifi_class_init (NMDeviceWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceWifi);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1 (nm_object_class, NMDeviceWifiPrivate, active_access_point);
	_NM_OBJECT_CLASS_INIT_PROPERTY_AO_FIELDS_1 (nm_object_class, NMDeviceWifiPrivate, access_points);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
	device_class->get_hw_address        = get_hw_address;

	/**
	 * NMDeviceWifi:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_WIFI_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:perm-hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	obj_properties[PROP_PERM_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:mode:
	 *
	 * The mode of the device.
	 **/
	obj_properties[PROP_MODE] =
	    g_param_spec_enum (NM_DEVICE_WIFI_MODE, "", "",
	                       NM_TYPE_802_11_MODE,
	                       NM_802_11_MODE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:bitrate:
	 *
	 * The bit rate of the device in kbit/s.
	 **/
	obj_properties[PROP_BITRATE] =
	    g_param_spec_uint (NM_DEVICE_WIFI_BITRATE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:active-access-point:
	 *
	 * The active #NMAccessPoint of the device.
	 **/
	obj_properties[PROP_ACTIVE_ACCESS_POINT] =
	    g_param_spec_object (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT, "", "",
	                         NM_TYPE_ACCESS_POINT,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:wireless-capabilities:
	 *
	 * The wireless capabilities of the device.
	 **/
	obj_properties[PROP_WIRELESS_CAPABILITIES] =
	    g_param_spec_flags (NM_DEVICE_WIFI_CAPABILITIES, "", "",
	                        NM_TYPE_DEVICE_WIFI_CAPABILITIES,
	                        NM_WIFI_DEVICE_CAP_NONE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:access-points: (type GPtrArray(NMAccessPoint))
	 *
	 * List of all Wi-Fi access points the device can see.
	 **/
	obj_properties[PROP_ACCESS_POINTS] =
	    g_param_spec_boxed (NM_DEVICE_WIFI_ACCESS_POINTS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifi:last-scan:
	 *
	 * The timestamp (in CLOCK_BOOTTIME seconds) for the last finished
	 * network scan. A value of -1 means the device never scanned for
	 * access points.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_LAST_SCAN] =
	    g_param_spec_int64 (NM_DEVICE_WIFI_LAST_SCAN, "", "",
	                        -1, G_MAXINT64, -1,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_wireless);

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
	                  0, NULL, NULL,
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
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);
}
