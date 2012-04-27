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
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <netinet/ether.h>

#include "nm-glib-compat.h"

#include <nm-setting-connection.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>

#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"
#include "nm-types-private.h"

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIFI, NMDeviceWifiPrivate))

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	char *perm_hw_address;
	NM80211Mode mode;
	guint32 rate;
	NMAccessPoint *active_ap;
	NMDeviceWifiCapabilities wireless_caps;
	GPtrArray *aps;

	gboolean wireless_enabled;
} NMDeviceWifiPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_WIRELESS_CAPABILITIES,

	LAST_PROP
};

#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_PERM_HW_ADDRESS "PermHwAddress"
#define DBUS_PROP_MODE "Mode"
#define DBUS_PROP_BITRATE "Bitrate"
#define DBUS_PROP_ACTIVE_ACCESS_POINT "ActiveAccessPoint"
#define DBUS_PROP_WIRELESS_CAPABILITIES "WirelessCapabilities"

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_device_wifi_error_quark:
 *
 * Registers an error quark for #NMDeviceWifi if necessary.
 *
 * Returns: the error quark used for #NMDeviceWifi errors.
 **/
GQuark
nm_device_wifi_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-wifi-error-quark");
	return quark;
}

/**
 * nm_device_wifi_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceWifi.
 *
 * Returns: (transfer full): a new WiFi device
 **/
GObject *
nm_device_wifi_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_WIFI,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

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

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_WIFI_GET_PRIVATE (device)->mode;
}

/**
 * nm_device_wifi_get_bitrate:
 * @device: a #NMDeviceWifi
 *
 * Gets the bit rate of the #NMDeviceWifi.
 *
 * Returns: the bit rate
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_WIFI_GET_PRIVATE (device)->rate;
}

/**
 * nm_device_wifi_get_capabilities:
 * @device: a #NMDeviceWifi
 *
 * Gets the WIFI capabilities of the #NMDeviceWifi.
 *
 * Returns: the capabilities
 **/
NMDeviceWifiCapabilities
nm_device_wifi_get_capabilities (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_WIFI_GET_PRIVATE (device)->active_ap;
}

/**
 * nm_device_wifi_get_access_points:
 * @device: a #NMDeviceWifi
 *
 * Gets all the scanned access points of the #NMDeviceWifi.
 *
 * Returns: (element-type NMClient.AccessPoint): a #GPtrArray containing all the
 * scanned #NMAccessPoint<!-- -->s.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_device_wifi_get_access_points (NMDeviceWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return handle_ptr_array_return (NM_DEVICE_WIFI_GET_PRIVATE (device)->aps);
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

static void
access_point_added (NMObject *self, NMObject *ap)
{
	g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, ap);
}

static void
access_point_removed (NMObject *self_obj, NMObject *ap_obj)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (self_obj);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap = NM_ACCESS_POINT (ap_obj);

	if (ap == priv->active_ap) {
		g_object_unref (priv->active_ap);
		priv->active_ap = NULL;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);

		priv->rate = 0;
		_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
	}

	g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);
}

static void
clean_up_aps (NMDeviceWifi *self, gboolean notify)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->active_ap) {
		g_object_unref (priv->active_ap);
		priv->active_ap = NULL;
	}

	if (priv->aps) {
		while (priv->aps->len) {
			NMAccessPoint *ap = NM_ACCESS_POINT (g_ptr_array_index (priv->aps, 0));

			if (notify)
				g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);
			g_ptr_array_remove (priv->aps, ap);
			g_object_unref (ap);
		}
		g_ptr_array_free (priv->aps, TRUE);
		priv->aps = NULL;
	}
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
		clean_up_aps (device, TRUE);
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
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *ctype;
	const GByteArray *mac;
	const char *hw_str;
	struct ether_addr *hw_mac;
	NMDeviceWifiCapabilities wifi_caps;
	const char *key_mgmt;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_WIRELESS_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_WIFI_ERROR, NM_DEVICE_WIFI_ERROR_NOT_WIFI_CONNECTION,
		             "The connection was not a Wi-Fi connection.");
		return FALSE;
	}

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi) {
		g_set_error (error, NM_DEVICE_WIFI_ERROR, NM_DEVICE_WIFI_ERROR_INVALID_WIFI_CONNECTION,
		             "The connection was not a valid Wi-Fi connection.");
		return FALSE;
	}

	/* Check MAC address */
	hw_str = nm_device_wifi_get_permanent_hw_address (NM_DEVICE_WIFI (device));
	if (hw_str) {
		hw_mac = ether_aton (hw_str);
		if (!hw_mac) {
			g_set_error (error, NM_DEVICE_WIFI_ERROR, NM_DEVICE_WIFI_ERROR_INVALID_DEVICE_MAC,
			             "Invalid device MAC address.");
			return FALSE;
		}
		mac = nm_setting_wireless_get_mac_address (s_wifi);
		if (mac && hw_mac && memcmp (mac->data, hw_mac->ether_addr_octet, ETH_ALEN)) {
			g_set_error (error, NM_DEVICE_WIFI_ERROR, NM_DEVICE_WIFI_ERROR_MAC_MISMATCH,
			             "The MACs of the device and the connection didn't match.");
			return FALSE;
		}
	}

	/* Check device capabilities; we assume all devices can do WEP at least */
	wifi_caps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec) {
		/* Connection has security, verify it against the device's capabilities */
		key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
		if (   !g_strcmp0 (key_mgmt, "wpa-none")
		    || !g_strcmp0 (key_mgmt, "wpa-psk")
		    || !g_strcmp0 (key_mgmt, "wpa-eap")) {

			/* Is device only WEP capable? */
			if (!(wifi_caps & WPA_CAPS)) {
				g_set_error (error, NM_DEVICE_WIFI_ERROR, NM_DEVICE_WIFI_ERROR_MISSING_DEVICE_WPA_CAPS,
				             "The device missed WPA capabilities required by the connection.");
				return FALSE;
			}

			/* Make sure WPA2/RSN-only connections don't get chosen for WPA-only cards */
			if (has_proto (s_wsec, "rsn") && !has_proto (s_wsec, "wpa") && !(wifi_caps & RSN_CAPS)) {
				g_set_error (error, NM_DEVICE_WIFI_ERROR, NM_DEVICE_WIFI_ERROR_MISSING_DEVICE_RSN_CAPS,
				             "The device missed WPA2/RSN capabilities required by the connection.");
				return FALSE;
			}
		}
	}

	return TRUE;
}

/**************************************************************/

static void
nm_device_wifi_init (NMDeviceWifi *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_WIFI);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_wifi_get_hw_address (self));
		break;
	case PROP_PERM_HW_ADDRESS:
		g_value_set_string (value, nm_device_wifi_get_permanent_hw_address (self));
		break;
	case PROP_MODE:
		g_value_set_uint (value, nm_device_wifi_get_mode (self));
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, nm_device_wifi_get_bitrate (self));
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		g_value_set_object (value, nm_device_wifi_get_active_access_point (self));
		break;
	case PROP_WIRELESS_CAPABILITIES:
		g_value_set_uint (value, nm_device_wifi_get_capabilities (self));
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
register_properties (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_WIFI_HW_ADDRESS,           &priv->hw_address },
		{ NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS, &priv->perm_hw_address },
		{ NM_DEVICE_WIFI_MODE,                 &priv->mode },
		{ NM_DEVICE_WIFI_BITRATE,              &priv->rate },
		{ NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT,  &priv->active_ap, NULL, NM_TYPE_ACCESS_POINT },
		{ NM_DEVICE_WIFI_CAPABILITIES,         &priv->wireless_caps },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);

	_nm_object_register_pseudo_property (NM_OBJECT (device),
	                                     priv->proxy,
	                                     "AccessPoints",
	                                     &priv->aps,
	                                     NM_TYPE_ACCESS_POINT,
	                                     access_point_added,
	                                     access_point_removed);
}

static void
constructed (GObject *object)
{
	NMDeviceWifiPrivate *priv;

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->constructed (object);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
											NM_DBUS_SERVICE,
											nm_object_get_path (NM_OBJECT (object)),
											NM_DBUS_INTERFACE_DEVICE_WIRELESS);

	register_properties (NM_DEVICE_WIFI (object));

	g_signal_connect (NM_DEVICE (object),
	                  "notify::" NM_DEVICE_STATE,
	                  G_CALLBACK (state_changed_cb),
	                  NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	clean_up_aps (NM_DEVICE_WIFI (object), FALSE);
	g_clear_object (&priv->proxy);

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
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wifi_class);

	g_type_class_add_private (wifi_class, sizeof (NMDeviceWifiPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	device_class->connection_compatible = connection_compatible;

	/* properties */

	/**
	 * NMDeviceWifi:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIFI_HW_ADDRESS,
						  "Active MAC Address",
						  "Currently set hardware MAC address",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDeviceWifi:perm-hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS,
						  "Permanent MAC Address",
						  "Permanent hardware MAC address",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDeviceWifi:mode:
	 *
	 * The mode of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_DEVICE_WIFI_MODE,
					    "Mode",
					    "Mode",
					    NM_802_11_MODE_UNKNOWN, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
					    G_PARAM_READABLE));

	/**
	 * NMDeviceWifi:bitrate:
	 *
	 * The bit rate of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_BITRATE,
		 g_param_spec_uint (NM_DEVICE_WIFI_BITRATE,
					    "Bit Rate",
					    "Bit Rate",
					    0, G_MAXUINT32, 0,
					    G_PARAM_READABLE));

	/**
	 * NMDeviceWifi:active-access-point:
	 *
	 * The active #NMAccessPoint of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_ACCESS_POINT,
		 g_param_spec_object (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT,
						 "Active Access Point",
						 "Active Access Point",
						 NM_TYPE_ACCESS_POINT,
						 G_PARAM_READABLE));

	/**
	 * NMDeviceWifi:wireless-capabilities:
	 *
	 * The wireless capabilities of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_WIFI_CAPABILITIES,
		                    "Wireless Capabilities",
		                    "Wireless Capabilities",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	/* signals */

	/**
	 * NMDeviceWifi::access-point-added:
	 * @device: the wifi device that received the signal
	 * @ap: the new access point
	 *
	 * Notifies that a #NMAccessPoint is added to the wifi device.
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
	 * @device: the wifi device that received the signal
	 * @ap: the removed access point
	 *
	 * Notifies that a #NMAccessPoint is removed from the wifi device.
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
