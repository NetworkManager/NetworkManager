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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <string.h>

#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"
#include "nm-types-private.h"

#include "nm-device-wifi-bindings.h"

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIFI, NMDeviceWifiPrivate))

static gboolean demarshal_active_ap (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field);

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);

typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *hw_address;
	char *perm_hw_address;
	NM80211Mode mode;
	guint32 rate;
	NMAccessPoint *active_ap;
	gboolean null_active_ap;
	guint32 wireless_caps;
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
 * nm_device_wifi_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceWifi.
 *
 * Returns: a new device
 **/
GObject *
nm_device_wifi_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_DEVICE_WIFI,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
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
	NMDeviceWifiPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (!priv->hw_address) {
		priv->hw_address = _nm_object_get_string_property (NM_OBJECT (device),
		                                                  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                                  DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
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
	NMDeviceWifiPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (!priv->perm_hw_address) {
		priv->perm_hw_address = _nm_object_get_string_property (NM_OBJECT (device),
		                                                        NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                                        DBUS_PROP_PERM_HW_ADDRESS);
	}

	return priv->perm_hw_address;
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
	NMDeviceWifiPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (!priv->mode) {
		priv->mode = _nm_object_get_uint_property (NM_OBJECT (device),
		                                          NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                          DBUS_PROP_MODE);
	}

	return priv->mode;
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
	NMDeviceWifiPrivate *priv;
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	state = nm_device_get_state (NM_DEVICE (device));
	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	default:
		return 0;
		break;
	}

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (!priv->rate) {
		priv->rate = _nm_object_get_uint_property (NM_OBJECT (device),
		                                         NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                         DBUS_PROP_BITRATE);
	}

	return priv->rate;
}

/**
 * nm_device_wifi_get_capabilities:
 * @device: a #NMDeviceWifi
 *
 * Gets the WIFI capabilities of the #NMDeviceWifi.
 *
 * Returns: the capabilities
 **/
guint32
nm_device_wifi_get_capabilities (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), 0);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (!priv->wireless_caps) {
		priv->wireless_caps = _nm_object_get_uint_property (NM_OBJECT (device),
		                                                   NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                                   DBUS_PROP_WIRELESS_CAPABILITIES);
	}

	return priv->wireless_caps;
}

/**
 * nm_device_wifi_get_active_access_point:
 * @device: a #NMDeviceWifi
 *
 * Gets the active #NMAccessPoint.
 *
 * Returns: the access point or %NULL if none is active
 **/
NMAccessPoint *
nm_device_wifi_get_active_access_point (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv;
	NMDeviceState state;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	state = nm_device_get_state (NM_DEVICE (device));
	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	default:
		return NULL;
		break;
	}

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (priv->active_ap)
		return priv->active_ap;
	if (priv->null_active_ap)
		return NULL;

	path = _nm_object_get_object_path_property (NM_OBJECT (device),
	                                           NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	                                           DBUS_PROP_ACTIVE_ACCESS_POINT);
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_active_ap (NM_OBJECT (device), NULL, &value, &priv->active_ap);
		g_value_unset (&value);
	}

	return priv->active_ap;
}

/**
 * nm_device_wifi_get_access_points:
 * @device: a #NMDeviceWifi
 *
 * Gets all the scanned access points of the #NMDeviceWifi.
 *
 * Returns: a #GPtrArray containing all the scanned #NMAccessPoint<!-- -->s.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_device_wifi_get_access_points (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv;
	DBusGConnection *connection;
	GValue value = { 0, };
	GError *error = NULL;
	GPtrArray *temp;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	if (priv->aps)
		return handle_ptr_array_return (priv->aps);

	if (!org_freedesktop_NetworkManager_Device_Wireless_get_access_points (priv->proxy, &temp, &error)) {
		g_warning ("%s: error getting access points: %s", __func__, error->message);
		g_error_free (error);
		return NULL;
	}

	g_value_init (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH);
	g_value_take_boxed (&value, temp);
	connection = nm_object_get_connection (NM_OBJECT (device));
	_nm_object_array_demarshal (&value, &priv->aps, connection, nm_access_point_new);
	g_value_unset (&value);

	return handle_ptr_array_return (priv->aps);
}

/**
 * nm_device_wifi_get_access_point_by_path:
 * @device: a #NMDeviceWifi
 * @path: the object path of the access point
 *
 * Gets a #NMAccessPoint by path.
 *
 * Returns: the access point or %NULL if none is found.
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
access_point_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv;
	GObject *ap;

	g_return_if_fail (self != NULL);

	ap = G_OBJECT (nm_device_wifi_get_access_point_by_path (self, path));
	if (!ap) {
		DBusGConnection *connection = nm_object_get_connection (NM_OBJECT (self));

		priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
		ap = G_OBJECT (_nm_object_cache_get (path));
		if (ap) {
			g_ptr_array_add (priv->aps, g_object_ref (ap));
		} else {
			ap = G_OBJECT (nm_access_point_new (connection, path));
			if (ap)
				g_ptr_array_add (priv->aps, ap);
		}
	}

	if (ap)
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, NM_ACCESS_POINT (ap));
}

static void
access_point_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);

	ap = nm_device_wifi_get_access_point_by_path (self, path);
	if (ap) {
		if (ap == priv->active_ap) {
			g_object_unref (priv->active_ap);
			priv->active_ap = NULL;
			priv->null_active_ap = FALSE;

			_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);
			priv->rate = 0;
			_nm_object_queue_notify (NM_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
		}

		g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);
		g_ptr_array_remove (priv->aps, ap);
		g_object_unref (G_OBJECT (ap));
	}
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


/**************************************************************/

static void
nm_device_wifi_init (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

	priv->disposed = FALSE;
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
			priv->null_active_ap = FALSE;
		}
		_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);
		priv->rate = 0;
		_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_WIFI_BITRATE);
		break;
	default:
		break;
	}
}

static gboolean
demarshal_active_ap (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);
	const char *path;
	NMAccessPoint *ap = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_active_ap = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_active_ap = TRUE;
		else {
			ap = NM_ACCESS_POINT (_nm_object_cache_get (path));
			if (ap)
				ap = g_object_ref (ap);
			else {
				connection = nm_object_get_connection (object);
				ap = NM_ACCESS_POINT (nm_access_point_new (connection, path));
			}
		}
	}

	if (priv->active_ap) {
		g_object_unref (priv->active_ap);
		priv->active_ap = NULL;
	}

	if (ap)
		priv->active_ap = ap;

	_nm_object_queue_notify (object, NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);
	return TRUE;
}

static void
register_for_property_changed (NMDeviceWifi *device)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_WIFI_HW_ADDRESS,           _nm_object_demarshal_generic, &priv->hw_address },
		{ NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS, _nm_object_demarshal_generic, &priv->perm_hw_address },
		{ NM_DEVICE_WIFI_MODE,                 _nm_object_demarshal_generic, &priv->mode },
		{ NM_DEVICE_WIFI_BITRATE,              _nm_object_demarshal_generic, &priv->rate },
		{ NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT,  demarshal_active_ap,         &priv->active_ap },
		{ NM_DEVICE_WIFI_CAPABILITIES,         _nm_object_demarshal_generic, &priv->wireless_caps },
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
	NMDeviceWifiPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_wifi_parent_class)->constructor (type,
																    n_construct_params,
																    construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
											NM_DBUS_SERVICE,
											nm_object_get_path (NM_OBJECT (object)),
											NM_DBUS_INTERFACE_DEVICE_WIRELESS);

	dbus_g_proxy_add_signal (priv->proxy, "AccessPointAdded",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "AccessPointAdded",
						    G_CALLBACK (access_point_added_proxy),
						    object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "AccessPointRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "AccessPointRemoved",
						    G_CALLBACK (access_point_removed_proxy),
						    object, NULL);

	register_for_property_changed (NM_DEVICE_WIFI (object));

	g_signal_connect (NM_DEVICE (object),
	                  "notify::" NM_DEVICE_STATE,
	                  G_CALLBACK (state_changed_cb),
	                  NULL);

	return object;
}

static void
dispose (GObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	clean_up_aps (NM_DEVICE_WIFI (object), FALSE);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	if (priv->hw_address)
		g_free (priv->hw_address);

	if (priv->perm_hw_address)
		g_free (priv->perm_hw_address);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->finalize (object);
}

static void
nm_device_wifi_class_init (NMDeviceWifiClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDeviceWifiPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

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
