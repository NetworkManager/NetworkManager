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
 * Copyright 2018 - 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-wifi-p2p.h"

#include "nm-setting-connection.h"
#include "nm-setting-wifi-p2p.h"
#include "nm-utils.h"
#include "nm-wifi-p2p-peer.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"
#include "nm-dbus-helpers.h"

#include "introspection/org.freedesktop.NetworkManager.Device.WifiP2P.h"

/*****************************************************************************/

typedef struct {
	NMDeviceWifiP2P *device;
	GSimpleAsyncResult *simple;
} RequestScanInfo;

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
	PROP_PEERS,
);

enum {
	PEER_ADDED,
	PEER_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMDBusDeviceWifiP2P *proxy;

	char *hw_address;

	GPtrArray   *peers;
} NMDeviceWifiP2PPrivate;

/**
 * NMDeviceWifiP2P:
 *
 * Since: 1.16
 */
struct _NMDeviceWifiP2P {
	NMDevice parent;
	NMDeviceWifiP2PPrivate _priv;
};

struct _NMDeviceWifiP2PClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceWifiP2P, nm_device_wifi_p2p, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_P2P_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceWifiP2P, NM_IS_DEVICE_WIFI_P2P, NMDevice, NMObject)

/*****************************************************************************/

/**
 * nm_device_wifi_p2p_get_hw_address:
 * @device: a #NMDeviceWifiP2P
 *
 * Gets the actual hardware (MAC) address of the #NMDeviceWifiP2P
 *
 * Returns: the actual hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.16
 **/
const char *
nm_device_wifi_p2p_get_hw_address (NMDeviceWifiP2P *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI_P2P (device), NULL);

	return nm_str_not_empty (NM_DEVICE_WIFI_P2P_GET_PRIVATE (device)->hw_address);
}

/**
 * nm_device_wifi_p2p_get_peers:
 * @device: a #NMDeviceWifiP2P
 *
 * Gets all the found peers of the #NMDeviceWifiP2P.
 *
 * Returns: (element-type NMWifiP2PPeer): a #GPtrArray containing all the
 *          found #NMWifiP2PPeers.
 * The returned array is owned by the client and should not be modified.
 *
 * Since: 1.16
 **/
const GPtrArray *
nm_device_wifi_p2p_get_peers (NMDeviceWifiP2P *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIFI_P2P (device), NULL);

	return NM_DEVICE_WIFI_P2P_GET_PRIVATE (device)->peers;
}

/**
 * nm_device_wifi_p2p_get_peer_by_path:
 * @device: a #NMDeviceWifiP2P
 * @path: the object path of the peer
 *
 * Gets a #NMWifiP2PPeer by path.
 *
 * Returns: (transfer none): the peer or %NULL if none is found.
 *
 * Since: 1.16
 **/
NMWifiP2PPeer *
nm_device_wifi_p2p_get_peer_by_path (NMDeviceWifiP2P *device,
                                     const char *path)
{
	const GPtrArray *peers;
	int i;
	NMWifiP2PPeer *peer = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI_P2P (device), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	peers = nm_device_wifi_p2p_get_peers (device);
	if (!peers)
		return NULL;

	for (i = 0; i < peers->len; i++) {
		NMWifiP2PPeer *candidate = g_ptr_array_index (peers, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), path)) {
			peer = candidate;
			break;
		}
	}

	return peer;
}

static void
start_find_finished_cb (GObject      *obj,
                        GAsyncResult *res,
                        gpointer user_data)
{
	NMDBusDeviceWifiP2P *proxy = (NMDBusDeviceWifiP2P*) obj;
	gs_unref_object GTask *task = G_TASK (user_data);
	GError *error = NULL;
	gboolean success;

	success = nmdbus_device_wifi_p2p_call_start_find_finish (proxy, res, &error);
	if (!success)
		g_task_return_error (task, error);
	else
		g_task_return_boolean (task, TRUE);
}

/**
 * nm_device_wifi_p2p_start_find:
 * @device: a #NMDeviceWifiP2P
 * @options: (allow-none): optional options passed to StartFind.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: a #GAsyncReadyCallback, or %NULL
 * @user_data: user_data for @callback
 *
 * Request NM to search for Wi-Fi P2P peers on @device. Note that the call
 * returns immediately after requesting the find, and it may take some time
 * after that for peers to be found.
 *
 * The find operation will run for 30s by default. You can stop it earlier
 * using nm_device_p2p_wifi_stop_find().
 *
 * Since: 1.16
 **/
void
nm_device_wifi_p2p_start_find (NMDeviceWifiP2P     *device,
                               GVariant            *options,
                               GCancellable        *cancellable,
                               GAsyncReadyCallback  callback,
                               gpointer             user_data)
{
	NMDeviceWifiP2PPrivate *priv = NM_DEVICE_WIFI_P2P_GET_PRIVATE (device);
	GTask *task;

	g_return_if_fail (NM_IS_DEVICE_WIFI_P2P (device));

	task = g_task_new (device, cancellable, callback, user_data);

	if (!options)
		options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
	nmdbus_device_wifi_p2p_call_start_find (priv->proxy,
	                                        options,
	                                        cancellable,
	                                        start_find_finished_cb,
	                                        task);
}

/**
 * nm_device_wifi_p2p_start_find_finish:
 * @device: a #NMDeviceWifiP2P
 * @result: the #GAsyncResult
 * @error: #GError return address
 *
 * Finish an operation started by nm_device_wifi_p2p_start_find().
 *
 * Returns: %TRUE if the call was successful
 *
 * Since: 1.16
 **/
gboolean
nm_device_wifi_p2p_start_find_finish (NMDeviceWifiP2P  *device,
                                      GAsyncResult     *result,
                                      GError          **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
stop_find_finished_cb (GObject      *obj,
                       GAsyncResult *res,
                       gpointer user_data)
{
	NMDBusDeviceWifiP2P *proxy = (NMDBusDeviceWifiP2P*) obj;
	gs_unref_object GTask *task = G_TASK (user_data);
	GError *error = NULL;
	gboolean success;

	success = nmdbus_device_wifi_p2p_call_stop_find_finish (proxy, res, &error);
	if (!success)
		g_task_return_error (task, error);
	else
		g_task_return_boolean (task, TRUE);
}

/**
 * nm_device_wifi_p2p_stop_find:
 * @device: a #NMDeviceWifiP2P
 * @cancellable: a #GCancellable, or %NULL
 * @callback: a #GAsyncReadyCallback, or %NULL
 * @user_data: user_data for @callback
 *
 * Request NM to stop any ongoing find operation for Wi-Fi P2P peers on @device.
 *
 * Since: 1.16
 **/
void
nm_device_wifi_p2p_stop_find (NMDeviceWifiP2P     *device,
                              GCancellable        *cancellable,
                              GAsyncReadyCallback  callback,
                              gpointer             user_data)
{
	NMDeviceWifiP2PPrivate *priv = NM_DEVICE_WIFI_P2P_GET_PRIVATE (device);
	GTask *task;

	g_return_if_fail (NM_IS_DEVICE_WIFI_P2P (device));

	task = g_task_new (device, cancellable, callback, user_data);

	nmdbus_device_wifi_p2p_call_stop_find (priv->proxy,
	                                       cancellable,
	                                       stop_find_finished_cb,
	                                       task);
}

/**
 * nm_device_wifi_p2p_stop_find_finish:
 * @device: a #NMDeviceWifiP2P
 * @result: the #GAsyncResult
 * @error: #GError return address
 *
 * Finish an operation started by nm_device_wifi_p2p_stop_find().
 *
 * Returns: %TRUE if the call was successful
 *
 * Since: 1.16
 **/
gboolean
nm_device_wifi_p2p_stop_find_finish (NMDeviceWifiP2P  *device,
                                      GAsyncResult     *result,
                                      GError          **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
clean_up_peers (NMDeviceWifiP2P *self)
{
	NMDeviceWifiP2PPrivate *priv = NM_DEVICE_WIFI_P2P_GET_PRIVATE (self);

	while (priv->peers->len > 0) {
		NMWifiP2PPeer *peer;

		peer = priv->peers->pdata[priv->peers->len - 1];
		g_ptr_array_remove_index (priv->peers, priv->peers->len - 1);

		g_signal_emit (self, signals[PEER_REMOVED], 0, peer);
	}
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_wifi_p2p_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_WIFI_P2P_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a Wi-Fi P2P connection."));
		return FALSE;
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
	return nm_device_wifi_p2p_get_hw_address (NM_DEVICE_WIFI_P2P (device));
}

static const char *
get_type_description (NMDevice *device)
{
	return "wifi-p2p";
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceWifiP2P *self = NM_DEVICE_WIFI_P2P (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_wifi_p2p_get_hw_address (self));
		break;
	case PROP_PEERS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_wifi_p2p_get_peers (self)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_wifi_p2p_init (NMDeviceWifiP2P *device)
{
	NMDeviceWifiP2PPrivate *priv = NM_DEVICE_WIFI_P2P_GET_PRIVATE (device);

	priv->peers = g_ptr_array_new ();
}

static void
init_dbus (NMObject *object)
{
	NMDeviceWifiP2PPrivate *priv = NM_DEVICE_WIFI_P2P_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_WIFI_P2P_HW_ADDRESS,           &priv->hw_address },
		{ NM_DEVICE_WIFI_P2P_PEERS,                &priv->peers, NULL, NM_TYPE_WIFI_P2P_PEER, "peer" },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_wifi_p2p_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_DEVICE_WIFI_P2P (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_DEVICE_WIFI_P2P));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_WIFI_P2P,
	                                property_info);
}

static void
dispose (GObject *object)
{
	clean_up_peers (NM_DEVICE_WIFI_P2P (object));

	G_OBJECT_CLASS (nm_device_wifi_p2p_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceWifiP2PPrivate *priv = NM_DEVICE_WIFI_P2P_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);
	g_free (priv->hw_address);
	if (priv->peers)
		g_ptr_array_unref (priv->peers);

	G_OBJECT_CLASS (nm_device_wifi_p2p_parent_class)->finalize (object);
}

static void
nm_device_wifi_p2p_class_init (NMDeviceWifiP2PClass *wifi_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wifi_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (wifi_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wifi_class);

	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
	device_class->get_hw_address        = get_hw_address;
	device_class->get_type_description  = get_type_description;

	nm_object_class->init_dbus = init_dbus;

	/**
	 * NMDeviceWifiP2P:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_WIFI_P2P_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceWifiP2P:peers: (type GPtrArray(NMWifiP2PPeer))
	 *
	 * List of all Wi-Fi P2P peers the device can see.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PEERS] =
	    g_param_spec_boxed (NM_DEVICE_WIFI_P2P_PEERS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	/**
	 * NMDeviceWifiP2P::peer-added:
	 * @device: the Wi-Fi P2P device that received the signal
	 * @peer: the new access point
	 *
	 * Notifies that a #NMWifiP2PPeer is added to the Wi-Fi P2P device.
	 *
	 * Since: 1.16
	 **/
	signals[PEER_ADDED] =
	    g_signal_new ("peer-added",
	                 G_OBJECT_CLASS_TYPE (object_class),
	                 G_SIGNAL_RUN_FIRST,
	                 0, NULL, NULL,
	                 g_cclosure_marshal_VOID__OBJECT,
	                 G_TYPE_NONE, 1,
	                 G_TYPE_OBJECT);

	/**
	 * NMDeviceWifiP2P::peer-removed:
	 * @device: the Wi-Fi P2P device that received the signal
	 * @peer: the removed access point
	 *
	 * Notifies that a #NMWifiP2PPeer is removed from the Wi-Fi P2P device.
	 *
	 * Since: 1.16
	 **/
	signals[PEER_REMOVED] =
	    g_signal_new ("peer-removed",
	                 G_OBJECT_CLASS_TYPE (object_class),
	                 G_SIGNAL_RUN_FIRST,
	                 0, NULL, NULL,
	                 g_cclosure_marshal_VOID__OBJECT,
	                 G_TYPE_NONE, 1,
	                 G_TYPE_OBJECT);
}
