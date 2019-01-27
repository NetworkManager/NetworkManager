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
 * Copyright 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-p2p-wifi.h"

#include <string.h>

#include "nm-setting-connection.h"
#include "nm-setting-p2p-wireless.h"
#include "nm-utils.h"

#include "nm-p2p-peer.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"
#include "nm-dbus-helpers.h"

#include "introspection/org.freedesktop.NetworkManager.Device.P2PWireless.h"

G_DEFINE_TYPE (NMDeviceP2PWifi, nm_device_p2p_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_P2P_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_P2P_WIFI, NMDeviceP2PWifiPrivate))

void _nm_device_p2p_wifi_set_p2p_wireless_enabled (NMDeviceP2PWifi *device, gboolean enabled);
static void state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data);

typedef struct {
	NMDeviceP2PWifi *device;
	GSimpleAsyncResult *simple;
} RequestScanInfo;

typedef struct {
	NMDBusDeviceP2PWifi *proxy;

	char *hw_address;

	gboolean     group_owner;
	GByteArray  *wfd_ies;
	GPtrArray   *peers;
} NMDeviceP2PWifiPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_GROUP_OWNER,
	PROP_WFDIES,
	PROP_PEERS,

	LAST_PROP
};

enum {
	PEER_ADDED,
	PEER_REMOVED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_device_p2p_wifi_get_hw_address:
 * @device: a #NMDeviceP2PWifi
 *
 * Gets the actual hardware (MAC) address of the #NMDeviceP2PWifi
 *
 * Returns: the actual hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.16
 **/
const char *
nm_device_p2p_wifi_get_hw_address (NMDeviceP2PWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_P2P_WIFI (device), NULL);

	return nm_str_not_empty (NM_DEVICE_P2P_WIFI_GET_PRIVATE (device)->hw_address);
}

/**
 * nm_device_p2p_wifi_get_group_owner:
 * @device: a #NMDeviceP2PWifi
 *
 * Gets whether the device is currently the P2P group owner. This is only
 * valid when a connection is established.
 *
 * Returns: Whether the device is the P2P group owner.
 *
 * Since: 1.16
 **/
gboolean
nm_device_p2p_wifi_get_group_owner (NMDeviceP2PWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_P2P_WIFI (device), FALSE);

	return NM_DEVICE_P2P_WIFI_GET_PRIVATE (device)->group_owner;
}

/**
 * nm_device_p2p_wifi_get_peers:
 * @device: a #NMDeviceP2PWifi
 *
 * Gets all the found peers of the #NMDeviceP2PWifi.
 *
 * Returns: (element-type NMP2PPeer): a #GPtrArray containing all the
 *          found #NMP2PPeers.
 * The returned array is owned by the client and should not be modified.
 *
 * Since: 1.16
 **/
const GPtrArray *
nm_device_p2p_wifi_get_peers (NMDeviceP2PWifi *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_P2P_WIFI (device), NULL);

	return NM_DEVICE_P2P_WIFI_GET_PRIVATE (device)->peers;
}

/**
 * nm_device_p2p_wifi_get_peer_by_path:
 * @device: a #NMDeviceP2PWifi
 * @path: the object path of the peer
 *
 * Gets a #NMP2PPeer by path.
 *
 * Returns: (transfer none): the peer or %NULL if none is found.
 *
 * Since: 1.16
 **/
NMP2PPeer *
nm_device_p2p_wifi_get_peer_by_path (NMDeviceP2PWifi *device,
                                     const char *path)
{
	const GPtrArray *peers;
	int i;
	NMP2PPeer *peer = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_P2P_WIFI (device), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	peers = nm_device_p2p_wifi_get_peers (device);
	if (!peers)
		return NULL;

	for (i = 0; i < peers->len; i++) {
		NMP2PPeer *candidate = g_ptr_array_index (peers, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), path)) {
			peer = candidate;
			break;
		}
	}

	return peer;
}

static void
clean_up_peers (NMDeviceP2PWifi *self, gboolean in_dispose)
{
	NMDeviceP2PWifiPrivate *priv;
	GPtrArray *peers;
	int i;

	g_return_if_fail (NM_IS_DEVICE_P2P_WIFI (self));

	priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (self);

	peers = priv->peers;

	if (in_dispose)
		priv->peers = NULL;
	else {
		priv->peers = g_ptr_array_new ();

		for (i = 0; i < peers->len; i++) {
			NMP2PPeer *peer = NM_P2P_PEER (g_ptr_array_index (peers, i));

			g_signal_emit (self, signals[PEER_REMOVED], 0, peer);
		}
	}

	g_ptr_array_unref (peers);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_p2p_wifi_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_P2P_WIRELESS_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a P2P Wi-Fi connection."));
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
	return nm_device_p2p_wifi_get_hw_address (NM_DEVICE_P2P_WIFI (device));
}

static GVariant *
nm_device_p2p_wifi_get_wfdies_as_variant (const NMDeviceP2PWifi *self)
{
	const NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (self);

	if (priv->wfd_ies) {
		return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                  priv->wfd_ies->data, priv->wfd_ies->len, 1);
	} else
		return g_variant_new_array (G_VARIANT_TYPE_BYTE, NULL, 0);
}

/**
 * nm_device_p2p_wifi_start_find:
 * @device: a #NMDeviceP2PWifi
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Request NM to search for P2P peers on @device. Note that the function
 * returns immediately after requesting the find, and it may take some time
 * after that for peers to be found.
 *
 * The find operation will run for 30s by default. You can stop it earlier
 * using nm_device_p2p_wifi_stop_find().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be
 * set.
 *
 * Since: 1.16
 **/
gboolean
nm_device_p2p_wifi_start_find (NMDeviceP2PWifi  *device,
                               GCancellable     *cancellable,
                               GError          **error)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (device);
	GVariant *options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
	gboolean ret;

	g_return_val_if_fail (NM_IS_DEVICE_P2P_WIFI (device), FALSE);

	ret = nmdbus_device_p2p_wifi_call_start_find_sync (priv->proxy,
	                                                   options,
	                                                   cancellable, error);

	if (error && *error)
		g_dbus_error_strip_remote_error (*error);

	return ret;
}

/**
 * nm_device_p2p_wifi_stop_find:
 * @device: a #NMDeviceP2PWifi
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Request NM to stop searching for P2P peers on @device.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be
 * set.
 *
 * Since: 1.16
 **/
gboolean
nm_device_p2p_wifi_stop_find (NMDeviceP2PWifi  *device,
                              GCancellable     *cancellable,
                              GError          **error)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (device);
	gboolean ret;

	g_return_val_if_fail (NM_IS_DEVICE_P2P_WIFI (device), FALSE);

	ret = nmdbus_device_p2p_wifi_call_stop_find_sync (priv->proxy,
	                                                  cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);

	return ret;
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceP2PWifi *self = NM_DEVICE_P2P_WIFI (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_p2p_wifi_get_hw_address (self));
		break;
	case PROP_GROUP_OWNER:
		g_value_set_enum (value, nm_device_p2p_wifi_get_group_owner (self));
		break;
	case PROP_WFDIES:
		g_value_take_variant (value, nm_device_p2p_wifi_get_wfdies_as_variant (self));
		break;
	case PROP_PEERS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_p2p_wifi_get_peers (self)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_p2p_wifi_init (NMDeviceP2PWifi *device)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (device);

	g_signal_connect (device,
	                  "notify::" NM_DEVICE_STATE,
	                  G_CALLBACK (state_changed_cb),
	                  NULL);

	priv->peers = g_ptr_array_new ();
}

static void
state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
#if 0
	NMDeviceP2PWifi *self = NM_DEVICE_P2P_WIFI (device);

	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		/* TODO: Do something? */
		break;
	default:
		break;
	}
#endif
}

static void
init_dbus (NMObject *object)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_P2P_WIFI_HW_ADDRESS,           &priv->hw_address },
		{ NM_DEVICE_P2P_WIFI_GROUP_OWNER,          &priv->group_owner },
		{ NM_DEVICE_P2P_WIFI_WFDIES,               &priv->wfd_ies },
		{ NM_DEVICE_P2P_WIFI_PEERS,                &priv->peers, NULL, NM_TYPE_P2P_PEER, "peer" },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_p2p_wifi_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_DEVICE_P2P_WIFI (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_DEVICE_P2P_WIRELESS));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_P2P_WIRELESS,
	                                property_info);
}

static void
dispose (GObject *object)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (object);

	if (priv->peers)
		clean_up_peers (NM_DEVICE_P2P_WIFI (object), TRUE);

	g_clear_object (&priv->proxy);
	if (priv->wfd_ies)
		g_byte_array_unref (priv->wfd_ies);
	priv->wfd_ies = NULL;

	G_OBJECT_CLASS (nm_device_p2p_wifi_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_p2p_wifi_parent_class)->finalize (object);
}

static void
nm_device_p2p_wifi_class_init (NMDeviceP2PWifiClass *wifi_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wifi_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (wifi_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wifi_class);

	g_type_class_add_private (wifi_class, sizeof (NMDeviceP2PWifiPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceP2PWifi:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.16
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_P2P_WIFI_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));


	/**
	 * NMDeviceP2PWifi:group-owner:
	 *
	 * Whether the device is currently the group owner.
	 *
	 * Since: 1.16
	 **/
	g_object_class_install_property
		(object_class, PROP_GROUP_OWNER,
		 g_param_spec_boolean (NM_DEVICE_P2P_WIFI_GROUP_OWNER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceP2PWifi:wfd-ies:
	 *
	 * Whether the device is currently the group owner.
	 *
	 * Since: 1.16
	 **/
	g_object_class_install_property
		(object_class, PROP_WFDIES,
	     g_param_spec_variant (NM_DEVICE_P2P_WIFI_WFDIES, "", "",
	                           G_VARIANT_TYPE ("ay"),
	                           NULL,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceP2PWifi:peers: (type GPtrArray(NMP2PPeer))
	 *
	 * List of all P2P Wi-Fi peers the device can see.
	 *
	 * Since: 1.16
	 **/
	g_object_class_install_property
		(object_class, PROP_PEERS,
		 g_param_spec_boxed (NM_DEVICE_P2P_WIFI_PEERS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMDeviceP2PWifi::peer-added:
	 * @device: the P2P Wi-Fi device that received the signal
	 * @peer: the new access point
	 *
	 * Notifies that a #NMP2PPeer is added to the P2P Wi-Fi device.
	 *
	 * Since: 1.16
	 **/
	signals[PEER_ADDED] =
		g_signal_new ("peer-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceP2PWifiClass, peer_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMDeviceP2PWifi::peer-removed:
	 * @device: the P2P Wi-Fi device that received the signal
	 * @peer: the removed access point
	 *
	 * Notifies that a #NMP2PPeer is removed from the P2P Wi-Fi device.
	 *
	 * Since: 1.16
	 **/
	signals[PEER_REMOVED] =
		g_signal_new ("peer-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceP2PWifiClass, peer_removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
}
