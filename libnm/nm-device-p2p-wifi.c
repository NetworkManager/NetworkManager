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

/*****************************************************************************/

typedef struct {
	NMDeviceP2PWifi *device;
	GSimpleAsyncResult *simple;
} RequestScanInfo;

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
	PROP_GROUP_OWNER,
	PROP_WFDIES,
	PROP_PEERS,
);

enum {
	PEER_ADDED,
	PEER_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMDBusDeviceP2PWifi *proxy;

	char *hw_address;

	GByteArray  *wfd_ies;
	GPtrArray   *peers;

	gboolean group_owner;
} NMDeviceP2PWifiPrivate;

/**
 * NMDeviceP2PWifi:
 *
 * Since: 1.16
 */
struct _NMDeviceP2PWifi {
	NMDevice parent;
	NMDeviceP2PWifiPrivate _priv;
};

struct _NMDeviceP2PWifiClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceP2PWifi, nm_device_p2p_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_P2P_WIFI_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceP2PWifi, NM_IS_DEVICE_P2P_WIFI, NMDevice, NMObject)

/*****************************************************************************/

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
clean_up_peers (NMDeviceP2PWifi *self)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (self);

	while (priv->peers->len > 0) {
		NMP2PPeer *peer;

		peer = priv->peers->pdata[priv->peers->len - 1];
		g_ptr_array_remove_index (priv->peers, priv->peers->len - 1);

		g_signal_emit (self, signals[PEER_REMOVED], 0, peer);
	}
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

	priv->peers = g_ptr_array_new ();
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
	clean_up_peers (NM_DEVICE_P2P_WIFI (object));

	G_OBJECT_CLASS (nm_device_p2p_wifi_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceP2PWifiPrivate *priv = NM_DEVICE_P2P_WIFI_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);
	g_free (priv->hw_address);
	if (priv->wfd_ies)
		g_byte_array_unref (priv->wfd_ies);
	if (priv->peers)
		g_ptr_array_unref (priv->peers);

	G_OBJECT_CLASS (nm_device_p2p_wifi_parent_class)->finalize (object);
}

static void
nm_device_p2p_wifi_class_init (NMDeviceP2PWifiClass *wifi_class)
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

	nm_object_class->init_dbus = init_dbus;

	/**
	 * NMDeviceP2PWifi:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_P2P_WIFI_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);


	/**
	 * NMDeviceP2PWifi:group-owner:
	 *
	 * Whether the device is currently the group owner.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_GROUP_OWNER] =
	    g_param_spec_boolean (NM_DEVICE_P2P_WIFI_GROUP_OWNER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceP2PWifi:wfd-ies:
	 *
	 * Whether the device is currently the group owner.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_WFDIES] =
	    g_param_spec_variant (NM_DEVICE_P2P_WIFI_WFDIES, "", "",
	                          G_VARIANT_TYPE ("ay"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceP2PWifi:peers: (type GPtrArray(NMP2PPeer))
	 *
	 * List of all P2P Wi-Fi peers the device can see.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PEERS] =
	    g_param_spec_boxed (NM_DEVICE_P2P_WIFI_PEERS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

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
	                 0, NULL, NULL,
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
	                 0, NULL, NULL,
	                 g_cclosure_marshal_VOID__OBJECT,
	                 G_TYPE_NONE, 1,
	                 G_TYPE_OBJECT);
}
