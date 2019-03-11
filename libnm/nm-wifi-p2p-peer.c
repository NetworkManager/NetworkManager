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

#include "nm-wifi-p2p-peer.h"

#include "nm-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-wifi-p2p.h"
#include "nm-utils.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_FLAGS,
	PROP_NAME,
	PROP_MANUFACTURER,
	PROP_MODEL,
	PROP_MODEL_NUMBER,
	PROP_SERIAL,
	PROP_WFD_IES,
	PROP_HW_ADDRESS,
	PROP_STRENGTH,
	PROP_LAST_SEEN,
);

typedef struct {
	char *name;
	char *manufacturer;
	char *model;
	char *model_number;
	char *serial;

	GBytes *wfd_ies;

	char *hw_address;

	int last_seen;

	NM80211ApFlags flags;

	guint8 strength;
} NMWifiP2PPeerPrivate;

/**
 * NMWifiP2PPeer:
 */
struct _NMWifiP2PPeer {
	NMObject parent;
	NMWifiP2PPeerPrivate _priv;
};

struct _NMWifiP2PPeerClass {
	NMObjectClass parent;
};

G_DEFINE_TYPE (NMWifiP2PPeer, nm_wifi_p2p_peer, NM_TYPE_OBJECT)

#define NM_WIFI_P2P_PEER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMWifiP2PPeer, NM_IS_WIFI_P2P_PEER, NMObject)

/*****************************************************************************/

/**
 * nm_wifi_p2p_peer_get_flags:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the flags of the P2P peer.
 *
 * Returns: the flags
 *
 * Since: 1.16
 **/
NM80211ApFlags
nm_wifi_p2p_peer_get_flags (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NM_802_11_AP_FLAGS_NONE);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->flags;
}

/**
 * nm_wifi_p2p_peer_get_name:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the name of the P2P peer.
 *
 * Returns: the name
 *
 * Since: 1.16
 **/
const char *
nm_wifi_p2p_peer_get_name (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->name;
}

/**
 * nm_wifi_p2p_peer_get_manufacturer:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the manufacturer of the P2P peer.
 *
 * Returns: the manufacturer
 *
 * Since: 1.16
 **/
const char *
nm_wifi_p2p_peer_get_manufacturer (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->manufacturer;
}

/**
 * nm_wifi_p2p_peer_get_model:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the model of the P2P peer.
 *
 * Returns: the model
 *
 * Since: 1.16
 **/
const char *
nm_wifi_p2p_peer_get_model (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->model;
}

/**
 * nm_wifi_p2p_peer_get_model_number:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the model number of the P2P peer.
 *
 * Returns: the model number
 *
 * Since: 1.16
 **/
const char *
nm_wifi_p2p_peer_get_model_number (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->model_number;
}

/**
 * nm_wifi_p2p_peer_get_serial:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the serial number of the P2P peer.
 *
 * Returns: the serial number
 *
 * Since: 1.16
 **/
const char *
nm_wifi_p2p_peer_get_serial (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->serial;
}

/**
 * nm_wifi_p2p_peer_get_wfd_ies:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the WFD information elements of the P2P peer.
 *
 * Returns: (transfer none): the #GBytes containing the WFD IEs, or %NULL.
 *
 * Since: 1.16
 **/
GBytes *
nm_wifi_p2p_peer_get_wfd_ies (NMWifiP2PPeer *peer)
{
	NMWifiP2PPeerPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);
	if (!priv->wfd_ies || g_bytes_get_size (priv->wfd_ies) == 0)
		return NULL;

	return priv->wfd_ies;
}

/**
 * nm_wifi_p2p_peer_get_hw_address:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the hardware address of the P2P peer.
 *
 * Returns: the hardware address
 *
 * Since: 1.16
 **/
const char *
nm_wifi_p2p_peer_get_hw_address (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->hw_address;
}

/**
 * nm_wifi_p2p_peer_get_strength:
 * @peer: a #NMWifiP2PPeer
 *
 * Gets the current signal strength of the P2P peer as a percentage.
 *
 * Returns: the signal strength (0 to 100)
 *
 * Since: 1.16
 **/
guint8
nm_wifi_p2p_peer_get_strength (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), 0);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->strength;
}

/**
 * nm_wifi_p2p_peer_get_last_seen:
 * @peer: a #NMWifiP2PPeer
 *
 * Returns the timestamp (in CLOCK_BOOTTIME seconds) for the last time the
 * P2P peer was seen.  A value of -1 means the P2P peer has never been seen.
 *
 * Returns: the last seen time in seconds
 *
 * Since: 1.16
 **/
int
nm_wifi_p2p_peer_get_last_seen (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), -1);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->last_seen;
}

/**
 * nm_wifi_p2p_peer_connection_valid:
 * @peer: an #NMWifiP2PPeer to validate @connection against
 * @connection: an #NMConnection to validate against @peer
 *
 * Validates a given connection against a given Wi-Fi P2P peer to ensure that
 * the connection may be activated with that peer. The connection must match the
 * @peer's address and in the future possibly other attributes.
 *
 * Returns: %TRUE if the connection may be activated with this Wi-Fi P2P Peer,
 * %FALSE if it cannot be.
 *
 * Since: 1.16
 **/
gboolean
nm_wifi_p2p_peer_connection_valid (NMWifiP2PPeer *peer, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingWifiP2P *s_wifi_p2p;
	const char *ctype;
	const char *hw_address;
	const char *setting_peer;

	s_wifi_p2p = (NMSettingWifiP2P *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIFI_P2P);
	if (!s_wifi_p2p)
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con)
		return FALSE;

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (   !ctype
	    || !nm_streq (ctype, NM_SETTING_WIFI_P2P_SETTING_NAME))
		return FALSE;

	/* HW Address check */
	hw_address = nm_wifi_p2p_peer_get_hw_address (peer);
	if (!hw_address)
		return FALSE;

	setting_peer = nm_setting_wifi_p2p_get_peer (s_wifi_p2p);
	if (   !setting_peer
	    || !nm_streq (hw_address, setting_peer))
		return FALSE;

	return TRUE;
}

/**
 * nm_wifi_p2p_peer_filter_connections:
 * @peer: an #NMWifiP2PPeer to filter connections for
 * @connections: (element-type NMConnection): an array of #NMConnections to
 * filter
 *
 * Filters a given array of connections for a given #NMWifiP2PPeer object and
 * returns connections which may be activated with the P2P peer.  Any
 * returned connections will match the @peers's HW address and in the future
 * possibly other attributes.
 *
 * To obtain the list of connections that are compatible with this P2P peer,
 * use nm_client_get_connections() and then filter the returned list for a given
 * #NMDevice using nm_device_filter_connections() and finally filter that list
 * with this function.
 *
 * Returns: (transfer container) (element-type NMConnection): an array of
 * #NMConnections that could be activated with the given @peer. The array should
 * be freed with g_ptr_array_unref() when it is no longer required.
 *
 * Since: 1.16
 **/
GPtrArray *
nm_wifi_p2p_peer_filter_connections (NMWifiP2PPeer *peer, const GPtrArray *connections)
{
	GPtrArray *filtered;
	guint i;

	filtered = g_ptr_array_new_with_free_func (g_object_unref);
	for (i = 0; i < connections->len; i++) {
		NMConnection *candidate = connections->pdata[i];

		if (nm_wifi_p2p_peer_connection_valid (peer, candidate))
			g_ptr_array_add (filtered, g_object_ref (candidate));
	}

	return filtered;
}

/*****************************************************************************/

static void
init_dbus (NMObject *object)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_WIFI_P2P_PEER_FLAGS,        &priv->flags },
		{ NM_WIFI_P2P_PEER_NAME,         &priv->name },
		{ NM_WIFI_P2P_PEER_MANUFACTURER, &priv->manufacturer },
		{ NM_WIFI_P2P_PEER_MODEL,        &priv->model },
		{ NM_WIFI_P2P_PEER_MODEL_NUMBER, &priv->model_number },
		{ NM_WIFI_P2P_PEER_SERIAL,       &priv->serial },
		{ NM_WIFI_P2P_PEER_WFD_IES,      &priv->wfd_ies },
		{ NM_WIFI_P2P_PEER_HW_ADDRESS,   &priv->hw_address },
		{ NM_WIFI_P2P_PEER_STRENGTH,     &priv->strength },
		{ NM_WIFI_P2P_PEER_LAST_SEEN,    &priv->last_seen },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_wifi_p2p_peer_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_WIFI_P2P_PEER,
	                                property_info);
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMWifiP2PPeer *peer = NM_WIFI_P2P_PEER (object);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_flags (value, nm_wifi_p2p_peer_get_flags (peer));
		break;
	case PROP_NAME:
		g_value_set_string (value, nm_wifi_p2p_peer_get_name (peer));
		break;
	case PROP_MANUFACTURER:
		g_value_set_string (value, nm_wifi_p2p_peer_get_manufacturer (peer));
		break;
	case PROP_MODEL:
		g_value_set_string (value, nm_wifi_p2p_peer_get_model (peer));
		break;
	case PROP_MODEL_NUMBER:
		g_value_set_string (value, nm_wifi_p2p_peer_get_model_number (peer));
		break;
	case PROP_SERIAL:
		g_value_set_string (value, nm_wifi_p2p_peer_get_serial (peer));
		break;
	case PROP_WFD_IES:
		g_value_set_boxed (value, nm_wifi_p2p_peer_get_wfd_ies (peer));
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_wifi_p2p_peer_get_hw_address (peer));
		break;
	case PROP_STRENGTH:
		g_value_set_uchar (value, nm_wifi_p2p_peer_get_strength (peer));
		break;
	case PROP_LAST_SEEN:
		g_value_set_int (value, nm_wifi_p2p_peer_get_last_seen (peer));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_wifi_p2p_peer_init (NMWifiP2PPeer *peer)
{
	NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->last_seen = -1;
}

static void
finalize (GObject *object)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (object);

	g_free (priv->name);
	g_free (priv->manufacturer);
	g_free (priv->model);
	g_free (priv->model_number);
	g_free (priv->serial);

	g_free (priv->hw_address);

	g_bytes_unref (priv->wfd_ies);

	G_OBJECT_CLASS (nm_wifi_p2p_peer_parent_class)->finalize (object);
}

static void
nm_wifi_p2p_peer_class_init (NMWifiP2PPeerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	nm_object_class->init_dbus = init_dbus;

	/**
	 * NMWifiP2PPeer:flags:
	 *
	 * The flags of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_FLAGS] =
	    g_param_spec_flags (NM_WIFI_P2P_PEER_FLAGS, "", "",
	                        NM_TYPE_802_11_AP_FLAGS,
	                        NM_802_11_AP_FLAGS_NONE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:name:
	 *
	 * The name of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_NAME] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_NAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:manufacturer:
	 *
	 * The manufacturer of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_MANUFACTURER] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_MANUFACTURER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:model:
	 *
	 * The model of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_MODEL] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_MODEL, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:model-number:
	 *
	 * The hardware address of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_MODEL_NUMBER] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_MODEL_NUMBER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:serial:
	 *
	 * The serial number of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_SERIAL] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_SERIAL, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:wfd-ies:
	 *
	 * The WFD information elements of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_WFD_IES] =
	    g_param_spec_boxed (NM_WIFI_P2P_PEER_WFD_IES, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	/**
	 * NMWifiP2PPeer:hw-address:
	 *
	 * The hardware address of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:strength:
	 *
	 * The current signal strength of the P2P peer.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_STRENGTH] =
	    g_param_spec_uchar (NM_WIFI_P2P_PEER_STRENGTH, "", "",
	                        0, G_MAXUINT8, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMWifiP2PPeer:last-seen:
	 *
	 * The timestamp (in CLOCK_BOOTTIME seconds) for the last time the
	 * P2P peer was found.  A value of -1 means the peer has never been seen.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_LAST_SEEN] =
	    g_param_spec_int (NM_WIFI_P2P_PEER_LAST_SEEN, "", "",
	                      -1, G_MAXINT, -1,
	                      G_PARAM_READABLE |
	                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
