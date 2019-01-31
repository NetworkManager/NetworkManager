/* NetworkManager -- Wi-Fi P2P Peer
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-wifi-p2p-peer.h"

#include <stdlib.h>

#include "nm-setting-wireless.h"

#include "nm-wifi-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "devices/nm-device.h"
#include "nm-dbus-manager.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMWifiP2PPeer,
	PROP_NAME,
	PROP_MANUFACTURER,
	PROP_MODEL,
	PROP_MODEL_NUMBER,
	PROP_SERIAL,
	PROP_WFD_IES,
	PROP_GROUPS,
	PROP_HW_ADDRESS,
	PROP_STRENGTH,
	PROP_LAST_SEEN,
	PROP_FLAGS,
);

struct _NMWifiP2PPeerPrivate {
	char *supplicant_path;   /* D-Bus object path of this Peer from wpa_supplicant */

	/* Scanned or cached values */
	char *             name;
	char *             manufacturer;
	char *             model;
	char *             model_number;
	char *             serial;

	char *             address;

	GBytes *           wfd_ies;
	char **            groups;

	guint8             strength;

	NM80211ApFlags     flags;      /* General flags */

	/* Non-scanned attributes */
	gint32             last_seen;    /* Timestamp when the Peer was seen lastly (obtained via nm_utils_get_monotonic_timestamp_s()) */
};

typedef struct _NMWifiP2PPeerPrivate NMWifiP2PPeerPrivate;

struct _NMWifiP2PPeerClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMWifiP2PPeer, nm_wifi_p2p_peer, NM_TYPE_DBUS_OBJECT)

#define NM_WIFI_P2P_PEER_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMWifiP2PPeer, NM_IS_WIFI_P2P_PEER)

/*****************************************************************************/

const char **
nm_wifi_p2p_peers_get_paths (const CList *peers_lst_head)
{
	NMWifiP2PPeer *peer;
	const char **list;
	const char *path;
	gsize i, n;

	n = c_list_length (peers_lst_head);
	list = g_new (const char *, n + 1);

	i = 0;
	if (n > 0) {
		c_list_for_each_entry (peer, peers_lst_head, peers_lst) {
			nm_assert (i < n);
			path = nm_dbus_object_get_path (NM_DBUS_OBJECT (peer));
			nm_assert (path);

			list[i++] = path;
		}
		nm_assert (i <= n);
	}
	list[i] = NULL;
	return list;
}

NMWifiP2PPeer *
nm_wifi_p2p_peers_find_first_compatible (const CList *peers_lst_head,
                                         NMConnection *connection)
{
	NMWifiP2PPeer *peer;

	g_return_val_if_fail (connection, NULL);

	c_list_for_each_entry (peer, peers_lst_head, peers_lst) {
		if (nm_wifi_p2p_peer_check_compatible (peer, connection))
			return peer;
	}
	return NULL;
}

NMWifiP2PPeer *
nm_wifi_p2p_peers_find_by_supplicant_path (const CList *peers_lst_head, const char *path)
{
	NMWifiP2PPeer *peer;

	g_return_val_if_fail (path != NULL, NULL);

	c_list_for_each_entry (peer, peers_lst_head, peers_lst) {
		if (nm_streq0 (path, nm_wifi_p2p_peer_get_supplicant_path (peer)))
			return peer;
	}
	return NULL;
}

/*****************************************************************************/

NMWifiP2PPeer *
nm_wifi_p2p_peer_lookup_for_device (NMDevice *device, const char *exported_path)
{
	NMWifiP2PPeer *peer;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	peer = (NMWifiP2PPeer *) nm_dbus_manager_lookup_object (nm_dbus_object_get_manager (NM_DBUS_OBJECT (device)),
	                                                        exported_path);
	if (   !peer
	    || !NM_IS_WIFI_P2P_PEER (peer)
	    || peer->wifi_device != device)
		return NULL;

	return peer;
}

/*****************************************************************************/

const char *
nm_wifi_p2p_peer_get_supplicant_path (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->supplicant_path;
}

const char *
nm_wifi_p2p_peer_get_name (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->name;
}

gboolean
nm_wifi_p2p_peer_set_name (NMWifiP2PPeer *peer, const char *name)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	if (g_strcmp0 (name, priv->name) == 0)
		return FALSE;

	g_clear_pointer (&priv->name, g_free);
	if (name)
		priv->name = g_strdup (name);

	_notify (peer, PROP_NAME);
	return TRUE;
}

const char *
nm_wifi_p2p_peer_get_manufacturer (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->manufacturer;
}

gboolean
nm_wifi_p2p_peer_set_manufacturer (NMWifiP2PPeer *peer, const char *manufacturer)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	if (g_strcmp0 (manufacturer, priv->manufacturer) == 0)
		return FALSE;

	g_clear_pointer (&priv->manufacturer, g_free);
	if (manufacturer)
		priv->manufacturer = g_strdup (manufacturer);

	_notify (peer, PROP_MANUFACTURER);
	return TRUE;
}

const char *
nm_wifi_p2p_peer_get_model (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->model;
}

gboolean
nm_wifi_p2p_peer_set_model (NMWifiP2PPeer *peer, const char *model)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	if (g_strcmp0 (model, priv->model) == 0)
		return FALSE;

	g_clear_pointer (&priv->model, g_free);
	if (model)
		priv->model = g_strdup (model);

	_notify (peer, PROP_MODEL);
	return TRUE;
}

const char *
nm_wifi_p2p_peer_get_model_number (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->model_number;
}

gboolean
nm_wifi_p2p_peer_set_model_number (NMWifiP2PPeer *peer, const char *model_number)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	if (g_strcmp0 (model_number, priv->model_number) == 0)
		return FALSE;

	g_clear_pointer (&priv->model_number, g_free);
	if (model_number)
		priv->model_number = g_strdup (model_number);

	_notify (peer, PROP_MODEL_NUMBER);
	return TRUE;
}

const char *
nm_wifi_p2p_peer_get_serial (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->serial;
}

gboolean
nm_wifi_p2p_peer_set_serial (NMWifiP2PPeer *peer, const char *serial)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	if (g_strcmp0 (serial, priv->serial) == 0)
		return FALSE;

	g_clear_pointer (&priv->serial, g_free);
	if (serial)
		priv->serial = g_strdup (serial);

	_notify (peer, PROP_SERIAL);
	return TRUE;
}

GBytes *
nm_wifi_p2p_peer_get_wfd_ies (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->wfd_ies;
}

gboolean
nm_wifi_p2p_peer_set_wfd_ies (NMWifiP2PPeer *peer, GBytes *wfd_ies)
{
	NMWifiP2PPeerPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (nm_gbytes_equal0 (priv->wfd_ies, wfd_ies))
		return FALSE;

	g_bytes_unref (priv->wfd_ies);
	priv->wfd_ies = wfd_ies ? g_bytes_ref (wfd_ies) : NULL;

	_notify (peer, PROP_WFD_IES);
	return TRUE;
}

const char *const*
nm_wifi_p2p_peer_get_groups (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return (const char * const*) NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->groups;
}

static gboolean
nm_wifi_p2p_peer_set_groups (NMWifiP2PPeer *peer, const char** groups)
{
	NMWifiP2PPeerPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);
	g_return_val_if_fail (groups != NULL, FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (_nm_utils_strv_equal (priv->groups, (char **) groups))
		return FALSE;

	g_strfreev (priv->groups);
	priv->groups = g_strdupv ((char**) groups);

	_notify (peer, PROP_GROUPS);
	return TRUE;
}

const char *
nm_wifi_p2p_peer_get_address (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->address;
}

static gboolean
nm_wifi_p2p_peer_set_address_bin (NMWifiP2PPeer *peer, const guint8 addr[static ETH_ALEN])
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (   priv->address
	    && nm_utils_hwaddr_matches (addr, ETH_ALEN, priv->address, -1))
		return FALSE;

	g_free (priv->address);
	priv->address = nm_utils_hwaddr_ntoa (addr, ETH_ALEN);
	_notify (peer, PROP_HW_ADDRESS);
	return TRUE;
}

gboolean
nm_wifi_p2p_peer_set_address (NMWifiP2PPeer *peer, const char *addr)
{
	guint8 addr_buf[ETH_ALEN];

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	if (   !addr
	    || !nm_utils_hwaddr_aton (addr, addr_buf, sizeof (addr_buf)))
		g_return_val_if_reached (FALSE);

	return nm_wifi_p2p_peer_set_address_bin (peer, addr_buf);
}

gint8
nm_wifi_p2p_peer_get_strength (NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), 0);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->strength;
}

gboolean
nm_wifi_p2p_peer_set_strength (NMWifiP2PPeer *peer, const gint8 strength)
{
	NMWifiP2PPeerPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (priv->strength != strength) {
		priv->strength = strength;
		_notify (peer, PROP_STRENGTH);
		return TRUE;
	}
	return FALSE;
}

NM80211ApFlags
nm_wifi_p2p_peer_get_flags (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NM_802_11_AP_FLAGS_NONE);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->flags;
}

static gboolean
nm_wifi_p2p_peer_set_last_seen (NMWifiP2PPeer *peer, gint32 last_seen)
{
	NMWifiP2PPeerPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (priv->last_seen != last_seen) {
		priv->last_seen = last_seen;
		_notify (peer, PROP_LAST_SEEN);
		return TRUE;
	}
	return FALSE;
}


/*****************************************************************************/

gboolean
nm_wifi_p2p_peer_update_from_properties (NMWifiP2PPeer *peer,
                                         const char *supplicant_path,
                                         GVariant *properties)
{
	NMWifiP2PPeerPrivate *priv;
	const guint8 *bytes;
	GVariant *v;
	gsize len;
	const char *s;
	const char **sv;
	gint32 i32;
	gboolean changed = FALSE;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);
	g_return_val_if_fail (properties, FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	g_object_freeze_notify (G_OBJECT (peer));

	if (g_variant_lookup (properties, "level", "i", &i32))
		changed |= nm_wifi_p2p_peer_set_strength (peer, nm_wifi_utils_level_to_quality (i32));

	if (g_variant_lookup (properties, "DeviceName", "&s", &s))
		changed |= nm_wifi_p2p_peer_set_name (peer, s);

	if (g_variant_lookup (properties, "Manufacturer", "&s", &s))
		changed |= nm_wifi_p2p_peer_set_manufacturer (peer, s);

	if (g_variant_lookup (properties, "Model", "&s", &s))
		changed |= nm_wifi_p2p_peer_set_model (peer, s);

	if (g_variant_lookup (properties, "ModelNumber", "&s", &s))
		changed |= nm_wifi_p2p_peer_set_model_number (peer, s);

	if (g_variant_lookup (properties, "Serial", "&s", &s))
		changed |= nm_wifi_p2p_peer_set_serial (peer, s);

	v = g_variant_lookup_value (properties, "DeviceAddress", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		if (   len == ETH_ALEN
		    && memcmp (bytes, nm_ip_addr_zero.addr_eth, ETH_ALEN) != 0
		    && memcmp (bytes, (char[ETH_ALEN]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, ETH_ALEN) != 0)
			changed |= nm_wifi_p2p_peer_set_address_bin (peer, bytes);
		g_variant_unref (v);
	}

	/* The IEs property contains the WFD R1 subelements */
	v = g_variant_lookup_value (properties, "IEs", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		gs_unref_bytes GBytes *b = NULL;

		bytes = g_variant_get_fixed_array (v, &len, 1);
		b = g_bytes_new (bytes, len);
		changed |= nm_wifi_p2p_peer_set_wfd_ies (peer, b);
		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "Groups", G_VARIANT_TYPE_OBJECT_PATH_ARRAY);
	if (v) {
		sv = g_variant_get_objv (v, NULL);
		changed |= nm_wifi_p2p_peer_set_groups (peer, sv);
		g_free (sv);
	}

	/*if (max_rate)
		changed |= nm_wifi_p2p_peer_set_max_bitrate (peer, max_rate / 1000);*/

	if (!priv->supplicant_path) {
		priv->supplicant_path = g_strdup (supplicant_path);
		changed = TRUE;
	}

	changed |= nm_wifi_p2p_peer_set_last_seen (peer, nm_utils_get_monotonic_timestamp_s ());

	g_object_thaw_notify (G_OBJECT (peer));

	return changed;
}

const char *
nm_wifi_p2p_peer_to_string (const NMWifiP2PPeer *self,
                            char *str_buf,
                            gsize buf_len,
                            gint32 now_s)
{
	const NMWifiP2PPeerPrivate *priv;
	const char *supplicant_id = "-";
	const char* export_path;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (self), NULL);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (self);

	if (priv->supplicant_path)
		supplicant_id = strrchr (priv->supplicant_path, '/') ?: supplicant_id;

	export_path = nm_dbus_object_get_path (NM_DBUS_OBJECT (self));
	if (export_path)
		export_path = strrchr (export_path, '/') ?: export_path;
	else
		export_path = "/";

	g_snprintf (str_buf, buf_len,
	            "%17s [n:%s, m:%s, mod:%s, mod_num:%s, ser:%s] %3us sup:%s [nm:%s]",
	            priv->address ?: "(none)",
	            priv->name,
	            priv->manufacturer,
	            priv->model,
	            priv->model_number,
	            priv->serial,
	            priv->last_seen > 0 ? ((now_s > 0 ? now_s : nm_utils_get_monotonic_timestamp_s ()) - priv->last_seen) : -1,
	            supplicant_id,
	            export_path);

	return str_buf;
}

gboolean
nm_wifi_p2p_peer_check_compatible (NMWifiP2PPeer *self,
                                   NMConnection *connection)
{
	NMWifiP2PPeerPrivate *priv;
	NMSettingWifiP2P *s_wifi_p2p;
	const char *hwaddr;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (self);

	s_wifi_p2p = NM_SETTING_WIFI_P2P (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIFI_P2P));
	if (s_wifi_p2p == NULL)
		return FALSE;

	hwaddr = nm_setting_wifi_p2p_get_peer (s_wifi_p2p);
	if (   hwaddr
	    && (   !priv->address
	        || !nm_utils_hwaddr_matches (hwaddr, -1, priv->address, -1)))
		return FALSE;

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMWifiP2PPeer *self = NM_WIFI_P2P_PEER (object);
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_MANUFACTURER:
		g_value_set_string (value, priv->manufacturer);
		break;
	case PROP_MODEL:
		g_value_set_string (value, priv->model);
		break;
	case PROP_MODEL_NUMBER:
		g_value_set_string (value, priv->model_number);
		break;
	case PROP_SERIAL:
		g_value_set_string (value, priv->serial);
		break;
	case PROP_WFD_IES:
		g_value_take_variant (value, nm_utils_gbytes_to_variant_ay (priv->wfd_ies));
		break;
	case PROP_GROUPS:
		g_value_set_variant (value,
		                      g_variant_new_strv (   (const char*const*) priv->groups
		                                          ?: NM_PTRARRAY_EMPTY (const char *),
		                                          -1));
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->address);
		break;
	case PROP_STRENGTH:
		g_value_set_uchar (value, priv->strength);
		break;
	case PROP_LAST_SEEN:
		g_value_set_int (value,
		                 priv->last_seen > 0
		                     ? (int) nm_utils_monotonic_timestamp_as_boottime (priv->last_seen, NM_UTILS_NS_PER_SECOND)
		                     : -1);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_wifi_p2p_peer_init (NMWifiP2PPeer *self)
{
	NMWifiP2PPeerPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_WIFI_P2P_PEER, NMWifiP2PPeerPrivate);

	self->_priv = priv;

	c_list_init (&self->peers_lst);

	priv->flags = NM_802_11_AP_FLAGS_NONE;
	priv->last_seen = -1;
}

NMWifiP2PPeer *
nm_wifi_p2p_peer_new_from_properties (const char *supplicant_path, GVariant *properties)
{
	NMWifiP2PPeer *peer;

	g_return_val_if_fail (supplicant_path != NULL, NULL);
	g_return_val_if_fail (properties != NULL, NULL);

	peer = (NMWifiP2PPeer *) g_object_new (NM_TYPE_WIFI_P2P_PEER, NULL);
	nm_wifi_p2p_peer_update_from_properties (peer, supplicant_path, properties);

	/* ignore peers with invalid or missing address */
	if (!nm_wifi_p2p_peer_get_address (peer)) {
		g_object_unref (peer);
		return NULL;
	}

	return peer;
}

static void
finalize (GObject *object)
{
	NMWifiP2PPeer *self = NM_WIFI_P2P_PEER (object);
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (self);

	nm_assert (!self->wifi_device);
	nm_assert (c_list_is_empty (&self->peers_lst));

	g_free (priv->supplicant_path);
	g_free (priv->name);
	g_free (priv->manufacturer);
	g_free (priv->model);
	g_free (priv->model_number);
	g_free (priv->serial);
	g_free (priv->address);
	g_bytes_unref (priv->wfd_ies);
	g_strfreev (priv->groups);

	G_OBJECT_CLASS (nm_wifi_p2p_peer_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_p2p_peer = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_WIFI_P2P_PEER,
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Flags",        "u",  NM_WIFI_P2P_PEER_FLAGS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Name",         "s",  NM_WIFI_P2P_PEER_NAME),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Manufacturer", "s",  NM_WIFI_P2P_PEER_MANUFACTURER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Model",        "s",  NM_WIFI_P2P_PEER_MODEL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("ModelNumber",  "s",  NM_WIFI_P2P_PEER_MODEL_NUMBER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Serial",       "s",  NM_WIFI_P2P_PEER_SERIAL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("WfdIEs",       "ay", NM_WIFI_P2P_PEER_WFD_IES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Groups",       "as", NM_WIFI_P2P_PEER_GROUPS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("HwAddress",    "s",  NM_WIFI_P2P_PEER_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Strength",     "y",  NM_WIFI_P2P_PEER_STRENGTH),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("LastSeen",     "i",  NM_WIFI_P2P_PEER_LAST_SEEN),
		),
	),
	.legacy_property_changed = FALSE,
};

static void
nm_wifi_p2p_peer_class_init (NMWifiP2PPeerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMWifiP2PPeerPrivate));

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH_WIFI_P2P_PEER);
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_p2p_peer);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	obj_properties[PROP_FLAGS] =
	    g_param_spec_uint (NM_WIFI_P2P_PEER_FLAGS, "", "",
	                       NM_802_11_AP_FLAGS_NONE,
	                       NM_802_11_AP_FLAGS_PRIVACY,
	                       NM_802_11_AP_FLAGS_NONE,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_NAME] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_NAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MANUFACTURER] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_MANUFACTURER, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MODEL] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_MODEL, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MODEL_NUMBER] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_MODEL_NUMBER, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SERIAL] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_SERIAL, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WFD_IES] =
	    g_param_spec_variant (NM_WIFI_P2P_PEER_WFD_IES, "", "",
	                          G_VARIANT_TYPE ("ay"),
	                          NULL,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_GROUPS] =
	    g_param_spec_variant (NM_WIFI_P2P_PEER_GROUPS, "", "",
	                          G_VARIANT_TYPE ("as"),
	                          NULL,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_WIFI_P2P_PEER_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STRENGTH] =
	    g_param_spec_uchar (NM_WIFI_P2P_PEER_STRENGTH, "", "",
	                        0, G_MAXINT8, 0,
	                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_LAST_SEEN] =
	    g_param_spec_int (NM_WIFI_P2P_PEER_LAST_SEEN, "", "",
	                      -1, G_MAXINT, -1,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
