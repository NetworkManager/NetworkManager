// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-wifi-p2p-peer.h"

#include <stdlib.h>

#include "NetworkManagerUtils.h"
#include "devices/nm-device.h"
#include "nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "nm-glib-aux/nm-ref-string.h"
#include "nm-setting-wireless.h"
#include "nm-utils.h"
#include "nm-wifi-utils.h"
#include "platform/nm-platform.h"
#include "supplicant/nm-supplicant-types.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMWifiP2PPeer,
	PROP_NAME,
	PROP_MANUFACTURER,
	PROP_MODEL,
	PROP_MODEL_NUMBER,
	PROP_SERIAL,
	PROP_WFD_IES,
	PROP_HW_ADDRESS,
	PROP_STRENGTH,
	PROP_LAST_SEEN,
	PROP_FLAGS,
);

struct _NMWifiP2PPeerPrivate {
	NMRefString *supplicant_path;   /* D-Bus object path of this Peer from wpa_supplicant */

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
	gint32             last_seen;    /* Timestamp when the Peer was seen lastly (obtained via nm_utils_get_monotonic_timestamp_sec()) */
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

	return nm_ref_string_get_str (NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->supplicant_path);
}

const char *
nm_wifi_p2p_peer_get_name (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->name;
}

gboolean
nm_wifi_p2p_peer_set_name (NMWifiP2PPeer *peer, const char *str)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (!nm_utils_strdup_reset (&priv->name, str))
		return FALSE;
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
nm_wifi_p2p_peer_set_manufacturer (NMWifiP2PPeer *peer, const char *str)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (!nm_utils_strdup_reset (&priv->manufacturer, str))
		return FALSE;
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
nm_wifi_p2p_peer_set_model (NMWifiP2PPeer *peer, const char *str)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (!nm_utils_strdup_reset (&priv->model, str))
		return FALSE;
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
nm_wifi_p2p_peer_set_model_number (NMWifiP2PPeer *peer, const char *str)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (!nm_utils_strdup_reset (&priv->model_number, str))
		return FALSE;
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
nm_wifi_p2p_peer_set_serial (NMWifiP2PPeer *peer, const char *str)
{
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (!nm_utils_strdup_reset (&priv->serial, str))
		return FALSE;
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
	gs_unref_bytes GBytes *wfd_ies_old = NULL;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	if (nm_gbytes_equal0 (priv->wfd_ies, wfd_ies))
		return FALSE;

	wfd_ies_old = g_steal_pointer (&priv->wfd_ies);
	priv->wfd_ies = wfd_ies ? g_bytes_ref (wfd_ies) : NULL;

	_notify (peer, PROP_WFD_IES);
	return TRUE;
}

const char *const*
nm_wifi_p2p_peer_get_groups (const NMWifiP2PPeer *peer)
{
	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), NULL);

	return (const char *const*) NM_WIFI_P2P_PEER_GET_PRIVATE (peer)->groups;
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
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

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
                                         const NMSupplicantPeerInfo *peer_info)
{
	NMWifiP2PPeerPrivate *priv;
	gboolean changed = FALSE;

	g_return_val_if_fail (NM_IS_WIFI_P2P_PEER (peer), FALSE);
	g_return_val_if_fail (peer_info, FALSE);
	nm_assert (NM_IS_REF_STRING (peer_info->peer_path));

	priv = NM_WIFI_P2P_PEER_GET_PRIVATE (peer);

	nm_assert (   !priv->supplicant_path
	           || priv->supplicant_path == peer_info->peer_path);

	g_object_freeze_notify (G_OBJECT (peer));

	if (!priv->supplicant_path) {
		priv->supplicant_path = nm_ref_string_ref (peer_info->peer_path);
		changed = TRUE;
	}

	changed |= nm_wifi_p2p_peer_set_strength (peer, peer_info->signal_percent);
	changed |= nm_wifi_p2p_peer_set_name (peer, peer_info->device_name);
	changed |= nm_wifi_p2p_peer_set_manufacturer (peer, peer_info->manufacturer);
	changed |= nm_wifi_p2p_peer_set_model (peer, peer_info->model);
	changed |= nm_wifi_p2p_peer_set_model_number (peer, peer_info->model_number);
	changed |= nm_wifi_p2p_peer_set_serial (peer, peer_info->serial);

	if (peer_info->address_valid)
		changed |= nm_wifi_p2p_peer_set_address_bin (peer, peer_info->address);
	else {
		/* we don't reset the address. */
	}

	changed |= nm_wifi_p2p_peer_set_wfd_ies (peer, peer_info->ies);
	changed |= nm_wifi_p2p_peer_set_last_seen (peer, peer_info->last_seen_msec / 1000u);

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
		supplicant_id = strrchr (priv->supplicant_path->str, '/') ?: supplicant_id;

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
	            priv->last_seen > 0 ? ((now_s > 0 ? now_s : nm_utils_get_monotonic_timestamp_sec ()) - priv->last_seen) : -1,
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
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->address);
		break;
	case PROP_STRENGTH:
		g_value_set_uchar (value, priv->strength);
		break;
	case PROP_LAST_SEEN:
		g_value_set_int (value,
		                 priv->last_seen > 0
		                     ? (int) nm_utils_monotonic_timestamp_as_boottime (priv->last_seen, NM_UTILS_NSEC_PER_SEC)
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
nm_wifi_p2p_peer_new_from_properties (const NMSupplicantPeerInfo *peer_info)
{
	NMWifiP2PPeer *peer;

	g_return_val_if_fail (peer_info, NULL);

	peer = g_object_new (NM_TYPE_WIFI_P2P_PEER, NULL);
	nm_wifi_p2p_peer_update_from_properties (peer, peer_info);
	return peer;
}

static void
finalize (GObject *object)
{
	NMWifiP2PPeer *self = NM_WIFI_P2P_PEER (object);
	NMWifiP2PPeerPrivate *priv = NM_WIFI_P2P_PEER_GET_PRIVATE (self);

	nm_assert (!self->wifi_device);
	nm_assert (c_list_is_empty (&self->peers_lst));

	nm_ref_string_unref (priv->supplicant_path);
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
			/* Before 1.24, we wrongly exposed a property "Groups" of type "as". Don't reuse that property name. */
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Flags",        "u",  NM_WIFI_P2P_PEER_FLAGS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Name",         "s",  NM_WIFI_P2P_PEER_NAME),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Manufacturer", "s",  NM_WIFI_P2P_PEER_MANUFACTURER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Model",        "s",  NM_WIFI_P2P_PEER_MODEL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("ModelNumber",  "s",  NM_WIFI_P2P_PEER_MODEL_NUMBER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Serial",       "s",  NM_WIFI_P2P_PEER_SERIAL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("WfdIEs",       "ay", NM_WIFI_P2P_PEER_WFD_IES),
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
