/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "config.h"

#include <net/ethernet.h>

#include "sd-lldp.h"
#include "lldp.h"
#include "nm-lldp-listener.h"
#include "nm-platform.h"
#include "nm-utils.h"

#define MAX_NEIGHBORS         4096
#define MIN_UPDATE_INTERVAL   2

typedef struct {
	char         *iface;
	int           ifindex;
	sd_lldp      *lldp_handle;
	GHashTable   *lldp_neighbors;
	guint         timer;
	guint         num_pending_events;
	GVariant     *variant;
} NMLldpListenerPrivate;

enum {
	PROP_0,
	PROP_NEIGHBORS,

	LAST_PROP
};

G_DEFINE_TYPE (NMLldpListener, nm_lldp_listener, G_TYPE_OBJECT)

#define NM_LLDP_LISTENER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LLDP_LISTENER, NMLldpListenerPrivate))

typedef struct {
	guint8 chassis_id_type;
	guint8 port_id_type;
	char *chassis_id;
	char *port_id;

	int dest;

	GHashTable *tlvs;
} LLDPNeighbor;

static void process_lldp_neighbors (NMLldpListener *self);

static void
gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GValue *
gvalue_new_nstr (const char *str, guint16 len)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_take_string (value, strndup (str, len));
	return value;
}

static GValue *
gvalue_new_uint (guint val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, val);
	return value;
}

static guint
lldp_neighbor_id_hash (gconstpointer ptr)
{
	const LLDPNeighbor *neigh = ptr;

	return g_str_hash (neigh->chassis_id) ^
	       g_str_hash (neigh->port_id) ^
	       neigh->chassis_id_type ^
	       (neigh->port_id_type * 33);
}

static gboolean
lldp_neighbor_id_equal (gconstpointer a, gconstpointer b)
{
	const LLDPNeighbor *x = a, *y = b;

	return x->chassis_id_type == y->chassis_id_type &&
	       x->port_id_type == y->port_id_type &&
	       !g_strcmp0 (x->chassis_id, y->chassis_id) &&
	       !g_strcmp0 (x->port_id, y->port_id);
}

static void
lldp_neighbor_free (gpointer data)
{
	LLDPNeighbor *neighbor = data;

	if (neighbor) {
		g_free (neighbor->chassis_id);
		g_free (neighbor->port_id);
		g_hash_table_unref (neighbor->tlvs);
		g_free (neighbor);
	}
}

static gboolean
lldp_neighbor_equal (LLDPNeighbor *a, LLDPNeighbor *b)
{
	GHashTableIter iter;
	gpointer k, v;

	g_return_val_if_fail (a && a->tlvs, FALSE);
	g_return_val_if_fail (b && b->tlvs, FALSE);

	if (   a->chassis_id_type != b->chassis_id_type
	    || a->port_id_type != b->port_id_type
	    || a->dest != b->dest
	    || g_strcmp0 (a->chassis_id, b->chassis_id)
	    || g_strcmp0 (a->port_id, b->port_id))
		return FALSE;

	if (g_hash_table_size (a->tlvs) != g_hash_table_size (b->tlvs))
		return FALSE;

	g_hash_table_iter_init (&iter, a->tlvs);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		GValue *value_a, *value_b;

		value_a = v;
		value_b = g_hash_table_lookup (b->tlvs, k);

		if (!value_b)
			return FALSE;

		g_return_val_if_fail (G_VALUE_TYPE (value_a) == G_VALUE_TYPE (value_b), FALSE);

		if (G_VALUE_HOLDS_STRING (value_a)) {
			if (g_strcmp0 (g_value_get_string (value_a), g_value_get_string (value_b)))
				return FALSE;
		} else if (G_VALUE_HOLDS_UINT (value_a)) {
			if (g_value_get_uint (value_a) != g_value_get_uint (value_b))
				return FALSE;
		} else
			g_return_val_if_reached (FALSE);
	}

	return TRUE;
}

static gboolean
lldp_hash_table_equal (GHashTable *a, GHashTable *b)
{
	GHashTableIter iter;
	gpointer val;

	g_return_val_if_fail (a, FALSE);
	g_return_val_if_fail (b, FALSE);

	if (g_hash_table_size (a) != g_hash_table_size (b))
		return FALSE;

	g_hash_table_iter_init (&iter, a);
	while (g_hash_table_iter_next (&iter, NULL, &val)) {
		LLDPNeighbor *neigh_a, *neigh_b;

		neigh_a = val;
		neigh_b = g_hash_table_lookup (b, val);

		if (!neigh_b)
			return FALSE;

		if (!lldp_neighbor_equal (neigh_a, neigh_b))
			return FALSE;
	}

	return TRUE;
}

static gboolean
lldp_timeout (gpointer user_data)
{
	NMLldpListener *self = NM_LLDP_LISTENER (user_data);
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	priv->timer = 0;

	if (priv->num_pending_events)
		process_lldp_neighbors (self);

	return G_SOURCE_REMOVE;
}

static void
process_lldp_neighbors (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);
	sd_lldp_packet **packets = NULL;
	GHashTable *hash;
	int num, i;

	num = sd_lldp_get_packets (priv->lldp_handle, &packets);
	if (num < 0) {
		nm_log_dbg (LOGD_DEVICE, "LLDP: error %d retrieving neighbor packets for %s",
		            num, priv->iface);
		return;
	}

	hash = g_hash_table_new_full (lldp_neighbor_id_hash, lldp_neighbor_id_equal,
	                              lldp_neighbor_free, NULL);

	for (i = 0; packets && i < num; i++) {
		uint8_t chassis_id_type, port_id_type, *chassis_id, *port_id, data8;
		uint16_t chassis_id_len, port_id_len, len, data16;
		LLDPNeighbor *neigh;
		GValue *value;
		char *str;
		int r;

		if (i >= MAX_NEIGHBORS)
			goto next_packet;

		r = sd_lldp_packet_read_chassis_id (packets[i], &chassis_id_type,
		                                    &chassis_id, &chassis_id_len);
		if (r < 0)
			goto next_packet;

		r = sd_lldp_packet_read_port_id (packets[i], &port_id_type,
		                                 &port_id, &port_id_len);
		if (r < 0)
			goto next_packet;

		neigh = g_malloc0 (sizeof (LLDPNeighbor));
		neigh->tlvs = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, gvalue_destroy);
		neigh->chassis_id_type = chassis_id_type;
		neigh->port_id_type = port_id_type;
		sd_lldp_packet_get_destination_type (packets[i], &neigh->dest);

		if (chassis_id_len < 1) {
			lldp_neighbor_free (neigh);
			goto next_packet;
		}

		switch (chassis_id_type) {
		case LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
		case LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
		case LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
		case LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
			neigh->chassis_id = strndup ((char *) chassis_id, chassis_id_len);
			break;
		case LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:
			neigh->chassis_id = nm_utils_hwaddr_ntoa (chassis_id, chassis_id_len);
			break;
		default:
			nm_log_dbg (LOGD_DEVICE, "LLDP: unsupported chassis ID type %d", chassis_id_type);
			lldp_neighbor_free (neigh);
			goto next_packet;
		}

		if (port_id_len < 1) {
			lldp_neighbor_free (neigh);
			goto next_packet;
		}

		switch (port_id_type) {
		case LLDP_PORT_SUBTYPE_INTERFACE_ALIAS:
		case LLDP_PORT_SUBTYPE_INTERFACE_NAME:
		case LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED:
		case LLDP_PORT_SUBTYPE_PORT_COMPONENT:
			neigh->port_id = strndup ((char *) port_id, port_id_len);
			break;
		case LLDP_PORT_SUBTYPE_MAC_ADDRESS:
			neigh->port_id = nm_utils_hwaddr_ntoa (port_id, port_id_len);
			break;
		default:
			nm_log_dbg (LOGD_DEVICE, "LLDP: unsupported port ID type %d", port_id_type);
			lldp_neighbor_free (neigh);
			goto next_packet;
		}

		if (sd_lldp_packet_read_port_description (packets[i], &str, &len) == 0) {
			value = gvalue_new_nstr (str, len);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_PORT_DESCRIPTION, value);
		}

		if (sd_lldp_packet_read_system_name (packets[i], &str, &len) == 0) {
			value = gvalue_new_nstr (str, len);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_SYSTEM_NAME, value);
		}

		if (sd_lldp_packet_read_system_description (packets[i], &str, &len) == 0) {
			value = gvalue_new_nstr (str, len);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, value);
		}

		if (sd_lldp_packet_read_system_capability (packets[i], &data16) == 0) {
			value = gvalue_new_uint (data16);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_SYSTEM_CAPABILITIES, value);
		}

		if (sd_lldp_packet_read_port_vlan_id (packets[i], &data16) == 0) {
			value = gvalue_new_uint (data16);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_PVID, value);
		}

		if (sd_lldp_packet_read_port_protocol_vlan_id (packets[i], &data8, &data16) == 0) {
			value = gvalue_new_uint (data16);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_PPVID, value);

			value = gvalue_new_uint (data8);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS, value);
		}

		if (sd_lldp_packet_read_vlan_name (packets[i], &data16, &str, &len) == 0) {
			value = gvalue_new_uint (data16);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_VID, value);

			value = gvalue_new_nstr (str, len);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME, value);
		}

		nm_log_dbg (LOGD_DEVICE, "LLDP: new neigh: CHASSIS='%s' PORT='%s'",
		            neigh->chassis_id, neigh->port_id);

		g_hash_table_add (hash, neigh);
next_packet:
		sd_lldp_packet_unref (packets[i]);
	}

	g_free (packets);

	if (lldp_hash_table_equal (priv->lldp_neighbors, hash)) {
		g_hash_table_destroy (hash);
	} else {
		g_hash_table_destroy (priv->lldp_neighbors);
		priv->lldp_neighbors = hash;
		nm_clear_g_variant (&priv->variant);
		g_object_notify (G_OBJECT (self), NM_LLDP_LISTENER_NEIGHBORS);
	}

	/* Since the processing of the neighbor list is potentially
	 * expensive when there are many neighbors, coalesce multiple
	 * events arriving in short time.
	 */
	priv->timer = g_timeout_add_seconds (MIN_UPDATE_INTERVAL, lldp_timeout, self);
	priv->num_pending_events = 0;
}

static void
lldp_event_handler (sd_lldp *lldp, int event, void *userdata)
{
	NMLldpListener *self = userdata;
	NMLldpListenerPrivate *priv;

	g_return_if_fail (NM_IS_LLDP_LISTENER (self));
	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (priv->timer > 0) {
		priv->num_pending_events++;
		return;
	}

	process_lldp_neighbors (self);
}

gboolean
nm_lldp_listener_start (NMLldpListener *self, int ifindex, const char *iface,
                        const guint8 *mac, guint mac_len, GError **error)
{
	NMLldpListenerPrivate *priv;
	int ret;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), FALSE);
	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (iface, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (priv->lldp_handle) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "already running");
		return FALSE;
	}

	if (!mac || mac_len != ETH_ALEN) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "unsupported device");
		return FALSE;
	}

	ret = sd_lldp_new (ifindex, iface, (struct ether_addr *) mac, &priv->lldp_handle);
	if (ret) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "initialization failed");
		return FALSE;
	}

	ret = sd_lldp_attach_event (priv->lldp_handle, NULL, 0);
	if (ret) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "attach event failed");
		goto err_free;
	}

	ret = sd_lldp_set_callback (priv->lldp_handle, lldp_event_handler, self);
	if (ret) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "set callback failed");
		goto err;
	}

	ret = sd_lldp_start (priv->lldp_handle);
	if (ret) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "start failed");
		goto err;
	}

	priv->ifindex = ifindex;
	priv->iface = strdup (iface);
	return TRUE;

err:
	sd_lldp_detach_event (priv->lldp_handle);
err_free:
	sd_lldp_free (priv->lldp_handle);
	priv->lldp_handle = NULL;
	return FALSE;
}

void
nm_lldp_listener_stop (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv;
	guint size;

	g_return_if_fail (NM_IS_LLDP_LISTENER (self));
	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (priv->lldp_handle) {
		sd_lldp_stop (priv->lldp_handle);
		sd_lldp_detach_event (priv->lldp_handle);
		sd_lldp_free (priv->lldp_handle);
		g_clear_pointer (&priv->iface, g_free);
		priv->lldp_handle = NULL;

		size = g_hash_table_size (priv->lldp_neighbors);
		g_hash_table_remove_all (priv->lldp_neighbors);
		if (size) {
			nm_clear_g_variant (&priv->variant);
			g_object_notify (G_OBJECT (self), NM_LLDP_LISTENER_NEIGHBORS);
		}
	}

	nm_clear_g_source (&priv->timer);
}

gboolean
nm_lldp_listener_is_running (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), FALSE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);
	return !!priv->lldp_handle;
}

GVariant *
nm_lldp_listener_get_neighbors (NMLldpListener *self)
{
	GVariantBuilder array_builder, neigh_builder;
	GHashTableIter iter;
	NMLldpListenerPrivate *priv;
	LLDPNeighbor *neigh;
	char *dest_str = NULL;

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (priv->variant)
		goto out;

	g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
	g_hash_table_iter_init (&iter, priv->lldp_neighbors);

	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &neigh)) {
		GHashTableIter val_iter;
		gpointer key, val;

		g_variant_builder_init (&neigh_builder, G_VARIANT_TYPE ("a{sv}"));

		g_variant_builder_add (&neigh_builder, "{sv}",
		                       NM_LLDP_ATTR_CHASSIS_ID_TYPE,
		                       g_variant_new_uint32 (neigh->chassis_id_type));
		g_variant_builder_add (&neigh_builder, "{sv}",
		                       NM_LLDP_ATTR_CHASSIS_ID,
		                       g_variant_new_string (neigh->chassis_id));
		g_variant_builder_add (&neigh_builder, "{sv}",
		                       NM_LLDP_ATTR_PORT_ID_TYPE,
		                       g_variant_new_uint32 (neigh->port_id_type));
		g_variant_builder_add (&neigh_builder, "{sv}",
		                       NM_LLDP_ATTR_PORT_ID,
		                       g_variant_new_string (neigh->port_id));

		switch (neigh->dest) {
		case SD_LLDP_DESTINATION_TYPE_NEAREST_BRIDGE:
			dest_str = NM_LLDP_DEST_NEAREST_BRIDGE;
			break;
		case SD_LLDP_DESTINATION_TYPE_NEAREST_NON_TPMR_BRIDGE:
			dest_str = NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE;
			break;
		case SD_LLDP_DESTINATION_TYPE_NEAREST_CUSTOMER_BRIDGE:
			dest_str = NM_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE;
			break;
		}

		if (dest_str) {
			g_variant_builder_add (&neigh_builder, "{sv}",
			                       NM_LLDP_ATTR_DESTINATION,
			                       g_variant_new_string (dest_str));
		}

		g_hash_table_iter_init (&val_iter, neigh->tlvs);
		while (g_hash_table_iter_next (&val_iter, &key, &val)) {
			GValue *item = val;

			if (G_VALUE_HOLDS_STRING (item)) {
				g_variant_builder_add (&neigh_builder, "{sv}",
				                       key,
				                       g_variant_new_string (g_value_get_string (item)));
			} else if (G_VALUE_HOLDS_UINT (item)) {
				g_variant_builder_add (&neigh_builder, "{sv}",
				                       key,
				                       g_variant_new_uint32 (g_value_get_uint (item)));
			}
		}

		g_variant_builder_add (&array_builder, "a{sv}", &neigh_builder);
	}

	priv->variant = g_variant_ref_sink (g_variant_builder_end (&array_builder));

out:
	return priv->variant;
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMLldpListener *self = NM_LLDP_LISTENER (object);

	switch (prop_id) {
	case PROP_NEIGHBORS:
		g_value_set_variant (value, nm_lldp_listener_get_neighbors (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_lldp_listener_init (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	priv->lldp_neighbors = g_hash_table_new_full (lldp_neighbor_id_hash,
	                                              lldp_neighbor_id_equal,
	                                              lldp_neighbor_free, NULL);
}

NMLldpListener *
nm_lldp_listener_new (void)
{
	return (NMLldpListener *) g_object_new (NM_TYPE_LLDP_LISTENER, NULL);
}

static void
dispose (GObject *object)
{
	nm_lldp_listener_stop (NM_LLDP_LISTENER (object));

	G_OBJECT_CLASS (nm_lldp_listener_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMLldpListener *self = NM_LLDP_LISTENER (object);
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	nm_lldp_listener_stop (self);
	g_hash_table_unref (priv->lldp_neighbors);

	nm_clear_g_variant (&priv->variant);

	G_OBJECT_CLASS (nm_lldp_listener_parent_class)->finalize (object);
}

static void
nm_lldp_listener_class_init (NMLldpListenerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMLldpListenerPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	g_object_class_install_property
		(object_class, PROP_NEIGHBORS,
		 g_param_spec_variant (NM_LLDP_LISTENER_NEIGHBORS, "", "",
		                       G_VARIANT_TYPE ("aa{sv}"),
		                       NULL,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
}

