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

#include "nm-default.h"

#include "nm-lldp-listener.h"

#include <net/ethernet.h>
#include <errno.h>

#include "nm-platform.h"
#include "nm-utils.h"

#include "sd-lldp.h"

#include "nm-sd-adapt.h"
#include "lldp.h"

#define MAX_NEIGHBORS         4096
#define MIN_UPDATE_INTERVAL   2

#define LLDP_MAC_NEAREST_BRIDGE          ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }))
#define LLDP_MAC_NEAREST_NON_TPMR_BRIDGE ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }))
#define LLDP_MAC_NEAREST_CUSTOMER_BRIDGE ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }))

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

	struct ether_addr destination_address;

	GHashTable *tlvs;
} LldpNeighbor;

static void process_lldp_neighbors (NMLldpListener *self);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "lldp"
#define _NMLOG_DOMAIN                     LOGD_DEVICE
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel _level = (level); \
        \
        if (nm_logging_enabled (_level, _NMLOG_DOMAIN)) { \
            char _sbuf[64]; \
            int _ifindex = (self) ? NM_LLDP_LISTENER_GET_PRIVATE (self)->ifindex : 0; \
            \
            _nm_log (_level, _NMLOG_DOMAIN, 0, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     ((_ifindex > 0) \
                        ? nm_sprintf_buf (_sbuf, "[%p,%d]", (self), _ifindex) \
                        : ((self) \
                            ? nm_sprintf_buf (_sbuf, "[%p]", (self)) \
                            : "")) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END \

/*****************************************************************************/

static gboolean
ether_addr_equal (const struct ether_addr *a1, const struct ether_addr *a2)
{
	nm_assert (a1);
	nm_assert (a2);

	G_STATIC_ASSERT_EXPR (sizeof (*a1) == ETH_ALEN);
	return memcmp (a1, a2, ETH_ALEN) == 0;
}

static void
gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GValue *
gvalue_new_str (const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str ?: "");
	return value;
}

static GValue *
gvalue_new_str_ptr (const void *str, gsize len)
{
	const char *s = str;
	const char *tmp;
	gsize len0 = len;
	gs_free char *str_free = NULL;
	gs_free char *str_escaped = NULL;

	/* truncate at first NUL, including removing trailing NULs*/
	tmp = memchr (s, '\0', len);
	if (tmp)
		len = tmp - s;

	if (!len)
		return gvalue_new_str ("");

	if (len0 <= len || s[len] != '\0') {
		/* hmpf, g_strescape needs a trailing NUL. Need to clone */
		s = str_free = g_strndup (s, len);
	}

	str_escaped = g_strescape (s, NULL);
	return gvalue_new_str (str_escaped);
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

static GValue *
gvalue_new_uint_u8 (const void *data)
{
	return gvalue_new_uint (*((const guint8 *) data));
}

static GValue *
gvalue_new_uint_u16 (const void *data)
{
	guint16 v;

	memcpy (&v, data, sizeof (v));
	return gvalue_new_uint (ntohs (v));
}

static guint
lldp_neighbor_id_hash (gconstpointer ptr)
{
	const LldpNeighbor *neigh = ptr;
	guint hash;

	hash =   23423423u  + ((guint) (neigh->chassis_id ? g_str_hash (neigh->chassis_id) : 12321u));
	hash = (hash * 33u) + ((guint) (neigh->port_id ? g_str_hash (neigh->port_id) : 34342343u));
	hash = (hash * 33u) + ((guint) neigh->chassis_id_type);
	hash = (hash * 33u) + ((guint) neigh->port_id_type);
	return hash;
}

static gboolean
lldp_neighbor_id_equal (gconstpointer a, gconstpointer b)
{
	const LldpNeighbor *x = a, *y = b;

	return x->chassis_id_type == y->chassis_id_type &&
	       x->port_id_type == y->port_id_type &&
	       !g_strcmp0 (x->chassis_id, y->chassis_id) &&
	       !g_strcmp0 (x->port_id, y->port_id);
}

static void
lldp_neighbor_free (LldpNeighbor *neighbor)
{
	if (neighbor) {
		g_free (neighbor->chassis_id);
		g_free (neighbor->port_id);
		g_hash_table_unref (neighbor->tlvs);
		g_slice_free (LldpNeighbor, neighbor);
	}
}

static void
lldp_neighbor_freep (LldpNeighbor **ptr)
{
	lldp_neighbor_free (*ptr);
}

static gboolean
lldp_neighbor_equal (LldpNeighbor *a, LldpNeighbor *b)
{
	GHashTableIter iter;
	gpointer k, v;

	g_return_val_if_fail (a && a->tlvs, FALSE);
	g_return_val_if_fail (b && b->tlvs, FALSE);

	if (   a->chassis_id_type != b->chassis_id_type
	    || a->port_id_type != b->port_id_type
	    || ether_addr_equal (&a->destination_address, &b->destination_address)
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
		LldpNeighbor *neigh_a, *neigh_b;

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
	NMLldpListener *self = user_data;
	NMLldpListenerPrivate *priv;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), G_SOURCE_REMOVE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	priv->timer = 0;

	if (priv->num_pending_events)
		process_lldp_neighbors (self);

	return G_SOURCE_REMOVE;
}

static void
process_lldp_neighbors (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);
	nm_auto_free sd_lldp_neighbor **neighbors = NULL;
	GHashTable *hash;
	int num, i, r;

	g_return_if_fail (priv->lldp_handle);

	num = sd_lldp_get_neighbors (priv->lldp_handle, &neighbors);
	if (num < 0) {
		_LOGD ("process: error %d retrieving neighbor packets for %s",
		        num, priv->iface);
		return;
	}

	hash = g_hash_table_new_full (lldp_neighbor_id_hash, lldp_neighbor_id_equal,
	                              (GDestroyNotify) lldp_neighbor_free, NULL);

	for (i = 0; neighbors && i < num; i++) {
		nm_auto (lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
		uint8_t chassis_id_type, port_id_type;
		uint16_t data16;
		uint8_t *data8;
		const void *chassis_id, *port_id;
		gsize chassis_id_len, port_id_len, len;
		GValue *value;
		const char *str;

		if (i >= MAX_NEIGHBORS)
			break;

		r = sd_lldp_neighbor_get_chassis_id (neighbors[i], &chassis_id_type,
		                                     &chassis_id, &chassis_id_len);
		if (r < 0)
			goto next_neighbor;
		if (chassis_id_len < 1)
			goto next_neighbor;

		r = sd_lldp_neighbor_get_port_id (neighbors[i], &port_id_type,
		                                  &port_id, &port_id_len);
		if (r < 0)
			goto next_neighbor;
		if (port_id_len < 1)
			goto next_neighbor;

		neigh = g_slice_new0 (LldpNeighbor);
		neigh->tlvs = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, gvalue_destroy);
		neigh->chassis_id_type = chassis_id_type;
		neigh->port_id_type = port_id_type;

		if (sd_lldp_neighbor_get_destination_address (neighbors[i], &neigh->destination_address) < 0)
			goto next_neighbor;

		switch (chassis_id_type) {
		case LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
		case LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
		case LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
		case LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
			neigh->chassis_id = g_strndup ((const char *) chassis_id, chassis_id_len);
			break;
		case LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:
			neigh->chassis_id = nm_utils_hwaddr_ntoa (chassis_id, chassis_id_len);
			break;
		default:
			_LOGD ("process: unsupported chassis ID type %d", chassis_id_type);
			goto next_neighbor;
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
			_LOGD ("process: unsupported port ID type %d", port_id_type);
			goto next_neighbor;
		}

		if (sd_lldp_neighbor_get_port_description (neighbors[i], &str) == 0) {
			value = gvalue_new_str (str);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_PORT_DESCRIPTION, value);
		}

		if (sd_lldp_neighbor_get_system_name (neighbors[i], &str) == 0) {
			value = gvalue_new_str (str);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_SYSTEM_NAME, value);
		}

		if (sd_lldp_neighbor_get_system_description (neighbors[i], &str) == 0) {
			value = gvalue_new_str (str);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, value);
		}

		if (sd_lldp_neighbor_get_system_capabilities (neighbors[i], &data16) == 0) {
			value = gvalue_new_uint (data16);
			g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_SYSTEM_CAPABILITIES, value);
		}

		if (sd_lldp_neighbor_tlv_rewind (neighbors[i]) < 0)
			goto next_neighbor;
		do {
			guint8 oui[3];
			guint8 subtype;

			r = sd_lldp_neighbor_tlv_get_oui (neighbors[i], oui, &subtype);
			if (r < 0) {
				if (r == -ENXIO)
					continue;
				goto next_neighbor;
			}

			if (!(   memcmp (oui, LLDP_OUI_802_1, sizeof (oui)) == 0
			      && NM_IN_SET (subtype,
			                    LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID,
			                    LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID,
			                    LLDP_OUI_802_1_SUBTYPE_VLAN_NAME)))
				continue;

			if (sd_lldp_neighbor_tlv_get_raw (neighbors[i], (void *) &data8, &len) < 0)
				continue;

			/* skip over leading TLV, OUI and subtype */
#ifdef WITH_MORE_ASSERTS
			{
				guint8 check_hdr[] = {
					0xfe | (((len - 2) >> 8) & 0x01), ((len - 2) & 0xFF),
					oui[0], oui[1], oui[2],
					subtype
				};

				nm_assert (len > 2 + 3 +1);
				nm_assert (memcmp (data8, check_hdr, sizeof check_hdr) == 0);
			}
#endif
			if (len <= 6)
				goto next_neighbor;
			data8 += 6;
			len -= 6;

			/*if (memcmp (oui, LLDP_OUI_802_1, sizeof (oui)) == 0)*/
			{
				switch (subtype) {
				case LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID:
					if (len != 2)
						goto next_neighbor;
					g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_PVID,
					                     gvalue_new_uint_u16 (data8));
					break;
				case LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID:
					if (len != 3)
						goto next_neighbor;
					g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS,
					                     gvalue_new_uint_u8 (&data8[0]));
					g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_PPVID,
					                     gvalue_new_uint_u16 (&data8[1]));
					break;
				case LLDP_OUI_802_1_SUBTYPE_VLAN_NAME: {
					int l;

					if (len <= 3)
						goto next_neighbor;

					l = data8[2];
					if (len != 3 + l)
						goto next_neighbor;

					g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_VID,
					                     gvalue_new_uint_u16 (&data8[0]));
					g_hash_table_insert (neigh->tlvs, NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME,
					                     gvalue_new_str_ptr (&data8[3], len));
					break;
				}
				default:
					g_assert_not_reached ();
				}
			}
		} while (sd_lldp_neighbor_tlv_next (neighbors[i]) > 0);

		_LOGD ("process: new neigh: CHASSIS='%s' PORT='%s'",
		        neigh->chassis_id, neigh->port_id);

		g_hash_table_add (hash, neigh);
		neigh = NULL;
next_neighbor:
		;
	}

	for (i = 0; neighbors && i < num; i++)
		sd_lldp_neighbor_unref (neighbors[i]);

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
lldp_event_handler (sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata)
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
nm_lldp_listener_start (NMLldpListener *self, int ifindex, GError **error)
{
	NMLldpListenerPrivate *priv;
	int ret;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), FALSE);
	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (priv->lldp_handle) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "already running");
		return FALSE;
	}

	ret = sd_lldp_new (&priv->lldp_handle, ifindex);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "initialization failed");
		return FALSE;
	}

	ret = sd_lldp_attach_event (priv->lldp_handle, NULL, 0);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "attach event failed");
		goto err_free;
	}

	ret = sd_lldp_set_callback (priv->lldp_handle, lldp_event_handler, self);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "set callback failed");
		goto err;
	}

	ret = sd_lldp_start (priv->lldp_handle);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "start failed");
		goto err;
	}

	priv->ifindex = ifindex;
	_LOGD ("start");
	return TRUE;

err:
	sd_lldp_detach_event (priv->lldp_handle);
err_free:
	sd_lldp_unref (priv->lldp_handle);
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
		_LOGD ("stop");
		sd_lldp_stop (priv->lldp_handle);
		sd_lldp_detach_event (priv->lldp_handle);
		sd_lldp_unref (priv->lldp_handle);
		priv->lldp_handle = NULL;

		size = g_hash_table_size (priv->lldp_neighbors);
		g_hash_table_remove_all (priv->lldp_neighbors);
		if (size) {
			nm_clear_g_variant (&priv->variant);
			g_object_notify (G_OBJECT (self), NM_LLDP_LISTENER_NEIGHBORS);
		}
	}

	nm_clear_g_source (&priv->timer);
	priv->ifindex = 0;
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
	LldpNeighbor *neigh;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), FALSE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (priv->variant)
		goto out;

	g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
	g_hash_table_iter_init (&iter, priv->lldp_neighbors);

	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &neigh)) {
		GHashTableIter val_iter;
		gpointer key, val;
		const char *dest_str;

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

		if (ether_addr_equal (&neigh->destination_address, LLDP_MAC_NEAREST_BRIDGE))
			dest_str = NM_LLDP_DEST_NEAREST_BRIDGE;
		else if (ether_addr_equal (&neigh->destination_address, LLDP_MAC_NEAREST_NON_TPMR_BRIDGE))
			dest_str = NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE;
		else if (ether_addr_equal (&neigh->destination_address, LLDP_MAC_NEAREST_CUSTOMER_BRIDGE))
			dest_str = NM_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE;
		else
			dest_str = NULL;
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
	                                              (GDestroyNotify) lldp_neighbor_free, NULL);

	_LOGT ("lldp listener created");
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

	_LOGT ("lldp listener destroyed");

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

