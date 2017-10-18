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

#include "platform/nm-platform.h"
#include "nm-utils.h"

#include "systemd/nm-sd.h"

#define MAX_NEIGHBORS         4096
#define MIN_UPDATE_INTERVAL_NS (2 * NM_UTILS_NS_PER_SECOND)

#define LLDP_MAC_NEAREST_BRIDGE          ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }))
#define LLDP_MAC_NEAREST_NON_TPMR_BRIDGE ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }))
#define LLDP_MAC_NEAREST_CUSTOMER_BRIDGE ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }))

typedef enum {
	LLDP_ATTR_TYPE_NONE,
	LLDP_ATTR_TYPE_UINT32,
	LLDP_ATTR_TYPE_STRING,
} LldpAttrType;

typedef enum {
	/* the order of the enum values determines the order of the fields in
	 * the variant. */
	LLDP_ATTR_ID_PORT_DESCRIPTION,
	LLDP_ATTR_ID_SYSTEM_NAME,
	LLDP_ATTR_ID_SYSTEM_DESCRIPTION,
	LLDP_ATTR_ID_SYSTEM_CAPABILITIES,
	LLDP_ATTR_ID_IEEE_802_1_PVID,
	LLDP_ATTR_ID_IEEE_802_1_PPVID,
	LLDP_ATTR_ID_IEEE_802_1_PPVID_FLAGS,
	LLDP_ATTR_ID_IEEE_802_1_VID,
	LLDP_ATTR_ID_IEEE_802_1_VLAN_NAME,
	_LLDP_PROP_ID_COUNT,
} LldpAttrId;

typedef struct {
	LldpAttrType attr_type;
	union {
		guint32 v_uint32;
		char *v_string;
	};
} LldpAttrData;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMLldpListener,
	PROP_NEIGHBORS,
);

typedef struct {
	char         *iface;
	int           ifindex;
	sd_lldp      *lldp_handle;
	GHashTable   *lldp_neighbors;

	/* the timestamp in nsec until which we delay updates. */
	gint64        ratelimit_next;
	guint         ratelimit_id;

	GVariant     *variant;
} NMLldpListenerPrivate;

struct _NMLldpListener {
	GObject parent;
	NMLldpListenerPrivate _priv;
};

struct _NMLldpListenerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMLldpListener, nm_lldp_listener, G_TYPE_OBJECT)

#define NM_LLDP_LISTENER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMLldpListener, NM_IS_LLDP_LISTENER)

/*****************************************************************************/

typedef struct {
	guint8 chassis_id_type;
	guint8 port_id_type;
	char *chassis_id;
	char *port_id;

	struct ether_addr destination_address;

	bool valid:1;

	LldpAttrData attrs[_LLDP_PROP_ID_COUNT];

	GVariant *variant;
} LldpNeighbor;

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
                     nm_platform_link_get_name (NM_PLATFORM_GET, _ifindex), \
                     NULL, \
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

#define LOG_NEIGH_FMT        "CHASSIS=%s%s%s PORT=%s%s%s"
#define LOG_NEIGH_ARG(neigh) NM_PRINT_FMT_QUOTE_STRING ((neigh)->chassis_id), NM_PRINT_FMT_QUOTE_STRING ((neigh)->port_id)

/*****************************************************************************/

static gboolean
ether_addr_equal (const struct ether_addr *a1, const struct ether_addr *a2)
{
	nm_assert (a1);
	nm_assert (a2);

	G_STATIC_ASSERT_EXPR (sizeof (*a1) == ETH_ALEN);
	return memcmp (a1, a2, ETH_ALEN) == 0;
}

static guint32
_access_uint8 (const void *data)
{
	return *((const guint8 *) data);
}

static guint32
_access_uint16 (const void *data)
{
	guint16 v;

	memcpy (&v, data, sizeof (v));
	return ntohs (v);
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_lldp_attr_id_to_name, LldpAttrId,
	NM_UTILS_LOOKUP_DEFAULT_WARN (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_PORT_DESCRIPTION,        NM_LLDP_ATTR_PORT_DESCRIPTION),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_SYSTEM_NAME,             NM_LLDP_ATTR_SYSTEM_NAME),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_SYSTEM_DESCRIPTION,      NM_LLDP_ATTR_SYSTEM_DESCRIPTION),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_SYSTEM_CAPABILITIES,     NM_LLDP_ATTR_SYSTEM_CAPABILITIES),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_IEEE_802_1_PVID,         NM_LLDP_ATTR_IEEE_802_1_PVID),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_IEEE_802_1_PPVID,        NM_LLDP_ATTR_IEEE_802_1_PPVID),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_IEEE_802_1_PPVID_FLAGS,  NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_IEEE_802_1_VID,          NM_LLDP_ATTR_IEEE_802_1_VID),
	NM_UTILS_LOOKUP_STR_ITEM (LLDP_ATTR_ID_IEEE_802_1_VLAN_NAME,    NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME),
	NM_UTILS_LOOKUP_ITEM_IGNORE (_LLDP_PROP_ID_COUNT),
);

_NM_UTILS_LOOKUP_DEFINE (static, _lldp_attr_id_to_type, LldpAttrId, LldpAttrType,
	NM_UTILS_LOOKUP_DEFAULT_WARN (LLDP_ATTR_TYPE_NONE),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_PORT_DESCRIPTION,            LLDP_ATTR_TYPE_STRING),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_SYSTEM_NAME,                 LLDP_ATTR_TYPE_STRING),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_SYSTEM_DESCRIPTION,          LLDP_ATTR_TYPE_STRING),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_SYSTEM_CAPABILITIES,         LLDP_ATTR_TYPE_UINT32),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_IEEE_802_1_PVID,             LLDP_ATTR_TYPE_UINT32),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_IEEE_802_1_PPVID,            LLDP_ATTR_TYPE_UINT32),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_IEEE_802_1_PPVID_FLAGS,      LLDP_ATTR_TYPE_UINT32),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_IEEE_802_1_VID,              LLDP_ATTR_TYPE_UINT32),
	NM_UTILS_LOOKUP_ITEM (LLDP_ATTR_ID_IEEE_802_1_VLAN_NAME,        LLDP_ATTR_TYPE_STRING),
	NM_UTILS_LOOKUP_ITEM_IGNORE (_LLDP_PROP_ID_COUNT),
);

static void
_lldp_attr_set_str (LldpAttrData *pdata, LldpAttrId attr_id, const char *v_string)
{
	nm_assert (pdata);
	nm_assert (_lldp_attr_id_to_type (attr_id) == LLDP_ATTR_TYPE_STRING);

	pdata = &pdata[attr_id];

	/* we ignore duplicate fields silently. */
	if (pdata->attr_type != LLDP_ATTR_TYPE_NONE)
		return;
	pdata->attr_type = LLDP_ATTR_TYPE_STRING;
	pdata->v_string = g_strdup (v_string ?: "");
}

static void
_lldp_attr_set_str_ptr (LldpAttrData *pdata, LldpAttrId attr_id, const void *str, gsize len)
{
	const char *s = str;
	const char *tmp;
	gsize len0 = len;
	gs_free char *str_free = NULL;

	nm_assert (pdata);
	nm_assert (_lldp_attr_id_to_type (attr_id) == LLDP_ATTR_TYPE_STRING);

	pdata = &pdata[attr_id];

	/* we ignore duplicate fields silently. */
	if (pdata->attr_type != LLDP_ATTR_TYPE_NONE)
		return;

	pdata->attr_type = LLDP_ATTR_TYPE_STRING;

	/* truncate at first NUL, including removing trailing NULs*/
	tmp = memchr (s, '\0', len);
	if (tmp)
		len = tmp - s;

	if (!len) {
		pdata->v_string = g_strdup ("");
		return;
	}

	if (len0 <= len || s[len] != '\0') {
		/* hmpf, g_strescape needs a trailing NUL. Need to clone */
		s = str_free = g_strndup (s, len);
	}

	pdata->v_string = g_strescape (s, NULL);
}

static void
_lldp_attr_set_uint32 (LldpAttrData *pdata, LldpAttrId attr_id, guint32 v_uint32)
{
	nm_assert (pdata);
	nm_assert (_lldp_attr_id_to_type (attr_id) == LLDP_ATTR_TYPE_UINT32);

	pdata = &pdata[attr_id];

	/* we ignore duplicate fields silently. */
	if (pdata->attr_type != LLDP_ATTR_TYPE_NONE)
		return;
	pdata->attr_type = LLDP_ATTR_TYPE_UINT32;
	pdata->v_uint32 = v_uint32;
}

/*****************************************************************************/

static guint
lldp_neighbor_id_hash (gconstpointer ptr)
{
	const LldpNeighbor *neigh = ptr;
	NMHashState h;

	nm_hash_init (&h, 23423423u);
	nm_hash_update_str0 (&h, neigh->chassis_id);
	nm_hash_update_str0 (&h, neigh->port_id);
	nm_hash_update_vals (&h,
	                     neigh->chassis_id_type,
	                     neigh->port_id_type);
	return nm_hash_complete (&h);
}

static int
lldp_neighbor_id_cmp (gconstpointer a, gconstpointer b)
{
	const LldpNeighbor *x = a, *y = b;
	int c;

	if (x->chassis_id_type != y->chassis_id_type)
		return x->chassis_id_type < y->chassis_id_type ? -1 : 1;
	if (x->port_id_type != y->port_id_type)
		return x->port_id_type < y->port_id_type ? -1 : 1;
	c = g_strcmp0 (x->chassis_id, y->chassis_id);
	if (c == 0)
		c = g_strcmp0 (x->port_id, y->port_id);
	return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

static gboolean
lldp_neighbor_id_equal (gconstpointer a, gconstpointer b)
{
	return lldp_neighbor_id_cmp (a, b) == 0;
}

static void
lldp_neighbor_free (LldpNeighbor *neighbor)
{
	LldpAttrId attr_id;

	if (neighbor) {
		g_free (neighbor->chassis_id);
		g_free (neighbor->port_id);
		for (attr_id = 0; attr_id < _LLDP_PROP_ID_COUNT; attr_id++) {
			if (neighbor->attrs[attr_id].attr_type == LLDP_ATTR_TYPE_STRING)
				g_free (neighbor->attrs[attr_id].v_string);
		}
		g_clear_pointer (&neighbor->variant, g_variant_unref);
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
	LldpAttrId attr_id;

	nm_assert (a);
	nm_assert (b);

	if (   a->chassis_id_type != b->chassis_id_type
	    || a->port_id_type != b->port_id_type
	    || ether_addr_equal (&a->destination_address, &b->destination_address)
	    || !nm_streq0 (a->chassis_id, b->chassis_id)
	    || !nm_streq0 (a->port_id, b->port_id))
		return FALSE;

	for (attr_id = 0; attr_id < _LLDP_PROP_ID_COUNT; attr_id++) {
		if (a->attrs[attr_id].attr_type != b->attrs[attr_id].attr_type)
			return FALSE;
		switch (a->attrs[attr_id].attr_type) {
		case LLDP_ATTR_TYPE_UINT32:
			if (a->attrs[attr_id].v_uint32 != b->attrs[attr_id].v_uint32)
				return FALSE;
			break;
		case LLDP_ATTR_TYPE_STRING:
			if (!nm_streq (a->attrs[attr_id].v_string, b->attrs[attr_id].v_string))
				return FALSE;
			break;
		default:
			nm_assert (a->attrs[attr_id].attr_type == LLDP_ATTR_TYPE_NONE);
			break;
		}
	}

	return TRUE;
}

static LldpNeighbor *
lldp_neighbor_new (sd_lldp_neighbor *neighbor_sd, GError **error)
{
	nm_auto (lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
	uint8_t chassis_id_type, port_id_type;
	uint16_t data16;
	uint8_t *data8;
	const void *chassis_id, *port_id;
	gsize chassis_id_len, port_id_len, len;
	const char *str;
	int r;

	r = sd_lldp_neighbor_get_chassis_id (neighbor_sd, &chassis_id_type,
	                                     &chassis_id, &chassis_id_len);
	if (r < 0) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failed reading chassis-id: %s", g_strerror (-r));
		return NULL;
	}
	if (chassis_id_len < 1) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "empty chassis-id");
		return NULL;
	}

	r = sd_lldp_neighbor_get_port_id (neighbor_sd, &port_id_type,
	                                  &port_id, &port_id_len);
	if (r < 0) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failed reading port-id: %s", g_strerror (-r));
		return NULL;
	}
	if (port_id_len < 1) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "empty port-id");
		return NULL;
	}

	neigh = g_slice_new0 (LldpNeighbor);
	neigh->chassis_id_type = chassis_id_type;
	neigh->port_id_type = port_id_type;

	r = sd_lldp_neighbor_get_destination_address (neighbor_sd, &neigh->destination_address);
	if (r < 0) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failed getting destination address: %s", g_strerror (-r));
		goto out;
	}

	switch (chassis_id_type) {
	case SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
	case SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
	case SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
	case SD_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
		neigh->chassis_id = g_strndup ((const char *) chassis_id, chassis_id_len);
		break;
	case SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:
		neigh->chassis_id = nm_utils_hwaddr_ntoa (chassis_id, chassis_id_len);
		break;
	default:
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "unsupported chassis-id type %d", chassis_id_type);
		goto out;
	}

	switch (port_id_type) {
	case SD_LLDP_PORT_SUBTYPE_INTERFACE_ALIAS:
	case SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME:
	case SD_LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED:
	case SD_LLDP_PORT_SUBTYPE_PORT_COMPONENT:
		neigh->port_id = strndup ((char *) port_id, port_id_len);
		break;
	case SD_LLDP_PORT_SUBTYPE_MAC_ADDRESS:
		neigh->port_id = nm_utils_hwaddr_ntoa (port_id, port_id_len);
		break;
	default:
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "unsupported port-id type %d", port_id_type);
		goto out;
	}

	if (sd_lldp_neighbor_get_port_description (neighbor_sd, &str) == 0)
		_lldp_attr_set_str (neigh->attrs, LLDP_ATTR_ID_PORT_DESCRIPTION, str);

	if (sd_lldp_neighbor_get_system_name (neighbor_sd, &str) == 0)
		_lldp_attr_set_str (neigh->attrs, LLDP_ATTR_ID_SYSTEM_NAME, str);

	if (sd_lldp_neighbor_get_system_description (neighbor_sd, &str) == 0)
		_lldp_attr_set_str (neigh->attrs, LLDP_ATTR_ID_SYSTEM_DESCRIPTION, str);

	if (sd_lldp_neighbor_get_system_capabilities (neighbor_sd, &data16) == 0)
		_lldp_attr_set_uint32 (neigh->attrs, LLDP_ATTR_ID_SYSTEM_CAPABILITIES, data16);

	r = sd_lldp_neighbor_tlv_rewind (neighbor_sd);
	if (r < 0) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failed reading tlv (rewind): %s", g_strerror (-r));
		goto out;
	}
	do {
		guint8 oui[3];
		guint8 subtype;

		r = sd_lldp_neighbor_tlv_get_oui (neighbor_sd, oui, &subtype);
		if (r < 0) {
			if (r == -ENXIO)
				continue;
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             "failed reading tlv: %s", g_strerror (-r));
			goto out;
		}

		if (!(   memcmp (oui, SD_LLDP_OUI_802_1, sizeof (oui)) == 0
		      && NM_IN_SET (subtype,
		                    SD_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID,
		                    SD_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID,
		                    SD_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME)))
			continue;

		if (sd_lldp_neighbor_tlv_get_raw (neighbor_sd, (void *) &data8, &len) < 0)
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
			continue;
		data8 += 6;
		len -= 6;

		/*if (memcmp (oui, SD_LLDP_OUI_802_1, sizeof (oui)) == 0)*/
		{
			switch (subtype) {
			case SD_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID:
				if (len != 2)
					continue;
				_lldp_attr_set_uint32 (neigh->attrs, LLDP_ATTR_ID_IEEE_802_1_PVID,
				                       _access_uint16 (data8));
				break;
			case SD_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID:
				if (len != 3)
					continue;
				_lldp_attr_set_uint32 (neigh->attrs, LLDP_ATTR_ID_IEEE_802_1_PPVID_FLAGS,
				                       _access_uint8 (&data8[0]));
				_lldp_attr_set_uint32 (neigh->attrs, LLDP_ATTR_ID_IEEE_802_1_PPVID,
				                       _access_uint16 (&data8[1]));
				break;
			case SD_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME: {
				int l;

				if (len <= 3)
					continue;

				l = data8[2];
				if (len != 3 + l)
					continue;

				_lldp_attr_set_uint32 (neigh->attrs, LLDP_ATTR_ID_IEEE_802_1_VID,
				                       _access_uint16 (&data8[0]));
				_lldp_attr_set_str_ptr (neigh->attrs, LLDP_ATTR_ID_IEEE_802_1_VLAN_NAME,
				                        &data8[3], len);
				break;
			}
			default:
				g_assert_not_reached ();
			}
		}
	} while (sd_lldp_neighbor_tlv_next (neighbor_sd) > 0);

	neigh->valid = TRUE;

out:
	return g_steal_pointer (&neigh);
}

static GVariant *
lldp_neighbor_to_variant (LldpNeighbor *neigh)
{
	GVariantBuilder builder;
	const char *dest_str;
	LldpAttrId attr_id;

	if (neigh->variant)
		return neigh->variant;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	g_variant_builder_add (&builder, "{sv}",
	                       NM_LLDP_ATTR_CHASSIS_ID_TYPE,
	                       g_variant_new_uint32 (neigh->chassis_id_type));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_LLDP_ATTR_CHASSIS_ID,
	                       g_variant_new_string (neigh->chassis_id));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_LLDP_ATTR_PORT_ID_TYPE,
	                       g_variant_new_uint32 (neigh->port_id_type));
	g_variant_builder_add (&builder, "{sv}",
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
		g_variant_builder_add (&builder, "{sv}",
		                       NM_LLDP_ATTR_DESTINATION,
		                       g_variant_new_string (dest_str));
	}

	for (attr_id = 0; attr_id < _LLDP_PROP_ID_COUNT; attr_id++) {
		const LldpAttrData *data = &neigh->attrs[attr_id];

		nm_assert (NM_IN_SET (data->attr_type, _lldp_attr_id_to_type (attr_id), LLDP_ATTR_TYPE_NONE));
		switch (data->attr_type) {
		case LLDP_ATTR_TYPE_UINT32:
			g_variant_builder_add (&builder, "{sv}",
			                       _lldp_attr_id_to_name (attr_id),
			                       g_variant_new_uint32 (data->v_uint32));
			break;
		case LLDP_ATTR_TYPE_STRING:
			g_variant_builder_add (&builder, "{sv}",
			                       _lldp_attr_id_to_name (attr_id),
			                       g_variant_new_string (data->v_string));
			break;
		default:
			break;
		}
	}

	return (neigh->variant = g_variant_ref_sink (g_variant_builder_end (&builder)));
}

/*****************************************************************************/

static void
data_changed_notify (NMLldpListener *self, NMLldpListenerPrivate *priv)
{
	nm_clear_g_variant (&priv->variant);
	_notify (self, PROP_NEIGHBORS);
}

static gboolean
data_changed_timeout (gpointer user_data)
{
	NMLldpListener *self = user_data;
	NMLldpListenerPrivate *priv;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), G_SOURCE_REMOVE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	priv->ratelimit_id = 0;
	priv->ratelimit_next = nm_utils_get_monotonic_timestamp_ns() + MIN_UPDATE_INTERVAL_NS;
	data_changed_notify (self, priv);
	return G_SOURCE_REMOVE;
}

static void
data_changed_schedule (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);
	gint64 now;

	now = nm_utils_get_monotonic_timestamp_ns ();
	if (now >= priv->ratelimit_next) {
		nm_clear_g_source (&priv->ratelimit_id);
		priv->ratelimit_next = now + MIN_UPDATE_INTERVAL_NS;
		data_changed_notify (self, priv);
	} else if (!priv->ratelimit_id)
		priv->ratelimit_id = g_timeout_add (NM_UTILS_NS_TO_MSEC_CEIL (priv->ratelimit_next - now), data_changed_timeout, self);
}

static void
process_lldp_neighbor (NMLldpListener *self, sd_lldp_neighbor *neighbor_sd, gboolean neighbor_valid)
{
	NMLldpListenerPrivate *priv;
	nm_auto (lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
	LldpNeighbor *neigh_old;
	gs_free_error GError *parse_error = NULL;
	GError **p_parse_error;
	gboolean changed = FALSE;

	g_return_if_fail (NM_IS_LLDP_LISTENER (self));

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	g_return_if_fail (priv->lldp_handle);
	g_return_if_fail (neighbor_sd);

	p_parse_error = _LOGT_ENABLED () ? &parse_error : NULL;

	neigh = lldp_neighbor_new (neighbor_sd, p_parse_error);
	if (!neigh) {
		_LOGT ("process: failed to parse neighbor: %s", parse_error->message);
		return;
	}

	if (!neigh->valid)
		neighbor_valid = FALSE;

	neigh_old = g_hash_table_lookup (priv->lldp_neighbors, neigh);
	if (neigh_old) {
		if (!neighbor_valid) {
			_LOGT ("process: %s neigh: "LOG_NEIGH_FMT"%s%s%s",
			       "remove", LOG_NEIGH_ARG (neigh),
			       NM_PRINT_FMT_QUOTED (parse_error, " (failed to parse: ", parse_error->message, ")", ""));

			g_hash_table_remove (priv->lldp_neighbors, neigh_old);
			changed = TRUE;
			goto done;
		} else if (lldp_neighbor_equal (neigh_old, neigh))
			return;
	} else if (!neighbor_valid) {
		if (parse_error)
			_LOGT ("process: failed to parse neighbor: %s", parse_error->message);
		return;
	}

	/* ensure that we have at most MAX_NEIGHBORS entries */
	if (   !neigh_old /* only matters in the "add" case. */
	    && (g_hash_table_size (priv->lldp_neighbors) + 1 > MAX_NEIGHBORS)) {
		_LOGT ("process: ignore neighbor due to overall limit of %d", MAX_NEIGHBORS);
		return;
	}

	_LOGD ("process: %s neigh: "LOG_NEIGH_FMT,
	        neigh_old ? "update" : "new",
	        LOG_NEIGH_ARG (neigh));

	changed = TRUE;
	g_hash_table_add (priv->lldp_neighbors, g_steal_pointer (&neigh));

done:
	if (changed)
		data_changed_schedule (self);
}

static void
lldp_event_handler (sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata)
{
	process_lldp_neighbor (userdata, n, event != SD_LLDP_EVENT_REMOVED);
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

	ret = sd_lldp_new (&priv->lldp_handle);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "initialization failed");
		return FALSE;
	}

	ret = sd_lldp_set_ifindex (priv->lldp_handle, ifindex);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "failed setting ifindex");
		goto err;
	}

	ret = sd_lldp_set_callback (priv->lldp_handle, lldp_event_handler, self);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "set callback failed");
		goto err;
	}

	priv->ifindex = ifindex;

	ret = sd_lldp_attach_event (priv->lldp_handle, NULL, 0);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "attach event failed");
		goto err_free;
	}

	ret = sd_lldp_start (priv->lldp_handle);
	if (ret < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "start failed");
		goto err;
	}

	_LOGD ("start");

	return TRUE;

err:
	sd_lldp_detach_event (priv->lldp_handle);
err_free:
	sd_lldp_unref (priv->lldp_handle);
	priv->lldp_handle = NULL;
	priv->ifindex = 0;
	return FALSE;
}

void
nm_lldp_listener_stop (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv;
	guint size;
	gboolean changed = FALSE;

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
		if (size || priv->ratelimit_id)
			changed = TRUE;
	}

	nm_clear_g_source (&priv->ratelimit_id);
	priv->ratelimit_next = 0;
	priv->ifindex = 0;

	if (changed)
		data_changed_notify (self, priv);
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
	NMLldpListenerPrivate *priv;
	GVariantBuilder array_builder;
	GList *neighbors, *iter;

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), FALSE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (!priv->variant) {
		g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
		neighbors = g_hash_table_get_keys (priv->lldp_neighbors);
		neighbors = g_list_sort (neighbors, lldp_neighbor_id_cmp);
		for (iter = neighbors; iter; iter = iter->next)
			g_variant_builder_add_value (&array_builder, lldp_neighbor_to_variant (iter->data));
		g_list_free (neighbors);
		priv->variant = g_variant_ref_sink (g_variant_builder_end (&array_builder));
	}
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

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	obj_properties[PROP_NEIGHBORS] =
	    g_param_spec_variant (NM_LLDP_LISTENER_NEIGHBORS, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

