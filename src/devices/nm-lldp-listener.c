// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-lldp-listener.h"

#include <net/ethernet.h>

#include "nm-std-aux/unaligned.h"
#include "platform/nm-platform.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-utils.h"

#include "systemd/nm-sd.h"

#define MAX_NEIGHBORS         128
#define MIN_UPDATE_INTERVAL_NS (2 * NM_UTILS_NSEC_PER_SEC)

#define LLDP_MAC_NEAREST_BRIDGE          ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }))
#define LLDP_MAC_NEAREST_NON_TPMR_BRIDGE ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }))
#define LLDP_MAC_NEAREST_CUSTOMER_BRIDGE ((const struct ether_addr *) ((uint8_t[ETH_ALEN]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }))

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
	GVariant *variant;
	char *chassis_id;
	char *port_id;

	sd_lldp_neighbor *neighbor_sd;

	struct ether_addr destination_address;

	guint8 chassis_id_type;
	guint8 port_id_type;

	bool valid:1;
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
                     _ifindex > 0 ? nm_platform_link_get_name (NM_PLATFORM_GET, _ifindex) : NULL, \
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

/*****************************************************************************/

static void
lldp_neighbor_get_raw (LldpNeighbor *neigh,
                       const guint8 **out_raw_data,
                       gsize *out_raw_len)
{
	gconstpointer raw_data;
	gsize raw_len;
	int r;

	nm_assert (neigh);

	r = sd_lldp_neighbor_get_raw (neigh->neighbor_sd, &raw_data, &raw_len);

	nm_assert (r >= 0);
	nm_assert (raw_data);
	nm_assert (raw_len > 0);

	*out_raw_data = raw_data;
	*out_raw_len = raw_len;
}

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
lldp_neighbor_id_cmp (const LldpNeighbor *x, const LldpNeighbor *y)
{
	NM_CMP_SELF (x, y);
	NM_CMP_FIELD (x, y, chassis_id_type);
	NM_CMP_FIELD (x, y, port_id_type);
	NM_CMP_FIELD_STR0 (x, y, chassis_id);
	NM_CMP_FIELD_STR0 (x, y, port_id);
	return 0;
}

static int
lldp_neighbor_id_cmp_p (gconstpointer a, gconstpointer b, gpointer user_data)
{
	return lldp_neighbor_id_cmp (*((const LldpNeighbor *const*) a),
	                             *((const LldpNeighbor *const*) b));
}

static gboolean
lldp_neighbor_id_equal (gconstpointer a, gconstpointer b)
{
	return lldp_neighbor_id_cmp (a, b) == 0;
}

static void
lldp_neighbor_free (LldpNeighbor *neighbor)
{
	if (!neighbor)
		return;

	g_free (neighbor->chassis_id);
	g_free (neighbor->port_id);
	nm_g_variant_unref (neighbor->variant);
	sd_lldp_neighbor_unref (neighbor->neighbor_sd);
	nm_g_slice_free (neighbor);
}

static void
lldp_neighbor_freep (LldpNeighbor **ptr)
{
	lldp_neighbor_free (*ptr);
}

static gboolean
lldp_neighbor_equal (LldpNeighbor *a, LldpNeighbor *b)
{
	const guint8 *raw_data_a;
	const guint8 *raw_data_b;
	gsize raw_len_a;
	gsize raw_len_b;
	gboolean equal;

	if (a->neighbor_sd == b->neighbor_sd)
		return TRUE;

	lldp_neighbor_get_raw (a, &raw_data_a, &raw_len_a);
	lldp_neighbor_get_raw (b, &raw_data_b, &raw_len_b);

	if (raw_len_a != raw_len_b)
		return FALSE;

	equal = (memcmp (raw_data_a, raw_data_b, raw_len_a) == 0);

	nm_assert (  !equal
	           || (   a->chassis_id_type == b->chassis_id_type
	               && a->port_id_type == b->port_id_type
	               && ether_addr_equal (&a->destination_address, &b->destination_address)
	               && nm_streq0 (a->chassis_id, b->chassis_id)
	               && nm_streq0 (a->port_id, b->port_id)));
	return equal;
}

static GVariant *
parse_management_address_tlv (const uint8_t *data, gsize len)
{
	GVariantBuilder builder;
	gsize addr_len;
	const guint8 *v_object_id_arr;
	gsize v_object_id_len;
	const guint8 *v_address_arr;
	gsize v_address_len;
	guint32 v_interface_number;
	guint32 v_interface_number_subtype;
	guint32 v_address_subtype;

	/* 802.1AB-2009 - Figure 8-11
	 *
	 * - TLV type / length        (2 bytes)
	 * - address string length    (1 byte)
	 * - address subtype          (1 byte)
	 * - address                  (1 to 31 bytes)
	 * - interface number subtype (1 byte)
	 * - interface number         (4 bytes)
	 * - OID string length        (1 byte)
	 * - OID                      (0 to 128 bytes)
	 */

	if (len < 11)
		return NULL;

	nm_assert ((data[0] >> 1) == SD_LLDP_TYPE_MGMT_ADDRESS);
	nm_assert ((((data[0] & 1) << 8) + data[1]) + 2 == len);

	data += 2;
	len -= 2;
	addr_len = *data; /* length of (address subtype + address) */

	if (addr_len < 2 || addr_len > 32)
		return NULL;
	if (len < (  1         /* address stringth length */
	           + addr_len  /* address subtype + address */
	           + 5         /* interface */
	           + 1))       /* oid */
		return NULL;

	data++;
	len--;
	v_address_subtype = *data;
	v_address_arr = &data[1];
	v_address_len = addr_len - 1;

	data += addr_len;
	len -= addr_len;
	v_interface_number_subtype = *data;

	data++;
	len--;
	v_interface_number = unaligned_read_be32 (data);

	data += 4;
	len -= 4;
	v_object_id_len = *data;
	if (len < (1 + v_object_id_len))
		return NULL;
	data++;
	v_object_id_arr = data;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	nm_g_variant_builder_add_sv_uint32 (&builder, "address-subtype", v_address_subtype);
	nm_g_variant_builder_add_sv_bytearray (&builder, "object-id", v_object_id_arr, v_object_id_len);
	nm_g_variant_builder_add_sv_uint32 (&builder, "interface-number", v_interface_number);
	nm_g_variant_builder_add_sv_bytearray (&builder, "address", v_address_arr, v_address_len);
	nm_g_variant_builder_add_sv_uint32 (&builder, "interface-number-subtype", v_interface_number_subtype);
	return g_variant_builder_end (&builder);
}

static LldpNeighbor *
lldp_neighbor_new (sd_lldp_neighbor *neighbor_sd, GError **error)
{
	nm_auto (lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
	uint8_t chassis_id_type, port_id_type;
	const void *chassis_id, *port_id;
	gsize chassis_id_len, port_id_len;
	int r;

	r = sd_lldp_neighbor_get_chassis_id (neighbor_sd, &chassis_id_type,
	                                     &chassis_id, &chassis_id_len);
	if (r < 0) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failed reading chassis-id: %s", nm_strerror_native (-r));
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
		             "failed reading port-id: %s", nm_strerror_native (-r));
		return NULL;
	}
	if (port_id_len < 1) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "empty port-id");
		return NULL;
	}

	neigh = g_slice_new (LldpNeighbor);
	*neigh = (LldpNeighbor) {
		.chassis_id_type = chassis_id_type,
		.port_id_type    = port_id_type,
		.neighbor_sd     = sd_lldp_neighbor_ref (neighbor_sd),
	};

	r = sd_lldp_neighbor_get_destination_address (neighbor_sd, &neigh->destination_address);
	if (r < 0) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failed getting destination address: %s", nm_strerror_native (-r));
		goto out;
	}

	switch (chassis_id_type) {
	case SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
	case SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
	case SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
	case SD_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
		neigh->chassis_id =    nm_utils_buf_utf8safe_escape_cp (chassis_id, chassis_id_len, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII)
		                    ?: g_new0 (char, 1);
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
		neigh->port_id =    nm_utils_buf_utf8safe_escape_cp (port_id, port_id_len, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII)
		                 ?: g_new0 (char, 1);
		break;
	case SD_LLDP_PORT_SUBTYPE_MAC_ADDRESS:
		neigh->port_id = nm_utils_hwaddr_ntoa (port_id, port_id_len);
		break;
	default:
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "unsupported port-id type %d", port_id_type);
		goto out;
	}

	neigh->valid = TRUE;

out:
	return g_steal_pointer (&neigh);
}

static GVariant *
lldp_neighbor_to_variant (LldpNeighbor *neigh)
{
	GVariantBuilder builder;
	const char *str;
	const guint8 *raw_data;
	gsize raw_len;
	uint16_t u16;
	uint8_t *data8;
	gsize len;
	int r;

	if (neigh->variant)
		return neigh->variant;

	lldp_neighbor_get_raw (neigh, &raw_data, &raw_len);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	nm_g_variant_builder_add_sv_bytearray (&builder,
	                                       NM_LLDP_ATTR_RAW,
	                                       raw_data,
	                                       raw_len);
	nm_g_variant_builder_add_sv_uint32 (&builder, NM_LLDP_ATTR_CHASSIS_ID_TYPE, neigh->chassis_id_type);
	nm_g_variant_builder_add_sv_str (&builder, NM_LLDP_ATTR_CHASSIS_ID, neigh->chassis_id);
	nm_g_variant_builder_add_sv_uint32 (&builder, NM_LLDP_ATTR_PORT_ID_TYPE, neigh->port_id_type);
	nm_g_variant_builder_add_sv_str (&builder, NM_LLDP_ATTR_PORT_ID, neigh->port_id);

	if (ether_addr_equal (&neigh->destination_address, LLDP_MAC_NEAREST_BRIDGE))
		str = NM_LLDP_DEST_NEAREST_BRIDGE;
	else if (ether_addr_equal (&neigh->destination_address, LLDP_MAC_NEAREST_NON_TPMR_BRIDGE))
		str = NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE;
	else if (ether_addr_equal (&neigh->destination_address, LLDP_MAC_NEAREST_CUSTOMER_BRIDGE))
		str = NM_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE;
	else
		str = NULL;
	if (str)
		nm_g_variant_builder_add_sv_str (&builder, NM_LLDP_ATTR_DESTINATION, str);

	if (sd_lldp_neighbor_get_port_description (neigh->neighbor_sd, &str) == 0)
		nm_g_variant_builder_add_sv_str (&builder, NM_LLDP_ATTR_PORT_DESCRIPTION, str);

	if (sd_lldp_neighbor_get_system_name (neigh->neighbor_sd, &str) == 0)
		nm_g_variant_builder_add_sv_str (&builder, NM_LLDP_ATTR_SYSTEM_NAME, str);

	if (sd_lldp_neighbor_get_system_description (neigh->neighbor_sd, &str) == 0)
		nm_g_variant_builder_add_sv_str (&builder, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, str);

	if (sd_lldp_neighbor_get_system_capabilities (neigh->neighbor_sd, &u16) == 0)
		nm_g_variant_builder_add_sv_uint32 (&builder, NM_LLDP_ATTR_SYSTEM_CAPABILITIES, u16);

	r = sd_lldp_neighbor_tlv_rewind (neigh->neighbor_sd);
	if (r < 0)
		nm_assert_not_reached ();
	else {
		gboolean v_management_addresses_has = FALSE;
		GVariantBuilder v_management_addresses;
		GVariant *v_ieee_802_1_pvid = NULL;
		GVariant *v_ieee_802_1_ppvid = NULL;
		GVariant *v_ieee_802_1_ppvid_flags = NULL;
		GVariantBuilder v_ieee_802_1_ppvids;
		GVariant *v_ieee_802_1_vid = NULL;
		GVariant *v_ieee_802_1_vlan_name = NULL;
		GVariantBuilder v_ieee_802_1_vlans;
		GVariant *v_ieee_802_3_mac_phy_conf = NULL;
		GVariant *v_ieee_802_3_power_via_mdi = NULL;
		GVariant *v_ieee_802_3_max_frame_size = NULL;
		GVariantBuilder tmp_builder;
		GVariant *tmp_variant;

		do {
			guint8 oui[3];
			guint8 type;
			guint8 subtype;

			if (sd_lldp_neighbor_tlv_get_type (neigh->neighbor_sd, &type) < 0)
				continue;

			if (sd_lldp_neighbor_tlv_get_raw (neigh->neighbor_sd, (void *) &data8, &len) < 0)
				continue;

			switch (type) {
			case SD_LLDP_TYPE_MGMT_ADDRESS:
				tmp_variant = parse_management_address_tlv (data8, len);
				if (tmp_variant) {
					if (!v_management_addresses_has) {
						v_management_addresses_has = TRUE;
						g_variant_builder_init (&v_management_addresses, G_VARIANT_TYPE ("aa{sv}"));
					}
					g_variant_builder_add_value (&v_management_addresses, tmp_variant);
				}
				continue;
			case SD_LLDP_TYPE_PRIVATE:
				break;
			default:
				continue;
			}

			r = sd_lldp_neighbor_tlv_get_oui (neigh->neighbor_sd, oui, &subtype);
			if (r < 0) {
				if (r == -ENXIO)
					continue;

				/* in other cases, something is seriously wrong. Abort, but
				 * keep what we parsed so far. */
				break;
			}

			if (   memcmp (oui, SD_LLDP_OUI_802_1, sizeof (oui)) != 0
			    && memcmp (oui, SD_LLDP_OUI_802_3, sizeof (oui)) != 0)
				continue;

			/* skip over leading TLV, OUI and subtype */
#if NM_MORE_ASSERTS > 5
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

			if (memcmp (oui, SD_LLDP_OUI_802_1, sizeof (oui)) == 0) {
				switch (subtype) {
				case SD_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID:
					if (len != 2)
						continue;
					if (!v_ieee_802_1_pvid)
						v_ieee_802_1_pvid = g_variant_new_uint32 (unaligned_read_be16 (data8));
					break;
				case SD_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID:
					if (len != 3)
						continue;
					if (!v_ieee_802_1_ppvid) {
						v_ieee_802_1_ppvid_flags = g_variant_new_uint32 (data8[0]);
						v_ieee_802_1_ppvid = g_variant_new_uint32 (unaligned_read_be16 (&data8[1]));
						g_variant_builder_init (&v_ieee_802_1_ppvids, G_VARIANT_TYPE ("aa{sv}"));
					}
					g_variant_builder_init (&tmp_builder, G_VARIANT_TYPE ("a{sv}"));
					nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "flags", data8[0]);
					nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "ppvid", unaligned_read_be16 (&data8[1]));
					g_variant_builder_add_value (&v_ieee_802_1_ppvids, g_variant_builder_end (&tmp_builder));
					break;
				case SD_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME: {
					gs_free char *name_to_free = NULL;
					const char *name;
					guint32 vid;
					int l;

					if (len <= 3)
						continue;

					l = data8[2];
					if (len != 3 + l)
						continue;
					if (l > 32)
						continue;

					name = nm_utils_buf_utf8safe_escape (&data8[3], l, 0, &name_to_free);
					vid = unaligned_read_be16 (&data8[0]);

					if (!v_ieee_802_1_vid) {
						v_ieee_802_1_vid = g_variant_new_uint32 (vid);
						v_ieee_802_1_vlan_name = g_variant_new_string (name);
						g_variant_builder_init (&v_ieee_802_1_vlans, G_VARIANT_TYPE ("aa{sv}"));
					}
					g_variant_builder_init (&tmp_builder, G_VARIANT_TYPE ("a{sv}"));
					nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "vid", vid);
					nm_g_variant_builder_add_sv_str (&tmp_builder, "name", name);
					g_variant_builder_add_value (&v_ieee_802_1_vlans, g_variant_builder_end (&tmp_builder));
					break;
				}
				default:
					continue;
				}
			} else if (memcmp (oui, SD_LLDP_OUI_802_3, sizeof (oui)) == 0) {
				switch (subtype) {
				case SD_LLDP_OUI_802_3_SUBTYPE_MAC_PHY_CONFIG_STATUS:
					if (len != 5)
						continue;

					if (!v_ieee_802_3_mac_phy_conf) {
						g_variant_builder_init (&tmp_builder, G_VARIANT_TYPE ("a{sv}"));
						nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "operational-mau-type", unaligned_read_be16 (&data8[3]));
						nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "autoneg", data8[0]);
						nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "pmd-autoneg-cap", unaligned_read_be16 (&data8[1]));
						v_ieee_802_3_mac_phy_conf = g_variant_builder_end (&tmp_builder);
					}
					break;
				case SD_LLDP_OUI_802_3_SUBTYPE_POWER_VIA_MDI:
					if (len != 3)
						continue;

					if (!v_ieee_802_3_power_via_mdi) {
						g_variant_builder_init (&tmp_builder, G_VARIANT_TYPE ("a{sv}"));
						nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "pse-power-pair", data8[1]);
						nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "mdi-power-support", data8[0]);
						nm_g_variant_builder_add_sv_uint32 (&tmp_builder, "power-class", data8[2]);
						v_ieee_802_3_power_via_mdi = g_variant_builder_end (&tmp_builder);
					}
					break;
				case SD_LLDP_OUI_802_3_SUBTYPE_MAXIMUM_FRAME_SIZE:
					if (len != 2)
						continue;
					if (!v_ieee_802_3_max_frame_size)
						v_ieee_802_3_max_frame_size = g_variant_new_uint32 (unaligned_read_be16 (data8));
					break;
				}
			}
		} while (sd_lldp_neighbor_tlv_next (neigh->neighbor_sd) > 0);

		if (v_management_addresses_has)
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_MANAGEMENT_ADDRESSES, g_variant_builder_end (&v_management_addresses));
		if (v_ieee_802_1_pvid)
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_PVID, v_ieee_802_1_pvid);
		if (v_ieee_802_1_ppvid) {
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_PPVID, v_ieee_802_1_ppvid);
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS, v_ieee_802_1_ppvid_flags);
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_PPVIDS, g_variant_builder_end (&v_ieee_802_1_ppvids));
		}
		if (v_ieee_802_1_vid) {
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_VID, v_ieee_802_1_vid);
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME, v_ieee_802_1_vlan_name);
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_1_VLANS, g_variant_builder_end (&v_ieee_802_1_vlans));
		}
		if (v_ieee_802_3_mac_phy_conf)
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_3_MAC_PHY_CONF, v_ieee_802_3_mac_phy_conf);
		if (v_ieee_802_3_power_via_mdi)
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_3_POWER_VIA_MDI, v_ieee_802_3_power_via_mdi);
		if (v_ieee_802_3_max_frame_size)
			nm_g_variant_builder_add_sv (&builder, NM_LLDP_ATTR_IEEE_802_3_MAX_FRAME_SIZE, v_ieee_802_3_max_frame_size);
	}

	return (neigh->variant = g_variant_ref_sink (g_variant_builder_end (&builder)));
}

/*****************************************************************************/

GVariant *
nmtst_lldp_parse_from_raw (const guint8 *raw_data,
                           gsize raw_len)
{
	nm_auto (sd_lldp_neighbor_unrefp) sd_lldp_neighbor *neighbor_sd = NULL;
	nm_auto (lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
	gs_free_error GError *error = NULL;
	GVariant *variant;
	int r;

	g_assert (raw_data);
	g_assert (raw_len > 0);

	r = sd_lldp_neighbor_from_raw (&neighbor_sd, raw_data, raw_len);
	g_assert (r >= 0);

	neigh = lldp_neighbor_new (neighbor_sd, &error);
	g_assert (neigh);
	g_assert (!error);

	variant = lldp_neighbor_to_variant (neigh);
	g_assert (variant);

	return g_variant_ref (variant);
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
	priv->ratelimit_next = nm_utils_get_monotonic_timestamp_nsec() + MIN_UPDATE_INTERVAL_NS;
	data_changed_notify (self, priv);
	return G_SOURCE_REMOVE;
}

static void
data_changed_schedule (NMLldpListener *self)
{
	NMLldpListenerPrivate *priv = NM_LLDP_LISTENER_GET_PRIVATE (self);
	gint64 now;

	now = nm_utils_get_monotonic_timestamp_nsec ();
	if (now < priv->ratelimit_next) {
		if (!priv->ratelimit_id)
			priv->ratelimit_id = g_timeout_add (NM_UTILS_NSEC_TO_MSEC_CEIL (priv->ratelimit_next - now), data_changed_timeout, self);
		return;
	}

	nm_clear_g_source (&priv->ratelimit_id);
	priv->ratelimit_next = now + MIN_UPDATE_INTERVAL_NS;
	data_changed_notify (self, priv);
}

static void
process_lldp_neighbor (NMLldpListener *self, sd_lldp_neighbor *neighbor_sd, gboolean neighbor_valid)
{
	NMLldpListenerPrivate *priv;
	nm_auto (lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
	LldpNeighbor *neigh_old;
	gs_free_error GError *parse_error = NULL;
	GError **p_parse_error;

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
			goto handle_changed;
		}
		if (lldp_neighbor_equal (neigh_old, neigh))
			return;
	} else if (!neighbor_valid) {
		if (parse_error)
			_LOGT ("process: failed to parse neighbor: %s", parse_error->message);
		return;
	}

	_LOGD ("process: %s neigh: "LOG_NEIGH_FMT,
	        neigh_old ? "update" : "new",
	        LOG_NEIGH_ARG (neigh));

	g_hash_table_add (priv->lldp_neighbors, g_steal_pointer (&neigh));

handle_changed:
	data_changed_schedule (self);
}

static void
lldp_event_handler (sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata)
{
	process_lldp_neighbor (userdata,
	                       n,
	                       NM_IN_SET (event, SD_LLDP_EVENT_ADDED,
	                                         SD_LLDP_EVENT_UPDATED,
	                                         SD_LLDP_EVENT_REFRESHED));
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

	ret = sd_lldp_set_neighbors_max (priv->lldp_handle, MAX_NEIGHBORS);
	nm_assert (ret == 0);

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

	g_return_val_if_fail (NM_IS_LLDP_LISTENER (self), FALSE);

	priv = NM_LLDP_LISTENER_GET_PRIVATE (self);

	if (G_UNLIKELY (!priv->variant)) {
		GVariantBuilder array_builder;
		gs_free LldpNeighbor **neighbors = NULL;
		guint i, n;

		g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
		neighbors = (LldpNeighbor **) nm_utils_hash_keys_to_array (priv->lldp_neighbors,
		                                                           lldp_neighbor_id_cmp_p,
		                                                           NULL,
		                                                           &n);
		for (i = 0; i < n; i++)
			g_variant_builder_add_value (&array_builder, lldp_neighbor_to_variant (neighbors[i]));
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
