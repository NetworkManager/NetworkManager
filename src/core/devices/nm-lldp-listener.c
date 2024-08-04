/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-lldp-listener.h"

#include <net/ethernet.h>

#include "NetworkManagerUtils.h"
#include "libnm-core-public/nm-errors.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-std-aux/unaligned.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-glib-aux/nm-c-list.h"
#include "libnm-lldp/nm-lldp-rx.h"
#include "nm-utils.h"

#define MAX_NEIGHBORS            128
#define MIN_UPDATE_INTERVAL_NSEC (2 * NM_UTILS_NSEC_PER_SEC)

#define LLDP_MAC_NEAREST_BRIDGE          (&NM_ETHER_ADDR_INIT(0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e))
#define LLDP_MAC_NEAREST_NON_TPMR_BRIDGE (&NM_ETHER_ADDR_INIT(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03))
#define LLDP_MAC_NEAREST_CUSTOMER_BRIDGE (&NM_ETHER_ADDR_INIT(0x01, 0x80, 0xc2, 0x00, 0x00, 0x00))

/*****************************************************************************/

struct _NMLldpListener {
    NMLldpRX   *lldp_rx;
    GHashTable *lldp_neighbors;
    GVariant   *variant;

    NMLldpListenerNotify notify_callback;
    gpointer             notify_user_data;

    /* the timestamp in nsec until which we delay updates. */
    GSource *ratelimit_source;
    gint64   ratelimit_next_nsec;

    int ifindex;
};

/*****************************************************************************/

typedef struct {
    GVariant       *variant;
    NMLldpNeighbor *neighbor_nm;
    char           *chassis_id;
    char           *port_id;
    guint8          chassis_id_type;
    guint8          port_id_type;
} LldpNeighbor;

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "lldp"
#define _NMLOG_DOMAIN      LOGD_DEVICE
#define _NMLOG(level, ...)                                                                       \
    G_STMT_START                                                                                 \
    {                                                                                            \
        const NMLogLevel _level = (level);                                                       \
                                                                                                 \
        if (nm_logging_enabled(_level, _NMLOG_DOMAIN)) {                                         \
            char _sbuf[100];                                                                     \
                                                                                                 \
            _nm_log(_level,                                                                      \
                    _NMLOG_DOMAIN,                                                               \
                    0,                                                                           \
                    (self) ? nm_platform_link_get_name(NM_PLATFORM_GET, (self)->ifindex) : NULL, \
                    NULL,                                                                        \
                    "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                                 \
                    _NMLOG_PREFIX_NAME,                                                          \
                    ((self) ? nm_sprintf_buf(_sbuf,                                              \
                                             "[" NM_HASH_OBFUSCATE_PTR_FMT ",%d]",               \
                                             NM_HASH_OBFUSCATE_PTR(self),                        \
                                             (self)->ifindex)                                    \
                            : "") _NM_UTILS_MACRO_REST(__VA_ARGS__));                            \
        }                                                                                        \
    }                                                                                            \
    G_STMT_END

#define LOG_NEIGH_FMT "CHASSIS=%u/%s PORT=%u/%s"
#define LOG_NEIGH_ARG(neigh) \
    (neigh)->chassis_id_type, (neigh)->chassis_id, (neigh)->port_id_type, (neigh)->port_id

/*****************************************************************************/

static void
lldp_neighbor_get_raw(LldpNeighbor *neigh, const guint8 **out_raw_data, gsize *out_raw_len)
{
    gconstpointer raw_data = NULL;
    gsize         raw_len  = 0;
    int           r;

    nm_assert(neigh);

    r = nm_lldp_neighbor_get_raw(neigh->neighbor_nm, &raw_data, &raw_len);

    nm_assert(r >= 0);
    nm_assert(raw_data);
    nm_assert(raw_len > 0);

    *out_raw_data = raw_data;
    *out_raw_len  = raw_len;
}

static gboolean
lldp_neighbor_id_get(NMLldpNeighbor *neighbor_nm,
                     guint8         *out_chassis_id_type,
                     const guint8  **out_chassis_id,
                     gsize          *out_chassis_id_len,
                     guint8         *out_port_id_type,
                     const guint8  **out_port_id,
                     gsize          *out_port_id_len)
{
    int r;

    r = nm_lldp_neighbor_get_chassis_id(neighbor_nm,
                                        out_chassis_id_type,
                                        (gconstpointer *) out_chassis_id,
                                        out_chassis_id_len);
    if (r < 0)
        return FALSE;

    r = nm_lldp_neighbor_get_port_id(neighbor_nm,
                                     out_port_id_type,
                                     (gconstpointer *) out_port_id,
                                     out_port_id_len);
    if (r < 0)
        return FALSE;

    return TRUE;
}

static guint
lldp_neighbor_id_hash(const LldpNeighbor *neigh)
{
    return nm_lldp_neighbor_id_hash(nm_lldp_neighbor_get_id(neigh->neighbor_nm));
}

static int
lldp_neighbor_id_cmp(const LldpNeighbor *a, const LldpNeighbor *b)
{
    return nm_lldp_neighbor_id_cmp(nm_lldp_neighbor_get_id(a->neighbor_nm),
                                   nm_lldp_neighbor_get_id(b->neighbor_nm));
}

static int
lldp_neighbor_id_cmp_p(gconstpointer a, gconstpointer b, gpointer user_data)
{
    return lldp_neighbor_id_cmp(*((const LldpNeighbor *const *) a),
                                *((const LldpNeighbor *const *) b));
}

static gboolean
lldp_neighbor_id_equal(const LldpNeighbor *a, const LldpNeighbor *b)
{
    return lldp_neighbor_id_cmp(a, b) == 0;
}

static void
lldp_neighbor_free(LldpNeighbor *neighbor)
{
    if (!neighbor)
        return;

    g_free(neighbor->chassis_id);
    g_free(neighbor->port_id);
    nm_g_variant_unref(neighbor->variant);
    nm_lldp_neighbor_unref(neighbor->neighbor_nm);
    nm_g_slice_free(neighbor);
}

static void
lldp_neighbor_freep(LldpNeighbor **ptr)
{
    lldp_neighbor_free(*ptr);
}

static gboolean
lldp_neighbor_equal(LldpNeighbor *a, LldpNeighbor *b)
{
    const guint8 *raw_data_a;
    const guint8 *raw_data_b;
    gsize         raw_len_a;
    gsize         raw_len_b;

    if (a->neighbor_nm == b->neighbor_nm)
        return TRUE;

    lldp_neighbor_get_raw(a, &raw_data_a, &raw_len_a);
    lldp_neighbor_get_raw(b, &raw_data_b, &raw_len_b);
    return raw_len_a == raw_len_b && (memcmp(raw_data_a, raw_data_b, raw_len_a) == 0);
}

static GVariant *
parse_management_address_tlv(const uint8_t *data, gsize len)
{
    GVariantBuilder builder;
    gsize           addr_len;
    const guint8   *v_object_id_arr;
    gsize           v_object_id_len;
    const guint8   *v_address_arr;
    gsize           v_address_len;
    guint32         v_interface_number;
    guint32         v_interface_number_subtype;
    guint32         v_address_subtype;

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

    nm_assert((data[0] >> 1) == NM_LLDP_TYPE_MGMT_ADDRESS);
    nm_assert((((data[0] & 1) << 8) + data[1]) + 2 == len);

    data += 2;
    len -= 2;
    addr_len = *data; /* length of (address subtype + address) */

    if (addr_len < 2 || addr_len > 32)
        return NULL;
    if (len < (1          /* address stringth length */
               + addr_len /* address subtype + address */
               + 5        /* interface */
               + 1))      /* oid */
        return NULL;

    data++;
    len--;
    v_address_subtype = *data;
    v_address_arr     = &data[1];
    v_address_len     = addr_len - 1;

    data += addr_len;
    len -= addr_len;
    v_interface_number_subtype = *data;

    data++;
    len--;
    v_interface_number = unaligned_read_be32(data);

    data += 4;
    len -= 4;
    v_object_id_len = *data;
    if (len < (1 + v_object_id_len))
        return NULL;
    data++;
    v_object_id_arr = data;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    nm_g_variant_builder_add_sv_uint32(&builder, "address-subtype", v_address_subtype);
    nm_g_variant_builder_add_sv_bytearray(&builder, "address", v_address_arr, v_address_len);
    nm_g_variant_builder_add_sv_uint32(&builder,
                                       "interface-number-subtype",
                                       v_interface_number_subtype);
    nm_g_variant_builder_add_sv_uint32(&builder, "interface-number", v_interface_number);
    if (v_object_id_len > 0)
        nm_g_variant_builder_add_sv_bytearray(&builder,
                                              "object-id",
                                              v_object_id_arr,
                                              v_object_id_len);
    return g_variant_builder_end(&builder);
}

static char *
format_network_address(const guint8 *data, gsize sz)
{
    NMIPAddr a;
    int      family;

    if (sz == 5 && data[0] == 1 /* LLDP_MGMT_ADDR_IP4 */) {
        memcpy(&a, &data[1], sizeof(a.addr4));
        family = AF_INET;
    } else if (sz == 17 && data[0] == 2 /* LLDP_MGMT_ADDR_IP6 */) {
        memcpy(&a, &data[1], sizeof(a.addr6));
        family = AF_INET6;
    } else
        return NULL;

    return nm_inet_ntop_dup(family, &a);
}

static const char *
format_string(const guint8 *data, gsize len, gboolean allow_trim, char **out_to_free)
{
    gboolean is_null_terminated = FALSE;

    nm_assert(out_to_free && !*out_to_free);

    if (allow_trim) {
        while (len > 0 && data[len - 1] == '\0') {
            is_null_terminated = TRUE;
            len--;
        }
    }

    if (len == 0)
        return NULL;

    if (memchr(data, len, '\0'))
        return NULL;

    return nm_utils_buf_utf8safe_escape(data,
                                        is_null_terminated ? -1 : (gssize) len,
                                        NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
                                            | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII,
                                        out_to_free);
}

static char *
format_string_cp(const guint8 *data, gsize len, gboolean allow_trim)
{
    char       *s_free = NULL;
    const char *s;

    s = format_string(data, len, allow_trim, &s_free);
    nm_assert(!s_free || s == s_free);
    return s ? (s_free ?: g_strdup(s)) : NULL;
}

static LldpNeighbor *
lldp_neighbor_new(NMLldpNeighbor *neighbor_nm)
{
    LldpNeighbor *neigh;
    guint8        chassis_id_type;
    guint8        port_id_type;
    const guint8 *chassis_id;
    const guint8 *port_id;
    gsize         chassis_id_len;
    gsize         port_id_len;
    gs_free char *s_chassis_id = NULL;
    gs_free char *s_port_id    = NULL;

    if (!lldp_neighbor_id_get(neighbor_nm,
                              &chassis_id_type,
                              &chassis_id,
                              &chassis_id_len,
                              &port_id_type,
                              &port_id,
                              &port_id_len))
        return NULL;

    switch (chassis_id_type) {
    case NM_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
    case NM_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
    case NM_LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT:
    case NM_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
    case NM_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
        s_chassis_id = format_string_cp(chassis_id, chassis_id_len, FALSE);
        break;
    case NM_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:
        s_chassis_id = nm_utils_hwaddr_ntoa(chassis_id, chassis_id_len);
        break;
    case NM_LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS:
        s_chassis_id = format_network_address(chassis_id, chassis_id_len);
        break;
    }
    if (!s_chassis_id) {
        /* Invalid/unsupported chassis_id? Expose as hex string. This format is not stable, and
         * in the future we may add a better string representation for these case (thus
         * changing the API). */
        s_chassis_id = nm_utils_bin2hexstr_full(chassis_id, chassis_id_len, '\0', FALSE, NULL);
    }

    switch (port_id_type) {
    case NM_LLDP_PORT_SUBTYPE_INTERFACE_ALIAS:
    case NM_LLDP_PORT_SUBTYPE_PORT_COMPONENT:
    case NM_LLDP_PORT_SUBTYPE_INTERFACE_NAME:
    case NM_LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED:
        s_port_id = format_string_cp(port_id, port_id_len, FALSE);
        break;
    case NM_LLDP_PORT_SUBTYPE_MAC_ADDRESS:
        s_port_id = nm_utils_hwaddr_ntoa(port_id, port_id_len);
        break;
    case NM_LLDP_PORT_SUBTYPE_NETWORK_ADDRESS:
        s_port_id = format_network_address(port_id, port_id_len);
        break;
    }
    if (!s_port_id) {
        /* Invalid/unsupported port_id? Expose as hex string. This format is not stable, and
         * in the future we may add a better string representation for these case (thus
         * changing the API). */
        s_port_id = nm_utils_bin2hexstr_full(port_id, port_id_len, '\0', FALSE, NULL);
    }

    neigh  = g_slice_new(LldpNeighbor);
    *neigh = (LldpNeighbor){
        .neighbor_nm     = nm_lldp_neighbor_ref(neighbor_nm),
        .chassis_id_type = chassis_id_type,
        .chassis_id      = g_steal_pointer(&s_chassis_id),
        .port_id_type    = port_id_type,
        .port_id         = g_steal_pointer(&s_port_id),
    };
    return neigh;
}

static GVariant *
lldp_neighbor_to_variant(LldpNeighbor *neigh)
{
    NMEtherAddr     destination_address;
    GVariantBuilder builder;
    const char     *str;
    const guint8   *raw_data;
    gsize           raw_len;
    uint16_t        u16;
    uint8_t        *data8;
    gsize           len;
    int             r;

    if (neigh->variant)
        return neigh->variant;

    lldp_neighbor_get_raw(neigh, &raw_data, &raw_len);

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));

    nm_g_variant_builder_add_sv_bytearray(&builder, NM_LLDP_ATTR_RAW, raw_data, raw_len);
    nm_g_variant_builder_add_sv_uint32(&builder,
                                       NM_LLDP_ATTR_CHASSIS_ID_TYPE,
                                       neigh->chassis_id_type);
    nm_g_variant_builder_add_sv_str(&builder, NM_LLDP_ATTR_CHASSIS_ID, neigh->chassis_id);
    nm_g_variant_builder_add_sv_uint32(&builder, NM_LLDP_ATTR_PORT_ID_TYPE, neigh->port_id_type);
    nm_g_variant_builder_add_sv_str(&builder, NM_LLDP_ATTR_PORT_ID, neigh->port_id);

    r = nm_lldp_neighbor_get_destination_address(neigh->neighbor_nm, &destination_address);
    if (r < 0)
        str = NULL;
    else if (nm_ether_addr_equal(&destination_address, LLDP_MAC_NEAREST_BRIDGE))
        str = NM_LLDP_DEST_NEAREST_BRIDGE;
    else if (nm_ether_addr_equal(&destination_address, LLDP_MAC_NEAREST_NON_TPMR_BRIDGE))
        str = NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE;
    else if (nm_ether_addr_equal(&destination_address, LLDP_MAC_NEAREST_CUSTOMER_BRIDGE))
        str = NM_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE;
    else
        str = NULL;
    if (str)
        nm_g_variant_builder_add_sv_str(&builder, NM_LLDP_ATTR_DESTINATION, str);

    if (nm_lldp_neighbor_get_port_description(neigh->neighbor_nm, &str) == 0)
        nm_g_variant_builder_add_sv_str(&builder, NM_LLDP_ATTR_PORT_DESCRIPTION, str);

    if (nm_lldp_neighbor_get_system_name(neigh->neighbor_nm, &str) == 0)
        nm_g_variant_builder_add_sv_str(&builder, NM_LLDP_ATTR_SYSTEM_NAME, str);

    if (nm_lldp_neighbor_get_system_description(neigh->neighbor_nm, &str) == 0)
        nm_g_variant_builder_add_sv_str(&builder, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, str);

    if (nm_lldp_neighbor_get_system_capabilities(neigh->neighbor_nm, &u16) == 0)
        nm_g_variant_builder_add_sv_uint32(&builder, NM_LLDP_ATTR_SYSTEM_CAPABILITIES, u16);

    r = nm_lldp_neighbor_tlv_rewind(neigh->neighbor_nm);
    if (r < 0)
        nm_assert_not_reached();
    else {
        gboolean        v_management_addresses_has = FALSE;
        GVariantBuilder v_management_addresses;
        GVariant       *v_ieee_802_1_pvid        = NULL;
        GVariant       *v_ieee_802_1_ppvid       = NULL;
        GVariant       *v_ieee_802_1_ppvid_flags = NULL;
        GVariantBuilder v_ieee_802_1_ppvids;
        GVariant       *v_ieee_802_1_vid       = NULL;
        GVariant       *v_ieee_802_1_vlan_name = NULL;
        GVariantBuilder v_ieee_802_1_vlans;
        GVariant       *v_ieee_802_3_mac_phy_conf   = NULL;
        GVariant       *v_ieee_802_3_power_via_mdi  = NULL;
        GVariant       *v_ieee_802_3_max_frame_size = NULL;
        GVariant       *v_mud_url                   = NULL;
        GVariantBuilder tmp_builder;
        GVariant       *tmp_variant;

        do {
            guint8 oui[3];
            guint8 type;
            guint8 subtype;

            if (nm_lldp_neighbor_tlv_get_type(neigh->neighbor_nm, &type) < 0)
                continue;

            if (nm_lldp_neighbor_tlv_get_raw(neigh->neighbor_nm, (void *) &data8, &len) < 0)
                continue;

            switch (type) {
            case NM_LLDP_TYPE_MGMT_ADDRESS:
                tmp_variant = parse_management_address_tlv(data8, len);
                if (tmp_variant) {
                    if (!v_management_addresses_has) {
                        v_management_addresses_has = TRUE;
                        g_variant_builder_init(&v_management_addresses, G_VARIANT_TYPE("aa{sv}"));
                    }
                    g_variant_builder_add_value(&v_management_addresses, tmp_variant);
                }
                continue;
            case NM_LLDP_TYPE_PRIVATE:
                break;
            default:
                continue;
            }

            r = nm_lldp_neighbor_tlv_get_oui(neigh->neighbor_nm, oui, &subtype);
            if (r < 0) {
                if (r == -ENXIO)
                    continue;

                /* in other cases, something is seriously wrong. Abort, but
                 * keep what we parsed so far. */
                break;
            }

            if (len <= 6)
                continue;

                /* skip over leading TLV, OUI and subtype */
#if NM_MORE_ASSERTS > 5
            {
                guint8 check_hdr[] = {0xfe | (((len - 2) >> 8) & 0x01),
                                      ((len - 2) & 0xFF),
                                      oui[0],
                                      oui[1],
                                      oui[2],
                                      subtype};

                nm_assert(len > 2 + 3 + 1);
                nm_assert(memcmp(data8, check_hdr, sizeof check_hdr) == 0);
            }
#endif
            data8 += 6;
            len -= 6;

            if (memcmp(oui, NM_LLDP_OUI_802_1, sizeof(oui)) == 0) {
                switch (subtype) {
                case NM_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID:
                    if (len != 2)
                        continue;
                    if (!v_ieee_802_1_pvid)
                        v_ieee_802_1_pvid = g_variant_new_uint32(unaligned_read_be16(data8));
                    break;
                case NM_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID:
                    if (len != 3)
                        continue;
                    if (!v_ieee_802_1_ppvid) {
                        v_ieee_802_1_ppvid_flags = g_variant_new_uint32(data8[0]);
                        v_ieee_802_1_ppvid = g_variant_new_uint32(unaligned_read_be16(&data8[1]));
                        g_variant_builder_init(&v_ieee_802_1_ppvids, G_VARIANT_TYPE("aa{sv}"));
                    }
                    g_variant_builder_init(&tmp_builder, G_VARIANT_TYPE("a{sv}"));
                    nm_g_variant_builder_add_sv_uint32(&tmp_builder,
                                                       "ppvid",
                                                       unaligned_read_be16(&data8[1]));
                    nm_g_variant_builder_add_sv_uint32(&tmp_builder, "flags", data8[0]);
                    g_variant_builder_add_value(&v_ieee_802_1_ppvids,
                                                g_variant_builder_end(&tmp_builder));
                    break;
                case NM_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME:
                {
                    gs_free char *name_to_free = NULL;
                    const char   *name;
                    guint32       vid;
                    gsize         l;

                    if (len <= 3)
                        continue;

                    l = data8[2];
                    if (len != 3 + l)
                        continue;
                    if (l > 32)
                        continue;

                    name = format_string(&data8[3], l, TRUE, &name_to_free);
                    if (!name)
                        continue;

                    vid = unaligned_read_be16(&data8[0]);
                    if (!v_ieee_802_1_vid) {
                        v_ieee_802_1_vid       = g_variant_new_uint32(vid);
                        v_ieee_802_1_vlan_name = g_variant_new_string(name);
                        g_variant_builder_init(&v_ieee_802_1_vlans, G_VARIANT_TYPE("aa{sv}"));
                    }
                    g_variant_builder_init(&tmp_builder, G_VARIANT_TYPE("a{sv}"));
                    nm_g_variant_builder_add_sv_uint32(&tmp_builder, "vid", vid);
                    nm_g_variant_builder_add_sv_str(&tmp_builder, "name", name);
                    g_variant_builder_add_value(&v_ieee_802_1_vlans,
                                                g_variant_builder_end(&tmp_builder));
                    break;
                }
                default:
                    continue;
                }
            } else if (memcmp(oui, NM_LLDP_OUI_802_3, sizeof(oui)) == 0) {
                switch (subtype) {
                case NM_LLDP_OUI_802_3_SUBTYPE_MAC_PHY_CONFIG_STATUS:
                    if (len != 5)
                        continue;

                    if (!v_ieee_802_3_mac_phy_conf) {
                        g_variant_builder_init(&tmp_builder, G_VARIANT_TYPE("a{sv}"));
                        nm_g_variant_builder_add_sv_uint32(&tmp_builder, "autoneg", data8[0]);
                        nm_g_variant_builder_add_sv_uint32(&tmp_builder,
                                                           "pmd-autoneg-cap",
                                                           unaligned_read_be16(&data8[1]));
                        nm_g_variant_builder_add_sv_uint32(&tmp_builder,
                                                           "operational-mau-type",
                                                           unaligned_read_be16(&data8[3]));
                        v_ieee_802_3_mac_phy_conf = g_variant_builder_end(&tmp_builder);
                    }
                    break;
                case NM_LLDP_OUI_802_3_SUBTYPE_POWER_VIA_MDI:
                    if (len != 3)
                        continue;

                    if (!v_ieee_802_3_power_via_mdi) {
                        g_variant_builder_init(&tmp_builder, G_VARIANT_TYPE("a{sv}"));
                        nm_g_variant_builder_add_sv_uint32(&tmp_builder,
                                                           "mdi-power-support",
                                                           data8[0]);
                        nm_g_variant_builder_add_sv_uint32(&tmp_builder,
                                                           "pse-power-pair",
                                                           data8[1]);
                        nm_g_variant_builder_add_sv_uint32(&tmp_builder, "power-class", data8[2]);
                        v_ieee_802_3_power_via_mdi = g_variant_builder_end(&tmp_builder);
                    }
                    break;
                case NM_LLDP_OUI_802_3_SUBTYPE_MAXIMUM_FRAME_SIZE:
                    if (len != 2)
                        continue;
                    if (!v_ieee_802_3_max_frame_size)
                        v_ieee_802_3_max_frame_size =
                            g_variant_new_uint32(unaligned_read_be16(data8));
                    break;
                }
            } else if (memcmp(oui, NM_LLDP_OUI_IANA, sizeof(oui)) == 0) {
                switch (subtype) {
                case NM_LLDP_OUI_IANA_SUBTYPE_MUD:
                    if (!v_mud_url) {
                        gs_free char *s_free = NULL;
                        const char   *s;

                        s = format_string(data8, len, TRUE, &s_free);
                        if (s)
                            v_mud_url = g_variant_new_string(s);
                    }
                    break;
                }
            }
        } while (nm_lldp_neighbor_tlv_next(neigh->neighbor_nm) > 0);

        if (v_management_addresses_has)
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_MANAGEMENT_ADDRESSES,
                                        g_variant_builder_end(&v_management_addresses));
        if (v_ieee_802_1_pvid)
            nm_g_variant_builder_add_sv(&builder, NM_LLDP_ATTR_IEEE_802_1_PVID, v_ieee_802_1_pvid);
        if (v_ieee_802_1_ppvid) {
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_1_PPVID,
                                        v_ieee_802_1_ppvid);
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS,
                                        v_ieee_802_1_ppvid_flags);
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_1_PPVIDS,
                                        g_variant_builder_end(&v_ieee_802_1_ppvids));
        }
        if (v_ieee_802_1_vid) {
            nm_g_variant_builder_add_sv(&builder, NM_LLDP_ATTR_IEEE_802_1_VID, v_ieee_802_1_vid);
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME,
                                        v_ieee_802_1_vlan_name);
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_1_VLANS,
                                        g_variant_builder_end(&v_ieee_802_1_vlans));
        }
        if (v_ieee_802_3_mac_phy_conf)
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_3_MAC_PHY_CONF,
                                        v_ieee_802_3_mac_phy_conf);
        if (v_ieee_802_3_power_via_mdi)
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_3_POWER_VIA_MDI,
                                        v_ieee_802_3_power_via_mdi);
        if (v_ieee_802_3_max_frame_size)
            nm_g_variant_builder_add_sv(&builder,
                                        NM_LLDP_ATTR_IEEE_802_3_MAX_FRAME_SIZE,
                                        v_ieee_802_3_max_frame_size);
        if (v_mud_url)
            nm_g_variant_builder_add_sv(&builder, NM_LLDP_ATTR_MUD_URL, v_mud_url);
    }

    return (neigh->variant = g_variant_ref_sink(g_variant_builder_end(&builder)));
}

/*****************************************************************************/

GVariant *
nmtst_lldp_parse_from_raw(const guint8 *raw_data, gsize raw_len)
{
    nm_auto(nm_lldp_neighbor_unrefp) NMLldpNeighbor *neighbor_nm = NULL;
    nm_auto(lldp_neighbor_freep) LldpNeighbor       *neigh       = NULL;
    GVariant                                        *variant;

    g_assert(raw_data);
    g_assert(raw_len > 0);

    neighbor_nm = nm_lldp_neighbor_new_from_raw(raw_data, raw_len);
    g_assert(neighbor_nm);

    neigh = lldp_neighbor_new(neighbor_nm);
    g_assert(neigh);

    variant = lldp_neighbor_to_variant(neigh);
    g_assert(variant);

    return g_variant_ref(variant);
}

/*****************************************************************************/

static void
data_changed_notify(NMLldpListener *self)
{
    nm_clear_g_variant(&self->variant);

    self->notify_callback(self, self->notify_user_data);
}

static gboolean
data_changed_timeout(gpointer user_data)
{
    NMLldpListener *self = user_data;

    nm_clear_g_source_inst(&self->ratelimit_source);
    self->ratelimit_next_nsec = nm_utils_get_monotonic_timestamp_nsec() + MIN_UPDATE_INTERVAL_NSEC;
    data_changed_notify(self);
    return G_SOURCE_CONTINUE;
}

static void
data_changed_schedule(NMLldpListener *self)
{
    gint64 now_nsec;

    if (self->ratelimit_source)
        return;

    now_nsec = nm_utils_get_monotonic_timestamp_nsec();
    if (now_nsec < self->ratelimit_next_nsec) {
        self->ratelimit_source = nm_g_timeout_source_new(
            NM_UTILS_NSEC_TO_MSEC_CEIL(self->ratelimit_next_nsec - now_nsec),
            G_PRIORITY_LOW,
            data_changed_timeout,
            self,
            NULL);
    } else {
        self->ratelimit_source =
            nm_g_idle_source_new(G_PRIORITY_LOW, data_changed_timeout, self, NULL);
    }

    g_source_attach(self->ratelimit_source, NULL);
}

static void
process_lldp_neighbor(NMLldpListener *self, NMLldpNeighbor *neighbor_nm, gboolean remove)
{
    nm_auto(lldp_neighbor_freep) LldpNeighbor *neigh = NULL;
    LldpNeighbor                              *neigh_old;

    nm_assert(self);
    nm_assert(self->lldp_rx);
    nm_assert(self->lldp_neighbors);

    g_return_if_fail(neighbor_nm);

    neigh = lldp_neighbor_new(neighbor_nm);
    if (!neigh) {
        _LOGT("process: failed to parse neighbor");
        return;
    }

    neigh_old = g_hash_table_lookup(self->lldp_neighbors, neigh);

    if (remove) {
        if (neigh_old) {
            _LOGT("process: %s neigh: " LOG_NEIGH_FMT, "remove", LOG_NEIGH_ARG(neigh));

            g_hash_table_remove(self->lldp_neighbors, neigh_old);
            goto handle_changed;
        }
        return;
    }

    if (neigh_old && lldp_neighbor_equal(neigh_old, neigh))
        return;

    _LOGD("process: %s neigh: " LOG_NEIGH_FMT, neigh_old ? "update" : "new", LOG_NEIGH_ARG(neigh));

    g_hash_table_add(self->lldp_neighbors, g_steal_pointer(&neigh));

handle_changed:
    data_changed_schedule(self);
}

static void
lldp_event_handler(NMLldpRX *lldp, NMLldpRXEvent event, NMLldpNeighbor *n, void *user_data)
{
    NMLldpListener *self = user_data;

    _LOGD("event: %s", nm_lldp_rx_event_to_string(event));
    process_lldp_neighbor(self,
                          n,
                          !NM_IN_SET(event,
                                     NM_LLDP_RX_EVENT_ADDED,
                                     NM_LLDP_RX_EVENT_UPDATED,
                                     NM_LLDP_RX_EVENT_REFRESHED));
}

/*****************************************************************************/

int
nm_lldp_listener_get_ifindex(NMLldpListener *self)
{
    g_return_val_if_fail(self, 0);

    return self->ifindex;
}

/*****************************************************************************/

GVariant *
nm_lldp_listener_get_neighbors(NMLldpListener *self)
{
    g_return_val_if_fail(self, FALSE);

    if (G_UNLIKELY(!self->variant)) {
        gs_free LldpNeighbor **neighbors = NULL;
        GVariantBuilder        array_builder;
        guint                  i, n;

        g_variant_builder_init(&array_builder, G_VARIANT_TYPE("aa{sv}"));
        neighbors = (LldpNeighbor **)
            nm_utils_hash_keys_to_array(self->lldp_neighbors, lldp_neighbor_id_cmp_p, NULL, &n);
        for (i = 0; i < n; i++)
            g_variant_builder_add_value(&array_builder, lldp_neighbor_to_variant(neighbors[i]));
        self->variant = g_variant_ref_sink(g_variant_builder_end(&array_builder));
    }

    return self->variant;
}

/*****************************************************************************/

NMLldpListener *
nm_lldp_listener_new(int                  ifindex,
                     NMLldpListenerNotify notify_callback,
                     gpointer             notify_user_data,
                     GError             **error)
{
    NMLldpListener                      *self    = NULL;
    nm_auto(nm_lldp_rx_unrefp) NMLldpRX *lldp_rx = NULL;
    int                                  r;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);
    g_return_val_if_fail(notify_callback, FALSE);

    self  = g_slice_new(NMLldpListener);
    *self = (NMLldpListener){
        .ifindex          = ifindex,
        .notify_callback  = notify_callback,
        .notify_user_data = notify_user_data,
    };

    nm_assert(nm_g_main_context_is_thread_default(g_main_context_default()));

    lldp_rx = nm_lldp_rx_new(&((NMLldpRXConfig){
        .ifindex       = ifindex,
        .neighbors_max = MAX_NEIGHBORS,
        .callback      = lldp_event_handler,
        .userdata      = self,
    }));

    r = nm_lldp_rx_start(lldp_rx);
    if (r < 0) {
        g_set_error_literal(error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED, "start failed");
        goto fail;
    }

    self->lldp_neighbors = g_hash_table_new_full((GHashFunc) lldp_neighbor_id_hash,
                                                 (GEqualFunc) lldp_neighbor_id_equal,
                                                 (GDestroyNotify) lldp_neighbor_free,
                                                 NULL);

    self->lldp_rx = g_steal_pointer(&lldp_rx);

    _LOGD("start lldp listener");
    return self;

fail:
    nm_g_slice_free(self);
    return NULL;
}

void
nm_lldp_listener_destroy(NMLldpListener *self)
{
    g_return_if_fail(self);

    nm_lldp_rx_stop(self->lldp_rx);
    nm_lldp_rx_unref(self->lldp_rx);

    nm_clear_g_source_inst(&self->ratelimit_source);

    g_hash_table_destroy(self->lldp_neighbors);

    nm_g_variant_unref(self->variant);

    _LOGT("lldp listener destroyed");

    nm_g_slice_free(self);
}
