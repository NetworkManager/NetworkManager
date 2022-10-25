/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-lldp-neighbor.h"

#include <net/ethernet.h>

#include "libnm-std-aux/unaligned.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "nm-lldp-network.h"
#include "nm-lldp.h"
#include "nm-lldp-rx-internal.h"

/*****************************************************************************/

guint
nm_lldp_neighbor_id_hash(const NMLldpNeighborID *id)
{
    NMHashState h;

    nm_assert(id);

    nm_hash_init(&h, 1925469911u);
    nm_hash_update_mem(&h, id->chassis_id, id->chassis_id_size);
    nm_hash_update_mem(&h, id->port_id, id->port_id_size);
    return nm_hash_complete(&h);
}

int
nm_lldp_neighbor_id_cmp(const NMLldpNeighborID *x, const NMLldpNeighborID *y)
{
    nm_assert(x);
    nm_assert(y);

    NM_CMP_SELF(x, y);
    NM_CMP_RETURN_DIRECT(
        nm_memcmp_n(x->chassis_id, x->chassis_id_size, y->chassis_id, y->chassis_id_size, 1));
    NM_CMP_RETURN_DIRECT(nm_memcmp_n(x->port_id, x->port_id_size, y->port_id, y->port_id_size, 1));
    return 0;
}

gboolean
nm_lldp_neighbor_id_equal(const NMLldpNeighborID *x, const NMLldpNeighborID *y)
{
    return nm_lldp_neighbor_id_cmp(x, y) == 0;
}

int
nm_lldp_neighbor_prioq_compare_func(const void *a, const void *b)
{
    const NMLldpNeighbor *x = a;
    const NMLldpNeighbor *y = b;

    nm_assert(x);
    nm_assert(y);

    NM_CMP_FIELD(x, y, until_usec);
    return 0;
}

static int
parse_string(NMLldpRX *lldp_rx, char **s, const void *q, size_t n)
{
    const char *p = q;
    char       *k;

    nm_assert(s);
    nm_assert(p || n == 0);

    if (*s) {
        _LOG2D(lldp_rx, "Found duplicate string, ignoring field.");
        return 0;
    }

    /* Strip trailing NULs, just to be nice */
    while (n > 0 && p[n - 1] == 0)
        n--;

    if (n <= 0) /* Ignore empty strings */
        return 0;

    /* Look for inner NULs */
    if (memchr(p, 0, n)) {
        _LOG2D(lldp_rx, "Found inner NUL in string, ignoring field.");
        return 0;
    }

    /* Let's escape weird chars, for security reasons */
    k = nm_utils_buf_utf8safe_escape_cp(p,
                                        n,
                                        NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
                                            | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII);

    g_free(*s);
    *s = k;

    return 1;
}

int
nm_lldp_neighbor_parse(NMLldpNeighbor *n)
{
    struct ether_header h;
    const uint8_t      *p;
    size_t              left;
    int                 r;

    nm_assert(n);

    if (n->raw_size < sizeof(struct ether_header)) {
        _LOG2D(n->lldp_rx, "Received truncated packet, ignoring.");
        return -NME_UNSPEC;
    }

    memcpy(&h, NM_LLDP_NEIGHBOR_RAW(n), sizeof(h));

    if (h.ether_type != htobe16(NM_ETHERTYPE_LLDP)) {
        _LOG2D(n->lldp_rx, "Received packet with wrong type, ignoring.");
        return -NME_UNSPEC;
    }

    if (h.ether_dhost[0] != 0x01 || h.ether_dhost[1] != 0x80 || h.ether_dhost[2] != 0xc2
        || h.ether_dhost[3] != 0x00 || h.ether_dhost[4] != 0x00
        || !NM_IN_SET(h.ether_dhost[5], 0x00, 0x03, 0x0e)) {
        _LOG2D(n->lldp_rx, "Received packet with wrong destination address, ignoring.");
        return -NME_UNSPEC;
    }

    memcpy(&n->source_address, h.ether_shost, sizeof(NMEtherAddr));
    memcpy(&n->destination_address, h.ether_dhost, sizeof(NMEtherAddr));

    p    = (const uint8_t *) NM_LLDP_NEIGHBOR_RAW(n) + sizeof(struct ether_header);
    left = n->raw_size - sizeof(struct ether_header);

    for (;;) {
        uint8_t  type;
        uint16_t length;

        if (left < 2) {
            _LOG2D(n->lldp_rx, "TLV lacks header, ignoring.");
            return -NME_UNSPEC;
        }

        type   = p[0] >> 1;
        length = p[1] + (((uint16_t) (p[0] & 1)) << 8);
        p += 2, left -= 2;

        if (left < length) {
            _LOG2D(n->lldp_rx, "TLV truncated, ignoring datagram.");
            return -NME_UNSPEC;
        }

        switch (type) {
        case NM_LLDP_TYPE_END:
            if (length != 0) {
                _LOG2D(n->lldp_rx, "End marker TLV not zero-sized, ignoring datagram.");
                return -NME_UNSPEC;
            }

            /* Note that after processing the NM_LLDP_TYPE_END left could still be > 0
             * as the message may contain padding (see IEEE 802.1AB-2016, sec. 8.5.12) */

            goto end_marker;

        case NM_LLDP_TYPE_CHASSIS_ID:
            if (length < 2 || length > 256) {
                /* includes the chassis subtype, hence one extra byte */
                _LOG2D(n->lldp_rx, "Chassis ID field size out of range, ignoring datagram.");
                return -NME_UNSPEC;
            }

            if (n->id.chassis_id) {
                _LOG2D(n->lldp_rx, "Duplicate chassis ID field, ignoring datagram.");
                return -NME_UNSPEC;
            }

            n->id.chassis_id      = nm_memdup(p, length);
            n->id.chassis_id_size = length;
            break;

        case NM_LLDP_TYPE_PORT_ID:
            if (length < 2 || length > 256) {
                /* includes the port subtype, hence one extra byte */
                _LOG2D(n->lldp_rx, "Port ID field size out of range, ignoring datagram.");
                return -NME_UNSPEC;
            }

            if (n->id.port_id) {
                _LOG2D(n->lldp_rx, "Duplicate port ID field, ignoring datagram.");
                return -NME_UNSPEC;
            }

            n->id.port_id      = nm_memdup(p, length);
            n->id.port_id_size = length;
            break;

        case NM_LLDP_TYPE_TTL:
            if (length != 2) {
                _LOG2D(n->lldp_rx, "TTL field has wrong size, ignoring datagram.");
                return -NME_UNSPEC;
            }

            if (n->has_ttl) {
                _LOG2D(n->lldp_rx, "Duplicate TTL field, ignoring datagram.");
                return -NME_UNSPEC;
            }

            n->ttl     = unaligned_read_be16(p);
            n->has_ttl = true;
            break;

        case NM_LLDP_TYPE_PORT_DESCRIPTION:
            r = parse_string(n->lldp_rx, &n->port_description, p, length);
            if (r < 0)
                return r;
            break;

        case NM_LLDP_TYPE_SYSTEM_NAME:
            r = parse_string(n->lldp_rx, &n->system_name, p, length);
            if (r < 0)
                return r;
            break;

        case NM_LLDP_TYPE_SYSTEM_DESCRIPTION:
            r = parse_string(n->lldp_rx, &n->system_description, p, length);
            if (r < 0)
                return r;
            break;

        case NM_LLDP_TYPE_SYSTEM_CAPABILITIES:
            if (length != 4) {
                _LOG2D(n->lldp_rx, "System capabilities field has wrong size.");
                return -NME_UNSPEC;
            }

            n->system_capabilities  = unaligned_read_be16(p);
            n->enabled_capabilities = unaligned_read_be16(p + 2);
            n->has_capabilities     = true;
            break;

        case NM_LLDP_TYPE_PRIVATE:
            if (length < 4) {
                _LOG2D(n->lldp_rx, "Found private TLV that is too short, ignoring.");
                return -NME_UNSPEC;
            }

            /* RFC 8520: MUD URL */
            if (memcmp(p, NM_LLDP_OUI_IANA_MUD, sizeof(NM_LLDP_OUI_IANA_MUD)) == 0) {
                r = parse_string(n->lldp_rx,
                                 &n->mud_url,
                                 p + sizeof(NM_LLDP_OUI_IANA_MUD),
                                 length - sizeof(NM_LLDP_OUI_IANA_MUD));
                if (r < 0)
                    return r;
            }
            break;
        }

        p += length, left -= length;
    }

end_marker:
    if (!n->id.chassis_id || !n->id.port_id || !n->has_ttl) {
        _LOG2D(n->lldp_rx, "One or more mandatory TLV missing in datagram. Ignoring.");
        return -NME_UNSPEC;
    }

    n->rindex = sizeof(struct ether_header);

    return 0;
}

void
nm_lldp_neighbor_start_ttl(NMLldpNeighbor *n)
{
    nm_assert(n);

    if (n->ttl > 0) {
        /* Use the packet's timestamp if there is one known */
        if (n->timestamp_usec <= 0) {
            /* Otherwise, take the current time */
            n->timestamp_usec = nm_utils_get_monotonic_timestamp_usec();
        }

        n->until_usec = n->timestamp_usec + (n->ttl * NM_UTILS_USEC_PER_SEC);
    } else
        n->until_usec = 0;

    if (n->lldp_rx)
        nm_prioq_reshuffle(&n->lldp_rx->neighbor_by_expiry, n, &n->prioq_idx);
}

int
nm_lldp_neighbor_cmp(const NMLldpNeighbor *a, const NMLldpNeighbor *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, raw_size);
    NM_CMP_DIRECT_MEMCMP(NM_LLDP_NEIGHBOR_RAW(a), NM_LLDP_NEIGHBOR_RAW(b), a->raw_size);
    return 0;
}

int
nm_lldp_neighbor_get_source_address(NMLldpNeighbor *n, NMEtherAddr *address)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(address, -EINVAL);

    *address = n->source_address;
    return 0;
}

int
nm_lldp_neighbor_get_destination_address(NMLldpNeighbor *n, NMEtherAddr *address)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(address, -EINVAL);

    *address = n->destination_address;
    return 0;
}

int
nm_lldp_neighbor_get_raw(NMLldpNeighbor *n, const void **ret, size_t *size)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);
    g_return_val_if_fail(size, -EINVAL);

    *ret  = NM_LLDP_NEIGHBOR_RAW(n);
    *size = n->raw_size;

    return 0;
}

int
nm_lldp_neighbor_get_chassis_id(NMLldpNeighbor *n, uint8_t *type, const void **ret, size_t *size)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(type, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);
    g_return_val_if_fail(size, -EINVAL);

    nm_assert(n->id.chassis_id_size > 0);

    *type = *(uint8_t *) n->id.chassis_id;
    *ret  = (uint8_t *) n->id.chassis_id + 1;
    *size = n->id.chassis_id_size - 1;

    return 0;
}

static char *
format_mac_address(const void *data, size_t sz)
{
    NMEtherAddr a;

    nm_assert(data || sz <= 0);

    if (sz != 7)
        return NULL;

    memcpy(&a, (uint8_t *) data + 1, sizeof(a));
    return nm_ether_addr_to_string_dup(&a);
}

static char *
format_network_address(const void *data, size_t sz)
{
    int      addr_family;
    NMIPAddr a;

    if (sz == 6 && ((uint8_t *) data)[1] == 1) {
        memcpy(&a.addr4, (uint8_t *) data + 2, sizeof(a.addr4));
        addr_family = AF_INET;
    } else if (sz == 18 && ((uint8_t *) data)[1] == 2) {
        memcpy(&a.addr6, (uint8_t *) data + 2, sizeof(a.addr6));
        addr_family = AF_INET6;
    } else
        return NULL;

    return nm_inet_ntop_dup(addr_family, &a);
}

const char *
nm_lldp_neighbor_get_chassis_id_as_string(NMLldpNeighbor *n)
{
    char *k;

    g_return_val_if_fail(n, NULL);

    if (n->chassis_id_as_string)
        return n->chassis_id_as_string;

    nm_assert(n->id.chassis_id_size > 0);

    switch (*(uint8_t *) n->id.chassis_id) {
    case NM_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
    case NM_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
    case NM_LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT:
    case NM_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
    case NM_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
        k = nm_utils_buf_utf8safe_escape_cp((char *) n->id.chassis_id + 1,
                                            n->id.chassis_id_size - 1,
                                            NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
                                                | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII);
        goto done;

    case NM_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:
        k = format_mac_address(n->id.chassis_id, n->id.chassis_id_size);
        if (k)
            goto done;
        break;

    case NM_LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS:
        k = format_network_address(n->id.chassis_id, n->id.chassis_id_size);
        if (k)
            goto done;
        break;
    }

    /* Generic fallback */
    k = nm_utils_bin2hexstr_full(n->id.chassis_id, n->id.chassis_id_size, '\0', FALSE, NULL);

done:
    nm_assert(k);
    return (n->chassis_id_as_string = k);
}

int
nm_lldp_neighbor_get_port_id(NMLldpNeighbor *n, uint8_t *type, const void **ret, size_t *size)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(type, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);
    g_return_val_if_fail(size, -EINVAL);

    nm_assert(n->id.port_id_size > 0);

    *type = *(uint8_t *) n->id.port_id;
    *ret  = (uint8_t *) n->id.port_id + 1;
    *size = n->id.port_id_size - 1;

    return 0;
}

const char *
nm_lldp_neighbor_get_port_id_as_string(NMLldpNeighbor *n)
{
    char *k;

    g_return_val_if_fail(n, NULL);

    if (n->port_id_as_string)
        return n->port_id_as_string;

    nm_assert(n->id.port_id_size > 0);

    switch (*(uint8_t *) n->id.port_id) {
    case NM_LLDP_PORT_SUBTYPE_INTERFACE_ALIAS:
    case NM_LLDP_PORT_SUBTYPE_PORT_COMPONENT:
    case NM_LLDP_PORT_SUBTYPE_INTERFACE_NAME:
    case NM_LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED:
        k = nm_utils_buf_utf8safe_escape_cp((char *) n->id.port_id + 1,
                                            n->id.port_id_size - 1,
                                            NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
                                                | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII);
        goto done;

    case NM_LLDP_PORT_SUBTYPE_MAC_ADDRESS:
        k = format_mac_address(n->id.port_id, n->id.port_id_size);
        if (k)
            goto done;
        break;

    case NM_LLDP_PORT_SUBTYPE_NETWORK_ADDRESS:
        k = format_network_address(n->id.port_id, n->id.port_id_size);
        if (k)
            goto done;
        break;
    }

    /* Generic fallback */
    k = nm_utils_bin2hexstr_full(n->id.port_id, n->id.port_id_size, '\0', FALSE, NULL);

done:
    nm_assert(k);
    return (n->port_id_as_string = k);
}

int
nm_lldp_neighbor_get_ttl(NMLldpNeighbor *n, uint16_t *ret_sec)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret_sec, -EINVAL);

    *ret_sec = n->ttl;
    return 0;
}

int
nm_lldp_neighbor_get_system_name(NMLldpNeighbor *n, const char **ret)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);

    if (!n->system_name)
        return -ENODATA;

    *ret = n->system_name;
    return 0;
}

int
nm_lldp_neighbor_get_system_description(NMLldpNeighbor *n, const char **ret)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);

    if (!n->system_description)
        return -ENODATA;

    *ret = n->system_description;
    return 0;
}

int
nm_lldp_neighbor_get_port_description(NMLldpNeighbor *n, const char **ret)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);

    if (!n->port_description)
        return -ENODATA;

    *ret = n->port_description;
    return 0;
}

int
nm_lldp_neighbor_get_mud_url(NMLldpNeighbor *n, const char **ret)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);

    if (!n->mud_url)
        return -ENODATA;

    *ret = n->mud_url;
    return 0;
}

int
nm_lldp_neighbor_get_system_capabilities(NMLldpNeighbor *n, uint16_t *ret)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);

    if (!n->has_capabilities)
        return -ENODATA;

    *ret = n->system_capabilities;
    return 0;
}

int
nm_lldp_neighbor_get_enabled_capabilities(NMLldpNeighbor *n, uint16_t *ret)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);

    if (!n->has_capabilities)
        return -ENODATA;

    *ret = n->enabled_capabilities;
    return 0;
}

int
nm_lldp_neighbor_tlv_rewind(NMLldpNeighbor *n)
{
    g_return_val_if_fail(n, -EINVAL);

    nm_assert(n->raw_size >= sizeof(struct ether_header));

    n->rindex = sizeof(struct ether_header);

    return n->rindex < n->raw_size;
}

int
nm_lldp_neighbor_tlv_next(NMLldpNeighbor *n)
{
    size_t length;

    g_return_val_if_fail(n, -EINVAL);

    if (n->rindex == n->raw_size) /* EOF */
        return -ESPIPE;

    if (n->rindex + 2 > n->raw_size) /* Truncated message */
        return -EBADMSG;

    length = NM_LLDP_NEIGHBOR_TLV_LENGTH(n);
    if (n->rindex + 2 + length > n->raw_size)
        return -EBADMSG;

    n->rindex += 2 + length;
    return n->rindex < n->raw_size;
}

int
nm_lldp_neighbor_tlv_get_type(NMLldpNeighbor *n, uint8_t *type)
{
    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(type, -EINVAL);

    if (n->rindex == n->raw_size) /* EOF */
        return -ESPIPE;

    if (n->rindex + 2 > n->raw_size)
        return -EBADMSG;

    *type = NM_LLDP_NEIGHBOR_TLV_TYPE(n);
    return 0;
}

int
nm_lldp_neighbor_tlv_is_type(NMLldpNeighbor *n, uint8_t type)
{
    uint8_t k;
    int     r;

    g_return_val_if_fail(n, -EINVAL);

    r = nm_lldp_neighbor_tlv_get_type(n, &k);
    if (r < 0)
        return r;

    return type == k;
}

int
nm_lldp_neighbor_tlv_get_oui(NMLldpNeighbor *n, uint8_t oui[static 3], uint8_t *subtype)
{
    const uint8_t *d;
    size_t         length;
    int            r;

    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(oui, -EINVAL);
    g_return_val_if_fail(subtype, -EINVAL);

    r = nm_lldp_neighbor_tlv_is_type(n, NM_LLDP_TYPE_PRIVATE);
    if (r < 0)
        return r;
    if (r == 0)
        return -ENXIO;

    length = NM_LLDP_NEIGHBOR_TLV_LENGTH(n);
    if (length < 4)
        return -EBADMSG;

    if (n->rindex + 2 + length > n->raw_size)
        return -EBADMSG;

    d = NM_LLDP_NEIGHBOR_TLV_DATA(n);
    memcpy(oui, d, 3);
    *subtype = d[3];

    return 0;
}

int
nm_lldp_neighbor_tlv_is_oui(NMLldpNeighbor *n, const uint8_t oui[static 3], uint8_t subtype)
{
    uint8_t k[3], st;
    int     r;

    r = nm_lldp_neighbor_tlv_get_oui(n, k, &st);
    if (r == -ENXIO)
        return 0;
    if (r < 0)
        return r;

    return memcmp(k, oui, 3) == 0 && st == subtype;
}

int
nm_lldp_neighbor_tlv_get_raw(NMLldpNeighbor *n, const void **ret, size_t *size)
{
    size_t length;

    g_return_val_if_fail(n, -EINVAL);
    g_return_val_if_fail(ret, -EINVAL);
    g_return_val_if_fail(size, -EINVAL);

    /* Note that this returns the full TLV, including the TLV header */

    if (n->rindex + 2 > n->raw_size)
        return -EBADMSG;

    length = NM_LLDP_NEIGHBOR_TLV_LENGTH(n);
    if (n->rindex + 2 + length > n->raw_size)
        return -EBADMSG;

    *ret  = (uint8_t *) NM_LLDP_NEIGHBOR_RAW(n) + n->rindex;
    *size = length + 2;

    return 0;
}

int
nm_lldp_neighbor_get_timestamp_usec(NMLldpNeighbor *n, gint64 *out_usec)
{
    g_return_val_if_fail(n, -EINVAL);

    if (n->timestamp_usec == 0)
        return -ENODATA;

    NM_SET_OUT(out_usec, n->timestamp_usec);
    return 0;
}

/*****************************************************************************/

NMLldpNeighbor *
nm_lldp_neighbor_new(size_t raw_size)
{
    NMLldpNeighbor *n;

    nm_assert(raw_size < SIZE_MAX - NM_ALIGN(sizeof(NMLldpNeighbor)));

    n = g_malloc0(NM_ALIGN(sizeof(NMLldpNeighbor)) + raw_size);

    n->raw_size  = raw_size;
    n->ref_count = 1;
    return n;
}

NMLldpNeighbor *
nm_lldp_neighbor_new_from_raw(const void *raw, size_t raw_size)
{
    nm_auto(nm_lldp_neighbor_unrefp) NMLldpNeighbor *n = NULL;
    int                                              r;

    g_return_val_if_fail(raw || raw_size <= 0, NULL);

    n = nm_lldp_neighbor_new(raw_size);

    nm_memcpy(NM_LLDP_NEIGHBOR_RAW(n), raw, raw_size);

    r = nm_lldp_neighbor_parse(n);
    if (r < 0)
        return NULL;

    return g_steal_pointer(&n);
}

NMLldpNeighbor *
nm_lldp_neighbor_ref(NMLldpNeighbor *n)
{
    if (!n)
        return NULL;

    nm_assert(n->ref_count > 0 || n->lldp_rx);

    n->ref_count++;
    return n;
}

static void
_lldp_neighbor_free(NMLldpNeighbor *n)
{
    if (!n)
        return;

    g_free((gpointer) n->id.port_id);
    g_free((gpointer) n->id.chassis_id);
    g_free(n->port_description);
    g_free(n->system_name);
    g_free(n->system_description);
    g_free(n->mud_url);
    g_free(n->chassis_id_as_string);
    g_free(n->port_id_as_string);
    g_free(n);
    return;
}

NMLldpNeighbor *
nm_lldp_neighbor_unref(NMLldpNeighbor *n)
{
    /* Drops one reference from the neighbor. Note that the object is not freed unless it is already unlinked from
     * the sd_lldp object. */

    if (!n)
        return NULL;

    nm_assert(n->ref_count > 0);
    n->ref_count--;

    if (n->ref_count <= 0 && !n->lldp_rx)
        _lldp_neighbor_free(n);

    return NULL;
}

void
nm_lldp_neighbor_unlink(NMLldpNeighbor *n)
{
    gpointer old_key;
    gpointer old_val;

    /* Removes the neighbor object from the LLDP object, and frees it if it also has no other reference. */

    if (!n)
        return;

    if (!n->lldp_rx)
        return;

    /* Only remove the neighbor object from the hash table if it's in there, don't complain if it isn't. This is
     * because we are used as destructor call for hashmap_clear() and thus sometimes are called to de-register
     * ourselves from the hashtable and sometimes are called after we already are de-registered. */

    if (g_hash_table_steal_extended(n->lldp_rx->neighbor_by_id, n, &old_key, &old_val)) {
        nm_assert(NM_IN_SET(old_val, NULL, old_key));
        if (old_key != n) {
            /* it wasn't the right key. Add it again. */
            g_hash_table_add(n->lldp_rx->neighbor_by_id, old_key);
        }
    }

    nm_prioq_remove(&n->lldp_rx->neighbor_by_expiry, n, &n->prioq_idx);

    n->lldp_rx = NULL;

    if (n->ref_count <= 0)
        _lldp_neighbor_free(n);

    return;
}
