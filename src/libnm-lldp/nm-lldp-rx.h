/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef __NM_LLDP_RX_H__
#define __NM_LLDP_RX_H__

#include "nm-lldp.h"

typedef struct _NMLldpRX       NMLldpRX;
typedef struct _NMLldpNeighbor NMLldpNeighbor;

typedef enum {
    NM_LLDP_RX_EVENT_ADDED,
    NM_LLDP_RX_EVENT_REMOVED,
    NM_LLDP_RX_EVENT_UPDATED,
    NM_LLDP_RX_EVENT_REFRESHED,
    _NM_LLDP_RX_EVENT_MAX,
    _NM_LLDP_RX_EVENT_INVALID = -EINVAL,
} NMLldpRXEvent;

const char *nm_lldp_rx_event_to_string(NMLldpRXEvent e) _nm_pure;

typedef struct {
    /* The spec calls this an "MSAP identifier" */
    const void *chassis_id;
    size_t      chassis_id_size;

    const void *port_id;
    size_t      port_id_size;
} NMLldpNeighborID;

guint    nm_lldp_neighbor_id_hash(const NMLldpNeighborID *id);
int      nm_lldp_neighbor_id_cmp(const NMLldpNeighborID *x, const NMLldpNeighborID *y);
gboolean nm_lldp_neighbor_id_equal(const NMLldpNeighborID *x, const NMLldpNeighborID *y);

typedef void (*NMLldpRXCallback)(NMLldpRX       *lldp_rx,
                                 NMLldpRXEvent   event,
                                 NMLldpNeighbor *n,
                                 void           *userdata);

typedef struct {
    int              ifindex;
    guint            neighbors_max;
    const char      *log_ifname;
    const char      *log_uuid;
    NMLldpRXCallback callback;
    void            *userdata;

    /* In order to deal nicely with bridges that send back our own packets, allow one address to be filtered, so
     * that our own can be filtered out here. */
    NMEtherAddr filter_address;

    uint16_t capability_mask;
    bool     has_capability_mask : 1;
} NMLldpRXConfig;

NMLldpRX *nm_lldp_rx_new(const NMLldpRXConfig *config);
NMLldpRX *nm_lldp_rx_ref(NMLldpRX *lldp_rx);
void      nm_lldp_rx_unref(NMLldpRX *lldp_rx);

NM_AUTO_DEFINE_FCN(NMLldpRX *, nm_lldp_rx_unrefp, nm_lldp_rx_unref);

int      nm_lldp_rx_start(NMLldpRX *lldp_rx);
int      nm_lldp_rx_stop(NMLldpRX *lldp_rx);
gboolean nm_lldp_rx_is_running(NMLldpRX *lldp_rx);

/* Controls how much and what to store in the neighbors database */

NMLldpNeighbor **nm_lldp_rx_get_neighbors(NMLldpRX *lldp_rx, guint *out_len);

/*****************************************************************************/

NMLldpNeighbor *nm_lldp_neighbor_new_from_raw(const void *raw, size_t raw_size);

NMLldpNeighbor *nm_lldp_neighbor_ref(NMLldpNeighbor *n);
NMLldpNeighbor *nm_lldp_neighbor_unref(NMLldpNeighbor *n);

NM_AUTO_DEFINE_FCN(NMLldpNeighbor *, nm_lldp_neighbor_unrefp, nm_lldp_neighbor_unref);

int nm_lldp_neighbor_cmp(const NMLldpNeighbor *a, const NMLldpNeighbor *b);

static inline gboolean
nm_lldp_neighbor_equal(const NMLldpNeighbor *a, const NMLldpNeighbor *b)
{
    return nm_lldp_neighbor_cmp(a, b) == 0;
}

/*****************************************************************************/

static inline const NMLldpNeighborID *
nm_lldp_neighbor_get_id(NMLldpNeighbor *lldp_neigbor)
{
    return (const NMLldpNeighborID *) ((gconstpointer) lldp_neigbor);
}

/* Access to LLDP frame metadata */
int nm_lldp_neighbor_get_source_address(NMLldpNeighbor *n, NMEtherAddr *address);
int nm_lldp_neighbor_get_destination_address(NMLldpNeighbor *n, NMEtherAddr *address);
int nm_lldp_neighbor_get_timestamp_usec(NMLldpNeighbor *n, gint64 *out_usec);
int nm_lldp_neighbor_get_raw(NMLldpNeighbor *n, const void **ret, size_t *size);

/* High-level, direct, parsed out field access. These fields exist at most once, hence may be queried directly. */
int
nm_lldp_neighbor_get_chassis_id(NMLldpNeighbor *n, uint8_t *type, const void **ret, size_t *size);
const char *nm_lldp_neighbor_get_chassis_id_as_string(NMLldpNeighbor *n);
int nm_lldp_neighbor_get_port_id(NMLldpNeighbor *n, uint8_t *type, const void **ret, size_t *size);
const char *nm_lldp_neighbor_get_port_id_as_string(NMLldpNeighbor *n);
int         nm_lldp_neighbor_get_ttl(NMLldpNeighbor *n, uint16_t *ret_sec);
int         nm_lldp_neighbor_get_system_name(NMLldpNeighbor *n, const char **ret);
int         nm_lldp_neighbor_get_system_description(NMLldpNeighbor *n, const char **ret);
int         nm_lldp_neighbor_get_port_description(NMLldpNeighbor *n, const char **ret);
int         nm_lldp_neighbor_get_mud_url(NMLldpNeighbor *n, const char **ret);
int         nm_lldp_neighbor_get_system_capabilities(NMLldpNeighbor *n, uint16_t *ret);
int         nm_lldp_neighbor_get_enabled_capabilities(NMLldpNeighbor *n, uint16_t *ret);

/* Low-level, iterative TLV access. This is for everything else, it iteratively goes through all available TLVs
 * (including the ones covered with the calls above), and allows multiple TLVs for the same fields. */
int nm_lldp_neighbor_tlv_rewind(NMLldpNeighbor *n);
int nm_lldp_neighbor_tlv_next(NMLldpNeighbor *n);
int nm_lldp_neighbor_tlv_get_type(NMLldpNeighbor *n, uint8_t *type);
int nm_lldp_neighbor_tlv_is_type(NMLldpNeighbor *n, uint8_t type);
int nm_lldp_neighbor_tlv_get_oui(NMLldpNeighbor *n, uint8_t oui[static 3], uint8_t *subtype);
int nm_lldp_neighbor_tlv_is_oui(NMLldpNeighbor *n, const uint8_t oui[static 3], uint8_t subtype);
int nm_lldp_neighbor_tlv_get_raw(NMLldpNeighbor *n, const void **ret, size_t *size);

#endif /* __NM_LLDP_RX_H__ */
