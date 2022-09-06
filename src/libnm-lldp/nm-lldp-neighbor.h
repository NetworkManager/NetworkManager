/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_LLDP_NEIGHBOR_H__
#define __NM_LLDP_NEIGHBOR_H__

#include "nm-lldp-rx.h"

struct _NMLldpNeighbor {
    NMLldpNeighborID id;

    /* Neighbor objects stay around as long as they are linked into an "NMLldpRX" object or n_ref > 0. */
    struct _NMLldpRX *lldp_rx;

    gint64 timestamp_usec;

    gint64 until_usec;

    int      ref_count;
    unsigned prioq_idx;

    NMEtherAddr source_address;
    NMEtherAddr destination_address;

    /* The raw packet size. The data is appended to the object, accessible via LLDP_NEIGHBOR_RAW() */
    size_t raw_size;

    /* The current read index for the iterative TLV interface */
    size_t rindex;

    /* And a couple of fields parsed out. */
    bool has_ttl : 1;
    bool has_capabilities : 1;
    bool has_port_vlan_id : 1;

    uint16_t ttl;

    uint16_t system_capabilities;
    uint16_t enabled_capabilities;

    char *port_description;
    char *system_name;
    char *system_description;
    char *mud_url;

    uint16_t port_vlan_id;

    char *chassis_id_as_string;
    char *port_id_as_string;
};

static inline void *
NM_LLDP_NEIGHBOR_RAW(const NMLldpNeighbor *n)
{
    return (uint8_t *) n + NM_ALIGN(sizeof(NMLldpNeighbor));
}

static inline uint8_t
NM_LLDP_NEIGHBOR_TLV_TYPE(const NMLldpNeighbor *n)
{
    return ((uint8_t *) NM_LLDP_NEIGHBOR_RAW(n))[n->rindex] >> 1;
}

static inline size_t
NM_LLDP_NEIGHBOR_TLV_LENGTH(const NMLldpNeighbor *n)
{
    uint8_t *p;

    p = (uint8_t *) NM_LLDP_NEIGHBOR_RAW(n) + n->rindex;
    return p[1] + (((size_t) (p[0] & 1)) << 8);
}

static inline void *
NM_LLDP_NEIGHBOR_TLV_DATA(const NMLldpNeighbor *n)
{
    return ((uint8_t *) NM_LLDP_NEIGHBOR_RAW(n)) + n->rindex + 2;
}

int nm_lldp_neighbor_prioq_compare_func(const void *a, const void *b);

void            nm_lldp_neighbor_unlink(NMLldpNeighbor *n);
NMLldpNeighbor *nm_lldp_neighbor_new(size_t raw_size);
int             nm_lldp_neighbor_parse(NMLldpNeighbor *n);
void            nm_lldp_neighbor_start_ttl(NMLldpNeighbor *n);

#endif /* __NM_LLDP_NEIGHBOR_H__ */
