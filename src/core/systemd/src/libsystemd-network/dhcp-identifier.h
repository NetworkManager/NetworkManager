/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "macro.h"
#include "sparse-endian.h"
#include "time-util.h"
#include "unaligned.h"

#define SYSTEMD_PEN    43793

typedef enum DUIDType {
        DUID_TYPE_LLT       = 1,
        DUID_TYPE_EN        = 2,
        DUID_TYPE_LL        = 3,
        DUID_TYPE_UUID      = 4,
        _DUID_TYPE_MAX,
        _DUID_TYPE_INVALID  = -EINVAL,
} DUIDType;

/* RFC 3315 section 9.1:
 *      A DUID can be no more than 128 octets long (not including the type code).
 */
#define MAX_DUID_LEN 128

/* https://tools.ietf.org/html/rfc3315#section-9.1 */
struct duid {
        be16_t type;
        union {
                struct {
                        /* DUID_TYPE_LLT */
                        be16_t htype;
                        be32_t time;
                        uint8_t haddr[0];
                } _packed_ llt;
                struct {
                        /* DUID_TYPE_EN */
                        be32_t pen;
                        uint8_t id[8];
                } _packed_ en;
                struct {
                        /* DUID_TYPE_LL */
                        be16_t htype;
                        uint8_t haddr[0];
                } _packed_ ll;
                struct {
                        /* DUID_TYPE_UUID */
                        sd_id128_t uuid;
                } _packed_ uuid;
                struct {
                        uint8_t data[MAX_DUID_LEN];
                } _packed_ raw;
        };
} _packed_;

int dhcp_validate_duid_len(uint16_t duid_type, size_t duid_len, bool strict);
int dhcp_identifier_set_duid_llt(struct duid *duid, usec_t t, const uint8_t *addr, size_t addr_len, uint16_t arp_type, size_t *len);
int dhcp_identifier_set_duid_ll(struct duid *duid, const uint8_t *addr, size_t addr_len, uint16_t arp_type, size_t *len);
int dhcp_identifier_set_duid_en(struct duid *duid, size_t *len);
int dhcp_identifier_set_duid_uuid(struct duid *duid, size_t *len);
int dhcp_identifier_set_iaid(int ifindex, const uint8_t *mac, size_t mac_len, bool legacy_unstable_byteorder, void *_id);
