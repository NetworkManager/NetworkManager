/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if_infiniband.h>
#include <net/ethernet.h>
#include <stdbool.h>

#include "hash-funcs.h"

/* This is MAX_ADDR_LEN as defined in linux/netdevice.h, but net/if_arp.h
 * defines a macro of the same name with a much lower size. */
#define HW_ADDR_MAX_SIZE 32

struct hw_addr_data {
        size_t length;
        union {
                struct ether_addr ether;
                uint8_t infiniband[INFINIBAND_ALEN];
                uint8_t bytes[HW_ADDR_MAX_SIZE];
        };
};

#define HW_ADDR_TO_STRING_MAX (3*HW_ADDR_MAX_SIZE)
char* hw_addr_to_string(const struct hw_addr_data *addr, char buffer[HW_ADDR_TO_STRING_MAX]);

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define HW_ADDR_TO_STR(hw_addr) hw_addr_to_string((hw_addr), (char[HW_ADDR_TO_STRING_MAX]){})

#define HW_ADDR_NULL ((const struct hw_addr_data){})

int hw_addr_compare(const struct hw_addr_data *a, const struct hw_addr_data *b);
static inline bool hw_addr_equal(const struct hw_addr_data *a, const struct hw_addr_data *b) {
        return hw_addr_compare(a, b) == 0;
}
static inline bool hw_addr_is_null(const struct hw_addr_data *addr) {
        return hw_addr_equal(addr, &HW_ADDR_NULL);
}

extern const struct hash_ops hw_addr_hash_ops;

#define ETHER_ADDR_FORMAT_STR "%02X%02X%02X%02X%02X%02X"
#define ETHER_ADDR_FORMAT_VAL(x) (x).ether_addr_octet[0], (x).ether_addr_octet[1], (x).ether_addr_octet[2], (x).ether_addr_octet[3], (x).ether_addr_octet[4], (x).ether_addr_octet[5]

#define ETHER_ADDR_TO_STRING_MAX (3*6)
char* ether_addr_to_string(const struct ether_addr *addr, char buffer[ETHER_ADDR_TO_STRING_MAX]);
int ether_addr_to_string_alloc(const struct ether_addr *addr, char **ret);
/* Use only as function argument, never stand-alone! */
#define ETHER_ADDR_TO_STR(addr) ether_addr_to_string((addr), (char[ETHER_ADDR_TO_STRING_MAX]){})

int ether_addr_compare(const struct ether_addr *a, const struct ether_addr *b);
static inline bool ether_addr_equal(const struct ether_addr *a, const struct ether_addr *b) {
        return ether_addr_compare(a, b) == 0;
}

#define ETHER_ADDR_NULL ((const struct ether_addr){})

static inline bool ether_addr_is_null(const struct ether_addr *addr) {
        return ether_addr_equal(addr, &ETHER_ADDR_NULL);
}

int ether_addr_from_string(const char *s, struct ether_addr *ret);

extern const struct hash_ops ether_addr_hash_ops;
