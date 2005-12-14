/*
 * wpa_supplicant - WPA definitions
 * Copyright (c) 2003-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this file may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef WPA_H
#define WPA_H

#include <stdint.h>

#define WPA_GENERIC_INFO_ELEM 0xdd
#define WPA_RSN_INFO_ELEM 0x30

#define WPA_MAX_IE_LEN 40

typedef struct wpa_ie_data {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
	int num_pmkid;
	const uint8_t *pmkid;
} wpa_ie_data;


wpa_ie_data * wpa_parse_wpa_ie (const uint8_t *wpa_ie, size_t wpa_ie_len);

#endif /* WPA_H */
