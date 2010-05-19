/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * WPA Supplicant - WPA state machine and EAPOL-Key processing
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

#include "wireless-helper.h"

#include <stdint.h>
#include <string.h>
#include <glib.h>

#include "wpa.h"
#include "nm-logging.h"

typedef guint16 u16;
typedef guint8 u8;

#define WPA_GET_LE16(a) ((u16) (((a)[1] << 8) | (a)[0]))

#define BIT(n) (1 << (n))
#define WPA_CAPABILITY_PREAUTH BIT(0)

#define WPA_REPLAY_COUNTER_LEN 8
#define WPA_NONCE_LEN 32

#define PMKID_LEN 16

static const int WPA_SELECTOR_LEN = 4;
static const u8 WPA_OUI_TYPE[] = { 0x00, 0x50, 0xf2, 1 };
static const u16 WPA_VERSION = 1;
static const u8 WPA_AUTH_KEY_MGMT_NONE[] = { 0x00, 0x50, 0xf2, 0 };
static const u8 WPA_AUTH_KEY_MGMT_UNSPEC_802_1X[] = { 0x00, 0x50, 0xf2, 1 };
static const u8 WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X[] = { 0x00, 0x50, 0xf2, 2 };
static const u8 WPA_CIPHER_SUITE_NONE[] = { 0x00, 0x50, 0xf2, 0 };
static const u8 WPA_CIPHER_SUITE_WEP40[] = { 0x00, 0x50, 0xf2, 1 };
static const u8 WPA_CIPHER_SUITE_TKIP[] = { 0x00, 0x50, 0xf2, 2 };
static const u8 WPA_CIPHER_SUITE_WRAP[] = { 0x00, 0x50, 0xf2, 3 };
static const u8 WPA_CIPHER_SUITE_CCMP[] = { 0x00, 0x50, 0xf2, 4 };
static const u8 WPA_CIPHER_SUITE_WEP104[] = { 0x00, 0x50, 0xf2, 5 };

/* WPA IE version 1
 * 00-50-f2:1 (OUI:OUI type)
 * 0x01 0x00 (version; little endian)
 * (all following fields are optional:)
 * Group Suite Selector (4 octets) (default: TKIP)
 * Pairwise Suite Count (2 octets, little endian) (default: 1)
 * Pairwise Suite List (4 * n octets) (default: TKIP)
 * Authenticated Key Management Suite Count (2 octets, little endian)
 *    (default: 1)
 * Authenticated Key Management Suite List (4 * n octets)
 *    (default: unspec 802.1X)
 * WPA Capabilities (2 octets, little endian) (default: 0)
 */

struct wpa_ie_hdr {
	u8 elem_id;
	u8 len;
	u8 oui[3];
	u8 oui_type;
	u8 version[2];
} __attribute__ ((packed));


static const int RSN_SELECTOR_LEN = 4;
static const u16 RSN_VERSION = 1;
static const u8 RSN_AUTH_KEY_MGMT_UNSPEC_802_1X[] = { 0x00, 0x0f, 0xac, 1 };
static const u8 RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X[] = { 0x00, 0x0f, 0xac, 2 };
static const u8 RSN_CIPHER_SUITE_NONE[] = { 0x00, 0x0f, 0xac, 0 };
static const u8 RSN_CIPHER_SUITE_WEP40[] = { 0x00, 0x0f, 0xac, 1 };
static const u8 RSN_CIPHER_SUITE_TKIP[] = { 0x00, 0x0f, 0xac, 2 };
static const u8 RSN_CIPHER_SUITE_WRAP[] = { 0x00, 0x0f, 0xac, 3 };
static const u8 RSN_CIPHER_SUITE_CCMP[] = { 0x00, 0x0f, 0xac, 4 };
static const u8 RSN_CIPHER_SUITE_WEP104[] = { 0x00, 0x0f, 0xac, 5 };

/* EAPOL-Key Key Data Encapsulation
 * GroupKey and STAKey require encryption, otherwise, encryption is optional.
 */
static const u8 RSN_KEY_DATA_GROUPKEY[] = { 0x00, 0x0f, 0xac, 1 };
static const u8 RSN_KEY_DATA_STAKEY[] = { 0x00, 0x0f, 0xac, 2 };
static const u8 RSN_KEY_DATA_MAC_ADDR[] = { 0x00, 0x0f, 0xac, 3 };
static const u8 RSN_KEY_DATA_PMKID[] = { 0x00, 0x0f, 0xac, 4 };

/* RSN IE version 1
 * 0x01 0x00 (version; little endian)
 * (all following fields are optional:)
 * Group Suite Selector (4 octets) (default: CCMP)
 * Pairwise Suite Count (2 octets, little endian) (default: 1)
 * Pairwise Suite List (4 * n octets) (default: CCMP)
 * Authenticated Key Management Suite Count (2 octets, little endian)
 *    (default: 1)
 * Authenticated Key Management Suite List (4 * n octets)
 *    (default: unspec 802.1X)
 * RSN Capabilities (2 octets, little endian) (default: 0)
 * PMKID Count (2 octets) (default: 0)
 * PMKID List (16 * n octets)
 */

struct rsn_ie_hdr {
	u8 elem_id; /* WLAN_EID_RSN */
	u8 len;
	u8 version[2];
} __attribute__ ((packed));


#define WPA_KEY_INFO_TYPE_MASK (BIT(0) | BIT(1) | BIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 BIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES BIT(1)
#define WPA_KEY_INFO_KEY_TYPE BIT(3) /* 1 = Pairwise, 0 = Group key */
/* bit4..5 is used in WPA, but is reserved in IEEE 802.11i/RSN */
#define WPA_KEY_INFO_KEY_INDEX_MASK (BIT(4) | BIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL BIT(6) /* pairwise */
#define WPA_KEY_INFO_TXRX BIT(6) /* group */
#define WPA_KEY_INFO_ACK BIT(7)
#define WPA_KEY_INFO_MIC BIT(8)
#define WPA_KEY_INFO_SECURE BIT(9)
#define WPA_KEY_INFO_ERROR BIT(10)
#define WPA_KEY_INFO_REQUEST BIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA BIT(12) /* IEEE 802.11i/RSN only */



static int wpa_selector_to_bitfield(const u8 *s)
{
	if (memcmp(s, WPA_CIPHER_SUITE_NONE, WPA_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_NONE;
	if (memcmp(s, WPA_CIPHER_SUITE_WEP40, WPA_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_WEP40;
	if (memcmp(s, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_TKIP;
	if (memcmp(s, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_CCMP;
	if (memcmp(s, WPA_CIPHER_SUITE_WEP104, WPA_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_WEP104;
	return 0;
}


static int wpa_key_mgmt_to_bitfield(const u8 *s)
{
	if (memcmp(s, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X, WPA_SELECTOR_LEN) == 0)
		return IW_AUTH_KEY_MGMT_802_1X;
	if (memcmp(s, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X, WPA_SELECTOR_LEN) ==
	    0)
		return IW_AUTH_KEY_MGMT_PSK;
	if (memcmp(s, WPA_AUTH_KEY_MGMT_NONE, WPA_SELECTOR_LEN) == 0)
		return 0;
	return 0;
}


static int rsn_selector_to_bitfield(const u8 *s)
{
	if (memcmp(s, RSN_CIPHER_SUITE_NONE, RSN_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_NONE;
	if (memcmp(s, RSN_CIPHER_SUITE_WEP40, RSN_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_WEP40;
	if (memcmp(s, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_TKIP;
	if (memcmp(s, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_CCMP;
	if (memcmp(s, RSN_CIPHER_SUITE_WEP104, RSN_SELECTOR_LEN) == 0)
		return IW_AUTH_CIPHER_WEP104;
	return 0;
}


static int rsn_key_mgmt_to_bitfield(const u8 *s)
{
	if (memcmp(s, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X, RSN_SELECTOR_LEN) == 0)
		return IW_AUTH_KEY_MGMT_802_1X;
	if (memcmp(s, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X, RSN_SELECTOR_LEN) ==
	    0)
		return IW_AUTH_KEY_MGMT_PSK;
	return 0;
}


static int wpa_parse_wpa_ie_wpa(const u8 *wpa_ie, size_t wpa_ie_len,
				struct wpa_ie_data *data)
{
	const struct wpa_ie_hdr *hdr;
	const u8 *pos;
	int left;
	int i, count;

	data->proto = IW_AUTH_WPA_VERSION_WPA;
	data->pairwise_cipher = IW_AUTH_CIPHER_TKIP;
	data->group_cipher = IW_AUTH_CIPHER_TKIP;
	data->key_mgmt = IW_AUTH_KEY_MGMT_802_1X;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;

	if (wpa_ie_len == 0) {
		/* No WPA IE - fail silently */
		return -1;
	}

	if (wpa_ie_len < sizeof(struct wpa_ie_hdr)) {
		nm_log_dbg (LOGD_WIFI, "IE len too short %lu",
			    (unsigned long) wpa_ie_len);
		return -1;
	}

	hdr = (const struct wpa_ie_hdr *) wpa_ie;

	if (hdr->elem_id != WPA_GENERIC_INFO_ELEM ||
	    hdr->len != wpa_ie_len - 2 ||
	    memcmp(hdr->oui, WPA_OUI_TYPE, WPA_SELECTOR_LEN) != 0 ||
	    WPA_GET_LE16(hdr->version) != WPA_VERSION) {
		nm_log_dbg (LOGD_WIFI, "malformed IE or unknown version");
		return -1;
	}

	pos = (const u8 *) (hdr + 1);
	left = wpa_ie_len - sizeof(*hdr);

	if (left >= WPA_SELECTOR_LEN) {
		data->group_cipher = wpa_selector_to_bitfield(pos);
		pos += WPA_SELECTOR_LEN;
		left -= WPA_SELECTOR_LEN;
	} else if (left > 0) {
		nm_log_dbg (LOGD_WIFI, "IE length mismatch, %u too much", left);
		return -1;
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
			nm_log_dbg (LOGD_WIFI, "IE count botch (pairwise), "
			            "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= wpa_selector_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
		nm_log_dbg (LOGD_WIFI, "IE too short (for key mgmt)");
		return -1;
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
			nm_log_dbg (LOGD_WIFI, "IE count botch (key mgmt), "
				   "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= wpa_key_mgmt_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
		nm_log_dbg (LOGD_WIFI, "IE too short (for capabilities)");
		return -1;
	}

	if (left >= 2) {
		if (WPA_GET_LE16 (pos) & WPA_CAPABILITY_PREAUTH)
			data->capabilities |= IW_PMKID_CAND_PREAUTH;
		pos += 2;
		left -= 2;
	}

	if (left > 0) {
		nm_log_dbg (LOGD_WIFI, "IE has %u trailing bytes", left);
		return -1;
	}

	return 0;
}


static int wpa_parse_wpa_ie_rsn(const u8 *rsn_ie, size_t rsn_ie_len,
				struct wpa_ie_data *data)
{
	const struct rsn_ie_hdr *hdr;
	const u8 *pos;
	int left;
	int i, count;

	data->proto = IW_AUTH_WPA_VERSION_WPA2;
	data->pairwise_cipher = IW_AUTH_CIPHER_CCMP;
	data->group_cipher = IW_AUTH_CIPHER_CCMP;
	data->key_mgmt = IW_AUTH_KEY_MGMT_802_1X;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;

	if (rsn_ie_len == 0) {
		/* No RSN IE - fail silently */
		return -1;
	}

	if (rsn_ie_len < sizeof(struct rsn_ie_hdr)) {
		nm_log_dbg (LOGD_WIFI, "IE len too short %lu",
			    (unsigned long) rsn_ie_len);
		return -1;
	}

	hdr = (const struct rsn_ie_hdr *) rsn_ie;

	if (hdr->elem_id != WPA_RSN_INFO_ELEM ||
	    hdr->len != rsn_ie_len - 2 ||
	    WPA_GET_LE16(hdr->version) != RSN_VERSION) {
		nm_log_dbg (LOGD_WIFI, "malformed IE or unknown version");
		return -1;
	}

	pos = (const u8 *) (hdr + 1);
	left = rsn_ie_len - sizeof(*hdr);

	if (left >= RSN_SELECTOR_LEN) {
		data->group_cipher = rsn_selector_to_bitfield(pos);
		pos += RSN_SELECTOR_LEN;
		left -= RSN_SELECTOR_LEN;
	} else if (left > 0) {
		nm_log_dbg (LOGD_WIFI, "IE length mismatch, %u too much", left);
		return -1;
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
			nm_log_dbg (LOGD_WIFI, "IE count botch (pairwise), "
				    "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
		nm_log_dbg (LOGD_WIFI, "IE too short (for key mgmt)");
		return -1;
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
			nm_log_dbg (LOGD_WIFI, "IE count botch (key mgmt), "
				   "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= rsn_key_mgmt_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
		nm_log_dbg (LOGD_WIFI, "IE too short (for capabilities)");
		return -1;
	}

	if (left >= 2) {
		if (WPA_GET_LE16 (pos) & WPA_CAPABILITY_PREAUTH)
			data->capabilities |= IW_PMKID_CAND_PREAUTH;
		pos += 2;
		left -= 2;
	}

	if (left >= 2) {
		data->num_pmkid = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (left < data->num_pmkid * PMKID_LEN) {
			nm_log_dbg (LOGD_WIFI, "PMKID underflow "
				    "(num_pmkid=%d left=%d)",
				    data->num_pmkid, left);
			data->num_pmkid = 0;
		} else {
			data->pmkid = pos;
			pos += data->num_pmkid * PMKID_LEN;
			left -= data->num_pmkid * PMKID_LEN;
		}
	}

	if (left > 0) {
		nm_log_dbg (LOGD_WIFI, "IE has %u trailing bytes - ignored", left);
	}

	return 0;
}


/**
 * wpa_parse_wpa_ie - Parse WPA/RSN IE
 * @wpa_ie: Pointer to WPA or RSN IE
 * @wpa_ie_len: Length of the WPA/RSN IE
 * @data: Pointer to data area for parsing results
 * Returns: parsed results on success, NULL on failure
 *
 * Parse the contents of WPA or RSN IE and write the parsed data into data.
 */
wpa_ie_data * wpa_parse_wpa_ie(const u8 *wpa_ie, size_t wpa_ie_len)
{
	wpa_ie_data *data = NULL;
	int err = -1;

	if (!wpa_ie || wpa_ie_len <= 0)
		return NULL;

	data = g_slice_new0 (wpa_ie_data);

	if (wpa_ie_len >= 1 && wpa_ie[0] == WPA_RSN_INFO_ELEM)
		err = wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
	else
		err = wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, data);

	if (err != 0) {
		g_slice_free (wpa_ie_data, data);
		data = NULL;
	}

	if (data) {
		nm_log_dbg (LOGD_WIFI, "WPA IE: -------------------");
		nm_log_dbg (LOGD_WIFI, "   proto        0x%X", data->proto);
		nm_log_dbg (LOGD_WIFI, "   pw cipher    0x%X", data->pairwise_cipher);
		nm_log_dbg (LOGD_WIFI, "   gr cipher    0x%X", data->group_cipher);
		nm_log_dbg (LOGD_WIFI, "   key mgmt     0x%X", data->key_mgmt);
		nm_log_dbg (LOGD_WIFI, "   capabilities 0x%X", data->capabilities);
		nm_log_dbg (LOGD_WIFI, "   # pmkid      0x%X", data->num_pmkid);
		nm_log_dbg (LOGD_WIFI, "");
	}

	return data;
}

