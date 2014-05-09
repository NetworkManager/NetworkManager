/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Ray Strode <rstrode@redhat.com>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 - 2013 Red Hat, Inc.
 */

#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <glib.h>

#include "nm-connection.h"
#include "nm-utils-enum-types.h"

G_BEGIN_DECLS

/* init, deinit nm_utils */
gboolean nm_utils_init (GError **error);
void     nm_utils_deinit (void);

/* SSID helpers */
gboolean    nm_utils_is_empty_ssid (const guint8 *ssid, int len);
const char *nm_utils_escape_ssid   (const guint8 *ssid, guint32 len);
gboolean    nm_utils_same_ssid     (const GByteArray *ssid1,
                                    const GByteArray *ssid2,
                                    gboolean ignore_trailing_null);
char *      nm_utils_ssid_to_utf8  (const GByteArray *ssid);

GHashTable *nm_utils_gvalue_hash_dup  (GHashTable *hash);

NM_DEPRECATED_IN_0_9_10
void        nm_utils_slist_free    (GSList *list, GDestroyNotify elem_destroy_fn);

/**
 * NMUtilsSecurityType:
 * @NMU_SEC_INVALID: unknown or invalid security, placeholder and not used
 * @NMU_SEC_NONE: unencrypted and open
 * @NMU_SEC_STATIC_WEP: static WEP keys are used for encryption
 * @NMU_SEC_LEAP: Cisco LEAP is used for authentication and for generating the
 * dynamic WEP keys automatically
 * @NMU_SEC_DYNAMIC_WEP: standard 802.1x is used for authentication and
 * generating the dynamic WEP keys automatically
 * @NMU_SEC_WPA_PSK: WPA1 is used with Pre-Shared Keys (PSK)
 * @NMU_SEC_WPA_ENTERPRISE: WPA1 is used with 802.1x authentication
 * @NMU_SEC_WPA2_PSK: WPA2/RSN is used with Pre-Shared Keys (PSK)
 * @NMU_SEC_WPA2_ENTERPRISE: WPA2 is used with 802.1x authentication
 *
 * Describes generic security mechanisms that 802.11 access points may offer.
 * Used with nm_utils_security_valid() for checking whether a given access
 * point is compatible with a network device.
 **/
typedef enum {
	NMU_SEC_INVALID = 0,
	NMU_SEC_NONE,
	NMU_SEC_STATIC_WEP,
	NMU_SEC_LEAP,
	NMU_SEC_DYNAMIC_WEP,
	NMU_SEC_WPA_PSK,
	NMU_SEC_WPA_ENTERPRISE,
	NMU_SEC_WPA2_PSK,
	NMU_SEC_WPA2_ENTERPRISE
} NMUtilsSecurityType;

gboolean nm_utils_security_valid (NMUtilsSecurityType type,
                                  NMDeviceWifiCapabilities wifi_caps,
                                  gboolean have_ap,
                                  gboolean adhoc,
                                  NM80211ApFlags ap_flags,
                                  NM80211ApSecurityFlags ap_wpa,
                                  NM80211ApSecurityFlags ap_rsn);

gboolean nm_utils_ap_mode_security_valid (NMUtilsSecurityType type,
                                          NMDeviceWifiCapabilities wifi_caps);

gboolean nm_utils_wep_key_valid (const char *key, NMWepKeyType wep_type);
gboolean nm_utils_wpa_psk_valid (const char *psk);

GSList *nm_utils_ip4_addresses_from_gvalue (const GValue *value);
void nm_utils_ip4_addresses_to_gvalue (GSList *list, GValue *value);

GSList *nm_utils_ip4_routes_from_gvalue (const GValue *value);
void nm_utils_ip4_routes_to_gvalue (GSList *list, GValue *value);

guint32 nm_utils_ip4_netmask_to_prefix (guint32 netmask);
guint32 nm_utils_ip4_prefix_to_netmask (guint32 prefix);
guint32 nm_utils_ip4_get_default_prefix (guint32 ip);

GSList *nm_utils_ip6_addresses_from_gvalue (const GValue *value);
void nm_utils_ip6_addresses_to_gvalue (GSList *list, GValue *value);

GSList *nm_utils_ip6_routes_from_gvalue (const GValue *value);
void nm_utils_ip6_routes_to_gvalue (GSList *list, GValue *value);

GSList *nm_utils_ip6_dns_from_gvalue (const GValue *value);
void nm_utils_ip6_dns_to_gvalue (GSList *list, GValue *value);

char *nm_utils_uuid_generate (void);
char *nm_utils_uuid_generate_from_string (const char *s);

GByteArray *nm_utils_rsa_key_encrypt (const GByteArray *data,
                                      const char *in_password,
                                      char **out_password,
                                      GError **error);
GByteArray *nm_utils_rsa_key_encrypt_aes (const GByteArray *data,
                                          const char *in_password,
                                          char **out_password,
                                          GError **error);
gboolean nm_utils_file_is_pkcs12 (const char *filename);

guint32 nm_utils_wifi_freq_to_channel (guint32 freq);
guint32 nm_utils_wifi_channel_to_freq (guint32 channel, const char *band);
guint32 nm_utils_wifi_find_next_channel (guint32 channel, int direction, char *band);
gboolean nm_utils_wifi_is_channel_valid (guint32 channel, const char *band);

/**
 * NM_UTILS_HWADDR_LEN_MAX:
 *
 * The maximum length of a hardware address of a type known by
 * nm_utils_hwaddr_len() or nm_utils_hwaddr_aton(). This can be used
 * as the size of the buffer passed to nm_utils_hwaddr_aton().
 */
#define NM_UTILS_HWADDR_LEN_MAX 20 /* INFINIBAND_ALEN */

int         nm_utils_hwaddr_len   (int type) G_GNUC_PURE;
NM_DEPRECATED_IN_0_9_10
int         nm_utils_hwaddr_type  (int len) G_GNUC_PURE;
char       *nm_utils_hwaddr_ntoa  (gconstpointer addr, int type);
GByteArray *nm_utils_hwaddr_atoba (const char *asc, int type);
guint8     *nm_utils_hwaddr_aton  (const char *asc, int type, gpointer buffer);

NM_AVAILABLE_IN_0_9_10
char       *nm_utils_hwaddr_ntoa_len  (gconstpointer addr, gsize length);
NM_AVAILABLE_IN_0_9_10
guint8     *nm_utils_hwaddr_aton_len  (const char *asc, gpointer buffer, gsize length);

NM_AVAILABLE_IN_0_9_10
gboolean    nm_utils_hwaddr_valid (const char *asc);

NM_AVAILABLE_IN_0_9_10
char *nm_utils_bin2hexstr (const char *bytes, int len, int final_len);
NM_AVAILABLE_IN_0_9_10
int   nm_utils_hex2byte   (const char *hex);
NM_AVAILABLE_IN_0_9_10
char *nm_utils_hexstr2bin (const char *hex, size_t len);

gboolean    nm_utils_iface_valid_name(const char *name);

gboolean nm_utils_is_uuid (const char *str);

/**
 * NM_UTILS_INET_ADDRSTRLEN:
 *
 * Defines the minimal length for a char buffer that is suitable as @dst argument
 * for both nm_utils_inet4_ntop() and nm_utils_inet6_ntop().
 **/
#define NM_UTILS_INET_ADDRSTRLEN     INET6_ADDRSTRLEN
NM_AVAILABLE_IN_0_9_10
const char *nm_utils_inet4_ntop (in_addr_t inaddr, char *dst);
NM_AVAILABLE_IN_0_9_10
const char *nm_utils_inet6_ntop (const struct in6_addr *in6addr, char *dst);

NM_AVAILABLE_IN_0_9_10
gboolean nm_utils_check_virtual_device_compatibility (GType virtual_type, GType other_type);

G_END_DECLS

#endif /* NM_UTILS_H */
