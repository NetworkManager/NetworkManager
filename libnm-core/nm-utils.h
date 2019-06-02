/*
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
 * Copyright 2005 - 2017 Red Hat, Inc.
 */

#ifndef __NM_UTILS_H__
#define __NM_UTILS_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <glib.h>

#include <netinet/in.h>

/* For ETH_ALEN and INFINIBAND_ALEN */
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "nm-core-enum-types.h"
#include "nm-setting-sriov.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-wireless-security.h"

G_BEGIN_DECLS

/*****************************************************************************/

typedef struct _NMVariantAttributeSpec NMVariantAttributeSpec;

/* SSID helpers */
gboolean    nm_utils_is_empty_ssid (const guint8 *ssid, gsize len);
const char *nm_utils_escape_ssid   (const guint8 *ssid, gsize len);
gboolean    nm_utils_same_ssid     (const guint8 *ssid1, gsize len1,
                                    const guint8 *ssid2, gsize len2,
                                    gboolean ignore_trailing_null);
char *      nm_utils_ssid_to_utf8  (const guint8 *ssid, gsize len);

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

NM_AVAILABLE_IN_1_6
gboolean nm_utils_is_json_object (const char *str, GError **error);

GVariant  *nm_utils_ip4_dns_to_variant (char **dns);
char     **nm_utils_ip4_dns_from_variant (GVariant *value);
GVariant  *nm_utils_ip4_addresses_to_variant (GPtrArray *addresses,
                                              const char *gateway);
GPtrArray *nm_utils_ip4_addresses_from_variant (GVariant *value,
                                                char **out_gateway);
GVariant  *nm_utils_ip4_routes_to_variant (GPtrArray *routes);
GPtrArray *nm_utils_ip4_routes_from_variant (GVariant *value);

guint32 nm_utils_ip4_netmask_to_prefix (guint32 netmask);
guint32 nm_utils_ip4_prefix_to_netmask (guint32 prefix);
guint32 nm_utils_ip4_get_default_prefix (guint32 ip);

GVariant  *nm_utils_ip6_dns_to_variant (char **dns);
char     **nm_utils_ip6_dns_from_variant (GVariant *value);
GVariant  *nm_utils_ip6_addresses_to_variant (GPtrArray *addresses,
                                              const char *gateway);
GPtrArray *nm_utils_ip6_addresses_from_variant (GVariant *value,
                                                char **out_gateway);
GVariant  *nm_utils_ip6_routes_to_variant (GPtrArray *routes);
GPtrArray *nm_utils_ip6_routes_from_variant (GVariant *value);

GVariant  *nm_utils_ip_addresses_to_variant (GPtrArray *addresses);
GPtrArray *nm_utils_ip_addresses_from_variant (GVariant *value,
                                               int family);
GVariant  *nm_utils_ip_routes_to_variant (GPtrArray *routes);
GPtrArray *nm_utils_ip_routes_from_variant (GVariant *value,
                                            int family);

char *nm_utils_uuid_generate (void);

gboolean nm_utils_file_is_certificate (const char *filename);
gboolean nm_utils_file_is_private_key (const char *filename, gboolean *out_encrypted);
gboolean nm_utils_file_is_pkcs12 (const char *filename);

typedef gboolean (*NMUtilsFileSearchInPathsPredicate) (const char *filename, gpointer user_data);

struct stat;

typedef gboolean (*NMUtilsCheckFilePredicate) (const char *filename, const struct stat *stat, gpointer user_data, GError **error);

const char *nm_utils_file_search_in_paths (const char *progname,
                                           const char *try_first,
                                           const char *const *paths,
                                           GFileTest file_test_flags,
                                           NMUtilsFileSearchInPathsPredicate predicate,
                                           gpointer user_data,
                                           GError **error);

guint32 nm_utils_wifi_freq_to_channel (guint32 freq);
guint32 nm_utils_wifi_channel_to_freq (guint32 channel, const char *band);
guint32 nm_utils_wifi_find_next_channel (guint32 channel, int direction, char *band);
gboolean nm_utils_wifi_is_channel_valid (guint32 channel, const char *band);
NM_AVAILABLE_IN_1_2
const guint *nm_utils_wifi_2ghz_freqs (void);
NM_AVAILABLE_IN_1_2
const guint *nm_utils_wifi_5ghz_freqs (void);

const char *nm_utils_wifi_strength_bars (guint8 strength);

/**
 * NM_UTILS_HWADDR_LEN_MAX:
 *
 * The maximum length of hardware addresses handled by NetworkManager itself,
 * nm_utils_hwaddr_len(), and nm_utils_hwaddr_aton().
 */
#define NM_UTILS_HWADDR_LEN_MAX 20 /* INFINIBAND_ALEN */

gsize       nm_utils_hwaddr_len       (int type) G_GNUC_PURE;

char       *nm_utils_hwaddr_ntoa      (gconstpointer addr, gsize length);
GByteArray *nm_utils_hwaddr_atoba     (const char *asc, gsize length);
guint8     *nm_utils_hwaddr_aton      (const char *asc, gpointer buffer, gsize length);

gboolean    nm_utils_hwaddr_valid     (const char *asc, gssize length);
char       *nm_utils_hwaddr_canonical (const char *asc, gssize length);
gboolean    nm_utils_hwaddr_matches   (gconstpointer hwaddr1,
                                       gssize        hwaddr1_len,
                                       gconstpointer hwaddr2,
                                       gssize        hwaddr2_len);

char *nm_utils_bin2hexstr (gconstpointer src, gsize len, int final_len);
GBytes *nm_utils_hexstr2bin (const char *hex);

NM_DEPRECATED_IN_1_6_FOR(nm_utils_is_valid_iface_name)
gboolean    nm_utils_iface_valid_name (const char *name);
NM_AVAILABLE_IN_1_6
gboolean    nm_utils_is_valid_iface_name (const char *name, GError **error);

gboolean nm_utils_is_uuid (const char *str);

/**
 * NM_UTILS_INET_ADDRSTRLEN:
 *
 * Defines the minimal length for a char buffer that is suitable as @dst argument
 * for both nm_utils_inet4_ntop() and nm_utils_inet6_ntop().
 **/
#define NM_UTILS_INET_ADDRSTRLEN     INET6_ADDRSTRLEN
const char *nm_utils_inet4_ntop (in_addr_t inaddr, char *dst);
const char *nm_utils_inet6_ntop (const struct in6_addr *in6addr, char *dst);

gboolean nm_utils_ipaddr_valid (int family, const char *ip);

gboolean nm_utils_check_virtual_device_compatibility (GType virtual_type, GType other_type);

NM_AVAILABLE_IN_1_2
int nm_utils_bond_mode_string_to_int (const char *mode);
NM_AVAILABLE_IN_1_2
const char *nm_utils_bond_mode_int_to_string (int mode);

NM_AVAILABLE_IN_1_2
char *nm_utils_enum_to_str (GType type, int value);

NM_AVAILABLE_IN_1_2
gboolean nm_utils_enum_from_str (GType type, const char *str, int *out_value, char **err_token);

NM_AVAILABLE_IN_1_2
const char **nm_utils_enum_get_values (GType type, int from, int to);

NM_AVAILABLE_IN_1_6
guint nm_utils_version (void);

NM_AVAILABLE_IN_1_8
GHashTable * nm_utils_parse_variant_attributes (const char *string,
                                                char attr_separator,
                                                char key_value_separator,
                                                gboolean ignore_unknown,
                                                const NMVariantAttributeSpec *const *spec,
                                                GError **error);

NM_AVAILABLE_IN_1_8
char * nm_utils_format_variant_attributes (GHashTable *attributes,
                                           char attr_separator,
                                           char key_value_separator);

/*****************************************************************************/

NM_AVAILABLE_IN_1_12
NMTCQdisc *nm_utils_tc_qdisc_from_str      (const char *str, GError **error);
NM_AVAILABLE_IN_1_12
char *nm_utils_tc_qdisc_to_str             (NMTCQdisc *qdisc, GError **error);

NM_AVAILABLE_IN_1_12
NMTCAction *nm_utils_tc_action_from_str    (const char *str, GError **error);
NM_AVAILABLE_IN_1_12
char *nm_utils_tc_action_to_str            (NMTCAction *action, GError **error);

NM_AVAILABLE_IN_1_12
NMTCTfilter *nm_utils_tc_tfilter_from_str  (const char *str, GError **error);
NM_AVAILABLE_IN_1_12
char *nm_utils_tc_tfilter_to_str           (NMTCTfilter *tfilter, GError **error);

/*****************************************************************************/

NM_AVAILABLE_IN_1_14
char *nm_utils_sriov_vf_to_str (const NMSriovVF *vf, gboolean omit_index, GError **error);
NM_AVAILABLE_IN_1_14
NMSriovVF *nm_utils_sriov_vf_from_str (const char *str, GError **error);

/*****************************************************************************/

NM_AVAILABLE_IN_1_12
gint64 nm_utils_get_timestamp_msec         (void);

NM_AVAILABLE_IN_1_16
gboolean nm_utils_base64secret_decode (const char *base64_key,
                                       gsize required_key_len,
                                       guint8 *out_key);

G_END_DECLS

#endif /* __NM_UTILS_H__ */
