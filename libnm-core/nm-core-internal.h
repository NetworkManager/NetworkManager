/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * (C) Copyright 2014 - 2017 Red Hat, Inc.
 */

#ifndef NM_CORE_NM_INTERNAL_H
#define NM_CORE_NM_INTERNAL_H

/* This header file contain functions that are provided as private API
 * by libnm-core. It will contain functions to give privileged access to
 * libnm-core. This can be useful for NetworkManager and libnm.so
 * which both are special users of libnm-core.
 * It also exposes some utility functions for reuse.
 *
 * These functions are not exported and are only available to components that link
 * statically against libnm-core. This basically means libnm-core, libnm, NetworkManager
 * and some test programs.
 **/


#include "nm-connection.h"
#include "nm-core-enum-types.h"
#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-bridge.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-dcb.h"
#include "nm-setting-dummy.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip-tunnel.h"
#include "nm-setting-proxy.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-macsec.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-patch.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-team-port.h"
#include "nm-setting-team.h"
#include "nm-setting-tun.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-vxlan.h"
#include "nm-setting-wimax.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wireless.h"
#include "nm-setting.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-core-types-internal.h"
#include "nm-vpn-editor-plugin.h"

/* IEEE 802.1D-1998 timer values */
#define NM_BR_MIN_HELLO_TIME    1
#define NM_BR_MAX_HELLO_TIME    10

#define NM_BR_MIN_FORWARD_DELAY 2
#define NM_BR_MAX_FORWARD_DELAY 30

#define NM_BR_MIN_MAX_AGE       6
#define NM_BR_MAX_MAX_AGE       40

/* IEEE 802.1D-1998 Table 7.4 */
#define NM_BR_MIN_AGEING_TIME   0
#define NM_BR_MAX_AGEING_TIME   1000000

/* NM_SETTING_COMPARE_FLAG_INFERRABLE: check whether a device-generated
 * connection can be replaced by a already-defined connection. This flag only
 * takes into account properties marked with the %NM_SETTING_PARAM_INFERRABLE
 * flag.
 */
#define NM_SETTING_COMPARE_FLAG_INFERRABLE ((NMSettingCompareFlags) 0x80000000)

/* NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY: this flag is used for properties
 * that automatically get re-applied on an active connection when the settings
 * connection is modified. For most properties, the applied-connection is distinct
 * from the setting-connection and changes don't propagate. Exceptions are the
 * firewall-zone and the metered property.
 */
#define NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY ((NMSettingCompareFlags) 0x40000000)

/* NM_SETTING_COMPARE_FLAG_NONE: for convenience, define a special flag NONE -- which
 * equals to numeric zero (NM_SETTING_COMPARE_FLAG_EXACT).
 */
#define NM_SETTING_COMPARE_FLAG_NONE ((NMSettingCompareFlags) 0)


#define NM_SETTING_SECRET_FLAGS_ALL \
	(NM_SETTING_SECRET_FLAG_NONE | \
	 NM_SETTING_SECRET_FLAG_AGENT_OWNED | \
	 NM_SETTING_SECRET_FLAG_NOT_SAVED | \
	 NM_SETTING_SECRET_FLAG_NOT_REQUIRED)

typedef enum { /*< skip >*/
	NM_SETTING_PARSE_FLAGS_NONE                     = 0,
	NM_SETTING_PARSE_FLAGS_STRICT                   = 1LL << 0,
	NM_SETTING_PARSE_FLAGS_BEST_EFFORT              = 1LL << 1,
	NM_SETTING_PARSE_FLAGS_NORMALIZE                = 1LL << 2,

	_NM_SETTING_PARSE_FLAGS_LAST,
	NM_SETTING_PARSE_FLAGS_ALL                      = ((_NM_SETTING_PARSE_FLAGS_LAST - 1) << 1) - 1,
} NMSettingParseFlags;

gboolean _nm_connection_replace_settings (NMConnection *connection,
                                          GVariant *new_settings,
                                          NMSettingParseFlags parse_flags,
                                          GError **error);

/**
 * NMSettingVerifyResult:
 * @NM_SETTING_VERIFY_SUCCESS: the setting verifies successfully
 * @NM_SETTING_VERIFY_ERROR: the setting has a serious misconfiguration
 * @NM_SETTING_VERIFY_NORMALIZABLE: the setting is valid but has properties
 * that should be normalized
 * @NM_SETTING_VERIFY_NORMALIZABLE_ERROR: the setting is invalid but the
 * errors can be fixed by nm_connection_normalize().
 */
typedef enum {
	NM_SETTING_VERIFY_SUCCESS       = TRUE,
	NM_SETTING_VERIFY_ERROR         = FALSE,
	NM_SETTING_VERIFY_NORMALIZABLE  = 2,
	NM_SETTING_VERIFY_NORMALIZABLE_ERROR = 3,
} NMSettingVerifyResult;

NMSettingVerifyResult _nm_connection_verify (NMConnection *connection, GError **error);

gboolean _nm_connection_remove_setting (NMConnection *connection, GType setting_type);

NMConnection *_nm_simple_connection_new_from_dbus (GVariant      *dict,
                                                   NMSettingParseFlags parse_flags,
                                                   GError       **error);

/*
 * A setting's priority should roughly follow the OSI layer model, but it also
 * controls which settings get asked for secrets first.  Thus settings which
 * relate to things that must be working first, like hardware, should get a
 * higher priority than things which layer on top of the hardware.  For example,
 * the GSM/CDMA settings should provide secrets before the PPP setting does,
 * because a PIN is required to unlock the device before PPP can even start.
 * Even settings without secrets should be assigned the right priority.
 *
 * 0: reserved for invalid
 *
 * 1: reserved for the Connection setting
 *
 * 2,3: hardware-related settings like Ethernet, Wi-Fi, InfiniBand, Bridge, etc.
 * These priority 1 settings are also "base types", which means that at least
 * one of them is required for the connection to be valid, and their name is
 * valid in the 'type' property of the Connection setting.
 *
 * 4: hardware-related auxiliary settings that require a base setting to be
 * successful first, like Wi-Fi security, 802.1x, etc.
 *
 * 5: hardware-independent settings that are required before IP connectivity
 * can be established, like PPP, PPPoE, etc.
 *
 * 6: IP-level stuff
 *
 * 10: NMSettingUser
 */
typedef enum { /*< skip >*/
	NM_SETTING_PRIORITY_INVALID     = 0,
	NM_SETTING_PRIORITY_CONNECTION  = 1,
	NM_SETTING_PRIORITY_HW_BASE     = 2,
	NM_SETTING_PRIORITY_HW_NON_BASE = 3,
	NM_SETTING_PRIORITY_HW_AUX      = 4,
	NM_SETTING_PRIORITY_AUX         = 5,
	NM_SETTING_PRIORITY_IP          = 6,
	NM_SETTING_PRIORITY_USER        = 10,
} NMSettingPriority;

NMSettingPriority _nm_setting_get_setting_priority (NMSetting *setting);

gboolean _nm_setting_get_property (NMSetting *setting, const char *name, GValue *value);

#define NM_UTILS_HWADDR_LEN_MAX_STR (NM_UTILS_HWADDR_LEN_MAX * 3)

guint8 *_nm_utils_hwaddr_aton (const char *asc, gpointer buffer, gsize buffer_length, gsize *out_length);
const char *nm_utils_hwaddr_ntoa_buf (gconstpointer addr, gsize addr_len, gboolean upper_case, char *buf, gsize buf_len);

char *_nm_utils_bin2str (gconstpointer addr, gsize length, gboolean upper_case);

GSList *    _nm_utils_hash_values_to_slist (GHashTable *hash);

GHashTable *_nm_utils_copy_strdict (GHashTable *strdict);

typedef gpointer (*NMUtilsCopyFunc) (gpointer);

gboolean _nm_ip_route_attribute_validate_all (const NMIPRoute *route);
const char **_nm_ip_route_get_attribute_names (const NMIPRoute *route, gboolean sorted, guint *out_length);
GHashTable *_nm_ip_route_get_attributes_direct (NMIPRoute *route);

static inline void
_nm_auto_ip_route_unref (NMIPRoute **v)
{
	if (*v)
		nm_ip_route_unref (*v);
}
#define nm_auto_ip_route_unref nm_auto (_nm_auto_ip_route_unref)

GPtrArray *_nm_utils_copy_slist_to_array (const GSList *list,
                                          NMUtilsCopyFunc copy_func,
                                          GDestroyNotify unref_func);
GSList    *_nm_utils_copy_array_to_slist (const GPtrArray *array,
                                          NMUtilsCopyFunc copy_func);

GPtrArray *_nm_utils_copy_array (const GPtrArray *array,
                                 NMUtilsCopyFunc copy_func,
                                 GDestroyNotify free_func);
GPtrArray *_nm_utils_copy_object_array (const GPtrArray *array);

gssize _nm_utils_ptrarray_find_first (gconstpointer *list, gssize len, gconstpointer needle);

gssize _nm_utils_ptrarray_find_binary_search (gconstpointer *list,
                                              gsize len,
                                              gconstpointer needle,
                                              GCompareDataFunc cmpfcn,
                                              gpointer user_data,
                                              gssize *out_idx_first,
                                              gssize *out_idx_last);
gssize _nm_utils_array_find_binary_search (gconstpointer list, gsize elem_size, gsize len, gconstpointer needle, GCompareDataFunc cmpfcn, gpointer user_data);

GSList *    _nm_utils_strv_to_slist (char **strv, gboolean deep_copy);
char **     _nm_utils_slist_to_strv (GSList *slist, gboolean deep_copy);

GPtrArray * _nm_utils_strv_to_ptrarray (char **strv);
char **     _nm_utils_ptrarray_to_strv (GPtrArray *ptrarray);
gboolean    _nm_utils_strv_equal (char **strv1, char **strv2);

gboolean _nm_utils_check_file (const char *filename,
                               gint64 check_owner,
                               NMUtilsCheckFilePredicate check_file,
                               gpointer user_data,
                               struct stat *out_st,
                               GError **error);

gboolean _nm_utils_check_module_file (const char *name,
                                      int check_owner,
                                      NMUtilsCheckFilePredicate check_file,
                                      gpointer user_data,
                                      GError **error);

#define NM_UTILS_UUID_TYPE_LEGACY            0
#define NM_UTILS_UUID_TYPE_VARIANT3          1

char *nm_utils_uuid_generate_from_string (const char *s, gssize slen, int uuid_type, gpointer type_args);

/* arbitrarily chosen namespace UUID for _nm_utils_uuid_generate_from_strings() */
#define NM_UTILS_UUID_NS "b425e9fb-7598-44b4-9e3b-5a2e3aaa4905"

char *_nm_utils_uuid_generate_from_strings (const char *string1, ...) G_GNUC_NULL_TERMINATED;

char *nm_utils_uuid_generate_buf_ (char *buf);
#define nm_utils_uuid_generate_buf(buf) \
	({ \
		G_STATIC_ASSERT (sizeof (buf) == G_N_ELEMENTS (buf) && sizeof (buf) >= 37); \
		nm_utils_uuid_generate_buf_ (buf); \
	})
#define nm_utils_uuid_generate_a() (nm_utils_uuid_generate_buf_ (g_alloca (37)))

void _nm_dbus_errors_init (void);

extern gboolean _nm_utils_is_manager_process;

GByteArray *nm_utils_rsa_key_encrypt (const guint8 *data,
                                      gsize len,
                                      const char *in_password,
                                      char **out_password,
                                      GError **error);

gulong _nm_dbus_signal_connect_data (GDBusProxy *proxy,
                                     const char *signal_name,
                                     const GVariantType *signature,
                                     GCallback c_handler,
                                     gpointer data,
                                     GClosureNotify destroy_data,
                                     GConnectFlags connect_flags);
#define _nm_dbus_signal_connect(proxy, name, signature, handler, data) \
	_nm_dbus_signal_connect_data (proxy, name, signature, handler, data, NULL, (GConnectFlags) 0)

GVariant *_nm_dbus_proxy_call_finish (GDBusProxy           *proxy,
                                      GAsyncResult         *res,
                                      const GVariantType   *reply_type,
                                      GError              **error);

GVariant *_nm_dbus_proxy_call_sync   (GDBusProxy           *proxy,
                                      const gchar          *method_name,
                                      GVariant             *parameters,
                                      const GVariantType   *reply_type,
                                      GDBusCallFlags        flags,
                                      gint                  timeout_msec,
                                      GCancellable         *cancellable,
                                      GError              **error);

gboolean _nm_dbus_error_has_name (GError     *error,
                                  const char *dbus_error_name);

/*****************************************************************************/

gboolean _nm_vpn_plugin_info_check_file (const char *filename,
                                         gboolean check_absolute,
                                         gboolean do_validate_filename,
                                         gint64 check_owner,
                                         NMUtilsCheckFilePredicate check_file,
                                         gpointer user_data,
                                         GError **error);

const char *_nm_vpn_plugin_info_get_default_dir_etc (void);
const char *_nm_vpn_plugin_info_get_default_dir_lib (void);
const char *_nm_vpn_plugin_info_get_default_dir_user (void);

GSList *_nm_vpn_plugin_info_list_load_dir (const char *dirname,
                                           gboolean do_validate_filename,
                                           gint64 check_owner,
                                           NMUtilsCheckFilePredicate check_file,
                                           gpointer user_data);

/*****************************************************************************/

typedef struct {
	const char *name;
	gboolean numeric;
	gboolean ipv6_only;
} NMUtilsDNSOptionDesc;

extern const NMUtilsDNSOptionDesc _nm_utils_dns_option_descs[];

gboolean    _nm_utils_dns_option_validate (const char *option, char **out_name,
                                           long *out_value, gboolean ipv6,
                                           const NMUtilsDNSOptionDesc *option_descs);
gssize      _nm_utils_dns_option_find_idx (GPtrArray *array, const char *option);

/*****************************************************************************/

typedef struct _NMUtilsStrStrDictKey NMUtilsStrStrDictKey;
guint                 _nm_utils_strstrdictkey_hash   (gconstpointer a);
gboolean              _nm_utils_strstrdictkey_equal  (gconstpointer a, gconstpointer b);
NMUtilsStrStrDictKey *_nm_utils_strstrdictkey_create (const char *v1, const char *v2);

#define _nm_utils_strstrdictkey_static(v1, v2) \
    ( (NMUtilsStrStrDictKey *) ("\03" v1 "\0" v2 "") )

/*****************************************************************************/

gboolean _nm_setting_vlan_set_priorities (NMSettingVlan *setting,
                                          NMVlanPriorityMap map,
                                          const NMVlanQosMapping *qos_map,
                                          guint n_qos_map);
void     _nm_setting_vlan_get_priorities (NMSettingVlan *setting,
                                          NMVlanPriorityMap map,
                                          NMVlanQosMapping **out_qos_map,
                                          guint *out_n_qos_map);

/*****************************************************************************/

struct ether_addr;

gboolean _nm_utils_generate_mac_address_mask_parse (const char *value,
                                                    struct ether_addr *out_mask,
                                                    struct ether_addr **out_ouis,
                                                    gsize *out_ouis_len,
                                                    GError **error);

/*****************************************************************************/

typedef enum {
	NM_BOND_OPTION_TYPE_INT,
	NM_BOND_OPTION_TYPE_STRING,
	NM_BOND_OPTION_TYPE_BOTH,
	NM_BOND_OPTION_TYPE_IP,
	NM_BOND_OPTION_TYPE_MAC,
	NM_BOND_OPTION_TYPE_IFNAME,
} NMBondOptionType;

NMBondOptionType
_nm_setting_bond_get_option_type (NMSettingBond *setting, const char *name);

/*****************************************************************************/

/* nm_connection_get_uuid() asserts against NULL, which is the right thing to
 * do in order to catch bugs. However, sometimes that behavior is inconvenient.
 * Just try or return NULL. */

static inline const char *
_nm_connection_get_id (NMConnection *connection)
{
	return connection ? nm_connection_get_id (connection) : NULL;
}

static inline const char *
_nm_connection_get_uuid (NMConnection *connection)
{
	return connection ? nm_connection_get_uuid (connection) : NULL;
}

/*****************************************************************************/

typedef enum {
	NM_BOND_MODE_UNKNOWN = 0,
	NM_BOND_MODE_ROUNDROBIN,
	NM_BOND_MODE_ACTIVEBACKUP,
	NM_BOND_MODE_XOR,
	NM_BOND_MODE_BROADCAST,
	NM_BOND_MODE_8023AD,
	NM_BOND_MODE_TLB,
	NM_BOND_MODE_ALB,
} NMBondMode;

NMBondMode _nm_setting_bond_mode_from_string (const char *str);
gboolean _nm_setting_bond_option_supported (const char *option, NMBondMode mode);

/*****************************************************************************/

NMSettingBluetooth *_nm_connection_get_setting_bluetooth_for_nap (NMConnection *connection);

/*****************************************************************************/

const char *nm_utils_inet_ntop (int addr_family, gconstpointer addr, char *dst);

gboolean _nm_utils_inet6_is_token (const struct in6_addr *in6addr);

/*****************************************************************************/

gboolean _nm_utils_team_config_equal (const char *conf1, const char *conf2, gboolean port);
GValue *_nm_utils_team_config_get (const char *conf,
                                   const char *key,
                                   const char *key2,
                                   const char *key3,
                                   gboolean port_config);

gboolean _nm_utils_team_config_set (char **conf,
                                    const char *key,
                                    const char *key2,
                                    const char *key3,
                                    const GValue *value);

/*****************************************************************************/

static inline int
nm_setting_ip_config_get_addr_family (NMSettingIPConfig *s_ip)
{
	if (NM_IS_SETTING_IP4_CONFIG (s_ip))
		return AF_INET;
	if (NM_IS_SETTING_IP6_CONFIG (s_ip))
		return AF_INET6;
	g_return_val_if_reached (AF_UNSPEC);
}

/*****************************************************************************/

guint32 _nm_utils_parse_tc_handle                (const char *str,
                                                  GError **error);
void _nm_utils_string_append_tc_parent           (GString *string,
                                                  const char *prefix,
                                                  guint32 parent);
void _nm_utils_string_append_tc_qdisc_rest       (GString *string,
                                                  NMTCQdisc *qdisc);
gboolean _nm_utils_string_append_tc_tfilter_rest (GString *string,
                                                  NMTCTfilter *tfilter,
                                                  GError **error);

/*****************************************************************************/

#endif
