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
 * (C) Copyright 2014 Red Hat, Inc.
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


#include "nm-default.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"
#include "nm-dbus-interface.h"
#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-bridge.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-dcb.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-team-port.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wimax.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wireless.h"
#include "nm-setting.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"
#include "nm-vpn-dbus-interface.h"

#define NM_UTILS_CLEAR_CANCELLABLE(c) \
	if (c) { \
		g_cancellable_cancel (c); \
		g_clear_object (&c); \
	}

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

guint32 _nm_setting_get_setting_priority (NMSetting *setting);

gboolean _nm_setting_get_property (NMSetting *setting, const char *name, GValue *value);

GSList *    _nm_utils_hash_values_to_slist (GHashTable *hash);

GHashTable *_nm_utils_copy_strdict (GHashTable *strdict);

typedef gpointer (*NMUtilsCopyFunc) (gpointer);

GPtrArray *_nm_utils_copy_slist_to_array (const GSList *list,
                                          NMUtilsCopyFunc copy_func,
                                          GDestroyNotify unref_func);
GSList    *_nm_utils_copy_array_to_slist (const GPtrArray *array,
                                          NMUtilsCopyFunc copy_func);

GPtrArray *_nm_utils_copy_array (const GPtrArray *array,
                                 NMUtilsCopyFunc copy_func,
                                 GDestroyNotify free_func);
GPtrArray *_nm_utils_copy_object_array (const GPtrArray *array);

gssize _nm_utils_ptrarray_find_first (gpointer *list, gssize len, gconstpointer needle);

gssize _nm_utils_ptrarray_find_binary_search (gpointer *list, gsize len, gpointer needle, GCompareDataFunc cmpfcn, gpointer user_data);

gboolean    _nm_utils_string_in_list   (const char *str,
                                        const char **valid_strings);

gssize      _nm_utils_strv_find_first (char **list, gssize len, const char *needle);

char **_nm_utils_strv_cleanup (char **strv,
                               gboolean strip_whitespace,
                               gboolean skip_empty,
                               gboolean skip_repeated);

char **     _nm_utils_strsplit_set (const char *str,
                                    const char *delimiters,
                                    int max_tokens);

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

/* arbitrarily choosen namespace UUID for _nm_utils_uuid_generate_from_strings() */
#define NM_UTILS_UUID_NS "b425e9fb-7598-44b4-9e3b-5a2e3aaa4905"

char *_nm_utils_uuid_generate_from_strings (const char *string1, ...) G_GNUC_NULL_TERMINATED;

void _nm_dbus_errors_init (void);

extern gboolean _nm_utils_is_manager_process;

GByteArray *nm_utils_rsa_key_encrypt (const guint8 *data,
                                      gsize len,
                                      const char *in_password,
                                      char **out_password,
                                      GError **error);

gint64 _nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback);

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

/***********************************************************/

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

/***********************************************************/

typedef struct {
	const char *name;
	gboolean numeric;
	gboolean ipv6_only;
} NMUtilsDNSOptionDesc;

extern const NMUtilsDNSOptionDesc _nm_utils_dns_option_descs[];

gboolean    _nm_utils_dns_option_validate (const char *option, char **out_name,
                                           long *out_value, gboolean ipv6,
                                           const NMUtilsDNSOptionDesc *option_descs);
int         _nm_utils_dns_option_find_idx (GPtrArray *array, const char *option);

/***********************************************************/

typedef struct _NMUtilsStrStrDictKey NMUtilsStrStrDictKey;
guint                 _nm_utils_strstrdictkey_hash   (gconstpointer a);
gboolean              _nm_utils_strstrdictkey_equal  (gconstpointer a, gconstpointer b);
NMUtilsStrStrDictKey *_nm_utils_strstrdictkey_create (const char *v1, const char *v2);

#define _nm_utils_strstrdictkey_static(v1, v2) \
    ( (NMUtilsStrStrDictKey *) ("\03" v1 "\0" v2 "") )

/***********************************************************/

#endif
