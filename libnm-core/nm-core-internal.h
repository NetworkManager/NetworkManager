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
#include "nm-version.h"
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
#define NM_SETTING_COMPARE_FLAG_INFERRABLE 0x80000000



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

char **     _nm_utils_strsplit_set (const char *str,
                                    const char *delimiters,
                                    int max_tokens);

#define NM_UTILS_UUID_TYPE_LEGACY            0
#define NM_UTILS_UUID_TYPE_VARIANT3          1

char *nm_utils_uuid_generate_from_string (const char *s, gssize slen, int uuid_type, gpointer type_args);

void _nm_dbus_errors_init (void);

extern gboolean _nm_utils_is_manager_process;

GByteArray *nm_utils_rsa_key_encrypt (const guint8 *data,
                                      gsize len,
                                      const char *in_password,
                                      char **out_password,
                                      GError **error);

/* These are public API in NM 1.2, but private on nm-1-0. */
int nm_utils_bond_mode_string_to_int (const char *mode);
const char *nm_utils_bond_mode_int_to_string (int mode);

gint64 _nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback);

#endif
