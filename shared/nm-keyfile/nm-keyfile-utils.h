// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 - 2015 Red Hat, Inc.
 */

#ifndef __NM_KEYFILE_UTILS_H__
#define __NM_KEYFILE_UTILS_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
#error Cannot use this header.
#endif

#define NM_KEYFILE_GROUP_VPN_SECRETS          "vpn-secrets"
#define NM_KEYFILE_GROUPPREFIX_WIREGUARD_PEER "wireguard-peer."

const char *nm_keyfile_plugin_get_alias_for_setting_name (const char *setting_name);

const char *nm_keyfile_plugin_get_setting_name_for_alias (const char *alias);

/*****************************************************************************/

int     *nm_keyfile_plugin_kf_get_integer_list (GKeyFile *kf, const char *group, const char *key, gsize *out_length, GError **error);
char   **nm_keyfile_plugin_kf_get_string_list  (GKeyFile *kf, const char *group, const char *key, gsize *out_length, GError **error);
char    *nm_keyfile_plugin_kf_get_string       (GKeyFile *kf, const char *group, const char *key, GError **error);
gboolean nm_keyfile_plugin_kf_get_boolean      (GKeyFile *kf, const char *group, const char *key, GError **error);
char    *nm_keyfile_plugin_kf_get_value        (GKeyFile *kf, const char *group, const char *key, GError **error);

void nm_keyfile_plugin_kf_set_integer_list_uint8 (GKeyFile *kf, const char *group, const char *key, const guint8     *list, gsize length);
void nm_keyfile_plugin_kf_set_integer_list       (GKeyFile *kf, const char *group, const char *key, int              *list, gsize length);
void nm_keyfile_plugin_kf_set_string_list        (GKeyFile *kf, const char *group, const char *key, const char *const*list, gsize length);

void nm_keyfile_plugin_kf_set_string       (GKeyFile *kf, const char *group, const char *key, const char *value);
void nm_keyfile_plugin_kf_set_boolean      (GKeyFile *kf, const char *group, const char *key, gboolean    value);
void nm_keyfile_plugin_kf_set_value        (GKeyFile *kf, const char *group, const char *key, const char *value);

gint64 nm_keyfile_plugin_kf_get_int64 (GKeyFile *kf,
                                       const char *group,
                                       const char *key,
                                       guint base,
                                       gint64 min,
                                       gint64 max,
                                       gint64 fallback,
                                       GError **error);

char **nm_keyfile_plugin_kf_get_keys (GKeyFile *kf,
                                      const char *group,
                                      gsize *out_length,
                                      GError **error);

gboolean nm_keyfile_plugin_kf_has_key (GKeyFile *kf,
                                       const char *group,
                                       const char *key,
                                       GError **error);

const char *nm_keyfile_key_encode (const char *name,
                                   char **out_to_free);

const char *nm_keyfile_key_decode (const char *key,
                                   char **out_to_free);

#endif  /* __NM_KEYFILE_UTILS_H__ */
