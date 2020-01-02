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

/* List helpers */
#define DEFINE_KF_LIST_WRAPPER_PROTO(stype, get_ctype, set_ctype) \
get_ctype nm_keyfile_plugin_kf_get_##stype##_list (GKeyFile *kf, \
                                                   const char *group, \
                                                   const char *key, \
                                                   gsize *out_length, \
                                                   GError **error); \
\
void nm_keyfile_plugin_kf_set_##stype##_list  (GKeyFile *kf, \
                                               const char *group, \
                                               const char *key, \
                                               set_ctype list[], \
                                               gsize length);
DEFINE_KF_LIST_WRAPPER_PROTO(integer, int*, int)
DEFINE_KF_LIST_WRAPPER_PROTO(string, char**, const char* const)

void nm_keyfile_plugin_kf_set_integer_list_uint8 (GKeyFile *kf,
                                                  const char *group,
                                                  const char *key,
                                                  const guint8 *list,
                                                  gsize length);

/* Single-value helpers */
#define DEFINE_KF_WRAPPER_PROTO(stype, get_ctype, set_ctype) \
get_ctype nm_keyfile_plugin_kf_get_##stype (GKeyFile *kf, \
                                            const char *group, \
                                            const char *key, \
                                            GError **error); \
\
void nm_keyfile_plugin_kf_set_##stype (GKeyFile *kf, \
                                       const char *group, \
                                       const char *key, \
                                       set_ctype value);
DEFINE_KF_WRAPPER_PROTO(string, char*, const char*)
DEFINE_KF_WRAPPER_PROTO(boolean, gboolean, gboolean)
DEFINE_KF_WRAPPER_PROTO(value, char*, const char*)

/* Misc */
gint64 nm_keyfile_plugin_kf_get_int64 (GKeyFile *kf,
                                       const char *group,
                                       const char *key,
                                       guint base,
                                       gint64 min,
                                       gint64 max,
                                       gint64 fallback,
                                       GError **error);

char ** nm_keyfile_plugin_kf_get_keys    (GKeyFile *kf,
                                           const char *group,
                                           gsize *out_length,
                                           GError **error);

gboolean nm_keyfile_plugin_kf_has_key     (GKeyFile *kf,
                                           const char *group,
                                           const char *key,
                                           GError **error);

const char *nm_keyfile_key_encode (const char *name,
                                   char **out_to_free);

const char *nm_keyfile_key_decode (const char *key,
                                   char **out_to_free);

#endif  /* __NM_KEYFILE_UTILS_H__ */
