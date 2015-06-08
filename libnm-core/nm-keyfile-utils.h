/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010-2015 Red Hat, Inc.
 */

#ifndef __NM_KEYFILE_UTILS_H__
#define __NM_KEYFILE_UTILS_H__

#include <glib.h>

#define NM_KEYFILE_GROUP_VPN_SECRETS "vpn-secrets"

const char *nm_keyfile_plugin_get_alias_for_setting_name (const char *setting_name);

const char *nm_keyfile_plugin_get_setting_name_for_alias (const char *alias);

/*********************************************************/

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
DEFINE_KF_LIST_WRAPPER_PROTO(integer, gint*, gint)
DEFINE_KF_LIST_WRAPPER_PROTO(string, gchar**, const gchar* const)

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
DEFINE_KF_WRAPPER_PROTO(string, gchar*, const gchar*)
DEFINE_KF_WRAPPER_PROTO(integer, gint, gint)
DEFINE_KF_WRAPPER_PROTO(uint64, guint64, guint64)
DEFINE_KF_WRAPPER_PROTO(boolean, gboolean, gboolean)
DEFINE_KF_WRAPPER_PROTO(value, gchar*, const gchar*)

/* Misc */
gchar ** nm_keyfile_plugin_kf_get_keys    (GKeyFile *kf,
                                           const char *group,
                                           gsize *out_length,
                                           GError **error);

gboolean nm_keyfile_plugin_kf_has_key     (GKeyFile *kf,
                                           const char *group,
                                           const char *key,
                                           GError **error);

#endif  /* __NM_KEYFILE_UTILS_H__ */

