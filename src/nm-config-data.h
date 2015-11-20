/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_CONFIG_DATA_H
#define NM_CONFIG_DATA_H


#include "nm-default.h"

G_BEGIN_DECLS

#define NM_TYPE_CONFIG_DATA            (nm_config_data_get_type ())
#define NM_CONFIG_DATA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG_DATA, NMConfigData))
#define NM_CONFIG_DATA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CONFIG_DATA, NMConfigDataClass))
#define NM_IS_CONFIG_DATA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG_DATA))
#define NM_IS_CONFIG_DATA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CONFIG_DATA))
#define NM_CONFIG_DATA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CONFIG_DATA, NMConfigDataClass))


#define NM_CONFIG_DATA_CONFIG_MAIN_FILE      "config-main-file"
#define NM_CONFIG_DATA_CONFIG_DESCRIPTION    "config-description"
#define NM_CONFIG_DATA_KEYFILE_USER          "keyfile-user"
#define NM_CONFIG_DATA_KEYFILE_INTERN        "keyfile-intern"
#define NM_CONFIG_DATA_CONNECTIVITY_URI      "connectivity-uri"
#define NM_CONFIG_DATA_CONNECTIVITY_INTERVAL "connectivity-interval"
#define NM_CONFIG_DATA_CONNECTIVITY_RESPONSE "connectivity-response"
#define NM_CONFIG_DATA_NO_AUTO_DEFAULT       "no-auto-default"
#define NM_CONFIG_DATA_DNS_MODE              "dns"

typedef enum { /*<flags >*/
	NM_CONFIG_GET_VALUE_NONE                   = 0,

	/* use g_key_file_get_value() instead of g_key_file_get_string(). */
	NM_CONFIG_GET_VALUE_RAW                    = (1LL << 0),

	/* strip whitespaces */
	NM_CONFIG_GET_VALUE_STRIP                  = (1LL << 1),

	/* if the returned string would be the empty word, return NULL. */
	NM_CONFIG_GET_VALUE_NO_EMPTY               = (1LL << 2),

	/* special flag to read device spec. You want to use this before passing the
	 * value to nm_match_spec_split(). */
	NM_CONFIG_GET_VALUE_TYPE_SPEC              = NM_CONFIG_GET_VALUE_RAW,
} NMConfigGetValueFlags;

typedef enum { /*< flags >*/
	NM_CONFIG_CHANGE_NONE                      = 0,

	NM_CONFIG_CHANGE_SIGHUP                    = (1L << 0),
	NM_CONFIG_CHANGE_SIGUSR1                   = (1L << 1),
	NM_CONFIG_CHANGE_SIGUSR2                   = (1L << 2),

	NM_CONFIG_CHANGE_CONFIG_FILES              = (1L << 3),
	NM_CONFIG_CHANGE_VALUES                    = (1L << 4),
	NM_CONFIG_CHANGE_VALUES_USER               = (1L << 5),
	NM_CONFIG_CHANGE_VALUES_INTERN             = (1L << 6),
	NM_CONFIG_CHANGE_CONNECTIVITY              = (1L << 7),
	NM_CONFIG_CHANGE_NO_AUTO_DEFAULT           = (1L << 8),
	NM_CONFIG_CHANGE_DNS_MODE                  = (1L << 9),
	NM_CONFIG_CHANGE_RC_MANAGER                = (1L << 10),
	NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG         = (1L << 11),

	_NM_CONFIG_CHANGE_LAST,
	NM_CONFIG_CHANGE_ALL                       = ((_NM_CONFIG_CHANGE_LAST - 1) << 1) - 1,
} NMConfigChangeFlags;

struct _NMConfigData {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMConfigDataClass;

typedef struct _NMGlobalDnsConfig NMGlobalDnsConfig;
typedef struct _NMGlobalDnsDomain NMGlobalDnsDomain;

GType nm_config_data_get_type (void);

NMConfigData *nm_config_data_new (const char *config_main_file,
                                  const char *config_description,
                                  const char *const*no_auto_default,
                                  GKeyFile *keyfile_user,
                                  GKeyFile *keyfile_intern);
NMConfigData *nm_config_data_new_update_keyfile_intern (const NMConfigData *base, GKeyFile *keyfile_intern);
NMConfigData *nm_config_data_new_update_no_auto_default (const NMConfigData *base, const char *const*no_auto_default);

NMConfigChangeFlags nm_config_data_diff (NMConfigData *old_data, NMConfigData *new_data);

void nm_config_data_log (const NMConfigData *self,
                               const char *prefix,
                               const char *key_prefix,
                               /* FILE* */ gpointer print_stream);

const char *nm_config_data_get_config_main_file (const NMConfigData *config_data);
const char *nm_config_data_get_config_description (const NMConfigData *config_data);

gboolean nm_config_data_has_group (const NMConfigData *self, const char *group);
gboolean nm_config_data_has_value (const NMConfigData *self, const char *group, const char *key, NMConfigGetValueFlags flags);
char *nm_config_data_get_value (const NMConfigData *config_data, const char *group, const char *key, NMConfigGetValueFlags flags);
const char *nm_config_data_get_value_cached (const NMConfigData *config_data, const char *group, const char *key, NMConfigGetValueFlags flags);
gint nm_config_data_get_value_boolean (const NMConfigData *self, const char *group, const char *key, gint default_value);

const char *nm_config_data_get_connectivity_uri (const NMConfigData *config_data);
const guint nm_config_data_get_connectivity_interval (const NMConfigData *config_data);
const char *nm_config_data_get_connectivity_response (const NMConfigData *config_data);

const char *const*nm_config_data_get_no_auto_default (const NMConfigData *config_data);
gboolean          nm_config_data_get_no_auto_default_for_device (const NMConfigData *self, NMDevice *device);

const char *nm_config_data_get_dns_mode (const NMConfigData *self);
const char *nm_config_data_get_rc_manager (const NMConfigData *self);

gboolean nm_config_data_get_ignore_carrier (const NMConfigData *self, NMDevice *device);
gboolean nm_config_data_get_assume_ipv6ll_only (const NMConfigData *self, NMDevice *device);
NMGlobalDnsConfig *nm_config_data_get_global_dns_config (const NMConfigData *self);

char *nm_config_data_get_connection_default (const NMConfigData *self,
                                             const char *property,
                                             NMDevice *device);

char **nm_config_data_get_groups (const NMConfigData *self);
char **nm_config_data_get_keys (const NMConfigData *self, const char *group);
gboolean nm_config_data_is_intern_atomic_group (const NMConfigData *self, const char *group);

GKeyFile *nm_config_data_clone_keyfile_intern (const NMConfigData *self);

const char *const *nm_global_dns_config_get_searches (const NMGlobalDnsConfig *dns);
const char *const *nm_global_dns_config_get_options (const NMGlobalDnsConfig *dns);
guint nm_global_dns_config_get_num_domains (const NMGlobalDnsConfig *dns);
NMGlobalDnsDomain *nm_global_dns_config_get_domain (const NMGlobalDnsConfig *dns, guint i);
NMGlobalDnsDomain *nm_global_dns_config_lookup_domain (const NMGlobalDnsConfig *dns, const char *name);
const char *nm_global_dns_domain_get_name (const NMGlobalDnsDomain *domain);
const char *const *nm_global_dns_domain_get_servers (const NMGlobalDnsDomain *domain);
const char *const *nm_global_dns_domain_get_options (const NMGlobalDnsDomain *domain);
gboolean nm_global_dns_config_is_internal (const NMGlobalDnsConfig *dns);
gboolean nm_global_dns_config_is_empty (const NMGlobalDnsConfig *dns);
void nm_global_dns_config_update_checksum (const NMGlobalDnsConfig *dns, GChecksum *sum);
void nm_global_dns_config_free (NMGlobalDnsConfig *conf);

NMGlobalDnsConfig *nm_global_dns_config_from_dbus (const GValue *value, GError **error);
void nm_global_dns_config_to_dbus (const NMGlobalDnsConfig *dns_config, GValue *value);

/* private accessors */
GKeyFile *_nm_config_data_get_keyfile (const NMConfigData *self);
GKeyFile *_nm_config_data_get_keyfile_user (const NMConfigData *self);
GKeyFile *_nm_config_data_get_keyfile_intern (const NMConfigData *self);

G_END_DECLS

#endif /* NM_CONFIG_DATA_H */

