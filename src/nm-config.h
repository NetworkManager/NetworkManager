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
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2013 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#ifndef __NETWORKMANAGER_CONFIG_H__
#define __NETWORKMANAGER_CONFIG_H__

#include <glib.h>
#include <glib-object.h>

#include "nm-types.h"
#include "nm-config-data.h"

G_BEGIN_DECLS

#define NM_TYPE_CONFIG            (nm_config_get_type ())
#define NM_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG, NMConfig))
#define NM_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CONFIG, NMConfigClass))
#define NM_IS_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG))
#define NM_IS_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CONFIG))
#define NM_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CONFIG, NMConfigClass))

/* Properties */
#define NM_CONFIG_CMD_LINE_OPTIONS                  "cmd-line-options"

/* Signals */
#define NM_CONFIG_SIGNAL_CONFIG_CHANGED             "config-changed"

#define NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL 300
#define NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE "NetworkManager is online" /* NOT LOCALIZED */

#define NM_CONFIG_KEYFILE_LIST_SEPARATOR ','

#define NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN                ".intern."
#define NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION            "connection"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST ".test-append-stringlist"

#define NM_CONFIG_KEYFILE_GROUP_MAIN                        "main"
#define NM_CONFIG_KEYFILE_GROUP_LOGGING                     "logging"
#define NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY                "connectivity"

#define NM_CONFIG_KEYFILE_GROUP_KEYFILE                     "keyfile"
#define NM_CONFIG_KEYFILE_GROUP_IFUPDOWN                    "ifupdown"
#define NM_CONFIG_KEYFILE_GROUP_IFNET                       "ifnet"

#define NM_CONFIG_KEYFILE_KEY_IFNET_AUTO_REFRESH            "auto_refresh"
#define NM_CONFIG_KEYFILE_KEY_IFNET_MANAGED                 "managed"
#define NM_CONFIG_KEYFILE_KEY_IFUPDOWN_MANAGED              "managed"

#define NM_CONFIG_KEYFILE_KEYPREFIX_WAS                     ".was."
#define NM_CONFIG_KEYFILE_KEYPREFIX_SET                     ".set."

typedef struct NMConfigCmdLineOptions NMConfigCmdLineOptions;

struct _NMConfig {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*config_changed) (NMConfig *config, GHashTable *changes, NMConfigData *old_data);
} NMConfigClass;

GType nm_config_get_type (void);

NMConfig *nm_config_get (void);

char *nm_config_change_flags_to_string (NMConfigChangeFlags flags);

NMConfigData *nm_config_get_data (NMConfig *config);
NMConfigData *nm_config_get_data_orig (NMConfig *config);

#define NM_CONFIG_GET_DATA      (nm_config_get_data (nm_config_get ()))
#define NM_CONFIG_GET_DATA_ORIG (nm_config_get_data_orig (nm_config_get ()))

const char **nm_config_get_plugins (NMConfig *config);
gboolean nm_config_get_monitor_connection_files (NMConfig *config);
gboolean nm_config_get_auth_polkit (NMConfig *config);
const char *nm_config_get_dhcp_client (NMConfig *config);
const char *nm_config_get_log_level (NMConfig *config);
const char *nm_config_get_log_domains (NMConfig *config);
const char *nm_config_get_debug (NMConfig *config);
gboolean nm_config_get_configure_and_quit (NMConfig *config);

void nm_config_set_values (NMConfig *self,
                           GKeyFile *keyfile_intern_new,
                           gboolean allow_write,
                           gboolean force_rewrite);

/* for main.c only */
NMConfigCmdLineOptions *nm_config_cmd_line_options_new (void);
void                    nm_config_cmd_line_options_free (NMConfigCmdLineOptions *cli);
void                    nm_config_cmd_line_options_add_to_entries (NMConfigCmdLineOptions *cli,
                                                                   GOptionContext *opt_ctx);

gboolean nm_config_get_no_auto_default_for_device (NMConfig *config, NMDevice *device);
void nm_config_set_no_auto_default_for_device  (NMConfig *config, NMDevice *device);

NMConfig *nm_config_new (const NMConfigCmdLineOptions *cli, GError **error);
NMConfig *nm_config_setup (const NMConfigCmdLineOptions *cli, GError **error);
void nm_config_reload (NMConfig *config, int signal);

gint nm_config_parse_boolean (const char *str, gint default_value);

GKeyFile *nm_config_create_keyfile (void);
gint nm_config_keyfile_get_boolean (GKeyFile *keyfile,
                                    const char *section,
                                    const char *key,
                                    gint default_value);
char *nm_config_keyfile_get_value (GKeyFile *keyfile,
                                   const char *section,
                                   const char *key,
                                   NMConfigGetValueFlags flags);
void nm_config_keyfile_set_string_list (GKeyFile *keyfile,
                                        const char *group,
                                        const char *key,
                                        const char *const* strv,
                                        gssize len);
GSList *nm_config_get_device_match_spec (const GKeyFile *keyfile, const char *group, const char *key, gboolean *out_has_key);

void _nm_config_sort_groups (char **groups, gsize ngroups);

G_END_DECLS

#endif /* __NETWORKMANAGER_CONFIG_H__ */

