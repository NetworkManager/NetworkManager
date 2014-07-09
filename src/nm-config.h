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

G_BEGIN_DECLS

#define NM_TYPE_CONFIG            (nm_config_get_type ())
#define NM_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG, NMConfig))
#define NM_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CONFIG, NMConfigClass))
#define NM_IS_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG))
#define NM_IS_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CONFIG))
#define NM_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CONFIG, NMConfigClass))

typedef struct NMConfigCmdLineOptions NMConfigCmdLineOptions;

struct _NMConfig {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMConfigClass;

GType nm_config_get_type (void);

NMConfig *nm_config_get (void);

const char *nm_config_get_path (NMConfig *config);
const char *nm_config_get_description (NMConfig *config);
const char **nm_config_get_plugins (NMConfig *config);
gboolean nm_config_get_monitor_connection_files (NMConfig *config);
gboolean nm_config_get_auth_polkit (NMConfig *config);
const char *nm_config_get_dhcp_client (NMConfig *config);
const char *nm_config_get_dns_mode (NMConfig *config);
const char *nm_config_get_log_level (NMConfig *config);
const char *nm_config_get_log_domains (NMConfig *config);
const char *nm_config_get_debug (NMConfig *config);
const char *nm_config_get_connectivity_uri (NMConfig *config);
guint nm_config_get_connectivity_interval (NMConfig *config);
const char *nm_config_get_connectivity_response (NMConfig *config);
gboolean nm_config_get_configure_and_quit (NMConfig *config);

gboolean nm_config_get_ethernet_can_auto_default (NMConfig *config, NMDevice *device);
void     nm_config_set_ethernet_no_auto_default  (NMConfig *config, NMDevice *device);

gboolean nm_config_get_ignore_carrier (NMConfig *config, NMDevice *device);

char *nm_config_get_value (NMConfig *config, const char *group, const char *key, GError **error);

/* for main.c only */
NMConfigCmdLineOptions *nm_config_cmd_line_options_new (void);
void                    nm_config_cmd_line_options_free (NMConfigCmdLineOptions *cli);
void                    nm_config_cmd_line_options_add_to_entries (NMConfigCmdLineOptions *cli,
                                                                   GOptionContext *opt_ctx);

NMConfig *nm_config_new (const NMConfigCmdLineOptions *cli, GError **error);
NMConfig *nm_config_setup (const NMConfigCmdLineOptions *cli, GError **error);

G_END_DECLS

#endif /* __NETWORKMANAGER_CONFIG_H__ */

