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
 */

#ifndef NM_CONFIG_H
#define NM_CONFIG_H

#include <glib.h>
#include <glib-object.h>

typedef struct NMConfig NMConfig;

typedef enum {
	NM_CONFIG_ERROR_NO_MEMORY = 0, /*< nick=NoMemory >*/
} NMConfigError;

#define NM_CONFIG_ERROR (nm_config_error_quark ())
GQuark nm_config_error_quark (void);


NMConfig *nm_config_new (const char *cli_config_path,
                         const char *cli_plugins,
                         const char *cli_log_level,
                         const char *cli_log_domains,
                         const char *cli_connectivity_check_uri,
                         const gint connectivity_check_interval,
                         const char *cli_connectivity_check_response,
                         GError **error);

const char *nm_config_get_path (NMConfig *config);
const char **nm_config_get_plugins (NMConfig *config);
const char *nm_config_get_dhcp_client (NMConfig *config);
const char **nm_config_get_dns_plugins (NMConfig *config);
const char *nm_config_get_log_level (NMConfig *config);
const char *nm_config_get_log_domains (NMConfig *config);
const char *nm_config_get_connectivity_uri (NMConfig *config);
const guint nm_config_get_connectivity_interval (NMConfig *config);
const char *nm_config_get_connectivity_response (NMConfig *config);

void nm_config_free (NMConfig *config);

#endif /* NM_CONFIG_H */

