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
 * (C) Copyright 2008 - 2012 Red Hat, Inc.
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <nm-connection.h>
#include "nm-default.h"
#include "shvar.h"
#include "common.h"

#define NM_IFCFG_CONNECTION_LOG_PATH(path)  str_if_set (path,"in-memory")
#define NM_IFCFG_CONNECTION_LOG_FMT         "%s (%s,\"%s\")"
#define NM_IFCFG_CONNECTION_LOG_ARG(con)    NM_IFCFG_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_connection_get_uuid ((NMConnection *) (con)), nm_connection_get_id ((NMConnection *) (con))
#define NM_IFCFG_CONNECTION_LOG_FMTD        "%s (%s,\"%s\",%p)"
#define NM_IFCFG_CONNECTION_LOG_ARGD(con)   NM_IFCFG_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_connection_get_uuid ((NMConnection *) (con)), nm_connection_get_id ((NMConnection *) (con)), (con)

char *utils_single_quote_string (const char *str);

char *utils_single_unquote_string (const char *str);

char *utils_cert_path (const char *parent, const char *suffix);

const char *utils_get_ifcfg_name (const char *file, gboolean only_ifcfg);

gboolean utils_should_ignore_file (const char *filename, gboolean only_ifcfg);

char *utils_get_ifcfg_path (const char *parent);
char *utils_get_keys_path (const char *parent);
char *utils_get_route_path (const char *parent);
char *utils_get_route6_path (const char *parent);

shvarFile *utils_get_extra_ifcfg (const char *parent, const char *tag, gboolean should_create);
shvarFile *utils_get_keys_ifcfg (const char *parent, gboolean should_create);
shvarFile *utils_get_route_ifcfg (const char *parent, gboolean should_create);
shvarFile *utils_get_route6_ifcfg (const char *parent, gboolean should_create);

gboolean utils_has_route_file_new_syntax (const char *filename);
gboolean utils_has_complex_routes (const char *filename);

gboolean utils_ignore_ip_config (NMConnection *connection);

gboolean utils_is_ifcfg_alias_file (const char *alias, const char *ifcfg);

char *utils_detect_ifcfg_path (const char *path, gboolean only_ifcfg);

#endif  /* _UTILS_H_ */

