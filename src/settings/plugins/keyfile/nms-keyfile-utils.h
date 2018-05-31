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
 * (C) Copyright 2010-2016 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_UTILS_H__
#define __NMS_KEYFILE_UTILS_H__

#include "NetworkManagerUtils.h"

#define NMS_KEYFILE_CONNECTION_LOG_PATH(path)  ((path) ?: "in-memory")
#define NMS_KEYFILE_CONNECTION_LOG_FMT         "%s (%s,\"%s\")"
#define NMS_KEYFILE_CONNECTION_LOG_ARG(con)    NMS_KEYFILE_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_connection_get_uuid ((NMConnection *) (con)), nm_connection_get_id ((NMConnection *) (con))
#define NMS_KEYFILE_CONNECTION_LOG_FMTD        "%s (%s,\"%s\",%p)"
#define NMS_KEYFILE_CONNECTION_LOG_ARGD(con)   NMS_KEYFILE_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_connection_get_uuid ((NMConnection *) (con)), nm_connection_get_id ((NMConnection *) (con)), (con)

gboolean nms_keyfile_utils_should_ignore_file (const char *filename);

char *nms_keyfile_utils_escape_filename (const char *filename);

const char *nms_keyfile_utils_get_path (void);

#endif /* __NMS_KEYFILE_UTILS_H__ */
