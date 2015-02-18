/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_KEYFILE_READER_H__
#define __NM_KEYFILE_READER_H__

#include <glib.h>

#include "nm-connection.h"


typedef enum {
	NM_KEYFILE_READ_TYPE_WARN               = 1,
}  NMKeyfileReadType;

/**
 * NMKeyfileReadHandler:
 *
 * Hook to nm_keyfile_read(). The user might fail the reading by setting
 * @error.
 *
 * Returns: should return TRUE, if the reading was handled. Otherwise,
 * a default action will be performed that depends on the @type.
 * For %NM_KEYFILE_READ_TYPE_WARN type, the default action is doing nothing.
 */
typedef gboolean (*NMKeyfileReadHandler) (GKeyFile *keyfile,
                                          NMConnection *connection,
                                          NMKeyfileReadType type,
                                          void *type_data,
                                          void *user_data,
                                          GError **error);

typedef enum {
	NM_KEYFILE_WARN_SEVERITY_DEBUG                  = 1000,
	NM_KEYFILE_WARN_SEVERITY_INFO                   = 2000,
	NM_KEYFILE_WARN_SEVERITY_WARN                   = 3000,
} NMKeyfileWarnSeverity;

/**
 * NMKeyfileReadTypeDataWarn:
 *
 * this struct is passed as @type_data for the @NMKeyfileReadHandler of
 * type %NM_KEYFILE_READ_TYPE_WARN.
 */
typedef struct {
	/* might be %NULL, if the warning is not about a group. */
	const char *group;

	/* might be %NULL, if the warning is not about a setting. */
	NMSetting *setting;

	/* might be %NULL, if the warning is not about a property. */
	const char *property_name;

	NMKeyfileWarnSeverity severity;
	const char *message;
} NMKeyfileReadTypeDataWarn;


NMConnection *nm_keyfile_read (GKeyFile *keyfile,
                               const char *keyfile_name,
                               const char *base_dir,
                               NMKeyfileReadHandler handler,
                               void *user_data,
                               GError **error);

#endif /* __NM_KEYFILE_READER_H__ */
