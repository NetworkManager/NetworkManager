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

#ifndef __NM_KEYFILE_INTERNAL_H__
#define __NM_KEYFILE_INTERNAL_H__

#include <sys/types.h>

#include "nm-default.h"
#include "nm-connection.h"
#include "nm-setting-8021x.h"

/*********************************************************/

#define NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB "data:;base64,"
#define NM_KEYFILE_CERT_SCHEME_PREFIX_PATH "file://"

char *nm_keyfile_detect_unqualified_path_scheme (const char *base_dir,
                                                 gconstpointer pdata,
                                                 gsize data_len,
                                                 gboolean consider_exists,
                                                 gboolean *out_exists);

typedef enum {
	NM_KEYFILE_READ_TYPE_WARN               = 1,
} NMKeyfileReadType;

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
	NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE      = 2901,
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

/*********************************************************/

typedef enum {
	NM_KEYFILE_WRITE_TYPE_CERT              = 1,
} NMKeyfileWriteType;

/**
 * NMKeyfileWriteHandler:
 *
 * This is a hook to tweak the serialization.
 *
 * Handler for certain properties or events that are not entirely contained
 * within the keyfile or that might be serialized differently. The @type and
 * @type_data arguments tell which kind of argument we have at hand.
 *
 * Currently only the type %NM_KEYFILE_WRITE_TYPE_CERT is supported, which provides
 * @type_data as %NMKeyfileWriteTypeDataCert. However, this handler should be generic enough
 * to support other types as well.
 *
 * This don't have to be only "properties". For example, nm_keyfile_read() uses
 * a similar handler to push warnings to the caller.
 *
 * If the handler raises an error, it should set the @error value. This causes
 * the an overall failure.
 *
 * Returns: whether the issue was handled. If the type was unhandled,
 * a default action will be performed. This might be raise an error,
 * do some fallback parsing, or do nothing.
 */
typedef gboolean (*NMKeyfileWriteHandler) (NMConnection *connection,
                                           GKeyFile *keyfile,
                                           NMKeyfileWriteType type,
                                           void *type_data,
                                           void *user_data,
                                           GError **error);

/**
 * NMKeyfileWriteTypeDataCert:
 *
 * this struct is passed as @type_data for the @NMKeyfileWriteHandler of
 * type %NM_KEYFILE_WRITE_TYPE_CERT.
 */
typedef struct {
	NMSetting8021x *setting;
	const char *property_name;

	/* The following functions are helpers that simplify the implementation
	 * of the handler. */
	const char *suffix;
	NMSetting8021xCKScheme (*scheme_func) (NMSetting8021x *setting);
	NMSetting8021xCKFormat (*format_func) (NMSetting8021x *setting);
	const char *           (*path_func)   (NMSetting8021x *setting);
	GBytes *               (*blob_func)   (NMSetting8021x *setting);
} NMKeyfileWriteTypeDataCert;


GKeyFile *nm_keyfile_write (NMConnection *connection,
                            NMKeyfileWriteHandler handler,
                            void *user_data,
                            GError **error);

/*********************************************************/

char *nm_keyfile_plugin_kf_get_string (GKeyFile *kf, const char *group, const char *key, GError **error);
void nm_keyfile_plugin_kf_set_string (GKeyFile *kf, const char *group, const char *key, const char *value);

void _nm_keyfile_copy (GKeyFile *dst, GKeyFile *src);
gboolean _nm_keyfile_a_contains_all_in_b (GKeyFile *kf_a, GKeyFile *kf_b);
gboolean _nm_keyfile_equals (GKeyFile *kf_a, GKeyFile *kf_b, gboolean consider_order);
gboolean _nm_keyfile_has_values (GKeyFile *keyfile);


#endif /* __NM_KEYFILE_INTERNAL_H__ */
