// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_KEYFILE_INTERNAL_H__
#define __NM_KEYFILE_INTERNAL_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
#error Cannot use this header.
#endif

#include <sys/types.h>

#include "nm-connection.h"
#include "nm-setting-8021x.h"

#include "nm-core-internal.h"
#include "nm-meta-setting.h"

/*****************************************************************************/

#define NM_KEYFILE_CERT_SCHEME_PREFIX_PATH "file://"
#define NM_KEYFILE_CERT_SCHEME_PREFIX_PKCS11 "pkcs11:"
#define NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB "data:;base64,"

char *nm_keyfile_detect_unqualified_path_scheme (const char *base_dir,
                                                 gconstpointer pdata,
                                                 gsize data_len,
                                                 gboolean consider_exists,
                                                 gboolean *out_exists);

typedef enum { /*< flags >*/
	NM_KEYFILE_HANDLER_FLAGS_NONE = 0,
} NMKeyfileHandlerFlags;

typedef enum {
	NM_KEYFILE_HANDLER_TYPE_WARN  = 1,
	NM_KEYFILE_HANDLER_TYPE_WRITE_CERT = 2,
} NMKeyfileHandlerType;

typedef struct _NMKeyfileHandlerData NMKeyfileHandlerData;

/**
 * NMKeyfileReadHandler:
 *
 * Hook to nm_keyfile_read(). The user might fail the reading by setting
 * @error.
 *
 * Returns: should return TRUE, if the reading was handled. Otherwise,
 * a default action will be performed that depends on the @handler_type.
 * For %NM_KEYFILE_HANDLER_TYPE_WARN handler_type, the default action is doing nothing.
 */
typedef gboolean (*NMKeyfileReadHandler) (GKeyFile *keyfile,
                                          NMConnection *connection,
                                          NMKeyfileHandlerType handler_type,
                                          NMKeyfileHandlerData *handler_data,
                                          void *user_data);

typedef enum {
	NM_KEYFILE_WARN_SEVERITY_DEBUG                  = 1000,
	NM_KEYFILE_WARN_SEVERITY_INFO                   = 2000,
	NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE      = 2901,
	NM_KEYFILE_WARN_SEVERITY_WARN                   = 3000,
} NMKeyfileWarnSeverity;

NMConnection *nm_keyfile_read (GKeyFile *keyfile,
                               const char *base_dir,
                               NMKeyfileHandlerFlags handler_flags,
                               NMKeyfileReadHandler handler,
                               void *user_data,
                               GError **error);

gboolean nm_keyfile_read_ensure_id (NMConnection *connection,
                                    const char *fallback_id);

gboolean nm_keyfile_read_ensure_uuid (NMConnection *connection,
                                      const char *fallback_uuid_seed);

/*****************************************************************************/

/**
 * NMKeyfileWriteHandler:
 *
 * This is a hook to tweak the serialization.
 *
 * Handler for certain properties or events that are not entirely contained
 * within the keyfile or that might be serialized differently. The @handler_type and
 * @handler_data arguments tell which kind of argument we have at hand.
 *
 * Currently only the handler_type %NM_KEYFILE_HANDLER_TYPE_WRITE_CERT is supported, which provides
 * @handler_data as %NMKeyfileHandlerDataWriteCert. However, this handler should be generic enough
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
                                           NMKeyfileHandlerType handler_type,
                                           NMKeyfileHandlerData *handler_data,
                                           void *user_data);

GKeyFile *nm_keyfile_write (NMConnection *connection,
                            NMKeyfileHandlerFlags handler_flags,
                            NMKeyfileWriteHandler handler,
                            void *user_data,
                            GError **error);

/*****************************************************************************/

/**
 * NMKeyfileHandlerDataWarn:
 *
 * this struct is passed as @handler_data for the @NMKeyfileReadHandler of
 * handler_type %NM_KEYFILE_HANDLER_TYPE_WARN.
 */
typedef struct {
	NMKeyfileWarnSeverity severity;
	char *message;
	const char *fmt;
	va_list ap;
} NMKeyfileHandlerDataWarn;

/**
 * NMKeyfileHandlerDataWriteCert:
 *
 * this struct is passed as @handler_data for the @NMKeyfileWriteHandler of
 * handler_type %NM_KEYFILE_HANDLER_TYPE_WRITE_CERT.
 */
typedef struct {
	const NMSetting8021xSchemeVtable *vtable;
} NMKeyfileHandlerDataWriteCert;

struct _NMKeyfileHandlerData {
	NMKeyfileHandlerType type;

	GError **p_error;

	const char *kf_group_name;
	const char *kf_key;

	NMSetting *cur_setting;
	const char *cur_property;

	union {
		NMKeyfileHandlerDataWarn      warn;
		NMKeyfileHandlerDataWriteCert write_cert;
	};
};

/*****************************************************************************/

void nm_keyfile_handler_data_fail_with_error (NMKeyfileHandlerData *handler_data,
                                              GError *src);

void nm_keyfile_handler_data_get_context (const NMKeyfileHandlerData *handler_data,
                                          const char **out_kf_group_name,
                                          const char **out_kf_key_name,
                                          NMSetting **out_cur_setting,
                                          const char **out_cur_property_name);

void nm_keyfile_handler_data_warn_get (const NMKeyfileHandlerData *handler_data,
                                       const char **out_message,
                                       NMKeyfileWarnSeverity *out_severity);

const char *_nm_keyfile_handler_data_warn_get_message (const NMKeyfileHandlerData *handler_data);

/*****************************************************************************/

char *nm_keyfile_plugin_kf_get_string (GKeyFile *kf, const char *group, const char *key, GError **error);
void nm_keyfile_plugin_kf_set_string (GKeyFile *kf, const char *group, const char *key, const char *value);

int nm_key_file_get_boolean (GKeyFile *kf, const char *group, const char *key, int default_value);

void _nm_keyfile_copy (GKeyFile *dst, GKeyFile *src);
gboolean _nm_keyfile_a_contains_all_in_b (GKeyFile *kf_a, GKeyFile *kf_b);
gboolean _nm_keyfile_equals (GKeyFile *kf_a, GKeyFile *kf_b, gboolean consider_order);
gboolean _nm_keyfile_has_values (GKeyFile *keyfile);

/*****************************************************************************/

#define NM_KEYFILE_GROUP_NMMETA                 ".nmmeta"
#define NM_KEYFILE_KEY_NMMETA_NM_GENERATED      "nm-generated"
#define NM_KEYFILE_KEY_NMMETA_VOLATILE          "volatile"
#define NM_KEYFILE_KEY_NMMETA_SHADOWED_STORAGE  "shadowed-storage"
#define NM_KEYFILE_KEY_NMMETA_SHADOWED_OWNED    "shadowed-owned"

#define NM_KEYFILE_PATH_NAME_LIB                 NMLIBDIR  "/system-connections"
#define NM_KEYFILE_PATH_NAME_ETC_DEFAULT         NMCONFDIR "/system-connections"
#define NM_KEYFILE_PATH_NAME_RUN                 NMRUNDIR  "/system-connections"

#define NM_KEYFILE_PATH_SUFFIX_NMCONNECTION      ".nmconnection"

#define NM_KEYFILE_PATH_SUFFIX_NMMETA            ".nmmeta"

#define NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL      "/dev/null"

gboolean nm_keyfile_utils_ignore_filename (const char *filename, gboolean require_extension);

char *nm_keyfile_utils_create_filename (const char *filename, gboolean with_extension);

#endif /* __NM_KEYFILE_INTERNAL_H__ */
