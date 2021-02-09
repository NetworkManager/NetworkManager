/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_KEYFILE_INTERNAL_H__
#define __NM_KEYFILE_INTERNAL_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
    #error Cannot use this header.
#endif

#include <sys/types.h>

#include "nm-keyfile.h"

#include "nm-connection.h"
#include "nm-setting-8021x.h"

#include "nm-core-internal.h"

/*****************************************************************************/

#define NM_KEYFILE_CERT_SCHEME_PREFIX_PATH   "file://"
#define NM_KEYFILE_CERT_SCHEME_PREFIX_PKCS11 "pkcs11:"
#define NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB   "data:;base64,"

char *nm_keyfile_detect_unqualified_path_scheme(const char *  base_dir,
                                                gconstpointer pdata,
                                                gsize         data_len,
                                                gboolean      consider_exists,
                                                gboolean *    out_exists);

gboolean nm_keyfile_read_ensure_id(NMConnection *connection, const char *fallback_id);

gboolean nm_keyfile_read_ensure_uuid(NMConnection *connection, const char *fallback_uuid_seed);

/*****************************************************************************/

/**
 * NMKeyfileHandlerDataWarn:
 *
 * this struct is passed as @handler_data for the @NMKeyfileReadHandler of
 * type %NM_KEYFILE_HANDLER_TYPE_WARN.
 */
typedef struct {
    NMKeyfileWarnSeverity severity;
    char *                message;
    const char *          fmt;
    va_list               ap;
} NMKeyfileHandlerDataWarn;

/**
 * NMKeyfileHandlerDataWriteCert:
 *
 * this struct is passed as @handler_data for the @NMKeyfileWriteHandler of
 * type %NM_KEYFILE_HANDLER_TYPE_WRITE_CERT.
 */
typedef struct {
    const NMSetting8021xSchemeVtable *vtable;
} NMKeyfileHandlerDataWriteCert;

struct _NMKeyfileHandlerData {
    NMKeyfileHandlerType type;

    GError **p_error;

    const char *kf_group_name;
    const char *kf_key;

    NMSetting * cur_setting;
    const char *cur_property;

    union {
        NMKeyfileHandlerDataWarn      warn;
        NMKeyfileHandlerDataWriteCert write_cert;
    };
};

/*****************************************************************************/

const char *_nm_keyfile_handler_data_warn_get_message(const NMKeyfileHandlerData *handler_data);

/*****************************************************************************/

char *
nm_keyfile_plugin_kf_get_string(GKeyFile *kf, const char *group, const char *key, GError **error);
void nm_keyfile_plugin_kf_set_string(GKeyFile *  kf,
                                     const char *group,
                                     const char *key,
                                     const char *value);

int nm_key_file_get_boolean(GKeyFile *kf, const char *group, const char *key, int default_value);

void     _nm_keyfile_copy(GKeyFile *dst, GKeyFile *src);
gboolean _nm_keyfile_a_contains_all_in_b(GKeyFile *kf_a, GKeyFile *kf_b);
gboolean _nm_keyfile_equals(GKeyFile *kf_a, GKeyFile *kf_b, gboolean consider_order);
gboolean _nm_keyfile_has_values(GKeyFile *keyfile);

/*****************************************************************************/

#define NM_KEYFILE_GROUP_NMMETA                ".nmmeta"
#define NM_KEYFILE_KEY_NMMETA_NM_GENERATED     "nm-generated"
#define NM_KEYFILE_KEY_NMMETA_VOLATILE         "volatile"
#define NM_KEYFILE_KEY_NMMETA_EXTERNAL         "external"
#define NM_KEYFILE_KEY_NMMETA_SHADOWED_STORAGE "shadowed-storage"
#define NM_KEYFILE_KEY_NMMETA_SHADOWED_OWNED   "shadowed-owned"

#define NM_KEYFILE_PATH_NAME_LIB         NMLIBDIR "/system-connections"
#define NM_KEYFILE_PATH_NAME_ETC_DEFAULT NMCONFDIR "/system-connections"
#define NM_KEYFILE_PATH_NAME_RUN         NMRUNDIR "/system-connections"

#define NM_KEYFILE_PATH_SUFFIX_NMCONNECTION ".nmconnection"

#define NM_KEYFILE_PATH_SUFFIX_NMMETA ".nmmeta"

#define NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL "/dev/null"

gboolean nm_keyfile_utils_ignore_filename(const char *filename, gboolean require_extension);

char *nm_keyfile_utils_create_filename(const char *filename, gboolean with_extension);

#endif /* __NM_KEYFILE_INTERNAL_H__ */
