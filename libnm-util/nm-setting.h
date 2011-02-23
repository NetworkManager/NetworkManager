/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_H
#define NM_SETTING_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING            (nm_setting_get_type ())
#define NM_SETTING(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING, NMSetting))
#define NM_SETTING_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING, NMSettingClass))
#define NM_IS_SETTING(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING))
#define NM_IS_SETTING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING))
#define NM_SETTING_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING, NMSettingClass))

/**
 * NMSettingError:
 * @NM_SETTING_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_ERROR_PROPERTY_NOT_FOUND: a property required by the operation
 *   was not found; for example, an attempt to update an invalid secret
 * @NM_SETTING_ERROR_PROPERTY_NOT_SECRET: an operation which requires a secret
 *   was attempted on a non-secret property
 * @NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH: the operation requires a property
 *   of a specific type, or the value couldn't be transformed to the same type
 *   as the property being acted upon
 *
 * Describes errors that may result from operations involving a #NMSetting.
 *
 **/
typedef enum
{
	NM_SETTING_ERROR_UNKNOWN = 0,
	NM_SETTING_ERROR_PROPERTY_NOT_FOUND,
	NM_SETTING_ERROR_PROPERTY_NOT_SECRET,
	NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH
} NMSettingError;

#define NM_TYPE_SETTING_ERROR (nm_setting_error_get_type ()) 
GType nm_setting_error_get_type (void);

#define NM_SETTING_ERROR nm_setting_error_quark ()
GQuark nm_setting_error_quark (void);


/* The property of the #NMSetting should be serialized */
#define NM_SETTING_PARAM_SERIALIZE    (1 << (0 + G_PARAM_USER_SHIFT))

/* The property of the #NMSetting is required for the setting to be valid */
#define NM_SETTING_PARAM_REQUIRED     (1 << (1 + G_PARAM_USER_SHIFT))

/* The property of the #NMSetting is a secret */
#define NM_SETTING_PARAM_SECRET       (1 << (2 + G_PARAM_USER_SHIFT))

/* The property of the #NMSetting should be ignored during comparisons that
 * use the %NM_SETTING_COMPARE_FLAG_FUZZY flag.
 */
#define NM_SETTING_PARAM_FUZZY_IGNORE (1 << (3 + G_PARAM_USER_SHIFT))

#define NM_SETTING_NAME "name"

/**
 * NMSettingSecretFlags:
 * @NM_SETTING_SECRET_FLAG_NONE: the system is responsible for providing and
 * storing this secret (default)
 * @NM_SETTING_SECRET_FLAG_AGENT_OWNED: a user secret agent is responsible
 * for providing and storing this secret; when it is required agents will be
 * asked to retrieve it
 * @NM_SETTING_SECRET_FLAG_NOT_SAVED: this secret should not be saved, but
 * should be requested from the user each time it is needed
 * @NM_SETTING_SECRET_FLAG_NOT_REQUIRED: in situations where it cannot be
 * automatically determined that the secret is required (some VPNs and PPP
 * providers dont require all secrets) this flag indicates that the specific
 * secret is not required
 *
 * These flags indicate specific behavior related to handling of a secret.  Each
 * secret has a corresponding set of these flags which indicate how the secret
 * is to be stored and/or requested when it is needed.
 *
 **/
typedef enum {
	NM_SETTING_SECRET_FLAG_NONE         = 0x00000000,
	NM_SETTING_SECRET_FLAG_AGENT_OWNED  = 0x00000001,
	NM_SETTING_SECRET_FLAG_NOT_SAVED    = 0x00000002,
	NM_SETTING_SECRET_FLAG_NOT_REQUIRED = 0x00000004

	/* NOTE: if adding flags, update nm-setting-private.h as well */
} NMSettingSecretFlags;

/**
 * NMSetting:
 *
 * The NMSetting struct contains only private data.
 * It should only be accessed through the functions described below.
 */
typedef struct {
	GObject parent;
} NMSetting;

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	gboolean    (*verify)            (NMSetting  *setting,
	                                  GSList     *all_settings,
	                                  GError     **error);

	GPtrArray  *(*need_secrets)      (NMSetting  *setting);

	gboolean    (*update_one_secret) (NMSetting  *setting,
	                                  const char *key,
	                                  GValue     *value,
	                                  GError    **error);

	gboolean    (*get_secret_flags)  (NMSetting  *setting,
	                                  const char *secret_name,
	                                  gboolean verify_secret,
	                                  NMSettingSecretFlags *out_flags,
	                                  GError **error);

	gboolean    (*set_secret_flags)  (NMSetting  *setting,
	                                  const char *secret_name,
	                                  gboolean verify_secret,
	                                  NMSettingSecretFlags flags,
	                                  GError **error);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingClass;

typedef void (*NMSettingValueIterFn) (NMSetting *setting,
                                      const char *key,
                                      const GValue *value,
                                      GParamFlags flags,
                                      gpointer user_data);


GType nm_setting_get_type (void);

/**
 * NMSettingHashFlags:
 * @NM_SETTING_HASH_FLAG_ALL: hash all properties (including secrets)
 * @NM_SETTING_HASH_FLAG_NO_SECRETS: do not include secrets
 * @NM_SETTING_HASH_FLAG_ONLY_SECRETS: only hash secrets
 *
 * These flags determine which properties are added to the resulting hash
 * when calling nm_setting_to_hash().
 *
 **/
typedef enum {
	NM_SETTING_HASH_FLAG_ALL = 0x00000000,
	NM_SETTING_HASH_FLAG_NO_SECRETS = 0x00000001,
	NM_SETTING_HASH_FLAG_ONLY_SECRETS = 0x00000002,
} NMSettingHashFlags;

GHashTable *nm_setting_to_hash       (NMSetting *setting,
                                      NMSettingHashFlags flags);

NMSetting  *nm_setting_new_from_hash (GType setting_type,
                                      GHashTable *hash);

NMSetting *nm_setting_duplicate      (NMSetting *setting);

const char *nm_setting_get_name      (NMSetting *setting);

gboolean    nm_setting_verify        (NMSetting *setting,
                                      GSList    *all_settings,
                                      GError    **error);

/**
 * NMSettingCompareFlags:
 * @NM_SETTING_COMPARE_FLAG_EXACT: match all properties exactly
 * @NM_SETTING_COMPARE_FLAG_FUZZY: match only important attributes, like SSID,
 *   type, security settings, etc.  Does not match, for example, connection ID
 *   or UUID.
 * @NM_SETTING_COMPARE_FLAG_IGNORE_ID: ignore the connection's ID
 * @NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS: ignore secrets
 *
 * These flags modify the comparison behavior when comparing two settings or
 * two connections.
 *
 **/
typedef enum {
	NM_SETTING_COMPARE_FLAG_EXACT = 0x00000000,
	NM_SETTING_COMPARE_FLAG_FUZZY = 0x00000001,
	NM_SETTING_COMPARE_FLAG_IGNORE_ID = 0x00000002,
	NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS = 0x00000004
} NMSettingCompareFlags;

gboolean    nm_setting_compare       (NMSetting *a,
                                      NMSetting *b,
                                      NMSettingCompareFlags flags);

/**
 * NMSettingDiffResult:
 * @NM_SETTING_DIFF_RESULT_UNKNOWN: unknown result
 * @NM_SETTING_DIFF_RESULT_IN_A: the property is present in setting A
 * @NM_SETTING_DIFF_RESULT_IN_B: the property is present in setting B
 *
 * These values indicate the result of a setting difference operation.
 **/
typedef enum {
	NM_SETTING_DIFF_RESULT_UNKNOWN = 0x00000000,
	NM_SETTING_DIFF_RESULT_IN_A =    0x00000001,
	NM_SETTING_DIFF_RESULT_IN_B =    0x00000002,
} NMSettingDiffResult;

gboolean    nm_setting_diff          (NMSetting *a,
                                      NMSetting *b,
                                      NMSettingCompareFlags flags,
                                      gboolean invert_results,
                                      GHashTable **results);

void        nm_setting_enumerate_values (NMSetting *setting,
                                         NMSettingValueIterFn func,
                                         gpointer user_data);

char       *nm_setting_to_string      (NMSetting *setting);

/* Secrets */
void        nm_setting_clear_secrets  (NMSetting *setting);
GPtrArray  *nm_setting_need_secrets   (NMSetting *setting);
gboolean    nm_setting_update_secrets (NMSetting *setting,
                                       GHashTable *secrets,
                                       GError **error);

gboolean    nm_setting_get_secret_flags (NMSetting *setting,
                                         const char *secret_name,
                                         NMSettingSecretFlags *out_flags,
                                         GError **error);

gboolean    nm_setting_set_secret_flags (NMSetting *setting,
                                         const char *secret_name,
                                         NMSettingSecretFlags flags,
                                         GError **error);

G_END_DECLS

#endif /* NM_SETTING_H */

