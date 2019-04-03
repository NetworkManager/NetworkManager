/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
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
 * Copyright 2007 - 2011 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_H
#define NM_SETTING_H

#include <glib.h>
#include <glib-object.h>

#include "nm-version.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING            (nm_setting_get_type ())
#define NM_SETTING(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING, NMSetting))
#define NM_SETTING_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING, NMSettingClass))
#define NM_IS_SETTING(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING))
#define NM_IS_SETTING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING))
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
	NM_SETTING_ERROR_UNKNOWN = 0,           /*< nick=UnknownError >*/
	NM_SETTING_ERROR_PROPERTY_NOT_FOUND,    /*< nick=PropertyNotFound >*/
	NM_SETTING_ERROR_PROPERTY_NOT_SECRET,   /*< nick=PropertyNotSecret >*/
	NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH /*< nick=PropertyTypeMismatch >*/
} NMSettingError;

#define NM_SETTING_ERROR nm_setting_error_quark ()
GQuark nm_setting_error_quark (void);

/* DEPRECATED AND UNUSED */
#define NM_SETTING_PARAM_SERIALIZE    (1 << (0 + G_PARAM_USER_SHIFT))

/* The property of the #NMSetting is required for the setting to be valid */
#define NM_SETTING_PARAM_REQUIRED     (1 << (1 + G_PARAM_USER_SHIFT))

/* The property of the #NMSetting is a secret */
#define NM_SETTING_PARAM_SECRET       (1 << (2 + G_PARAM_USER_SHIFT))

/* The property of the #NMSetting should be ignored during comparisons that
 * use the %NM_SETTING_COMPARE_FLAG_FUZZY flag.
 */
#define NM_SETTING_PARAM_FUZZY_IGNORE (1 << (3 + G_PARAM_USER_SHIFT))

/* Note: all non-glib GParamFlags bits are reserved by NetworkManager */

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
 * providers don't require all secrets) this flag indicates that the specific
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
 * NMSettingCompareFlags:
 * @NM_SETTING_COMPARE_FLAG_EXACT: match all properties exactly
 * @NM_SETTING_COMPARE_FLAG_FUZZY: match only important attributes, like SSID,
 *   type, security settings, etc.  Does not match, for example, connection ID
 *   or UUID.
 * @NM_SETTING_COMPARE_FLAG_IGNORE_ID: ignore the connection's ID
 * @NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS: ignore all secrets
 * @NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS: ignore secrets for which
 * the secret's flags indicate the secret is owned by a user secret agent
 * (ie, the secret's flag includes @NM_SETTING_SECRET_FLAG_AGENT_OWNED)
 * @NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS: ignore secrets for which
 * the secret's flags indicate the secret should not be saved to persistent
 * storage (ie, the secret's flag includes @NM_SETTING_SECRET_FLAG_NOT_SAVED)
 * @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT: if this flag is set,
 * nm_setting_diff() and nm_connection_diff() will also include properties that
 * are set to their default value. See also @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT.
 * @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT: if this flag is set,
 * nm_setting_diff() and nm_connection_diff() will not include properties that
 * are set to their default value. This is the opposite of
 * @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT. If both flags are set together,
 * @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT wins. If both flags are unset,
 * this means to exclude default properties if there is a setting to compare,
 * but include all properties, if the setting 'b' is missing. This is the legacy
 * behaviour of libnm-util, where nm_setting_diff() behaved differently depending
 * on whether the setting 'b' was available. If @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT
 * is set, nm_setting_diff() will also set the flags @NM_SETTING_DIFF_RESULT_IN_A_DEFAULT
 * and @NM_SETTING_DIFF_RESULT_IN_B_DEFAULT, if the values are default values.
 *
 * These flags modify the comparison behavior when comparing two settings or
 * two connections.
 *
 **/
typedef enum {
	NM_SETTING_COMPARE_FLAG_EXACT = 0x00000000,
	NM_SETTING_COMPARE_FLAG_FUZZY = 0x00000001,
	NM_SETTING_COMPARE_FLAG_IGNORE_ID = 0x00000002,
	NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS = 0x00000004,
	NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS = 0x00000008,
	NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS = 0x00000010,
	NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT = 0x00000020,
	NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT = 0x00000040,

	/* 0x80000000 is used for a private flag */
} NMSettingCompareFlags;

/**
 * NMSetting:
 *
 * The NMSetting struct contains only private data.
 * It should only be accessed through the functions described below.
 */
typedef struct {
	GObject parent;
} NMSetting;

/**
 * NMSettingClearSecretsWithFlagsFn:
 * @setting: The setting for which secrets are being iterated
 * @secret: The secret's name
 * @flags: The secret's flags, eg %NM_SETTING_SECRET_FLAG_AGENT_OWNED
 * @user_data: User data passed to nm_connection_clear_secrets_with_flags()
 *
 * Returns: %TRUE to clear the secret, %FALSE to not clear the secret
 */
typedef gboolean (*NMSettingClearSecretsWithFlagsFn) (NMSetting *setting,
                                                      const char *secret,
                                                      NMSettingSecretFlags flags,
                                                      gpointer user_data);

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	int         (*verify)            (NMSetting  *setting,
	                                  GSList     *all_settings,
	                                  GError     **error);

	GPtrArray  *(*need_secrets)      (NMSetting  *setting);

	int         (*update_one_secret) (NMSetting  *setting,
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

	/* Returns TRUE if the given property contains the same value in both settings */
	gboolean    (*compare_property)  (NMSetting *setting,
	                                  NMSetting *other,
	                                  const GParamSpec *prop_spec,
	                                  NMSettingCompareFlags flags);

	gboolean    (*clear_secrets_with_flags) (NMSetting *setting,
	                                         GParamSpec *pspec,
	                                         NMSettingClearSecretsWithFlagsFn func,
	                                         gpointer user_data);

	const char *(*get_virtual_iface_name) (NMSetting *setting);

	/* Padding for future expansion */
	void (*_reserved1) (void);
} NMSettingClass;

/**
 * NMSettingValueIterFn:
 * @setting: The setting for which properties are being iterated, given to
 * nm_setting_enumerate_values()
 * @key: The value/property name
 * @value: The property's value
 * @flags: The property's flags, like %NM_SETTING_PARAM_SECRET
 * @user_data: User data passed to nm_setting_enumerate_values()
 */
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

gboolean    nm_setting_compare       (NMSetting *a,
                                      NMSetting *b,
                                      NMSettingCompareFlags flags);

/**
 * NMSettingDiffResult:
 * @NM_SETTING_DIFF_RESULT_UNKNOWN: unknown result
 * @NM_SETTING_DIFF_RESULT_IN_A: the property is present in setting A
 * @NM_SETTING_DIFF_RESULT_IN_B: the property is present in setting B
 * @NM_SETTING_DIFF_RESULT_IN_A_DEFAULT: the property is present in
 * setting A but is set to the default value. This flag is only set,
 * if you specify @NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT.
 * @NM_SETTING_DIFF_RESULT_IN_B_DEFAULT: analog to @NM_SETTING_DIFF_RESULT_IN_A_DEFAULT.
 *
 * These values indicate the result of a setting difference operation.
 **/
typedef enum {
	NM_SETTING_DIFF_RESULT_UNKNOWN = 0x00000000,
	NM_SETTING_DIFF_RESULT_IN_A =    0x00000001,
	NM_SETTING_DIFF_RESULT_IN_B =    0x00000002,
	NM_SETTING_DIFF_RESULT_IN_A_DEFAULT = 0x00000004,
	NM_SETTING_DIFF_RESULT_IN_B_DEFAULT = 0x00000004,
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

void        nm_setting_clear_secrets_with_flags (NMSetting *setting,
                                                 NMSettingClearSecretsWithFlagsFn func,
                                                 gpointer user_data);

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

const char *nm_setting_get_virtual_iface_name (NMSetting *setting);

G_END_DECLS

#endif /* NM_SETTING_H */
