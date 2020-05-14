// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-ethtool.h"

#include "nm-setting-private.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

/*****************************************************************************/

/**
 * SECTION:nm-setting-ethtool
 * @short_description: Describes connection properties for ethtool related options
 *
 * The #NMSettingEthtool object is a #NMSetting subclass that describes properties
 * to control network driver and hardware settings.
 **/

/*****************************************************************************/

static const GVariantType *
get_variant_type_from_ethtool_id (NMEthtoolID ethtool_id)
{
	if (nm_ethtool_id_is_feature (ethtool_id))
		return G_VARIANT_TYPE_BOOLEAN;

	if (   nm_ethtool_id_is_coalesce (ethtool_id)
	    || nm_ethtool_id_is_ring (ethtool_id))
		return G_VARIANT_TYPE_UINT32;

	return NULL;
}

/*****************************************************************************/

/**
 * nm_ethtool_optname_is_feature:
 * @optname: (allow-none): the option name to check
 *
 * Checks whether @optname is a valid option name for an offload feature.
 *
 * %Returns: %TRUE, if @optname is valid
 *
 * Since: 1.20
 *
 * Note that nm_ethtool_optname_is_feature() was first added to the libnm header files
 * in 1.14.0 but forgot to actually add to the library. This happened belatedly in 1.20.0 and
 * the stable versions 1.18.2, 1.16.4 and 1.14.8 (with linker version "libnm_1_14_8").
 */
gboolean
nm_ethtool_optname_is_feature (const char *optname)
{
	return optname && nm_ethtool_id_is_feature (nm_ethtool_id_get_by_name (optname));
}

/**
 * nm_ethtool_optname_is_coalesce:
 * @optname: (allow-none): the option name to check
 *
 * Checks whether @optname is a valid option name for a coalesce setting.
 *
 * %Returns: %TRUE, if @optname is valid
 *
 * Since: 1.26
 */
gboolean
nm_ethtool_optname_is_coalesce (const char *optname)
{
	return optname && nm_ethtool_id_is_coalesce (nm_ethtool_id_get_by_name (optname));
}

/**
 * nm_ethtool_optname_is_ring:
 * @optname: (allow-none): the option name to check
 *
 * Checks whether @optname is a valid option name for a ring setting.
 *
 * %Returns: %TRUE, if @optname is valid
 *
 * Since: 1.26
 */
gboolean
nm_ethtool_optname_is_ring (const char *optname)
{
	return optname && nm_ethtool_id_is_ring (nm_ethtool_id_get_by_name (optname));
}

/*****************************************************************************/

/**
 * NMSettingEthtool:
 *
 * Ethtool Ethernet Settings
 *
 * Since: 1.14
 */
struct _NMSettingEthtool {
	NMSetting parent;
};

struct _NMSettingEthtoolClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingEthtool, nm_setting_ethtool, NM_TYPE_SETTING)

#define NM_SETTING_ETHTOOL_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettingEthtool, NM_IS_SETTING_ETHTOOL, NMSetting)

/*****************************************************************************/

static void
_notify_attributes (NMSettingEthtool *self)
{
	_nm_setting_gendata_notify (NM_SETTING (self), TRUE);
}

/*****************************************************************************/

/**
 * nm_setting_ethtool_get_feature:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the offload feature to get
 *
 * Gets and offload feature setting. Returns %NM_TERNARY_DEFAULT if the
 * feature is not set.
 *
 * Note that @optname must be a valid name for a feature, according to
 * nm_ethtool_optname_is_feature().
 *
 * Returns: a #NMTernary value indicating whether the offload feature
 *   is enabled, disabled, or left untouched.
 *
 * Since: 1.14
 */
NMTernary
nm_setting_ethtool_get_feature (NMSettingEthtool *setting,
                                const char *optname)
{
	GVariant *v;

	g_return_val_if_fail (NM_IS_SETTING_ETHTOOL (setting), NM_TERNARY_DEFAULT);
	g_return_val_if_fail (optname && nm_ethtool_optname_is_feature (optname), NM_TERNARY_DEFAULT);

	v = nm_setting_gendata_get (NM_SETTING (setting), optname);
	if (   v
	    && g_variant_is_of_type (v, G_VARIANT_TYPE_BOOLEAN)) {
		return g_variant_get_boolean (v)
		       ? NM_TERNARY_TRUE
		       : NM_TERNARY_FALSE;
	}
	return NM_TERNARY_DEFAULT;
}

/**
 * nm_setting_ethtool_set_feature:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the offload feature to get
 * @value: the new value to set. The special value %NM_TERNARY_DEFAULT
 *   means to clear the offload feature setting.
 *
 * Sets and offload feature setting.
 *
 * Note that @optname must be a valid name for a feature, according to
 * nm_ethtool_optname_is_feature().
 *
 * Since: 1.14
 */
void
nm_setting_ethtool_set_feature (NMSettingEthtool *setting,
                                const char *optname,
                                NMTernary value)
{
	GHashTable *hash;
	GVariant *v;

	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));
	g_return_if_fail (optname && nm_ethtool_optname_is_feature (optname));
	g_return_if_fail (NM_IN_SET (value, NM_TERNARY_DEFAULT,
	                                    NM_TERNARY_FALSE,
	                                    NM_TERNARY_TRUE));

	hash = _nm_setting_gendata_hash (NM_SETTING (setting),
	                                 value != NM_TERNARY_DEFAULT);

	if (value == NM_TERNARY_DEFAULT) {
		if (hash) {
			if (g_hash_table_remove (hash, optname))
				_notify_attributes (setting);
		}
		return;
	}

	v = g_hash_table_lookup (hash, optname);
	if (   v
	    && g_variant_is_of_type (v, G_VARIANT_TYPE_BOOLEAN)) {
		if (g_variant_get_boolean (v)) {
			if (value == NM_TERNARY_TRUE)
				return;
		} else {
			if (value == NM_TERNARY_FALSE)
				return;
		}
	}

	v = g_variant_ref_sink (g_variant_new_boolean (value != NM_TERNARY_FALSE));
	g_hash_table_insert (hash,
	                     g_strdup (optname),
	                     v);
	_notify_attributes (setting);
}

/**
 * nm_setting_ethtool_clear_features:
 * @setting: the #NMSettingEthtool
 *
 * Clears all offload features settings
 *
 * Since: 1.14
 */
void
nm_setting_ethtool_clear_features (NMSettingEthtool *setting)
{
	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));

	if (nm_setting_gendata_clear_all (NM_SETTING (setting),
	                                  &nm_ethtool_optname_is_feature))
		_notify_attributes (setting);
}

guint
nm_setting_ethtool_init_features (NMSettingEthtool *setting,
                                  NMTernary *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */)
{
	GHashTable *hash;
	GHashTableIter iter;
	guint i;
	guint n_req = 0;
	const char *name;
	GVariant *variant;

	nm_assert (NM_IS_SETTING_ETHTOOL (setting));
	nm_assert (requested);

	for (i = 0; i < _NM_ETHTOOL_ID_FEATURE_NUM; i++)
		requested[i] = NM_TERNARY_DEFAULT;

	hash = _nm_setting_gendata_hash (NM_SETTING (setting), FALSE);
	if (!hash)
		return 0;

	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &variant)) {
		NMEthtoolID ethtool_id = nm_ethtool_id_get_by_name (name);

		if (!nm_ethtool_id_is_feature (ethtool_id))
			continue;
		if (!g_variant_is_of_type (variant, G_VARIANT_TYPE_BOOLEAN))
			continue;

		requested[_NM_ETHTOOL_ID_FEATURE_AS_IDX (ethtool_id)] =   g_variant_get_boolean (variant)
		                                                        ? NM_TERNARY_TRUE
		                                                        : NM_TERNARY_FALSE;
		n_req++;
	}

	return n_req;
}

/**
 * nm_setting_ethtool_get_coalesce:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the coalescing setting to get
 * @out_value (out) (allow-none): value of the coalescing setting
 *
 * Gets the value of coalescing setting.
 *
 * Note that @optname must be a valid name for a setting, according to
 * nm_ethtool_optname_is_coalesce().
 *
 *
 * Returns: %TRUE and places the coalesce setting value in @out_value or %FALSE if unset.
 *
 * Since: 1.26
 */
gboolean
nm_setting_ethtool_get_coalesce (NMSettingEthtool *setting,
                                 const char *optname,
                                 guint32 *out_value)
{
	g_return_val_if_fail (NM_IS_SETTING_ETHTOOL (setting), FALSE);
	g_return_val_if_fail (nm_ethtool_optname_is_coalesce (optname), FALSE);

	return nm_setting_gendata_get_uint32 (NM_SETTING (setting),
	                                      optname,
	                                      out_value);
}

/**
 * nm_setting_ethtool_set_coalesce:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the coalesce setting
 * @value: the new value to set.
 *
 * Sets a coalesce setting.
 *
 * Note that @optname must be a valid name for a coalesce setting, according to
 * nm_ethtool_optname_is_coalesce().
 *
 * Since: 1.26
 */
void
nm_setting_ethtool_set_coalesce (NMSettingEthtool *setting,
                                 const char *optname,
                                 guint32 value)
{
	NMEthtoolID ethtool_id;

	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));

	ethtool_id = nm_ethtool_id_get_by_name (optname);

	g_return_if_fail (nm_ethtool_id_is_coalesce (ethtool_id));

	if (NM_IN_SET (ethtool_id,
	               NM_ETHTOOL_ID_COALESCE_ADAPTIVE_RX,
	               NM_ETHTOOL_ID_COALESCE_ADAPTIVE_TX))
		value = !!value;

	nm_setting_gendata_set_uint32 (NM_SETTING (setting),
	                               optname,
	                               value);
	_notify_attributes (setting);
}

/**
 * nm_setting_ethtool_clear_coalesce:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the coalesce setting
 *
 * Clear a coalesce setting
 *
 * Since: 1.26
 */
void
nm_setting_ethtool_clear_coalesce (NMSettingEthtool *setting,
                                   const char *optname)
{
	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));
	g_return_if_fail (nm_str_not_empty (optname));

	if (nm_setting_gendata_clear (NM_SETTING (setting), optname))
		_notify_attributes (setting);
}

/**
 * nm_setting_ethtool_clear_coalesce_all:
 * @setting: the #NMSettingEthtool
 *
 * Clears all coalesce settings
 *
 * Since: 1.26
 */
void
nm_setting_ethtool_clear_coalesce_all (NMSettingEthtool *setting)
{
	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));

	if (nm_setting_gendata_clear_all (NM_SETTING (setting),
	                                  &nm_ethtool_optname_is_coalesce))
		_notify_attributes (setting);
}

/**
 * nm_setting_ethtool_get_ring:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the ring setting to get
 * @out_value (out) (allow-none): value of the ring setting
 *
 * Gets the value of ring setting.
 *
 * Note that @optname must be a valid name for a setting, according to
 * nm_ethtool_optname_is_ring().
 *
 *
 * Returns: %TRUE and places the ring setting value in @out_value or %FALSE if unset.
 *
 * Since: 1.26
 */
gboolean
nm_setting_ethtool_get_ring (NMSettingEthtool *setting,
                             const char *optname,
                             guint32 *out_value)
{
	g_return_val_if_fail (NM_IS_SETTING_ETHTOOL (setting), FALSE);
	g_return_val_if_fail (nm_ethtool_optname_is_ring (optname), FALSE);

	return nm_setting_gendata_get_uint32 (NM_SETTING (setting),
	                                      optname,
	                                      out_value);
}

/**
 * nm_setting_ethtool_set_ring:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the ring setting
 * @value: the new value to set.
 *
 * Sets a ring setting.
 *
 * Note that @optname must be a valid name for a ring setting, according to
 * nm_ethtool_optname_is_ring().
 *
 * Since: 1.26
 */
void
nm_setting_ethtool_set_ring (NMSettingEthtool *setting,
                             const char *optname,
                             guint32 value)
{
	NMEthtoolID ethtool_id;

	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));

	ethtool_id = nm_ethtool_id_get_by_name (optname);

	g_return_if_fail (nm_ethtool_id_is_ring (ethtool_id));

	nm_setting_gendata_set_uint32 (NM_SETTING (setting),
	                               optname,
	                               value);
	_notify_attributes (setting);
}

/**
 * nm_setting_ethtool_clear_ring:
 * @setting: the #NMSettingEthtool
 * @optname: option name of the ring setting
 *
 * Clear a ring setting
 *
 * Since: 1.26
 */
void
nm_setting_ethtool_clear_ring (NMSettingEthtool *setting,
                               const char *optname)
{
	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));
	g_return_if_fail (nm_str_not_empty (optname));

	if (nm_setting_gendata_clear (NM_SETTING (setting), optname))
		_notify_attributes (setting);
}

/**
 * nm_setting_ethtool_clear_ring_all:
 * @setting: the #NMSettingEthtool
 *
 * Clears all ring settings
 *
 * Since: 1.26
 */
void
nm_setting_ethtool_clear_ring_all (NMSettingEthtool *setting)
{
	g_return_if_fail (NM_IS_SETTING_ETHTOOL (setting));

	if (nm_setting_gendata_clear_all (NM_SETTING (setting),
	                                  &nm_ethtool_optname_is_ring))
		_notify_attributes (setting);
}

/*****************************************************************************/

/**
 * nm_setting_ethtool_get_optnames:
 * @setting: the #NMSettingEthtool instance.
 * @out_length: (out) (optional): return location for the number of keys returned, or %NULL
 *
 * This returns all options names that are set. This includes the feature names
 * like %NM_ETHTOOL_OPTNAME_FEATURE_GRO. See nm_ethtool_optname_is_feature() to
 * check whether the option name is valid for offload features.
 *
 * Returns: (array zero-terminated=1) (transfer container): list of set option
 *   names or %NULL if no options are set. The option names are still owned by
 *   @setting and may get invalidated when @setting gets modified.
 *
 * Since: 1.20
 */
const char **
nm_setting_ethtool_get_optnames (NMSettingEthtool *setting,
                                 guint *out_length)
{
	g_return_val_if_fail (NM_IS_SETTING_ETHTOOL (setting), NULL);

	return nm_utils_strdict_get_keys (_nm_setting_gendata_hash (NM_SETTING (setting), FALSE),
	                                  TRUE,
	                                  out_length);
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	GHashTable *hash;
	GHashTableIter iter;
	const char *optname;
	GVariant *variant;

	hash = _nm_setting_gendata_hash (setting, FALSE);
	if (!hash)
		return TRUE;

	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &optname, (gpointer *) &variant)) {
		const GVariantType *variant_type;
		NMEthtoolID ethtool_id;

		ethtool_id = nm_ethtool_id_get_by_name (optname);
		variant_type = get_variant_type_from_ethtool_id (ethtool_id);

		if (!variant_type) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("unsupported ethtool setting"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_ETHTOOL_SETTING_NAME, optname);
			return FALSE;
		}

		if (!g_variant_is_of_type (variant, variant_type)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("setting has invalid variant type"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_ETHTOOL_SETTING_NAME, optname);
			return FALSE;
		}
	}

	return TRUE;
}

/*****************************************************************************/

static const GVariantType *
get_variant_type (const NMSettInfoSetting *sett_info,
                  const char *name,
                  GError **error)
{
	const GVariantType *variant_type;

	variant_type = get_variant_type_from_ethtool_id (nm_ethtool_id_get_by_name (name));

	if (!variant_type) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("unknown ethtool option '%s'"),
		             name);
		return NULL;
	}

	return variant_type;
}

/*****************************************************************************/

static void
nm_setting_ethtool_init (NMSettingEthtool *setting)
{
}

/**
 * nm_setting_ethtool_new:
 *
 * Creates a new #NMSettingEthtool object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingEthtool object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_ethtool_new (void)
{
	return g_object_new (NM_TYPE_SETTING_ETHTOOL, NULL);
}

static void
nm_setting_ethtool_class_init (NMSettingEthtoolClass *klass)
{
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	setting_class->verify = verify;

	_nm_setting_class_commit_full (setting_class,
	                               NM_META_SETTING_TYPE_ETHTOOL,
	                               NM_SETT_INFO_SETT_DETAIL (
	                                 .gendata_info = NM_SETT_INFO_SETT_GENDATA (
	                                     .get_variant_type = get_variant_type,
	                                 ),
	                               ),
	                               NULL);
}
