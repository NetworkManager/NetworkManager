/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-core/nm-default-libnm-core.h"

#include "nm-setting-ethtool.h"

#include "nm-setting-private.h"
#include "nm-base/nm-ethtool-base.h"

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
get_variant_type_from_ethtool_id(NMEthtoolID ethtool_id)
{
    if (nm_ethtool_id_is_feature(ethtool_id))
        return G_VARIANT_TYPE_BOOLEAN;

    if (nm_ethtool_id_is_coalesce(ethtool_id) || nm_ethtool_id_is_ring(ethtool_id))
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
nm_ethtool_optname_is_feature(const char *optname)
{
    return optname && nm_ethtool_id_is_feature(nm_ethtool_id_get_by_name(optname));
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
nm_ethtool_optname_is_coalesce(const char *optname)
{
    return optname && nm_ethtool_id_is_coalesce(nm_ethtool_id_get_by_name(optname));
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
nm_ethtool_optname_is_ring(const char *optname)
{
    return optname && nm_ethtool_id_is_ring(nm_ethtool_id_get_by_name(optname));
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

G_DEFINE_TYPE(NMSettingEthtool, nm_setting_ethtool, NM_TYPE_SETTING)

#define NM_SETTING_ETHTOOL_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingEthtool, NM_IS_SETTING_ETHTOOL, NMSetting)

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
 *
 * Deprecated: 1.26: use nm_setting_option_get_boolean() instead.
 */
NMTernary
nm_setting_ethtool_get_feature(NMSettingEthtool *setting, const char *optname)
{
    gboolean v;

    g_return_val_if_fail(NM_IS_SETTING_ETHTOOL(setting), NM_TERNARY_DEFAULT);
    g_return_val_if_fail(optname && nm_ethtool_optname_is_feature(optname), NM_TERNARY_DEFAULT);

    if (!nm_setting_option_get_boolean(NM_SETTING(setting), optname, &v))
        return NM_TERNARY_DEFAULT;
    return v ? NM_TERNARY_TRUE : NM_TERNARY_FALSE;
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
 *
 * Deprecated: 1.26: use nm_setting_option_set() or nm_setting_option_set_boolean() instead.
 */
void
nm_setting_ethtool_set_feature(NMSettingEthtool *setting, const char *optname, NMTernary value)
{
    g_return_if_fail(NM_IS_SETTING_ETHTOOL(setting));
    g_return_if_fail(optname && nm_ethtool_optname_is_feature(optname));
    g_return_if_fail(NM_IN_SET(value, NM_TERNARY_DEFAULT, NM_TERNARY_FALSE, NM_TERNARY_TRUE));

    if (value == NM_TERNARY_DEFAULT)
        nm_setting_option_set(NM_SETTING(setting), optname, NULL);
    else
        nm_setting_option_set_boolean(NM_SETTING(setting), optname, (value != NM_TERNARY_FALSE));
}

/**
 * nm_setting_ethtool_clear_features:
 * @setting: the #NMSettingEthtool
 *
 * Clears all offload features settings
 *
 * Since: 1.14
 *
 * Deprecated: 1.26: use nm_setting_option_clear_by_name() with nm_ethtool_optname_is_feature() predicate instead.
 */
void
nm_setting_ethtool_clear_features(NMSettingEthtool *setting)
{
    g_return_if_fail(NM_IS_SETTING_ETHTOOL(setting));

    nm_setting_option_clear_by_name(NM_SETTING(setting), nm_ethtool_optname_is_feature);
}

/*****************************************************************************/

guint
nm_setting_ethtool_init_features(
    NMSettingEthtool *setting,
    NMOptionBool *    requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */)
{
    GHashTable *   hash;
    GHashTableIter iter;
    guint          i;
    guint          n_req = 0;
    const char *   name;
    GVariant *     variant;

    nm_assert(NM_IS_SETTING_ETHTOOL(setting));
    nm_assert(requested);

    for (i = 0; i < _NM_ETHTOOL_ID_FEATURE_NUM; i++)
        requested[i] = NM_OPTION_BOOL_DEFAULT;

    hash = _nm_setting_option_hash(NM_SETTING(setting), FALSE);
    if (!hash)
        return 0;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &name, (gpointer *) &variant)) {
        NMEthtoolID ethtool_id = nm_ethtool_id_get_by_name(name);

        if (!nm_ethtool_id_is_feature(ethtool_id))
            continue;
        if (!g_variant_is_of_type(variant, G_VARIANT_TYPE_BOOLEAN))
            continue;

        requested[_NM_ETHTOOL_ID_FEATURE_AS_IDX(ethtool_id)] =
            g_variant_get_boolean(variant) ? NM_OPTION_BOOL_TRUE : NM_OPTION_BOOL_FALSE;
        n_req++;
    }

    return n_req;
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
 *
 * Deprecated: 1.26: use nm_setting_option_get_all_names() instead.
 */
const char **
nm_setting_ethtool_get_optnames(NMSettingEthtool *setting, guint *out_length)
{
    const char *const *names;
    guint              len = 0;

    g_return_val_if_fail(NM_IS_SETTING_ETHTOOL(setting), NULL);

    names = nm_setting_option_get_all_names(NM_SETTING(setting), &len);
    NM_SET_OUT(out_length, len);
    return len > 0 ? nm_memdup(names, sizeof(names[0]) * (((gsize) len) + 1u)) : NULL;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    const char *const *optnames;
    GVariant *const *  variants;
    guint              len;
    guint              i;

    len = _nm_setting_option_get_all(setting, &optnames, &variants);

    for (i = 0; i < len; i++) {
        const char *        optname = optnames[i];
        GVariant *          variant = variants[i];
        const GVariantType *variant_type;
        NMEthtoolID         ethtool_id;

        ethtool_id   = nm_ethtool_id_get_by_name(optname);
        variant_type = get_variant_type_from_ethtool_id(ethtool_id);

        if (!variant_type) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("unsupported ethtool setting"));
            g_prefix_error(error, "%s.%s: ", NM_SETTING_ETHTOOL_SETTING_NAME, optname);
            return FALSE;
        }

        if (!g_variant_is_of_type(variant, variant_type)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("setting has invalid variant type"));
            g_prefix_error(error, "%s.%s: ", NM_SETTING_ETHTOOL_SETTING_NAME, optname);
            return FALSE;
        }

        if (NM_IN_SET(ethtool_id,
                      NM_ETHTOOL_ID_COALESCE_ADAPTIVE_RX,
                      NM_ETHTOOL_ID_COALESCE_ADAPTIVE_TX)) {
            if (!NM_IN_SET(g_variant_get_uint32(variant), 0, 1)) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("coalesce option must be either 0 or 1"));
                g_prefix_error(error, "%s.%s: ", NM_SETTING_ETHTOOL_SETTING_NAME, optname);
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*****************************************************************************/

static const GVariantType *
get_variant_type(const NMSettInfoSetting *sett_info, const char *name, GError **error)
{
    const GVariantType *variant_type;

    variant_type = get_variant_type_from_ethtool_id(nm_ethtool_id_get_by_name(name));

    if (!variant_type) {
        g_set_error(error,
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
nm_setting_ethtool_init(NMSettingEthtool *setting)
{}

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
nm_setting_ethtool_new(void)
{
    return g_object_new(NM_TYPE_SETTING_ETHTOOL, NULL);
}

static void
nm_setting_ethtool_class_init(NMSettingEthtoolClass *klass)
{
    NMSettingClass *setting_class = NM_SETTING_CLASS(klass);

    setting_class->verify = verify;

    _nm_setting_class_commit_full(
        setting_class,
        NM_META_SETTING_TYPE_ETHTOOL,
        NM_SETT_INFO_SETT_DETAIL(.gendata_info =
                                     NM_SETT_INFO_SETT_GENDATA(.get_variant_type =
                                                                   get_variant_type, ), ),
        NULL);
}
