/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 - 2020, 2022 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ovs-other-config.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"

#define MAX_NUM_KEYS 256

/*****************************************************************************/

/**
 * SECTION:nm-setting-ovs-other-config
 * @short_description: Other-config settings for OVS
 *
 * The #NMSettingOvsOtherConfig object is a #NMSetting subclass that allows to
 * configure other_config settings for OVS. See also "other_config" in the
 * "ovs-vswitchd.conf.db" manual for the keys that OVS supports.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingOvsOtherConfig, PROP_DATA, );

typedef struct {
    GHashTable  *data;
    const char **data_keys;
} NMSettingOvsOtherConfigPrivate;

/**
 * NMSettingOvsOtherConfig:
 *
 * OVS Other Config Settings
 *
 * Since: 1.42
 */
struct _NMSettingOvsOtherConfig {
    NMSetting                      parent;
    NMSettingOvsOtherConfigPrivate _priv;
};

struct _NMSettingOvsOtherConfigClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsOtherConfig, nm_setting_ovs_other_config, NM_TYPE_SETTING)

#define NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingOvsOtherConfig, NM_IS_SETTING_OVS_OTHER_CONFIG)

/*****************************************************************************/

static GHashTable *
_create_data_hash(void)
{
    return g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
}

GHashTable *
_nm_setting_ovs_other_config_get_data(NMSettingOvsOtherConfig *self)
{
    return NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self)->data;
}

/**
 * nm_setting_ovs_other_config_get_data_keys:
 * @setting: the #NMSettingOvsOtherConfig
 * @out_len: (out): the length of the returned array
 *
 * Returns: (array length=out_len) (transfer none): a
 *   %NULL-terminated array containing each key from the table.
 *
 * Since: 1.42
  **/
const char *const *
nm_setting_ovs_other_config_get_data_keys(NMSettingOvsOtherConfig *setting, guint *out_len)
{
    NMSettingOvsOtherConfig        *self = setting;
    NMSettingOvsOtherConfigPrivate *priv;

    NM_SET_OUT(out_len, 0);

    g_return_val_if_fail(NM_IS_SETTING_OVS_OTHER_CONFIG(self), NULL);

    priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);

    if (priv->data_keys) {
        NM_SET_OUT(out_len, g_hash_table_size(priv->data));
        return priv->data_keys;
    }

    priv->data_keys = nm_strdict_get_keys(priv->data, TRUE, out_len);

    /* don't return %NULL, but hijack the @data_keys fields as a pseudo
     * empty strv array. */
    return priv->data_keys ?: ((const char **) &priv->data_keys);
}

/*****************************************************************************/

/**
 * nm_setting_ovs_other_config_get_data:
 * @setting: the #NMSettingOvsOtherConfig instance
 * @key: the other-config to lookup
 *
 * Since: 1.42
 *
 * Returns: (transfer none): the value associated with @key or %NULL if no such
 *   value exists.
 */
const char *
nm_setting_ovs_other_config_get_data(NMSettingOvsOtherConfig *setting, const char *key)
{
    NMSettingOvsOtherConfig        *self = setting;
    NMSettingOvsOtherConfigPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_OVS_OTHER_CONFIG(self), NULL);
    g_return_val_if_fail(key, NULL);

    priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);

    if (!priv->data)
        return NULL;

    return g_hash_table_lookup(priv->data, key);
}

/**
 * nm_setting_ovs_other_config_set_data:
 * @setting: the #NMSettingOvsOtherConfig instance
 * @key: the key to set
 * @val: (allow-none): the value to set or %NULL to clear a key.
 *
 * Since: 1.42
 */
void
nm_setting_ovs_other_config_set_data(NMSettingOvsOtherConfig *setting,
                                     const char              *key,
                                     const char              *val)
{
    NMSettingOvsOtherConfig        *self = setting;
    NMSettingOvsOtherConfigPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_OVS_OTHER_CONFIG(self));

    priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);

    if (!val) {
        if (priv->data && g_hash_table_remove(priv->data, key))
            goto out_changed;
        return;
    }

    if (priv->data) {
        const char *val2;

        if (g_hash_table_lookup_extended(priv->data, key, NULL, (gpointer *) &val2)) {
            if (nm_streq(val, val2))
                return;
        }
    } else
        priv->data = _create_data_hash();

    g_hash_table_insert(priv->data, g_strdup(key), g_strdup(val));

out_changed:
    nm_clear_g_free(&priv->data_keys);
    _notify(self, PROP_DATA);
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingOvsOtherConfig        *self = NM_SETTING_OVS_OTHER_CONFIG(setting);
    NMSettingOvsOtherConfigPrivate *priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);

    if (priv->data) {
        gs_free_error GError *local = NULL;
        const char *const    *keys;
        guint                 len;
        guint                 i;

        keys = nm_setting_ovs_other_config_get_data_keys(self, &len);

        for (i = 0; i < len; i++) {
            const char *key = keys[i];
            const char *val = g_hash_table_lookup(priv->data, key);

            if (!nm_setting_ovs_other_config_check_key(key, &local)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_FAILED,
                            _("invalid key \"%s\": %s"),
                            key,
                            local->message);
            } else if (!nm_setting_ovs_other_config_check_val(val, &local)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_FAILED,
                            _("invalid value for \"%s\": %s"),
                            key,
                            local->message);
            } else
                continue;
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_OVS_OTHER_CONFIG_SETTING_NAME,
                           NM_SETTING_OVS_OTHER_CONFIG_DATA);
            return FALSE;
        }
    }

    if (priv->data && g_hash_table_size(priv->data) > MAX_NUM_KEYS) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("maximum number of entries reached (%u instead of %u)"),
                    g_hash_table_size(priv->data),
                    (unsigned) MAX_NUM_KEYS);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_OTHER_CONFIG_SETTING_NAME,
                       NM_SETTING_OVS_OTHER_CONFIG_DATA);
        return FALSE;
    }

    if (!_nm_setting_ovs_verify_connection_type(NM_TYPE_SETTING_OVS_OTHER_CONFIG,
                                                connection,
                                                error))
        return FALSE;

    return TRUE;
}

static NMTernary
compare_fcn_data(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil)
{
    NMSettingOvsOtherConfigPrivate *priv;
    NMSettingOvsOtherConfigPrivate *pri2;

    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_INFERRABLE))
        return NM_TERNARY_DEFAULT;

    if (!set_b)
        return TRUE;

    priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(NM_SETTING_OVS_OTHER_CONFIG(set_a));
    pri2 = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(NM_SETTING_OVS_OTHER_CONFIG(set_b));
    return nm_utils_hashtable_equal(priv->data, pri2->data, TRUE, g_str_equal);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingOvsOtherConfig        *self = NM_SETTING_OVS_OTHER_CONFIG(object);
    NMSettingOvsOtherConfigPrivate *priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);
    GHashTableIter                  iter;
    GHashTable                     *data;
    const char                     *key;
    const char                     *val;

    switch (prop_id) {
    case PROP_DATA:
        data = _create_data_hash();
        if (priv->data) {
            g_hash_table_iter_init(&iter, priv->data);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val))
                g_hash_table_insert(data, g_strdup(key), g_strdup(val));
        }
        g_value_take_boxed(value, data);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingOvsOtherConfig        *self = NM_SETTING_OVS_OTHER_CONFIG(object);
    NMSettingOvsOtherConfigPrivate *priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_DATA:
    {
        gs_unref_hashtable GHashTable *old = NULL;
        GHashTableIter                 iter;
        GHashTable                    *data;
        const char                    *key;
        const char                    *val;

        nm_clear_g_free(&priv->data_keys);

        old = g_steal_pointer(&priv->data);

        data = g_value_get_boxed(value);
        if (nm_g_hash_table_size(data) <= 0)
            return;

        priv->data = _create_data_hash();
        g_hash_table_iter_init(&iter, data);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val))
            g_hash_table_insert(priv->data, g_strdup(key), g_strdup(val));
        break;
    }
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_ovs_other_config_init(NMSettingOvsOtherConfig *self)
{}

/**
 * nm_setting_ovs_other_config_new:
 *
 * Creates a new #NMSettingOvsOtherConfig object with default values.
 *
 * Returns: (transfer full) (type NMSettingOvsOtherConfig): the new empty
 * #NMSettingOvsOtherConfig object
 *
 * Since: 1.42
 */
NMSetting *
nm_setting_ovs_other_config_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_OTHER_CONFIG, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingOvsOtherConfig        *self = NM_SETTING_OVS_OTHER_CONFIG(object);
    NMSettingOvsOtherConfigPrivate *priv = NM_SETTING_OVS_OTHER_CONFIG_GET_PRIVATE(self);

    g_free(priv->data_keys);
    if (priv->data)
        g_hash_table_unref(priv->data);

    G_OBJECT_CLASS(nm_setting_ovs_other_config_parent_class)->finalize(object);
}

static void
nm_setting_ovs_other_config_class_init(NMSettingOvsOtherConfigClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingOvsOtherConfig:data: (type GHashTable(utf8,utf8))
     *
     * A dictionary of key/value pairs with other_config settings for OVS.
     * See also "other_config" in the "ovs-vswitchd.conf.db" manual for the keys
     * that OVS supports.
     *
     * Since: 1.42
     **/
    obj_properties[PROP_DATA] = g_param_spec_boxed(NM_SETTING_OVS_OTHER_CONFIG_DATA,
                                                   "",
                                                   "",
                                                   G_TYPE_HASH_TABLE,
                                                   G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_DATA],
        NM_SETT_INFO_PROPERT_TYPE_GPROP(NM_G_VARIANT_TYPE("a{ss}"),
                                        .typdata_from_dbus.gprop_fcn = _nm_utils_strdict_from_dbus,
                                        .typdata_to_dbus.gprop_type =
                                            NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_STRDICT,
                                        .compare_fcn   = compare_fcn_data,
                                        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_gprop,
                                        .from_dbus_is_full = TRUE));

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OVS_OTHER_CONFIG,
                             NULL,
                             properties_override,
                             0);
}
