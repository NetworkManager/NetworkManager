/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 - 2020 Red Hat, Inc.
 */

#include "libnm-core/nm-default-libnm-core.h"

#include "nm-setting-ovs-external-ids.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"

#define MAX_NUM_KEYS 256

/*****************************************************************************/

/**
 * SECTION:nm-setting-ovs-external-ids
 * @short_description: External-IDs for OVS database
 *
 * The #NMSettingOvsExternalIDs object is a #NMSetting subclass that allow to
 * configure external ids for OVS.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingOvsExternalIDs, PROP_DATA, );

typedef struct {
    GHashTable * data;
    const char **data_keys;
} NMSettingOvsExternalIDsPrivate;

/**
 * NMSettingOvsExternalIDs:
 *
 * OVS External IDs Settings
 */
struct _NMSettingOvsExternalIDs {
    NMSetting                      parent;
    NMSettingOvsExternalIDsPrivate _priv;
};

struct _NMSettingOvsExternalIDsClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsExternalIDs, nm_setting_ovs_external_ids, NM_TYPE_SETTING)

#define NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMSettingOvsExternalIDs, NM_IS_SETTING_OVS_EXTERNAL_IDS)

/*****************************************************************************/

static gboolean
_exid_key_char_is_regular(char ch)
{
    /* allow words of printable characters, plus some
     * special characters, for example to support base64 encoding. */
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
           || NM_IN_SET(ch, '-', '_', '+', '/', '=', '.');
}

/**
 * nm_setting_ovs_external_ids_check_key:
 * @key: (allow-none): the key to check
 * @error: a #GError, %NULL to ignore.
 *
 * Checks whether @key is a valid key for OVS' external-ids.
 * This means, the key cannot be %NULL, not too large and valid ASCII.
 * Also, only digits and numbers are allowed with a few special
 * characters. They key must also not start with "NM.".
 *
 * Since: 1.30
 *
 * Returns: %TRUE if @key is a valid user data key.
 */
gboolean
nm_setting_ovs_external_ids_check_key(const char *key, GError **error)
{
    gsize len;

    g_return_val_if_fail(!error || !*error, FALSE);

    if (!key || !key[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("missing key"));
        return FALSE;
    }
    len = strlen(key);
    if (len > 255u) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key is too long"));
        return FALSE;
    }
    if (!g_utf8_validate(key, len, NULL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key must be UTF8"));
        return FALSE;
    }
    if (!NM_STRCHAR_ALL(key, ch, _exid_key_char_is_regular(ch))) {
        /* Probably OVS is more forgiving about what makes a valid key for
         * an external-id. However, we are strict (at least, for now). */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key contains invalid characters"));
        return FALSE;
    }

    if (NM_STR_HAS_PREFIX(key, NM_OVS_EXTERNAL_ID_NM_PREFIX)) {
        /* these keys are reserved. */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key cannot start with \"NM.\""));
        return FALSE;
    }

    return TRUE;
}

/**
 * nm_setting_ovs_external_ids_check_val:
 * @val: (allow-none): the value to check
 * @error: a #GError, %NULL to ignore.
 *
 * Checks whether @val is a valid user data value. This means,
 * value is not %NULL, not too large and valid UTF-8.
 *
 * Since: 1.30
 *
 * Returns: %TRUE if @val is a valid user data value.
 */
gboolean
nm_setting_ovs_external_ids_check_val(const char *val, GError **error)
{
    gsize len;

    g_return_val_if_fail(!error || !*error, FALSE);

    if (!val) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value is missing"));
        return FALSE;
    }

    len = strlen(val);
    if (len > (8u * 1024u)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value is too large"));
        return FALSE;
    }

    if (!g_utf8_validate(val, len, NULL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value is not valid UTF8"));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static GHashTable *
_create_data_hash(void)
{
    return g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
}

GHashTable *
_nm_setting_ovs_external_ids_get_data(NMSettingOvsExternalIDs *self)
{
    return NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self)->data;
}

/**
 * nm_setting_ovs_external_ids_get_data_keys:
 * @setting: the #NMSettingOvsExternalIDs
 * @out_len: (out): the length of the returned array
 *
 * Returns: (array length=out_len) (transfer none): a
 *   %NULL-terminated array containing each key from the table.
  **/
const char *const *
nm_setting_ovs_external_ids_get_data_keys(NMSettingOvsExternalIDs *setting, guint *out_len)
{
    NMSettingOvsExternalIDs *       self = setting;
    NMSettingOvsExternalIDsPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_OVS_EXTERNAL_IDS(self), NULL);

    priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);

    if (priv->data_keys) {
        NM_SET_OUT(out_len, g_hash_table_size(priv->data));
        return priv->data_keys;
    }

    priv->data_keys = nm_utils_strdict_get_keys(priv->data, TRUE, out_len);

    /* don't return %NULL, but hijack the @data_keys fields as a pseudo
     * empty strv array. */
    return priv->data_keys ?: ((const char **) &priv->data_keys);
}

/*****************************************************************************/

/**
 * nm_setting_ovs_external_ids_get_data:
 * @setting: the #NMSettingOvsExternalIDs instance
 * @key: the external-id to lookup
 *
 * Since: 1.30
 *
 * Returns: (transfer none): the value associated with @key or %NULL if no such
 *   value exists.
 */
const char *
nm_setting_ovs_external_ids_get_data(NMSettingOvsExternalIDs *setting, const char *key)
{
    NMSettingOvsExternalIDs *       self = setting;
    NMSettingOvsExternalIDsPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_OVS_EXTERNAL_IDS(self), NULL);
    g_return_val_if_fail(key, NULL);

    priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);

    if (!priv->data)
        return NULL;

    return g_hash_table_lookup(priv->data, key);
}

/**
 * nm_setting_ovs_external_ids_set_data:
 * @setting: the #NMSettingOvsExternalIDs instance
 * @key: the key to set
 * @val: (allow-none): the value to set or %NULL to clear a key.
 *
 * Since: 1.30
 */
void
nm_setting_ovs_external_ids_set_data(NMSettingOvsExternalIDs *setting,
                                     const char *             key,
                                     const char *             val)
{
    NMSettingOvsExternalIDs *       self = setting;
    NMSettingOvsExternalIDsPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_OVS_EXTERNAL_IDS(self));

    priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);

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
    NMSettingOvsExternalIDs *       self = NM_SETTING_OVS_EXTERNAL_IDS(setting);
    NMSettingOvsExternalIDsPrivate *priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);

    if (priv->data) {
        gs_free_error GError *local = NULL;
        GHashTableIter        iter;
        const char *          key;
        const char *          val;

        g_hash_table_iter_init(&iter, priv->data);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
            if (!nm_setting_ovs_external_ids_check_key(key, &local)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_FAILED,
                            _("invalid key \"%s\": %s"),
                            key,
                            local->message);
            } else if (!nm_setting_ovs_external_ids_check_val(val, &local)) {
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
                           NM_SETTING_OVS_EXTERNAL_IDS_SETTING_NAME,
                           NM_SETTING_OVS_EXTERNAL_IDS_DATA);
            return FALSE;
        }
    }

    if (priv->data && g_hash_table_size(priv->data) > MAX_NUM_KEYS) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("maximum number of user data entries reached (%u instead of %u)"),
                    g_hash_table_size(priv->data),
                    (unsigned) MAX_NUM_KEYS);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_EXTERNAL_IDS_SETTING_NAME,
                       NM_SETTING_OVS_EXTERNAL_IDS_DATA);
        return FALSE;
    }

    if (connection) {
        NMSettingConnection *s_con;
        const char *         type;
        const char *         slave_type;

        type = nm_connection_get_connection_type(connection);
        if (!type) {
            NMSetting *s_base;

            s_base = _nm_connection_find_base_type_setting(connection);
            if (s_base)
                type = nm_setting_get_name(s_base);
        }
        if (NM_IN_STRSET(type,
                         NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                         NM_SETTING_OVS_PORT_SETTING_NAME,
                         NM_SETTING_OVS_INTERFACE_SETTING_NAME))
            goto connection_type_is_good;

        if ((s_con = nm_connection_get_setting_connection(connection))
            && _nm_connection_detect_slave_type_full(s_con,
                                                     connection,
                                                     &slave_type,
                                                     NULL,
                                                     NULL,
                                                     NULL,
                                                     NULL)
            && nm_streq0(slave_type, NM_SETTING_OVS_PORT_SETTING_NAME))
            goto connection_type_is_good;

        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("OVS external IDs can only be added to a profile of type OVS "
                              "bridge/port/interface or to OVS system interface"));
        return FALSE;
    }
connection_type_is_good:

    return TRUE;
}

static NMTernary
compare_property(const NMSettInfoSetting *sett_info,
                 guint                    property_idx,
                 NMConnection *           con_a,
                 NMSetting *              set_a,
                 NMConnection *           con_b,
                 NMSetting *              set_b,
                 NMSettingCompareFlags    flags)
{
    NMSettingOvsExternalIDsPrivate *priv;
    NMSettingOvsExternalIDsPrivate *pri2;

    if (nm_streq(sett_info->property_infos[property_idx].name, NM_SETTING_OVS_EXTERNAL_IDS_DATA)) {
        if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_INFERRABLE))
            return NM_TERNARY_DEFAULT;

        if (!set_b)
            return TRUE;

        priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(NM_SETTING_OVS_EXTERNAL_IDS(set_a));
        pri2 = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(NM_SETTING_OVS_EXTERNAL_IDS(set_b));
        return nm_utils_hashtable_equal(priv->data, pri2->data, TRUE, g_str_equal);
    }

    return NM_SETTING_CLASS(nm_setting_ovs_external_ids_parent_class)
        ->compare_property(sett_info, property_idx, con_a, set_a, con_b, set_b, flags);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingOvsExternalIDs *       self = NM_SETTING_OVS_EXTERNAL_IDS(object);
    NMSettingOvsExternalIDsPrivate *priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);
    GHashTableIter                  iter;
    GHashTable *                    data;
    const char *                    key;
    const char *                    val;

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
    NMSettingOvsExternalIDs *       self = NM_SETTING_OVS_EXTERNAL_IDS(object);
    NMSettingOvsExternalIDsPrivate *priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_DATA:
    {
        gs_unref_hashtable GHashTable *old = NULL;
        GHashTableIter                 iter;
        GHashTable *                   data;
        const char *                   key;
        const char *                   val;

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
nm_setting_ovs_external_ids_init(NMSettingOvsExternalIDs *self)
{}

/**
 * nm_setting_ovs_external_ids_new:
 *
 * Creates a new #NMSettingOvsExternalIDs object with default values.
 *
 * Returns: (transfer full) (type NMSettingOvsExternalIDs): the new empty
 * #NMSettingOvsExternalIDs object
 *
 * Since: 1.30
 */
NMSetting *
nm_setting_ovs_external_ids_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_EXTERNAL_IDS, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingOvsExternalIDs *       self = NM_SETTING_OVS_EXTERNAL_IDS(object);
    NMSettingOvsExternalIDsPrivate *priv = NM_SETTING_OVS_EXTERNAL_IDS_GET_PRIVATE(self);

    g_free(priv->data_keys);
    if (priv->data)
        g_hash_table_unref(priv->data);

    G_OBJECT_CLASS(nm_setting_ovs_external_ids_parent_class)->finalize(object);
}

static void
nm_setting_ovs_external_ids_class_init(NMSettingOvsExternalIDsClass *klass)
{
    GObjectClass *  object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray *        properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->compare_property = compare_property;
    setting_class->verify           = verify;

    /**
     * NMSettingOvsExternalIDs:data: (type GHashTable(utf8,utf8))
     *
     * A dictionary of key/value pairs with exernal-ids for OVS.
     *
     * Since: 1.30
     **/
    obj_properties[PROP_DATA] = g_param_spec_boxed(NM_SETTING_OVS_EXTERNAL_IDS_DATA,
                                                   "",
                                                   "",
                                                   G_TYPE_HASH_TABLE,
                                                   G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(properties_override,
                                 obj_properties[PROP_DATA],
                                 &nm_sett_info_propert_type_strdict);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit_full(setting_class,
                                  NM_META_SETTING_TYPE_OVS_EXTERNAL_IDS,
                                  NULL,
                                  properties_override);
}
