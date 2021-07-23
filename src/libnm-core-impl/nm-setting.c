/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting.h"

#include "nm-setting-private.h"
#include "nm-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-utils-private.h"
#include "nm-property-compare.h"

/**
 * SECTION:nm-setting
 * @short_description: Describes related configuration information
 *
 * Each #NMSetting contains properties that describe configuration that applies
 * to a specific network layer (like IPv4 or IPv6 configuration) or device type
 * (like Ethernet, or Wi-Fi).  A collection of individual settings together
 * make up an #NMConnection. Each property is strongly typed and usually has
 * a number of allowed values.  See each #NMSetting subclass for a description
 * of properties and allowed values.
 */

/*****************************************************************************/

typedef struct {
    GHashTable * hash;
    const char **names;
    GVariant **  values;
} GenData;

typedef struct {
    const char *      name;
    GType             type;
    NMSettingPriority priority;
} SettingInfo;

NM_GOBJECT_PROPERTIES_DEFINE(NMSetting, PROP_NAME, );

typedef struct {
    GenData *gendata;
} NMSettingPrivate;

G_DEFINE_ABSTRACT_TYPE(NMSetting, nm_setting, G_TYPE_OBJECT)

#define NM_SETTING_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING, NMSettingPrivate))

/*****************************************************************************/

static GenData *_gendata_hash(NMSetting *setting, gboolean create_if_necessary);
static gboolean set_property_from_dbus(const NMSettInfoProperty *property_info,
                                       GVariant *                src_value,
                                       GValue *                  dst_value);

/*****************************************************************************/

NMSettingPriority
_nm_setting_get_setting_priority(NMSetting *setting)
{
    const NMMetaSettingInfo *setting_info;

    g_return_val_if_fail(NM_IS_SETTING(setting), NM_SETTING_PRIORITY_INVALID);

    setting_info = NM_SETTING_GET_CLASS(setting)->setting_info;
    return setting_info ? setting_info->setting_priority : NM_SETTING_PRIORITY_INVALID;
}

NMSettingPriority
_nm_setting_get_base_type_priority(NMSetting *setting)
{
    g_return_val_if_fail(NM_IS_SETTING(setting), NM_SETTING_PRIORITY_INVALID);

    return nm_meta_setting_info_get_base_type_priority(NM_SETTING_GET_CLASS(setting)->setting_info,
                                                       G_OBJECT_TYPE(setting));
}

/**
 * nm_setting_lookup_type:
 * @name: a setting name
 *
 * Returns the #GType of the setting's class for a given setting name.
 *
 * Returns: the #GType of the setting's class, or %G_TYPE_INVALID if
 *   @name is not recognized.
 **/
GType
nm_setting_lookup_type(const char *name)
{
    const NMMetaSettingInfo *setting_info;

    g_return_val_if_fail(name, G_TYPE_INVALID);

    setting_info = nm_meta_setting_infos_by_name(name);
    return setting_info ? setting_info->get_setting_gtype() : G_TYPE_INVALID;
}

int
_nm_setting_compare_priority(gconstpointer a, gconstpointer b)
{
    NMSettingPriority prio_a, prio_b;

    prio_a = _nm_setting_get_setting_priority((NMSetting *) a);
    prio_b = _nm_setting_get_setting_priority((NMSetting *) b);

    if (prio_a < prio_b)
        return -1;
    else if (prio_a == prio_b)
        return 0;
    return 1;
}

/*****************************************************************************/

gboolean
_nm_setting_slave_type_is_valid(const char *slave_type, const char **out_port_type)
{
    const char *port_type = NULL;
    gboolean    found     = TRUE;

    if (!slave_type)
        found = FALSE;
    else if (NM_IN_STRSET(slave_type, NM_SETTING_BOND_SETTING_NAME, NM_SETTING_VRF_SETTING_NAME)) {
        /* pass */
    } else if (nm_streq(slave_type, NM_SETTING_BRIDGE_SETTING_NAME))
        port_type = NM_SETTING_BRIDGE_PORT_SETTING_NAME;
    else if (nm_streq(slave_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME))
        port_type = NM_SETTING_OVS_PORT_SETTING_NAME;
    else if (nm_streq(slave_type, NM_SETTING_OVS_PORT_SETTING_NAME))
        port_type = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
    else if (nm_streq(slave_type, NM_SETTING_TEAM_SETTING_NAME))
        port_type = NM_SETTING_TEAM_PORT_SETTING_NAME;
    else
        found = FALSE;

    if (out_port_type)
        *out_port_type = port_type;
    return found;
}

/*****************************************************************************/

static const NMSettInfoProperty *
_nm_sett_info_property_find_in_array(const NMSettInfoProperty *properties,
                                     guint                     len,
                                     const char *              name)
{
    guint i;

    for (i = 0; i < len; i++) {
        if (nm_streq(name, properties[i].name))
            return &properties[i];
    }
    return NULL;
}

gboolean
_nm_properties_override_assert(const NMSettInfoProperty *prop_info)
{
#if NM_MORE_ASSERTS
    nm_assert(prop_info);
    nm_assert((!!prop_info->name) != (!!prop_info->param_spec));
    nm_assert(!prop_info->param_spec || !prop_info->name
              || nm_streq0(prop_info->name, prop_info->param_spec->name));

    if (prop_info->property_type) {
        const NMSettInfoPropertType *property_type = prop_info->property_type;

        /* we always require a dbus_type. */
        nm_assert(property_type->dbus_type);

        if (property_type->typdata_from_dbus.gprop_fcn)
            nm_assert(property_type->from_dbus_fcn == _nm_setting_property_from_dbus_fcn_gprop);

        if (property_type->from_dbus_fcn == _nm_setting_property_from_dbus_fcn_gprop)
            nm_assert(prop_info->param_spec);

        if (!prop_info->param_spec) {
            /* if we don't have a param_spec, we cannot have typdata_from_dbus.gprop_fcn. */
            nm_assert(property_type->from_dbus_fcn || !property_type->typdata_from_dbus.gprop_fcn);
        }
    }
#endif
    return TRUE;
}

static NMSettInfoSetting _sett_info_settings[_NM_META_SETTING_TYPE_NUM];

const NMSettInfoSetting *
nmtst_sett_info_settings(void)
{
    return _sett_info_settings;
}

static int
_property_infos_sort_cmp_setting_connection(gconstpointer p_a,
                                            gconstpointer p_b,
                                            gpointer      user_data)
{
    const NMSettInfoProperty *a = *((const NMSettInfoProperty *const *) p_a);
    const NMSettInfoProperty *b = *((const NMSettInfoProperty *const *) p_b);
    int                       c_name;

    c_name = strcmp(a->name, b->name);
    nm_assert(c_name != 0);

#define CMP_AND_RETURN(n_a, n_b, name)         \
    G_STMT_START                               \
    {                                          \
        gboolean _is = nm_streq(n_a, "" name); \
                                               \
        if (_is || nm_streq(n_b, "" name))     \
            return _is ? -1 : 1;               \
    }                                          \
    G_STMT_END

    /* for [connection], report first id, uuid, type in that order. */
    if (c_name != 0) {
        CMP_AND_RETURN(a->name, b->name, NM_SETTING_CONNECTION_ID);
        CMP_AND_RETURN(a->name, b->name, NM_SETTING_CONNECTION_UUID);
        CMP_AND_RETURN(a->name, b->name, NM_SETTING_CONNECTION_TYPE);
    }

#undef CMP_AND_RETURN

    return c_name;
}

static const NMSettInfoProperty *const *
_property_infos_sort(const NMSettInfoProperty *property_infos,
                     guint16                   property_infos_len,
                     NMSettingClass *          setting_class)
{
    const NMSettInfoProperty **arr;
    guint16                    i;

#if NM_MORE_ASSERTS > 5
    /* assert that the property names are all unique and sorted. */
    for (i = 0; i < property_infos_len; i++) {
        if (property_infos[i].param_spec)
            nm_assert(nm_streq(property_infos[i].name, property_infos[i].param_spec->name));
        if (i > 0)
            nm_assert(strcmp(property_infos[i - 1].name, property_infos[i].name) < 0);
    }
#endif

    if (property_infos_len <= 1)
        return NULL;
    if (G_TYPE_FROM_CLASS(setting_class) != NM_TYPE_SETTING_CONNECTION) {
        /* we only do something special for certain setting types. This one,
         * has just alphabetical sorting. */
        return NULL;
    }

    arr = g_new(const NMSettInfoProperty *, property_infos_len);
    for (i = 0; i < property_infos_len; i++)
        arr[i] = &property_infos[i];

    g_qsort_with_data(arr,
                      property_infos_len,
                      sizeof(const NMSettInfoProperty *),
                      _property_infos_sort_cmp_setting_connection,
                      NULL);
    return arr;
}

static int
_property_lookup_by_param_spec_sort(gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
    const NMSettInfoPropertLookupByParamSpec *a = p_a;
    const NMSettInfoPropertLookupByParamSpec *b = p_b;

    NM_CMP_DIRECT(a->param_spec_as_uint, b->param_spec_as_uint);
    return 0;
}

void
_nm_setting_class_commit(NMSettingClass *            setting_class,
                         NMMetaSettingType           meta_type,
                         const NMSettInfoSettDetail *detail,
                         GArray *                    properties_override,
                         gint16                      private_offset)
{
    NMSettInfoSetting *sett_info;
    gs_free GParamSpec **               property_specs = NULL;
    guint                               n_property_specs;
    NMSettInfoPropertLookupByParamSpec *lookup_by_iter;
    guint                               override_len;
    guint                               i;
    guint16                             j;

    nm_assert(NM_IS_SETTING_CLASS(setting_class));
    nm_assert(!setting_class->setting_info);

    nm_assert(meta_type < G_N_ELEMENTS(_sett_info_settings));

    sett_info = &_sett_info_settings[meta_type];

    nm_assert(!sett_info->setting_class);
    nm_assert(!sett_info->property_infos_len);
    nm_assert(!sett_info->property_infos);

    property_specs =
        g_object_class_list_properties(G_OBJECT_CLASS(setting_class), &n_property_specs);

    if (!properties_override) {
        override_len        = 0;
        properties_override = _nm_sett_info_property_override_create_array_sized(n_property_specs);
    } else {
        override_len = properties_override->len;

        for (i = 0; i < override_len; i++) {
            NMSettInfoProperty *p = &g_array_index(properties_override, NMSettInfoProperty, i);

            nm_assert((!!p->name) != (!!p->param_spec));

            if (!p->name) {
                nm_assert(p->param_spec);
                p->name = p->param_spec->name;
            } else
                nm_assert(!p->param_spec);
        }
    }

#if NM_MORE_ASSERTS > 10
    /* assert that properties_override is constructed consistently. */
    for (i = 0; i < override_len; i++) {
        const NMSettInfoProperty *p = &g_array_index(properties_override, NMSettInfoProperty, i);
        gboolean                  found = FALSE;
        guint                     k;

        nm_assert(
            !_nm_sett_info_property_find_in_array((NMSettInfoProperty *) properties_override->data,
                                                  i,
                                                  p->name));
        for (k = 0; k < n_property_specs; k++) {
            if (!nm_streq(property_specs[k]->name, p->name))
                continue;
            nm_assert(!found);
            found = TRUE;
            nm_assert(p->param_spec == property_specs[k]);
        }
        nm_assert(found == (p->param_spec != NULL));
    }
#endif

    for (i = 0; i < n_property_specs; i++) {
        const char *        name = property_specs[i]->name;
        NMSettInfoProperty *p;

        if (_nm_sett_info_property_find_in_array((NMSettInfoProperty *) properties_override->data,
                                                 override_len,
                                                 name))
            continue;

        g_array_set_size(properties_override, properties_override->len + 1);
        p = &g_array_index(properties_override, NMSettInfoProperty, properties_override->len - 1);
        memset(p, 0, sizeof(*p));
        p->name       = name;
        p->param_spec = property_specs[i];
    }

    for (i = 0; i < properties_override->len; i++) {
        NMSettInfoProperty *p = &g_array_index(properties_override, NMSettInfoProperty, i);
        GType               vtype;

        if (p->property_type)
            goto has_property_type;

        nm_assert(p->param_spec);

        vtype = p->param_spec->value_type;
        if (vtype == G_TYPE_BOOLEAN)
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_BOOLEAN,
                .compare_fcn       = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full = TRUE);
        else if (vtype == G_TYPE_UCHAR)
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_BYTE,
                .compare_fcn       = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full = TRUE);
        else if (vtype == G_TYPE_INT)
            p->property_type = &nm_sett_info_propert_type_plain_i;
        else if (vtype == G_TYPE_UINT)
            p->property_type = &nm_sett_info_propert_type_plain_u;
        else if (vtype == G_TYPE_INT64)
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_INT64,
                .compare_fcn       = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full = TRUE);
        else if (vtype == G_TYPE_UINT64)
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_UINT64,
                .compare_fcn       = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full = TRUE);
        else if (vtype == G_TYPE_STRING) {
            nm_assert(nm_streq(p->name, NM_SETTING_NAME)
                      == (!NM_FLAGS_HAS(p->param_spec->flags, G_PARAM_WRITABLE)));
            if (!NM_FLAGS_HAS(p->param_spec->flags, G_PARAM_WRITABLE))
                p->property_type = &nm_sett_info_propert_type_setting_name;
            else {
                p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                    G_VARIANT_TYPE_STRING,
                    .compare_fcn       = _nm_setting_property_compare_fcn_default,
                    .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                    .from_dbus_is_full = TRUE);
            }
        } else if (vtype == G_TYPE_DOUBLE)
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_DOUBLE,
                .compare_fcn       = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full = TRUE);
        else if (vtype == G_TYPE_STRV)
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_STRING_ARRAY,
                .compare_fcn       = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn     = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full = TRUE);
        else if (vtype == G_TYPE_BYTES) {
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_BYTESTRING,
                .typdata_to_dbus.gprop_type = NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_BYTES,
                .compare_fcn                = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn              = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full          = TRUE);
        } else if (g_type_is_a(vtype, G_TYPE_ENUM)) {
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_INT32,
                .typdata_to_dbus.gprop_type = NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_ENUM,
                .compare_fcn                = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn              = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full          = TRUE);
        } else if (g_type_is_a(vtype, G_TYPE_FLAGS)) {
            p->property_type = NM_SETT_INFO_PROPERT_TYPE_GPROP(
                G_VARIANT_TYPE_UINT32,
                .typdata_to_dbus.gprop_type = NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_FLAGS,
                .compare_fcn                = _nm_setting_property_compare_fcn_default,
                .from_dbus_fcn              = _nm_setting_property_from_dbus_fcn_gprop,
                .from_dbus_is_full          = TRUE);
        } else
            nm_assert_not_reached();

has_property_type:
        nm_assert(p->property_type);
        nm_assert(p->property_type->dbus_type);
        nm_assert(g_variant_type_string_is_valid((const char *) p->property_type->dbus_type));
    }

    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(NMSettInfoProperty, name) == 0);
    g_array_sort(properties_override, nm_strcmp_p);

    setting_class->setting_info = &nm_meta_setting_infos[meta_type];
    sett_info->setting_class    = setting_class;

    if (private_offset == NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS) {
        int o;

        o = g_type_class_get_instance_private_offset(setting_class);
        nm_assert(o != NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
        nm_assert(o > G_MININT16);
        nm_assert(o < 0);
        private_offset = o;
    }
    sett_info->private_offset = private_offset;

    if (detail)
        sett_info->detail = *detail;
    nm_assert(properties_override->len > 0);
    nm_assert(properties_override->len < G_MAXUINT16);
    sett_info->property_infos_len = properties_override->len;
    sett_info->property_infos =
        nm_memdup(properties_override->data, sizeof(NMSettInfoProperty) * properties_override->len);

    sett_info->property_infos_sorted = _property_infos_sort(sett_info->property_infos,
                                                            sett_info->property_infos_len,
                                                            setting_class);

    nm_assert(sett_info->property_infos_len < G_MAXUINT16);
    sett_info->property_lookup_by_param_spec_len = 0;
    for (j = 0; j < sett_info->property_infos_len; j++) {
        if (sett_info->property_infos[j].param_spec) {
            sett_info->property_lookup_by_param_spec_len++;
        }
    }
    sett_info->property_lookup_by_param_spec =
        g_new(NMSettInfoPropertLookupByParamSpec, sett_info->property_lookup_by_param_spec_len);
    lookup_by_iter =
        (NMSettInfoPropertLookupByParamSpec *) sett_info->property_lookup_by_param_spec;
    for (j = 0; j < sett_info->property_infos_len; j++) {
        const NMSettInfoProperty *property_info = &sett_info->property_infos[j];

        if (property_info->param_spec) {
            *(lookup_by_iter++) = (NMSettInfoPropertLookupByParamSpec){
                .param_spec_as_uint = (uintptr_t) ((gpointer) property_info->param_spec),
                .property_info      = property_info,
            };
        }
    }
    g_qsort_with_data(sett_info->property_lookup_by_param_spec,
                      sett_info->property_lookup_by_param_spec_len,
                      sizeof(NMSettInfoPropertLookupByParamSpec),
                      _property_lookup_by_param_spec_sort,
                      NULL);

    g_array_free(properties_override, TRUE);
}

const NMSettInfoProperty *
_nm_sett_info_setting_get_property_info(const NMSettInfoSetting *sett_info,
                                        const char *             property_name)
{
    const NMSettInfoProperty *property_info;
    gssize                    idx;

    nm_assert(property_name);

    if (!sett_info)
        return NULL;

    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(NMSettInfoProperty, name) == 0);
    idx = nm_utils_array_find_binary_search(sett_info->property_infos,
                                            sizeof(NMSettInfoProperty),
                                            sett_info->property_infos_len,
                                            &property_name,
                                            nm_strcmp_p_with_data,
                                            NULL);

    if (idx < 0)
        return NULL;

    property_info = &sett_info->property_infos[idx];

    nm_assert(idx == 0 || strcmp(property_info[-1].name, property_info[0].name) < 0);
    nm_assert(idx == sett_info->property_infos_len - 1
              || strcmp(property_info[0].name, property_info[1].name) < 0);

    return property_info;
}

const NMSettInfoSetting *
_nm_setting_class_get_sett_info(NMSettingClass *setting_class)
{
    const NMSettInfoSetting *sett_info;

    if (!NM_IS_SETTING_CLASS(setting_class) || !setting_class->setting_info)
        return NULL;

    nm_assert(setting_class->setting_info->meta_type < G_N_ELEMENTS(_sett_info_settings));
    sett_info = &_sett_info_settings[setting_class->setting_info->meta_type];
    nm_assert(sett_info->setting_class == setting_class);
    return sett_info;
}

const NMSettInfoProperty *
_nm_sett_info_property_lookup_by_param_spec(const NMSettInfoSetting *sett_info,
                                            const GParamSpec *       param_spec)
{
    NMSettInfoPropertLookupByParamSpec needle;
    int                                imin;
    int                                imax;
    int                                imid;
    int                                cmp;

    nm_assert(sett_info);
    nm_assert(param_spec);

    /* ensure that "int" is large enough to contain the index variables. */
    G_STATIC_ASSERT_EXPR(sizeof(int) > sizeof(sett_info->property_lookup_by_param_spec_len));

    if (sett_info->property_lookup_by_param_spec_len == 0)
        return NULL;

    needle.param_spec_as_uint = (uintptr_t) ((gpointer) param_spec);

    imin = 0;
    imax = sett_info->property_lookup_by_param_spec_len - 1;
    while (imin <= imax) {
        imid = imin + (imax - imin) / 2;

        cmp = _property_lookup_by_param_spec_sort(&sett_info->property_lookup_by_param_spec[imid],
                                                  &needle,
                                                  NULL);
        if (cmp == 0)
            return sett_info->property_lookup_by_param_spec[imid].property_info;

        if (cmp < 0)
            imin = imid + 1;
        else
            imax = imid - 1;
    }

    return NULL;
}

/*****************************************************************************/

void
_nm_setting_emit_property_changed(NMSetting *setting)
{
    /* Some settings have "properties" that are not implemented as GObject properties.
     *
     * For example:
     *
     *   - gendata-base settings like NMSettingEthtool. Here properties are just
     *     GVariant values in the gendata hash.
     *
     *   - NMSettingWireGuard's peers are not backed by a GObject property. Instead
     *     there is C-API to access/modify peers.
     *
     * We still want to emit property-changed notifications for such properties,
     * in particular because NMConnection registers to such signals to re-emit
     * it as NM_CONNECTION_CHANGED signal. In fact, there are unlikely any other
     * uses of such a property-changed signal, because generally it doesn't make
     * too much sense.
     *
     * So, instead of adding yet another (artificial) signal "setting-changed",
     * hijack the "notify" signal and just notify about changes of the "name".
     * Of course, the "name" doesn't really ever change, because it's tied to
     * the GObject's type.
     */
    _notify(setting, PROP_NAME);
}

/*****************************************************************************/

gboolean
_nm_setting_use_legacy_property(NMSetting * setting,
                                GVariant *  connection_dict,
                                const char *legacy_property,
                                const char *new_property)
{
    GVariant *setting_dict, *value;

    setting_dict = g_variant_lookup_value(connection_dict,
                                          nm_setting_get_name(NM_SETTING(setting)),
                                          NM_VARIANT_TYPE_SETTING);
    g_return_val_if_fail(setting_dict != NULL, FALSE);

    /* If the new property isn't set, we have to use the legacy property. */
    value = g_variant_lookup_value(setting_dict, new_property, NULL);
    if (!value) {
        g_variant_unref(setting_dict);
        return TRUE;
    }
    g_variant_unref(value);

    /* Otherwise, clients always prefer new properties sent from the daemon. */
    if (!_nm_utils_is_manager_process) {
        g_variant_unref(setting_dict);
        return FALSE;
    }

    /* The daemon prefers the legacy property if it exists. */
    value = g_variant_lookup_value(setting_dict, legacy_property, NULL);
    g_variant_unref(setting_dict);

    if (value) {
        g_variant_unref(value);
        return TRUE;
    } else
        return FALSE;
}

/*****************************************************************************/

static gboolean
_property_direct_set_string(const NMSettInfoProperty *property_info, char **dst, const char *src)
{
    if (property_info->direct_set_string_ascii_strdown)
        return nm_utils_strdup_reset_take(dst, src ? g_ascii_strdown(src, -1) : NULL);
    if (property_info->direct_set_string_mac_address_len > 0) {
        return nm_utils_strdup_reset_take(dst,
                                          _nm_utils_hwaddr_canonical_or_invalid(
                                              src,
                                              property_info->direct_set_string_mac_address_len));
    }
    if (property_info->direct_set_string_ip_address_addr_family != 0) {
        return nm_utils_strdup_reset_take(
            dst,
            _nm_utils_ipaddr_canonical_or_invalid(
                property_info->direct_set_string_ip_address_addr_family,
                src));
    }
    return nm_utils_strdup_reset(dst, src);
}

void
_nm_setting_property_get_property_direct(GObject *   object,
                                         guint       prop_id,
                                         GValue *    value,
                                         GParamSpec *pspec)
{
    NMSetting *               setting = NM_SETTING(object);
    const NMSettInfoSetting * sett_info;
    const NMSettInfoProperty *property_info;

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    nm_assert(sett_info);

    property_info = _nm_sett_info_property_lookup_by_param_spec(sett_info, pspec);
    if (!property_info)
        goto out_fail;

    nm_assert(property_info->param_spec == pspec);

    switch (property_info->property_type->direct_type) {
    case NM_VALUE_TYPE_BOOL:
    {
        const bool *p_val =
            _nm_setting_get_private(setting, sett_info, property_info->direct_offset);

        g_value_set_boolean(value, *p_val);
        return;
    }
    case NM_VALUE_TYPE_INT32:
    {
        const gint32 *p_val =
            _nm_setting_get_private(setting, sett_info, property_info->direct_offset);

        g_value_set_int(value, *p_val);
        return;
    }
    case NM_VALUE_TYPE_UINT32:
    {
        const guint32 *p_val =
            _nm_setting_get_private(setting, sett_info, property_info->direct_offset);

        g_value_set_uint(value, *p_val);
        return;
    }
    case NM_VALUE_TYPE_STRING:
    {
        const char *const *p_val =
            _nm_setting_get_private(setting, sett_info, property_info->direct_offset);

        g_value_set_string(value, *p_val);
        return;
    }
    default:
        goto out_fail;
    }

    return;

out_fail:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
}

void
_nm_setting_property_set_property_direct(GObject *     object,
                                         guint         prop_id,
                                         const GValue *value,
                                         GParamSpec *  pspec)
{
    NMSetting *               setting = NM_SETTING(object);
    const NMSettInfoSetting * sett_info;
    const NMSettInfoProperty *property_info;

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    nm_assert(sett_info);

    property_info = _nm_sett_info_property_lookup_by_param_spec(sett_info, pspec);
    if (!property_info)
        goto out_fail;

    nm_assert(property_info->param_spec == pspec);

    switch (property_info->property_type->direct_type) {
    case NM_VALUE_TYPE_BOOL:
    {
        bool *   p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        gboolean v;

        v = g_value_get_boolean(value);
        if (*p_val == v)
            return;
        *p_val = v;
        goto out_notify;
    }
    case NM_VALUE_TYPE_INT32:
    {
        gint32 *p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        int     v;

        v = g_value_get_int(value);
        if (*p_val == v)
            return;
        *p_val = v;

        /* truncation cannot happen, because the param_spec is supposed to have suitable
         * minimum/maximum values so that we are in range for int32. */
        nm_assert(*p_val == v);
        goto out_notify;
    }
    case NM_VALUE_TYPE_UINT32:
    {
        guint32 *p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        guint    v;

        v = g_value_get_uint(value);
        if (*p_val == v)
            return;
        *p_val = v;

        /* truncation cannot happen, because the param_spec is supposed to have suitable
         * minimum/maximum values so that we are in range for uint32. */
        nm_assert(*p_val == v);
        goto out_notify;
    }
    case NM_VALUE_TYPE_STRING:
        if (!_property_direct_set_string(
                property_info,
                _nm_setting_get_private(setting, sett_info, property_info->direct_offset),
                g_value_get_string(value)))
            return;
        goto out_notify;
    default:
        goto out_fail;
    }

    return;

out_notify:
    /* If explicit-notify would be set, we would need to emit g_object_notify_by_pspec().
     *
     * Currently we never set that, also because we still support glib 2.40. */
    nm_assert(!NM_FLAGS_HAS(pspec->flags, 1 << 30 /* G_PARAM_EXPLICIT_NOTIFY */));
    return;

out_fail:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
}

/*****************************************************************************/

static void
_init_direct(NMSetting *setting)
{
    const NMSettInfoSetting *sett_info;
    guint16                  i;

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    nm_assert(sett_info);

    for (i = 0; i < sett_info->property_infos_len; i++) {
        const NMSettInfoProperty *property_info = &sett_info->property_infos[i];

        /* We don't emit any g_object_notify_by_pspec(), because this is
         * only supposed to be called during initialization of the GObject
         * instance. */

        switch (property_info->property_type->direct_type) {
        case NM_VALUE_TYPE_NONE:
            break;
        case NM_VALUE_TYPE_BOOL:
        {
            bool *p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
            gboolean def_val;

            def_val = NM_G_PARAM_SPEC_GET_DEFAULT_BOOLEAN(property_info->param_spec);
            nm_assert(*p_val == FALSE);
            *p_val = def_val;
            break;
        }
        case NM_VALUE_TYPE_INT32:
        {
            gint32 *p_val =
                _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
            int def_val;

            def_val = NM_G_PARAM_SPEC_GET_DEFAULT_INT(property_info->param_spec);
            nm_assert(*p_val == 0);
            *p_val = def_val;
            break;
        }
        case NM_VALUE_TYPE_UINT32:
        {
            guint32 *p_val =
                _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
            guint def_val;

            def_val = NM_G_PARAM_SPEC_GET_DEFAULT_UINT(property_info->param_spec);
            nm_assert(*p_val == 0);
            *p_val = def_val;
            break;
        }
        case NM_VALUE_TYPE_STRING:
            nm_assert(!NM_G_PARAM_SPEC_GET_DEFAULT_STRING(property_info->param_spec));
            nm_assert(!(
                *((const char *const *)
                      _nm_setting_get_private(setting, sett_info, property_info->direct_offset))));
            break;
        default:
            nm_assert_not_reached();
            break;
        }
    }
}

static void
_finalize_direct(NMSetting *setting)
{
    const NMSettInfoSetting *sett_info;
    guint16                  i;

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    nm_assert(sett_info);

    for (i = 0; i < sett_info->property_infos_len; i++) {
        const NMSettInfoProperty *property_info = &sett_info->property_infos[i];

        /* We only:
         *
         * - reset fields where there is something to free. E.g. boolean
         *   properties are not reset to their default.
         * - clear/free properties, without emitting g_object_notify_by_pspec(),
         *   because this is called only during finalization. */

        switch (property_info->property_type->direct_type) {
        case NM_VALUE_TYPE_NONE:
        case NM_VALUE_TYPE_BOOL:
        case NM_VALUE_TYPE_INT32:
        case NM_VALUE_TYPE_UINT32:
            break;
        case NM_VALUE_TYPE_STRING:
        {
            char **p_val =
                _nm_setting_get_private(setting, sett_info, property_info->direct_offset);

            nm_clear_g_free(p_val);
            break;
        }
        default:
            nm_assert_not_reached();
            break;
        }
    }
}

/*****************************************************************************/

GVariant *
_nm_setting_property_to_dbus_fcn_direct(const NMSettInfoSetting *               sett_info,
                                        const NMSettInfoProperty *              property_info,
                                        NMConnection *                          connection,
                                        NMSetting *                             setting,
                                        NMConnectionSerializationFlags          flags,
                                        const NMConnectionSerializationOptions *options)
{
    switch (property_info->property_type->direct_type) {
    case NM_VALUE_TYPE_BOOL:
    {
        gboolean val;

        val = *((bool *) _nm_setting_get_private(setting, sett_info, property_info->direct_offset));
        if (!property_info->to_dbus_including_default
            && val == NM_G_PARAM_SPEC_GET_DEFAULT_BOOLEAN(property_info->param_spec))
            return NULL;
        return g_variant_ref(nm_g_variant_singleton_b(val));
    }
    case NM_VALUE_TYPE_INT32:
    {
        gint32 val;

        val =
            *((gint32 *) _nm_setting_get_private(setting, sett_info, property_info->direct_offset));
        if (!property_info->to_dbus_including_default
            && val == NM_G_PARAM_SPEC_GET_DEFAULT_INT(property_info->param_spec))
            return NULL;
        return g_variant_new_int32(val);
    }
    case NM_VALUE_TYPE_UINT32:
    {
        guint32 val;

        val = *(
            (guint32 *) _nm_setting_get_private(setting, sett_info, property_info->direct_offset));
        if (!property_info->to_dbus_including_default
            && val == NM_G_PARAM_SPEC_GET_DEFAULT_UINT(property_info->param_spec))
            return NULL;
        return g_variant_new_uint32(val);
    }
    case NM_VALUE_TYPE_STRING:
    {
        const char *val;

        /* For string properties that are implemented via this function, the default is always NULL.
         * In general, having strings default to NULL is most advisable.
         *
         * Setting "including_default" for a string makes no sense because a
         * GVariant of type "s" cannot express NULL. */
        nm_assert(!NM_G_PARAM_SPEC_GET_DEFAULT_STRING(property_info->param_spec));
        nm_assert(!property_info->to_dbus_including_default);

        val = *((const char *const *) _nm_setting_get_private(setting,
                                                              sett_info,
                                                              property_info->direct_offset));
        if (!val)
            return NULL;
        if (!val[0])
            return g_variant_ref(nm_g_variant_singleton_s_empty());
        return g_variant_new_string(val);
    }
    default:
        return nm_assert_unreachable_val(NULL);
    }
}

GVariant *
_nm_setting_property_to_dbus_fcn_direct_mac_address(const NMSettInfoSetting *      sett_info,
                                                    const NMSettInfoProperty *     property_info,
                                                    NMConnection *                 connection,
                                                    NMSetting *                    setting,
                                                    NMConnectionSerializationFlags flags,
                                                    const NMConnectionSerializationOptions *options)
{
    const char *val;

    nm_assert(property_info->property_type == &nm_sett_info_propert_type_direct_mac_address);
    nm_assert(property_info->property_type->direct_type == NM_VALUE_TYPE_STRING);
    nm_assert(!NM_G_PARAM_SPEC_GET_DEFAULT_STRING(property_info->param_spec));
    nm_assert(!property_info->to_dbus_including_default);

    val = *((const char *const *) _nm_setting_get_private(setting,
                                                          sett_info,
                                                          property_info->direct_offset));
    return nm_utils_hwaddr_to_dbus(val);
}

GVariant *
_nm_setting_property_to_dbus_fcn_ignore(const NMSettInfoSetting *               sett_info,
                                        const NMSettInfoProperty *              property_info,
                                        NMConnection *                          connection,
                                        NMSetting *                             setting,
                                        NMConnectionSerializationFlags          flags,
                                        const NMConnectionSerializationOptions *options)
{
    return NULL;
}

GVariant *
_nm_setting_property_to_dbus_fcn_gprop(const NMSettInfoSetting *               sett_info,
                                       const NMSettInfoProperty *              property_info,
                                       NMConnection *                          connection,
                                       NMSetting *                             setting,
                                       NMConnectionSerializationFlags          flags,
                                       const NMConnectionSerializationOptions *options)
{
    nm_auto_unset_gvalue GValue prop_value = {
        0,
    };
    GArray *tmp_array;

    nm_assert(property_info->param_spec);
    nm_assert(property_info->property_type->to_dbus_fcn == _nm_setting_property_to_dbus_fcn_gprop);

    g_value_init(&prop_value, property_info->param_spec->value_type);

    g_object_get_property(G_OBJECT(setting), property_info->param_spec->name, &prop_value);

    if (!property_info->to_dbus_including_default
        && g_param_value_defaults(property_info->param_spec, &prop_value))
        return NULL;

    switch (property_info->property_type->typdata_to_dbus.gprop_type) {
    case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_DEFAULT:
        return g_dbus_gvalue_to_gvariant(&prop_value, property_info->property_type->dbus_type);
    case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_BYTES:
        nm_assert(G_VALUE_HOLDS(&prop_value, G_TYPE_BYTES));
        return nm_utils_gbytes_to_variant_ay(g_value_get_boxed(&prop_value));
    case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_ENUM:
        return g_variant_new_int32(g_value_get_enum(&prop_value));
    case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_FLAGS:
        return g_variant_new_uint32(g_value_get_flags(&prop_value));
    case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_GARRAY_UINT:
        G_STATIC_ASSERT_EXPR(sizeof(guint) == sizeof(guint32));
        nm_assert(G_VALUE_HOLDS(&prop_value, G_TYPE_ARRAY));
        tmp_array = g_value_get_boxed(&prop_value);
        nm_assert(tmp_array);
        return nm_g_variant_new_au((const guint32 *) tmp_array->data, tmp_array->len);
    case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_STRDICT:
        nm_assert(G_VALUE_HOLDS(&prop_value, G_TYPE_HASH_TABLE));
        return nm_utils_strdict_to_variant_ass(g_value_get_boxed(&prop_value));
    }

    return nm_assert_unreachable_val(NULL);
}

gboolean
_nm_setting_property_from_dbus_fcn_ignore(const NMSettInfoSetting * sett_info,
                                          const NMSettInfoProperty *property_info,
                                          NMSetting *               setting,
                                          GVariant *                connection_dict,
                                          GVariant *                value,
                                          NMSettingParseFlags       parse_flags,
                                          GError **                 error)
{
    return TRUE;
}

gboolean
_nm_setting_property_from_dbus_fcn_direct_mac_address(const NMSettInfoSetting * sett_info,
                                                      const NMSettInfoProperty *property_info,
                                                      NMSetting *               setting,
                                                      GVariant *                connection_dict,
                                                      GVariant *                value,
                                                      NMSettingParseFlags       parse_flags,
                                                      GError **                 error)
{
    gsize         length = 0;
    const guint8 *array;

    nm_assert(property_info->param_spec);
    nm_assert(property_info->property_type == &nm_sett_info_propert_type_direct_mac_address);
    nm_assert(g_variant_type_equal(property_info->property_type->dbus_type, "ay"));
    nm_assert(
        g_variant_type_equal(g_variant_get_type(value), property_info->property_type->dbus_type));
    nm_assert(property_info->direct_set_string_mac_address_len > 0);

    array = g_variant_get_fixed_array(value, &length, 1);

    if (nm_utils_strdup_reset_take(
            _nm_setting_get_private(setting, sett_info, property_info->direct_offset),
            length > 0 ? nm_utils_hwaddr_ntoa(array, length) : NULL))
        g_object_notify_by_pspec(G_OBJECT(setting), property_info->param_spec);

    return TRUE;
}

gboolean
_nm_setting_property_from_dbus_fcn_direct(const NMSettInfoSetting * sett_info,
                                          const NMSettInfoProperty *property_info,
                                          NMSetting *               setting,
                                          GVariant *                connection_dict,
                                          GVariant *                value,
                                          NMSettingParseFlags       parse_flags,
                                          GError **                 error)
{
    nm_assert(property_info->param_spec);
    nm_assert(NM_FLAGS_HAS(property_info->param_spec->flags, G_PARAM_WRITABLE));
    nm_assert(!NM_FLAGS_HAS(property_info->param_spec->flags, G_PARAM_CONSTRUCT_ONLY));
    nm_assert(!property_info->property_type->typdata_from_dbus.gprop_fcn);

#define _variant_get_value_transform(property_info, value, gtype, gvalue_get, out_val) \
    ({                                                                                 \
        const NMSettInfoProperty const *_property_info = (property_info);              \
        const GType                     _gtype         = (gtype);                      \
        GVariant *                      _value         = (value);                      \
        gboolean                        _success       = FALSE;                        \
                                                                                       \
        nm_assert(_property_info->param_spec->value_type == _gtype);                   \
        if (_property_info->property_type->from_dbus_direct_allow_transform) {         \
            nm_auto_unset_gvalue GValue _gvalue = G_VALUE_INIT;                        \
                                                                                       \
            g_value_init(&_gvalue, _gtype);                                            \
            if (_nm_property_variant_to_gvalue(_value, &_gvalue)) {                    \
                *(out_val) = (gvalue_get(&_gvalue));                                   \
                _success   = TRUE;                                                     \
            }                                                                          \
        }                                                                              \
        _success;                                                                      \
    })

    switch (property_info->property_type->direct_type) {
    case NM_VALUE_TYPE_BOOL:
    {
        bool *   p_val;
        gboolean v;

        if (g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
            v = g_variant_get_boolean(value);
        else {
            if (!_variant_get_value_transform(property_info,
                                              value,
                                              G_TYPE_BOOLEAN,
                                              g_value_get_boolean,
                                              &v))
                goto out_error_wrong_dbus_type;
            v = !!v;
        }

        p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        if (*p_val == v)
            goto out_unchanged;
        *p_val = v;
        goto out_notify;
    }
    case NM_VALUE_TYPE_INT32:
    {
        const GParamSpecInt *param_spec;
        gint32 *             p_val;
        int                  v;

        if (g_variant_is_of_type(value, G_VARIANT_TYPE_INT32)) {
            G_STATIC_ASSERT(sizeof(int) >= sizeof(gint32));
            v = g_variant_get_int32(value);
        } else {
            if (!_variant_get_value_transform(property_info,
                                              value,
                                              G_TYPE_INT,
                                              g_value_get_int,
                                              &v))
                goto out_error_wrong_dbus_type;
        }

        p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        if (*p_val == v)
            goto out_unchanged;

        param_spec = NM_G_PARAM_SPEC_CAST_INT(property_info->param_spec);
        if (v < param_spec->minimum || v > param_spec->maximum)
            goto out_error_param_spec_validation;
        *p_val = v;
        goto out_notify;
    }
    case NM_VALUE_TYPE_UINT32:
    {
        const GParamSpecUInt *param_spec;
        guint32 *             p_val;
        guint                 v;

        if (g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32)) {
            G_STATIC_ASSERT(sizeof(guint) >= sizeof(guint32));
            v = g_variant_get_uint32(value);
        } else {
            if (!_variant_get_value_transform(property_info,
                                              value,
                                              G_TYPE_UINT,
                                              g_value_get_uint,
                                              &v))
                goto out_error_wrong_dbus_type;
        }

        p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        if (*p_val == v)
            goto out_unchanged;

        param_spec = NM_G_PARAM_SPEC_CAST_UINT(property_info->param_spec);
        if (v < param_spec->minimum || v > param_spec->maximum)
            goto out_error_param_spec_validation;
        *p_val = v;
        goto out_notify;
    }
    case NM_VALUE_TYPE_STRING:
    {
        gs_free char *v_free = NULL;
        char **       p_val;
        const char *  v;

        if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
            v = g_variant_get_string(value, NULL);
        } else {
            if (!_variant_get_value_transform(property_info,
                                              value,
                                              G_TYPE_STRING,
                                              g_value_dup_string,
                                              &v_free))
                goto out_error_wrong_dbus_type;
            v = v_free;
        }

        p_val = _nm_setting_get_private(setting, sett_info, property_info->direct_offset);
        if (!_property_direct_set_string(property_info, p_val, v))
            goto out_unchanged;

        goto out_notify;
    }
    default:
        break;
    }

    nm_assert_not_reached();

out_unchanged:
    return TRUE;

out_notify:
    g_object_notify_by_pspec(G_OBJECT(setting), property_info->param_spec);
    return TRUE;

out_error_wrong_dbus_type:
    if (NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_BEST_EFFORT))
        return TRUE;
    g_set_error(error,
                NM_CONNECTION_ERROR,
                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                _("can't set property of type '%s' from value of type '%s'"),
                property_info->property_type->dbus_type
                    ? g_variant_type_peek_string(property_info->property_type->dbus_type)
                    : (property_info->param_spec
                           ? g_type_name(property_info->param_spec->value_type)
                           : "(unknown)"),
                g_variant_get_type_string(value));
    g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
    return FALSE;

out_error_param_spec_validation:
    if (NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_BEST_EFFORT))
        return TRUE;
    g_set_error(error,
                NM_UTILS_ERROR,
                NM_UTILS_ERROR_UNKNOWN,
                _("value of type '%s' is invalid or out of range for property '%s'"),
                g_variant_get_type_string(value),
                property_info->name);
    g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
    return FALSE;
}

gboolean
_nm_setting_property_from_dbus_fcn_gprop(const NMSettInfoSetting * sett_info,
                                         const NMSettInfoProperty *property_info,
                                         NMSetting *               setting,
                                         GVariant *                connection_dict,
                                         GVariant *                value,
                                         NMSettingParseFlags       parse_flags,
                                         GError **                 error)
{
    nm_auto_unset_gvalue GValue object_value = G_VALUE_INIT;
    gs_free_error GError *local              = NULL;

    nm_assert(property_info->param_spec);

    g_value_init(&object_value, property_info->param_spec->value_type);
    if (!set_property_from_dbus(property_info, value, &object_value)) {
        /* for backward behavior, fail unless best-effort is chosen. */
        if (NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_BEST_EFFORT))
            return TRUE;
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("can't set property of type '%s' from value of type '%s'"),
                    property_info->property_type->dbus_type
                        ? g_variant_type_peek_string(property_info->property_type->dbus_type)
                        : (property_info->param_spec
                               ? g_type_name(property_info->param_spec->value_type)
                               : "(unknown)"),
                    g_variant_get_type_string(value));
        g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
        return FALSE;
    }

    if (!nm_g_object_set_property(G_OBJECT(setting),
                                  property_info->param_spec->name,
                                  &object_value,
                                  &local)) {
        if (!NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_STRICT))
            return TRUE;
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("can not set property: %s"),
                    local->message);
        g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
        return FALSE;
    }

    return TRUE;
}

static GVariant *
property_to_dbus(const NMSettInfoSetting *               sett_info,
                 const NMSettInfoProperty *              property_info,
                 NMConnection *                          connection,
                 NMSetting *                             setting,
                 NMConnectionSerializationFlags          flags,
                 const NMConnectionSerializationOptions *options,
                 gboolean                                ignore_flags)
{
    GVariant *variant;

    nm_assert(property_info->property_type->dbus_type);

    if (!property_info->property_type->to_dbus_fcn) {
        nm_assert(!property_info->param_spec);
        return NULL;
    }

    nm_assert(!property_info->param_spec
              || NM_FLAGS_HAS(property_info->param_spec->flags, G_PARAM_WRITABLE)
              || property_info->property_type == &nm_sett_info_propert_type_setting_name);

    if (property_info->param_spec && !ignore_flags
        && !NM_FLAGS_HAS(property_info->param_spec->flags, NM_SETTING_PARAM_TO_DBUS_IGNORE_FLAGS)) {
        if (NM_FLAGS_HAS(property_info->param_spec->flags, NM_SETTING_PARAM_LEGACY)
            && !_nm_utils_is_manager_process)
            return NULL;

        if (NM_FLAGS_HAS(property_info->param_spec->flags, NM_SETTING_PARAM_SECRET)) {
            NMSettingSecretFlags f = NM_SETTING_SECRET_FLAG_NONE;

            if (NM_FLAGS_ANY(flags,
                             NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED
                                 | NM_CONNECTION_SERIALIZE_WITH_SECRETS_SYSTEM_OWNED
                                 | NM_CONNECTION_SERIALIZE_WITH_SECRETS_NOT_SAVED)) {
                if (!nm_setting_get_secret_flags(setting,
                                                 property_info->param_spec->name,
                                                 &f,
                                                 NULL))
                    return NULL;
            }

            if (!_nm_connection_serialize_secrets(flags, f))
                return NULL;
        } else {
            if (!_nm_connection_serialize_non_secret(flags))
                return NULL;
        }
    }

    variant = property_info->property_type
                  ->to_dbus_fcn(sett_info, property_info, connection, setting, flags, options);
    nm_g_variant_take_ref(variant);

    nm_assert(!variant || g_variant_is_of_type(variant, property_info->property_type->dbus_type));

    return variant;
}

static gboolean
set_property_from_dbus(const NMSettInfoProperty *property_info,
                       GVariant *                src_value,
                       GValue *                  dst_value)
{
    nm_assert(property_info->param_spec);
    nm_assert(property_info->property_type->dbus_type);

    if (property_info->property_type->typdata_from_dbus.gprop_fcn) {
        if (!g_variant_type_equal(g_variant_get_type(src_value),
                                  property_info->property_type->dbus_type))
            return FALSE;
        property_info->property_type->typdata_from_dbus.gprop_fcn(src_value, dst_value);
        return TRUE;
    }

    if (dst_value->g_type == G_TYPE_BYTES) {
        if (!g_variant_is_of_type(src_value, G_VARIANT_TYPE_BYTESTRING))
            return FALSE;

        _nm_utils_bytes_from_dbus(src_value, dst_value);
        return TRUE;
    }

    return _nm_property_variant_to_gvalue(src_value, dst_value);
}

/**
 * _nm_setting_to_dbus:
 * @setting: the #NMSetting
 * @connection: the #NMConnection containing @setting
 * @flags: hash flags, e.g. %NM_CONNECTION_SERIALIZE_ALL
 * @options: the #NMConnectionSerializationOptions options to control
 *   what/how gets serialized.
 *
 * Converts the #NMSetting into a #GVariant of type #NM_VARIANT_TYPE_SETTING
 * mapping each setting property name to a value describing that property,
 * suitable for marshalling over D-Bus or serializing.
 *
 * Returns: (transfer none): a new floating #GVariant describing the setting's
 * properties
 **/
GVariant *
_nm_setting_to_dbus(NMSetting *                             setting,
                    NMConnection *                          connection,
                    NMConnectionSerializationFlags          flags,
                    const NMConnectionSerializationOptions *options)
{
    NMSettingPrivate *       priv;
    GVariantBuilder          builder;
    const NMSettInfoSetting *sett_info;
    guint                    n_properties;
    guint                    i;
    guint16                  j;
    const char *const *      gendata_keys;

    g_return_val_if_fail(NM_IS_SETTING(setting), NULL);

    priv = NM_SETTING_GET_PRIVATE(setting);

    g_variant_builder_init(&builder, NM_VARIANT_TYPE_SETTING);

    n_properties = _nm_setting_option_get_all(setting, &gendata_keys, NULL);
    for (i = 0; i < n_properties; i++) {
        g_variant_builder_add(&builder,
                              "{sv}",
                              gendata_keys[i],
                              g_hash_table_lookup(priv->gendata->hash, gendata_keys[i]));
    }

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    for (j = 0; j < sett_info->property_infos_len; j++) {
        const NMSettInfoProperty *property_info = &sett_info->property_infos[j];
        gs_unref_variant GVariant *dbus_value   = NULL;

        dbus_value =
            property_to_dbus(sett_info, property_info, connection, setting, flags, options, FALSE);
        if (dbus_value) {
            g_variant_builder_add(&builder, "{sv}", property_info->name, dbus_value);
        }
    }

    return g_variant_builder_end(&builder);
}

/**
 * _nm_setting_new_from_dbus:
 * @setting_type: the #NMSetting type which the hash contains properties for
 * @setting_dict: the #GVariant containing an %NM_VARIANT_TYPE_SETTING dictionary
 *   mapping property names to values
 * @connection_dict: the #GVariant containing an %NM_VARIANT_TYPE_CONNECTION
 *   dictionary mapping setting names to dictionaries.
 * @parse_flags: flags to determine behavior during parsing.
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMSetting object and populates that object with the properties
 * contained in @setting_dict, using each key as the property to set, and each
 * value as the value to set that property to.  Setting properties are strongly
 * typed, thus the #GVariantType of the dict value must be correct.  See the
 * documentation on each #NMSetting object subclass for the correct property
 * names and value types.
 *
 * Returns: a new #NMSetting object populated with the properties from the
 * hash table, or %NULL if @setting_hash could not be deserialized.
 **/
NMSetting *
_nm_setting_new_from_dbus(GType               setting_type,
                          GVariant *          setting_dict,
                          GVariant *          connection_dict,
                          NMSettingParseFlags parse_flags,
                          GError **           error)
{
    gs_unref_ptrarray GPtrArray *keys_keep_variant = NULL;
    gs_unref_object NMSetting *setting             = NULL;
    gs_unref_hashtable GHashTable *keys            = NULL;

    g_return_val_if_fail(G_TYPE_IS_INSTANTIATABLE(setting_type), NULL);
    g_return_val_if_fail(g_variant_is_of_type(setting_dict, NM_VARIANT_TYPE_SETTING), NULL);

    nm_assert(!NM_FLAGS_ANY(parse_flags, ~NM_SETTING_PARSE_FLAGS_ALL));
    nm_assert(!NM_FLAGS_ALL(parse_flags,
                            NM_SETTING_PARSE_FLAGS_STRICT | NM_SETTING_PARSE_FLAGS_BEST_EFFORT));

    /* connection_dict is not technically optional, but some tests in test-general
     * don't bother with it in cases where they know it's not needed.
     */
    if (connection_dict)
        g_return_val_if_fail(g_variant_is_of_type(connection_dict, NM_VARIANT_TYPE_CONNECTION),
                             NULL);

    /* Build the setting object from the properties we know about; we assume
     * that any propreties in @setting_dict that we don't know about can
     * either be ignored or else has a backward-compatibility equivalent
     * that we do know about.
     */
    setting = g_object_new(setting_type, NULL);

    if (NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
        GVariantIter iter;
        GVariant *   entry, *entry_key;
        const char * key;

        keys_keep_variant = g_ptr_array_new_with_free_func((GDestroyNotify) g_variant_unref);
        keys              = g_hash_table_new(nm_str_hash, g_str_equal);

        g_variant_iter_init(&iter, setting_dict);
        while ((entry = g_variant_iter_next_value(&iter))) {
            entry_key = g_variant_get_child_value(entry, 0);
            g_ptr_array_add(keys_keep_variant, entry_key);
            g_variant_unref(entry);

            key = g_variant_get_string(entry_key, NULL);
            if (!g_hash_table_add(keys, (char *) key)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_SETTING,
                            _("duplicate property"));
                g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), key);
                return NULL;
            }
        }
    }

    if (!NM_SETTING_GET_CLASS(setting)
             ->init_from_dbus(setting, keys, setting_dict, connection_dict, parse_flags, error))
        return NULL;

    if (NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_STRICT) && g_hash_table_size(keys) > 0) {
        GHashTableIter iter;
        const char *   key;

        g_hash_table_iter_init(&iter, keys);
        if (g_hash_table_iter_next(&iter, (gpointer *) &key, NULL)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("unknown property"));
            g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), key);
            return NULL;
        }
    }

    return g_steal_pointer(&setting);
}

static gboolean
init_from_dbus(NMSetting *                     setting,
               GHashTable *                    keys,
               GVariant *                      setting_dict,
               GVariant *                      connection_dict,
               guint /* NMSettingParseFlags */ parse_flags,
               GError **                       error)
{
    const NMSettInfoSetting *sett_info;
    guint16                  i;

    nm_assert(NM_IS_SETTING(setting));
    nm_assert(!NM_FLAGS_ANY(parse_flags, ~NM_SETTING_PARSE_FLAGS_ALL));
    nm_assert(!NM_FLAGS_ALL(parse_flags,
                            NM_SETTING_PARSE_FLAGS_STRICT | NM_SETTING_PARSE_FLAGS_BEST_EFFORT));

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));

    if (sett_info->detail.gendata_info) {
        GHashTable * hash;
        GVariantIter iter;
        char *       key;
        GVariant *   val;

        hash = _gendata_hash(setting, TRUE)->hash;

        g_variant_iter_init(&iter, setting_dict);
        while (g_variant_iter_next(&iter, "{sv}", &key, &val)) {
            g_hash_table_insert(hash, key, val);
            if (keys)
                g_hash_table_remove(keys, key);
        }

        _nm_setting_option_notify(setting, TRUE);

        /* Currently, only NMSettingEthtool supports gendata based options, and
         * that one has no other properties (except "name"). That means, we
         * consumed all options above.
         *
         * In the future it may be interesting to have settings that are both
         * based on gendata and regular properties. In that case, we would need
         * to handle this case differently. */
        nm_assert(nm_streq(G_OBJECT_TYPE_NAME(setting), "NMSettingEthtool"));
        nm_assert(sett_info->property_infos_len == 1);

        return TRUE;
    }

    for (i = 0; i < sett_info->property_infos_len; i++) {
        const NMSettInfoProperty *property_info = &sett_info->property_infos[i];
        gs_unref_variant GVariant *value        = NULL;
        gs_free_error GError *local             = NULL;

        if (property_info->property_type == &nm_sett_info_propert_type_setting_name)
            continue;

        nm_assert(!property_info->param_spec
                  || NM_FLAGS_HAS(property_info->param_spec->flags, G_PARAM_WRITABLE));

        value = g_variant_lookup_value(setting_dict, property_info->name, NULL);

        if (!value) {
            if (property_info->property_type->missing_from_dbus_fcn
                && !property_info->property_type->missing_from_dbus_fcn(setting,
                                                                        connection_dict,
                                                                        property_info->name,
                                                                        parse_flags,
                                                                        &local)) {
                if (!NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_STRICT))
                    continue;
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("failed to set property: %s"),
                            local->message);
                g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
                return FALSE;
            }
            continue;
        }

        if (keys)
            g_hash_table_remove(keys, property_info->name);

        if (property_info->property_type->from_dbus_fcn) {
            if (property_info->property_type->from_dbus_is_full) {
                /* These hooks perform their own type checking, and can coerce/ignore
                 * a value regardless of the D-Bus type. */
            } else if (!g_variant_type_equal(g_variant_get_type(value),
                                             property_info->property_type->dbus_type)) {
                /* for backward behavior, fail unless best-effort is chosen. */
                if (NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_BEST_EFFORT))
                    continue;
                g_set_error(
                    error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("can't set property of type '%s' from value of type '%s'"),
                    property_info->property_type->dbus_type
                        ? g_variant_type_peek_string(property_info->property_type->dbus_type)
                    : property_info->param_spec ? g_type_name(property_info->param_spec->value_type)
                                                : "(unknown)",
                    g_variant_get_type_string(value));
                g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
                return FALSE;
            }

            if (!property_info->property_type->from_dbus_fcn(sett_info,
                                                             property_info,
                                                             setting,
                                                             connection_dict,
                                                             value,
                                                             parse_flags,
                                                             &local)) {
                if (property_info->property_type->from_dbus_is_full) {
                    /* the error we received from from_dbus_fcn() should be propagated, even
                     * in non-strict mode. */
                } else if (!NM_FLAGS_HAS(parse_flags, NM_SETTING_PARSE_FLAGS_STRICT))
                    continue;
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("failed to set property: %s"),
                            local->message);
                g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), property_info->name);
                return FALSE;
            }
            continue;
        }

        nm_assert(!property_info->param_spec);
    }

    return TRUE;
}

/**
 * nm_setting_get_dbus_property_type:
 * @setting: an #NMSetting
 * @property_name: the property of @setting to get the type of
 *
 * Gets the D-Bus marshalling type of a property. @property_name is a D-Bus
 * property name, which may not necessarily be a #GObject property.
 *
 * Returns: the D-Bus marshalling type of @property on @setting.
 */
const GVariantType *
nm_setting_get_dbus_property_type(NMSetting *setting, const char *property_name)
{
    const NMSettInfoProperty *property_info;

    g_return_val_if_fail(NM_IS_SETTING(setting), NULL);
    g_return_val_if_fail(property_name != NULL, NULL);

    property_info =
        _nm_setting_class_get_property_info(NM_SETTING_GET_CLASS(setting), property_name);

    g_return_val_if_fail(property_info != NULL, NULL);

    nm_assert(property_info->property_type);
    nm_assert(
        g_variant_type_string_is_valid((const char *) property_info->property_type->dbus_type));

    return property_info->property_type->dbus_type;
}

gboolean
_nm_setting_get_property(NMSetting *setting, const char *property_name, GValue *value)
{
    const NMSettInfoSetting * sett_info;
    const NMSettInfoProperty *property_info;

    g_return_val_if_fail(NM_IS_SETTING(setting), FALSE);
    g_return_val_if_fail(property_name, FALSE);
    g_return_val_if_fail(value, FALSE);

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));

    if (sett_info->detail.gendata_info) {
        GVariant *variant;
        GenData * gendata = _gendata_hash(setting, FALSE);

        variant = gendata ? g_hash_table_lookup(gendata->hash, property_name) : NULL;

        if (!variant) {
            g_value_unset(value);
            return FALSE;
        }

        g_value_init(value, G_TYPE_VARIANT);
        g_value_set_variant(value, variant);
        return TRUE;
    }

    property_info = _nm_sett_info_setting_get_property_info(sett_info, property_name);
    if (!property_info || !property_info->param_spec) {
        g_value_unset(value);
        return FALSE;
    }

    g_value_init(value, property_info->param_spec->value_type);
    g_object_get_property(G_OBJECT(setting), property_name, value);
    return TRUE;
}

static void
_gobject_copy_property(GObject *src, GObject *dst, const char *property_name, GType gtype)
{
    nm_auto_unset_gvalue GValue value = G_VALUE_INIT;

    nm_assert(G_IS_OBJECT(src));
    nm_assert(G_IS_OBJECT(dst));

    g_value_init(&value, gtype);
    g_object_get_property(src, property_name, &value);
    g_object_set_property(dst, property_name, &value);
}

static void
duplicate_copy_properties(const NMSettInfoSetting *sett_info, NMSetting *src, NMSetting *dst)
{
    gboolean frozen = FALSE;
    guint16  i;

    if (sett_info->detail.gendata_info) {
        GenData *gendata = _gendata_hash(src, FALSE);

        nm_assert(!_gendata_hash(dst, FALSE));

        if (gendata && g_hash_table_size(gendata->hash) > 0) {
            GHashTableIter iter;
            GHashTable *   h = _gendata_hash(dst, TRUE)->hash;
            const char *   key;
            GVariant *     val;

            g_hash_table_iter_init(&iter, gendata->hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
                g_hash_table_insert(h, g_strdup(key), g_variant_ref(val));
            }
        }
    }

    for (i = 0; i < sett_info->property_infos_len; i++) {
        const NMSettInfoProperty *property_info = &sett_info->property_infos[i];

        if (!property_info->param_spec)
            continue;

        nm_assert(!NM_FLAGS_HAS(property_info->param_spec->flags, G_PARAM_CONSTRUCT_ONLY));
        if (property_info->property_type == &nm_sett_info_propert_type_setting_name)
            continue;

        nm_assert(NM_FLAGS_HAS(property_info->param_spec->flags, G_PARAM_WRITABLE));

        if (!frozen) {
            g_object_freeze_notify(G_OBJECT(dst));
            frozen = TRUE;
        }
        _gobject_copy_property(G_OBJECT(src),
                               G_OBJECT(dst),
                               property_info->param_spec->name,
                               G_PARAM_SPEC_VALUE_TYPE(property_info->param_spec));
    }

    if (frozen)
        g_object_thaw_notify(G_OBJECT(dst));
}

/**
 * nm_setting_duplicate:
 * @setting: the #NMSetting to duplicate
 *
 * Duplicates a #NMSetting.
 *
 * Returns: (transfer full): a new #NMSetting containing the same properties and values as the
 * source #NMSetting
 **/
NMSetting *
nm_setting_duplicate(NMSetting *setting)
{
    const NMSettInfoSetting *sett_info;
    NMSettingClass *         klass;
    NMSetting *              dst;

    g_return_val_if_fail(NM_IS_SETTING(setting), NULL);

    klass = NM_SETTING_GET_CLASS(setting);
    nm_assert(NM_IS_SETTING_CLASS(klass));
    nm_assert(klass->duplicate_copy_properties);

    dst = g_object_new(G_TYPE_FROM_CLASS(klass), NULL);

    sett_info = _nm_setting_class_get_sett_info(klass);
    nm_assert(sett_info);

    klass->duplicate_copy_properties(sett_info, setting, dst);
    return dst;
}

/**
 * nm_setting_get_name:
 * @setting: the #NMSetting
 *
 * Returns the type name of the #NMSetting object
 *
 * Returns: a string containing the type name of the #NMSetting object,
 * like 'ppp' or 'wireless' or 'wired'.
 **/
const char *
nm_setting_get_name(NMSetting *setting)
{
    const NMMetaSettingInfo *setting_info;

    g_return_val_if_fail(NM_IS_SETTING(setting), NULL);

    setting_info = NM_SETTING_GET_CLASS(setting)->setting_info;
    return setting_info ? setting_info->setting_name : NULL;
}

/**
 * nm_setting_verify:
 * @setting: the #NMSetting to verify
 * @connection: (allow-none): the #NMConnection that @setting came from, or
 *   %NULL if @setting is being verified in isolation.
 * @error: location to store error, or %NULL
 *
 * Validates the setting.  Each setting's properties have allowed values, and
 * some are dependent on other values (hence the need for @connection).  The
 * returned #GError contains information about which property of the setting
 * failed validation, and in what way that property failed validation.
 *
 * Returns: %TRUE if the setting is valid, %FALSE if it is not
 **/
gboolean
nm_setting_verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingVerifyResult result = _nm_setting_verify(setting, connection, error);

    if (result == NM_SETTING_VERIFY_NORMALIZABLE)
        g_clear_error(error);

    return result == NM_SETTING_VERIFY_SUCCESS || result == NM_SETTING_VERIFY_NORMALIZABLE;
}

NMSettingVerifyResult
_nm_setting_verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    g_return_val_if_fail(NM_IS_SETTING(setting), NM_SETTING_VERIFY_ERROR);
    g_return_val_if_fail(!connection || NM_IS_CONNECTION(connection), NM_SETTING_VERIFY_ERROR);
    g_return_val_if_fail(!error || *error == NULL, NM_SETTING_VERIFY_ERROR);

    if (NM_SETTING_GET_CLASS(setting)->verify)
        return NM_SETTING_GET_CLASS(setting)->verify(setting, connection, error);

    return NM_SETTING_VERIFY_SUCCESS;
}

/**
 * nm_setting_verify_secrets:
 * @setting: the #NMSetting to verify secrets in
 * @connection: (allow-none): the #NMConnection that @setting came from, or
 *   %NULL if @setting is being verified in isolation.
 * @error: location to store error, or %NULL
 *
 * Verifies the secrets in the setting.
 * The returned #GError contains information about which secret of the setting
 * failed validation, and in what way that secret failed validation.
 * The secret validation is done separately from main setting validation, because
 * in some cases connection failure is not desired just for the secrets.
 *
 * Returns: %TRUE if the setting secrets are valid, %FALSE if they are not
 *
 * Since: 1.2
 **/
gboolean
nm_setting_verify_secrets(NMSetting *setting, NMConnection *connection, GError **error)
{
    g_return_val_if_fail(NM_IS_SETTING(setting), NM_SETTING_VERIFY_ERROR);
    g_return_val_if_fail(!connection || NM_IS_CONNECTION(connection), NM_SETTING_VERIFY_ERROR);
    g_return_val_if_fail(!error || *error == NULL, NM_SETTING_VERIFY_ERROR);

    if (NM_SETTING_GET_CLASS(setting)->verify_secrets)
        return NM_SETTING_GET_CLASS(setting)->verify_secrets(setting, connection, error);

    return NM_SETTING_VERIFY_SUCCESS;
}

gboolean
_nm_setting_verify_secret_string(const char *str,
                                 const char *setting_name,
                                 const char *property,
                                 GError **   error)
{
    if (str && !*str) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", setting_name, property);
        return FALSE;
    }
    return TRUE;
}

gboolean
_nm_setting_should_compare_secret_property(NMSetting *           setting,
                                           NMSetting *           other,
                                           const char *          secret_name,
                                           NMSettingCompareFlags flags)
{
    NMSettingSecretFlags a_secret_flags = NM_SETTING_SECRET_FLAG_NONE;
    NMSettingSecretFlags b_secret_flags = NM_SETTING_SECRET_FLAG_NONE;

    nm_assert(NM_IS_SETTING(setting));
    nm_assert(!other || G_OBJECT_TYPE(setting) == G_OBJECT_TYPE(other));

    /* secret_name must be a valid secret for @setting. */
    nm_assert(nm_setting_get_secret_flags(setting, secret_name, NULL, NULL));

    if (!NM_FLAGS_ANY(flags,
                      NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS
                          | NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS))
        return TRUE;

    nm_setting_get_secret_flags(setting, secret_name, &a_secret_flags, NULL);
    if (other) {
        if (!nm_setting_get_secret_flags(other, secret_name, &b_secret_flags, NULL)) {
            /* secret-name may not be a valid secret for @other. That is fine, we ignore that
             * and treat @b_secret_flags as NM_SETTING_SECRET_FLAG_NONE.
             *
             * This can happen with VPN secrets, where the caller knows that @secret_name
             * is a secret for setting, but it may not be a secret for @other. Accept that.
             *
             * Mark @other as missing. */
            other = NULL;
        }
    }

    /* when @setting has the secret-flags that should be ignored,
     * we skip the comparison if:
     *
     *   - @other is not present,
     *   - @other does not have a secret named @secret_name
     *   - @other also has the secret flat to be ignored.
     *
     * This makes the check symmetric (aside the fact that @setting must
     * have the secret while @other may not -- which is asymmetric). */
    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS)
        && NM_FLAGS_HAS(a_secret_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED)
        && (!other || NM_FLAGS_HAS(b_secret_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED)))
        return FALSE;

    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
        && NM_FLAGS_HAS(a_secret_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED)
        && (!other || NM_FLAGS_HAS(b_secret_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED)))
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

gboolean
_nm_setting_compare_flags_check(const GParamSpec *    param_spec,
                                NMSettingCompareFlags flags,
                                NMSetting *           set_a,
                                NMSetting *           set_b)
{
    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_FUZZY)
        && NM_FLAGS_ANY(param_spec->flags, NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_SECRET))
        return FALSE;

    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_INFERRABLE)
        && !NM_FLAGS_HAS(param_spec->flags, NM_SETTING_PARAM_INFERRABLE))
        return FALSE;

    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY)
        && NM_FLAGS_HAS(param_spec->flags, NM_SETTING_PARAM_REAPPLY_IMMEDIATELY))
        return FALSE;

    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS)
        && NM_FLAGS_HAS(param_spec->flags, NM_SETTING_PARAM_SECRET))
        return FALSE;

    if (NM_FLAGS_HAS(param_spec->flags, NM_SETTING_PARAM_SECRET)
        && !_nm_setting_should_compare_secret_property(set_a, set_b, param_spec->name, flags))
        return FALSE;

    return TRUE;
}

NMTernary
_nm_setting_property_compare_fcn_ignore(const NMSettInfoSetting * sett_info,
                                        const NMSettInfoProperty *property_info,
                                        NMConnection *            con_a,
                                        NMSetting *               set_a,
                                        NMConnection *            con_b,
                                        NMSetting *               set_b,
                                        NMSettingCompareFlags     flags)
{
    return NM_TERNARY_DEFAULT;
}

NMTernary
_nm_setting_property_compare_fcn_direct(const NMSettInfoSetting * sett_info,
                                        const NMSettInfoProperty *property_info,
                                        NMConnection *            con_a,
                                        NMSetting *               set_a,
                                        NMConnection *            con_b,
                                        NMSetting *               set_b,
                                        NMSettingCompareFlags     flags)
{
    gconstpointer p_a;
    gconstpointer p_b;

    nm_assert(NM_IN_SET(property_info->property_type->to_dbus_fcn,
                        _nm_setting_property_to_dbus_fcn_direct,
                        _nm_setting_property_to_dbus_fcn_direct_mac_address));

    if (!property_info->param_spec)
        return nm_assert_unreachable_val(NM_TERNARY_DEFAULT);

    if (!_nm_setting_compare_flags_check(property_info->param_spec, flags, set_a, set_b))
        return NM_TERNARY_DEFAULT;

    if (!set_b)
        return TRUE;

    p_a = _nm_setting_get_private(set_a, sett_info, property_info->direct_offset);
    p_b = _nm_setting_get_private(set_b, sett_info, property_info->direct_offset);

    switch (property_info->property_type->direct_type) {
    case NM_VALUE_TYPE_BOOL:
        return *((const bool *) p_a) == *((const bool *) p_b);
    case NM_VALUE_TYPE_INT32:
        return *((const gint32 *) p_a) == *((const gint32 *) p_b);
    case NM_VALUE_TYPE_UINT32:
        return *((const guint32 *) p_a) == *((const guint32 *) p_b);
    case NM_VALUE_TYPE_STRING:
        return nm_streq0(*((const char *const *) p_a), *((const char *const *) p_b));
    default:
        return nm_assert_unreachable_val(TRUE);
    }
}

NMTernary
_nm_setting_property_compare_fcn_default(const NMSettInfoSetting * sett_info,
                                         const NMSettInfoProperty *property_info,
                                         NMConnection *            con_a,
                                         NMSetting *               set_a,
                                         NMConnection *            con_b,
                                         NMSetting *               set_b,
                                         NMSettingCompareFlags     flags)
{
    nm_assert(property_info->property_type->direct_type == NM_VALUE_TYPE_NONE);

    if (!property_info->param_spec)
        return nm_assert_unreachable_val(NM_TERNARY_DEFAULT);

    if (!_nm_setting_compare_flags_check(property_info->param_spec, flags, set_a, set_b))
        return NM_TERNARY_DEFAULT;

    if (!set_b)
        return TRUE;

    {
        gs_unref_variant GVariant *value1 = NULL;
        gs_unref_variant GVariant *value2 = NULL;

        value1 = property_to_dbus(sett_info,
                                  property_info,
                                  con_a,
                                  set_a,
                                  NM_CONNECTION_SERIALIZE_ALL,
                                  NULL,
                                  TRUE);
        value2 = property_to_dbus(sett_info,
                                  property_info,
                                  con_b,
                                  set_b,
                                  NM_CONNECTION_SERIALIZE_ALL,
                                  NULL,
                                  TRUE);
        return nm_property_compare(value1, value2) == 0;
    }
}

static NMTernary
_compare_property(const NMSettInfoSetting * sett_info,
                  const NMSettInfoProperty *property_info,
                  NMConnection *            con_a,
                  NMSetting *               set_a,
                  NMConnection *            con_b,
                  NMSetting *               set_b,
                  NMSettingCompareFlags     flags)
{
    NMTernary compare_result;

    nm_assert(sett_info);
    nm_assert(NM_IS_SETTING_CLASS(sett_info->setting_class));
    nm_assert(property_info);
    nm_assert(NM_SETTING_GET_CLASS(set_a) == sett_info->setting_class);
    nm_assert(!set_b || NM_SETTING_GET_CLASS(set_b) == sett_info->setting_class);

    compare_result = property_info->property_type
                         ->compare_fcn(sett_info, property_info, con_a, set_a, con_b, set_b, flags);

    nm_assert_is_ternary(compare_result);

    /* check that the inferable flag and the GObject property flag corresponds. */
    nm_assert(!NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_INFERRABLE) || !property_info->param_spec
              || NM_FLAGS_HAS(property_info->param_spec->flags, NM_SETTING_PARAM_INFERRABLE)
              || compare_result == NM_TERNARY_DEFAULT);

#if NM_MORE_ASSERTS > 10
    /* assert that compare_fcn() is symeric. */
    nm_assert(
        !set_b
        || compare_result
               == property_info->property_type
                      ->compare_fcn(sett_info, property_info, con_b, set_b, con_a, set_a, flags));
#endif

    return compare_result;
}

/**
 * nm_setting_compare:
 * @a: a #NMSetting
 * @b: a second #NMSetting to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 *
 * Compares two #NMSetting objects for similarity, with comparison behavior
 * modified by a set of flags.  See the documentation for #NMSettingCompareFlags
 * for a description of each flag's behavior.
 *
 * Returns: %TRUE if the comparison succeeds, %FALSE if it does not
 **/
gboolean
nm_setting_compare(NMSetting *a, NMSetting *b, NMSettingCompareFlags flags)
{
    return _nm_setting_compare(NULL, a, NULL, b, flags);
}

gboolean
_nm_setting_compare(NMConnection *        con_a,
                    NMSetting *           a,
                    NMConnection *        con_b,
                    NMSetting *           b,
                    NMSettingCompareFlags flags)
{
    const NMSettInfoSetting *sett_info;
    guint16                  i;

    g_return_val_if_fail(NM_IS_SETTING(a), FALSE);
    g_return_val_if_fail(NM_IS_SETTING(b), FALSE);

    nm_assert(!con_a || NM_IS_CONNECTION(con_a));
    nm_assert(!con_b || NM_IS_CONNECTION(con_b));

    /* First check that both have the same type */
    if (G_OBJECT_TYPE(a) != G_OBJECT_TYPE(b))
        return FALSE;

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(a));

    if (sett_info->detail.gendata_info) {
        GenData *a_gendata = _gendata_hash(a, FALSE);
        GenData *b_gendata = _gendata_hash(b, FALSE);

        return nm_utils_hashtable_equal(a_gendata ? a_gendata->hash : NULL,
                                        b_gendata ? b_gendata->hash : NULL,
                                        TRUE,
                                        g_variant_equal);
    }

    for (i = 0; i < sett_info->property_infos_len; i++) {
        if (_compare_property(sett_info, &sett_info->property_infos[i], con_a, a, con_b, b, flags)
            == NM_TERNARY_FALSE)
            return FALSE;
    }

    return TRUE;
}

static void
_setting_diff_add_result(GHashTable *results, const char *prop_name, NMSettingDiffResult r)
{
    void *p;

    if (r == NM_SETTING_DIFF_RESULT_UNKNOWN)
        return;

    if (g_hash_table_lookup_extended(results, prop_name, NULL, &p)) {
        if (!NM_FLAGS_ALL((guint) r, GPOINTER_TO_UINT(p)))
            g_hash_table_insert(results,
                                g_strdup(prop_name),
                                GUINT_TO_POINTER(((guint) r) | GPOINTER_TO_UINT(p)));
    } else
        g_hash_table_insert(results, g_strdup(prop_name), GUINT_TO_POINTER(r));
}

/**
 * nm_setting_diff:
 * @a: a #NMSetting
 * @b: a second #NMSetting to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 * @invert_results: this parameter is used internally by libnm and should
 * be set to %FALSE.  If %TRUE inverts the meaning of the #NMSettingDiffResult.
 * @results: (inout) (transfer full) (element-type utf8 guint32): if the
 * settings differ, on return a hash table mapping the differing keys to one or
 * more %NMSettingDiffResult values OR-ed together.  If the settings do not
 * differ, any hash table passed in is unmodified.  If no hash table is passed
 * in and the settings differ, a new one is created and returned.
 *
 * Compares two #NMSetting objects for similarity, with comparison behavior
 * modified by a set of flags.  See the documentation for #NMSettingCompareFlags
 * for a description of each flag's behavior.  If the settings differ, the keys
 * of each setting that differ from the other are added to @results, mapped to
 * one or more #NMSettingDiffResult values.
 *
 * Returns: %TRUE if the settings contain the same values, %FALSE if they do not
 **/
gboolean
nm_setting_diff(NMSetting *           a,
                NMSetting *           b,
                NMSettingCompareFlags flags,
                gboolean              invert_results,
                GHashTable **         results)
{
    return _nm_setting_diff(NULL, a, NULL, b, flags, invert_results, results);
}

gboolean
_nm_setting_diff(NMConnection *        con_a,
                 NMSetting *           a,
                 NMConnection *        con_b,
                 NMSetting *           b,
                 NMSettingCompareFlags flags,
                 gboolean              invert_results,
                 GHashTable **         results)
{
    const NMSettInfoSetting *sett_info;
    NMSettingDiffResult      a_result         = NM_SETTING_DIFF_RESULT_IN_A;
    NMSettingDiffResult      b_result         = NM_SETTING_DIFF_RESULT_IN_B;
    NMSettingDiffResult      a_result_default = NM_SETTING_DIFF_RESULT_IN_A_DEFAULT;
    NMSettingDiffResult      b_result_default = NM_SETTING_DIFF_RESULT_IN_B_DEFAULT;
    gboolean                 results_created  = FALSE;
    gboolean                 compared_any     = FALSE;
    gboolean                 diff_found       = FALSE;
    guint16                  i;

    g_return_val_if_fail(results != NULL, FALSE);
    g_return_val_if_fail(NM_IS_SETTING(a), FALSE);
    if (b) {
        g_return_val_if_fail(NM_IS_SETTING(b), FALSE);
        g_return_val_if_fail(G_OBJECT_TYPE(a) == G_OBJECT_TYPE(b), FALSE);
    }

    nm_assert(!con_a || NM_IS_CONNECTION(con_a));
    nm_assert(!con_b || NM_IS_CONNECTION(con_b));

    if ((flags
         & (NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT
            | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT))
        == (NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT
            | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT)) {
        /* conflicting flags: default to WITH_DEFAULT (clearing NO_DEFAULT). */
        flags &= ~NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT;
    }

    /* If the caller is calling this function in a pattern like this to get
     * complete diffs:
     *
     * nm_setting_diff (A, B, FALSE, &results);
     * nm_setting_diff (B, A, TRUE, &results);
     *
     * and wants us to invert the results so that the second invocation comes
     * out correctly, do that here.
     */
    if (invert_results) {
        a_result         = NM_SETTING_DIFF_RESULT_IN_B;
        b_result         = NM_SETTING_DIFF_RESULT_IN_A;
        a_result_default = NM_SETTING_DIFF_RESULT_IN_B_DEFAULT;
        b_result_default = NM_SETTING_DIFF_RESULT_IN_A_DEFAULT;
    }

    if (*results == NULL) {
        *results        = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, NULL);
        results_created = TRUE;
    }

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(a));

    if (sett_info->detail.gendata_info) {
        const char *   key;
        GVariant *     val, *val2;
        GHashTableIter iter;
        GenData *      a_gendata = _gendata_hash(a, FALSE);
        GenData *      b_gendata = b ? _gendata_hash(b, FALSE) : NULL;

        if (!a_gendata || !b_gendata) {
            if (a_gendata || b_gendata) {
                NMSettingDiffResult one_sided_result;

                one_sided_result = a_gendata ? a_result : b_result;
                g_hash_table_iter_init(&iter, a_gendata ? a_gendata->hash : b_gendata->hash);
                while (g_hash_table_iter_next(&iter, (gpointer *) &key, NULL)) {
                    diff_found = TRUE;
                    _setting_diff_add_result(*results, key, one_sided_result);
                }
            }
        } else {
            g_hash_table_iter_init(&iter, a_gendata->hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
                val2         = g_hash_table_lookup(b_gendata->hash, key);
                compared_any = TRUE;
                if (!val2 || !g_variant_equal(val, val2)) {
                    diff_found = TRUE;
                    _setting_diff_add_result(*results, key, a_result);
                }
            }
            g_hash_table_iter_init(&iter, b_gendata->hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
                val2         = g_hash_table_lookup(a_gendata->hash, key);
                compared_any = TRUE;
                if (!val2 || !g_variant_equal(val, val2)) {
                    diff_found = TRUE;
                    _setting_diff_add_result(*results, key, b_result);
                }
            }
        }
    } else {
        for (i = 0; i < sett_info->property_infos_len; i++) {
            NMSettingDiffResult       r             = NM_SETTING_DIFF_RESULT_UNKNOWN;
            const NMSettInfoProperty *property_info = &sett_info->property_infos[i];
            NMTernary                 compare_result;
            GParamSpec *              prop_spec;

            compare_result = _compare_property(sett_info, property_info, con_a, a, con_b, b, flags);
            if (compare_result == NM_TERNARY_DEFAULT)
                continue;

            if (NM_FLAGS_ANY(flags,
                             NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS
                                 | NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
                && b && compare_result == NM_TERNARY_FALSE) {
                /* we have setting @b and the property is not the same. But we also are instructed
                 * to ignore secrets based on the flags.
                 *
                 * Note that compare_property() called with two settings will ignore secrets
                 * based on the flags, but it will do so if *both* settings have the flag we
                 * look for. So that is symmetric behavior and good.
                 *
                 * But for the purpose of diff(), we do a asymmetric comparison because and
                 * we want to skip testing the property if setting @a alone indicates to do
                 * so.
                 *
                 * We need to double-check whether the property should be ignored by
                 * looking at @a alone. */
                if (_compare_property(sett_info, property_info, con_a, a, NULL, NULL, flags)
                    == NM_TERNARY_DEFAULT)
                    continue;
            }

            compared_any = TRUE;

            prop_spec = property_info->param_spec;

            if (b) {
                if (compare_result == NM_TERNARY_FALSE) {
                    if (prop_spec) {
                        gboolean a_is_default, b_is_default;
                        GValue   value = G_VALUE_INIT;

                        g_value_init(&value, prop_spec->value_type);
                        g_object_get_property(G_OBJECT(a), prop_spec->name, &value);
                        a_is_default = g_param_value_defaults(prop_spec, &value);

                        g_value_reset(&value);
                        g_object_get_property(G_OBJECT(b), prop_spec->name, &value);
                        b_is_default = g_param_value_defaults(prop_spec, &value);

                        g_value_unset(&value);
                        if (!NM_FLAGS_HAS(flags,
                                          NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT)) {
                            if (!a_is_default)
                                r |= a_result;
                            if (!b_is_default)
                                r |= b_result;
                        } else {
                            r |= a_result | b_result;
                            if (a_is_default)
                                r |= a_result_default;
                            if (b_is_default)
                                r |= b_result_default;
                        }
                    } else
                        r |= a_result | b_result;
                }
            } else if ((flags
                        & (NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT
                           | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT))
                       == 0)
                r = a_result; /* only in A */
            else {
                if (prop_spec) {
                    GValue value = G_VALUE_INIT;

                    g_value_init(&value, prop_spec->value_type);
                    g_object_get_property(G_OBJECT(a), prop_spec->name, &value);
                    if (!g_param_value_defaults(prop_spec, &value))
                        r |= a_result;
                    else if (flags & NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT)
                        r |= a_result | a_result_default;

                    g_value_unset(&value);
                } else
                    r |= a_result;
            }

            if (r != NM_SETTING_DIFF_RESULT_UNKNOWN) {
                diff_found = TRUE;
                _setting_diff_add_result(*results, property_info->name, r);
            }
        }
    }

    if (!compared_any && !b) {
        /* special case: the setting has no properties, and the opposite
         * setting @b is not given. The settings differ, and we signal that
         * by returning an empty results hash. */
        diff_found = TRUE;
    }

    if (diff_found) {
        /* if there is a difference, we always return FALSE. It also means, we might
         * have allocated a new @results hash, and return it to the caller. */
        return FALSE;
    } else {
        if (results_created) {
            /* the allocated hash is unused. Clear it again. */
            g_hash_table_destroy(*results);
            *results = NULL;
        } else {
            /* we found no diff, and return false. However, the input
             * @result is returned unmodified. */
        }
        return TRUE;
    }
}

static void
enumerate_values(const NMSettInfoProperty *property_info,
                 NMSetting *               setting,
                 NMSettingValueIterFn      func,
                 gpointer                  user_data)
{
    GValue value = G_VALUE_INIT;

    if (!property_info->param_spec)
        return;

    g_value_init(&value, G_PARAM_SPEC_VALUE_TYPE(property_info->param_spec));
    g_object_get_property(G_OBJECT(setting), property_info->param_spec->name, &value);
    func(setting,
         property_info->param_spec->name,
         &value,
         property_info->param_spec->flags,
         user_data);
    g_value_unset(&value);
}

/**
 * nm_setting_enumerate_values:
 * @setting: the #NMSetting
 * @func: (scope call): user-supplied function called for each property of the setting
 * @user_data: user data passed to @func at each invocation
 *
 * Iterates over each property of the #NMSetting object, calling the supplied
 * user function for each property.
 **/
void
nm_setting_enumerate_values(NMSetting *setting, NMSettingValueIterFn func, gpointer user_data)
{
    const NMSettInfoSetting *sett_info;
    guint                    i;
    guint16                  j;

    g_return_if_fail(NM_IS_SETTING(setting));
    g_return_if_fail(func != NULL);

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));

    if (sett_info->detail.gendata_info) {
        const char *const *names;
        guint              n_properties;

        /* the properties of this setting are not real GObject properties.
         * Hence, this API makes little sense (or does it?). Still, call
         * @func with each value. */
        n_properties = _nm_setting_option_get_all(setting, &names, NULL);
        if (n_properties > 0) {
            gs_strfreev char **keys = g_strdupv((char **) names);
            GHashTable *       h    = _gendata_hash(setting, FALSE)->hash;

            for (i = 0; i < n_properties; i++) {
                GValue    value = G_VALUE_INIT;
                GVariant *val   = g_hash_table_lookup(h, keys[i]);

                if (!val) {
                    /* was deleted in the meantime? Skip */
                    continue;
                }

                g_value_init(&value, G_TYPE_VARIANT);
                g_value_set_variant(&value, val);
                /* call it will GParamFlags 0. It shall indicate that this
                 * is not a "real" GObject property. */
                func(setting, keys[i], &value, 0, user_data);
                g_value_unset(&value);
            }
        }
        return;
    }

    for (j = 0; j < sett_info->property_infos_len; j++) {
        NM_SETTING_GET_CLASS(setting)->enumerate_values(
            _nm_sett_info_property_info_get_sorted(sett_info, j),
            setting,
            func,
            user_data);
    }
}

static gboolean
aggregate(NMSetting *setting, int type_i, gpointer arg)
{
    NMConnectionAggregateType type = type_i;
    const NMSettInfoSetting * sett_info;
    guint16                   i;

    nm_assert(NM_IN_SET(type,
                        NM_CONNECTION_AGGREGATE_ANY_SECRETS,
                        NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS));

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    for (i = 0; i < sett_info->property_infos_len; i++) {
        const NMSettInfoProperty *  property_info = &sett_info->property_infos[i];
        GParamSpec *                prop_spec     = property_info->param_spec;
        nm_auto_unset_gvalue GValue value         = G_VALUE_INIT;
        NMSettingSecretFlags        secret_flags;

        if (!prop_spec || !NM_FLAGS_HAS(prop_spec->flags, NM_SETTING_PARAM_SECRET)) {
            nm_assert(!nm_setting_get_secret_flags(setting, property_info->name, NULL, NULL));
            continue;
        }

        /* for the moment, all aggregate types only care about secrets. */
        nm_assert(nm_setting_get_secret_flags(setting, property_info->name, NULL, NULL));

        switch (type) {
        case NM_CONNECTION_AGGREGATE_ANY_SECRETS:
            g_value_init(&value, G_PARAM_SPEC_VALUE_TYPE(prop_spec));
            g_object_get_property(G_OBJECT(setting), prop_spec->name, &value);
            if (!g_param_value_defaults(prop_spec, &value)) {
                *((gboolean *) arg) = TRUE;
                return TRUE;
            }
            break;

        case NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS:
            if (!nm_setting_get_secret_flags(setting, prop_spec->name, &secret_flags, NULL))
                nm_assert_not_reached();
            if (secret_flags == NM_SETTING_SECRET_FLAG_NONE) {
                *((gboolean *) arg) = TRUE;
                return TRUE;
            }
            break;
        }
    }

    return FALSE;
}

/**
 * _nm_setting_aggregate:
 * @setting: the #NMSetting to aggregate.
 * @type: the #NMConnectionAggregateType aggregate type.
 * @arg: the in/out arguments for aggregation. They depend on @type.
 *
 * This is the implementation detail of _nm_connection_aggregate(). It
 * makes no sense to call this function directly outside of _nm_connection_aggregate().
 *
 * Returns: %TRUE if afterwards the aggregation is complete. That means,
 *   the only caller _nm_connection_aggregate() will not visit other settings
 *   after a setting returns %TRUE (indicating that there is nothing further
 *   to aggregate). Note that is very different from the boolean return
 *   argument of _nm_connection_aggregate(), which serves a different purpose.
 */
gboolean
_nm_setting_aggregate(NMSetting *setting, NMConnectionAggregateType type, gpointer arg)
{
    g_return_val_if_fail(NM_IS_SETTING(setting), FALSE);
    g_return_val_if_fail(arg, FALSE);
    g_return_val_if_fail(NM_IN_SET(type,
                                   NM_CONNECTION_AGGREGATE_ANY_SECRETS,
                                   NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS),
                         FALSE);

    return NM_SETTING_GET_CLASS(setting)->aggregate(setting, type, arg);
}

static gboolean
clear_secrets(const NMSettInfoSetting *        sett_info,
              const NMSettInfoProperty *       property_info,
              NMSetting *                      setting,
              NMSettingClearSecretsWithFlagsFn func,
              gpointer                         user_data)
{
    NMSettingSecretFlags flags      = NM_SETTING_SECRET_FLAG_NONE;
    GParamSpec *         param_spec = property_info->param_spec;

    if (!param_spec)
        return FALSE;

    if (!NM_FLAGS_HAS(param_spec->flags, NM_SETTING_PARAM_SECRET))
        return FALSE;

    if (func) {
        if (!nm_setting_get_secret_flags(setting, param_spec->name, &flags, NULL))
            nm_assert_not_reached();
        if (!func(setting, param_spec->name, flags, user_data))
            return FALSE;
    } else
        nm_assert(nm_setting_get_secret_flags(setting, param_spec->name, NULL, NULL));

    {
        nm_auto_unset_gvalue GValue value = G_VALUE_INIT;

        g_value_init(&value, param_spec->value_type);
        g_object_get_property(G_OBJECT(setting), param_spec->name, &value);
        if (g_param_value_defaults(param_spec, &value))
            return FALSE;

        g_param_value_set_default(param_spec, &value);
        g_object_set_property(G_OBJECT(setting), param_spec->name, &value);
    }

    return TRUE;
}

/**
 * _nm_setting_clear_secrets:
 * @setting: the #NMSetting
 * @func: (scope call): function to be called to determine whether a
 *     specific secret should be cleared or not
 * @user_data: caller-supplied data passed to @func
 *
 * Clears and frees secrets determined by @func.
 *
 * Returns: %TRUE if the setting changed at all
 **/
gboolean
_nm_setting_clear_secrets(NMSetting *                      setting,
                          NMSettingClearSecretsWithFlagsFn func,
                          gpointer                         user_data)
{
    const NMSettInfoSetting *sett_info;
    gboolean                 changed = FALSE;
    guint16                  i;
    gboolean (*my_clear_secrets)(const struct _NMSettInfoSetting *sett_info,
                                 const NMSettInfoProperty *       property_info,
                                 NMSetting *                      setting,
                                 NMSettingClearSecretsWithFlagsFn func,
                                 gpointer                         user_data);

    g_return_val_if_fail(NM_IS_SETTING(setting), FALSE);

    my_clear_secrets = NM_SETTING_GET_CLASS(setting)->clear_secrets;

    sett_info = _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting));
    for (i = 0; i < sett_info->property_infos_len; i++) {
        changed |=
            my_clear_secrets(sett_info, &sett_info->property_infos[i], setting, func, user_data);
    }
    return changed;
}

/**
 * _nm_setting_need_secrets:
 * @setting: the #NMSetting
 *
 * Returns an array of property names for each secret which may be required
 * to make a successful connection.  The returned hints are only intended as a
 * guide to what secrets may be required, because in some circumstances, there
 * is no way to conclusively determine exactly which secrets are needed.
 *
 * Returns: (transfer container) (element-type utf8): a #GPtrArray containing
 * the property names of secrets of the #NMSetting which may be required; the
 * caller owns the array and must free it with g_ptr_array_free(), but must not
 * free the elements.
 **/
GPtrArray *
_nm_setting_need_secrets(NMSetting *setting)
{
    GPtrArray *secrets = NULL;

    g_return_val_if_fail(NM_IS_SETTING(setting), NULL);

    if (NM_SETTING_GET_CLASS(setting)->need_secrets)
        secrets = NM_SETTING_GET_CLASS(setting)->need_secrets(setting);

    return secrets;
}

static int
update_one_secret(NMSetting *setting, const char *key, GVariant *value, GError **error)
{
    const NMSettInfoProperty *property;
    GParamSpec *              prop_spec;
    GValue                    prop_value = {
        0,
    };

    property = _nm_setting_class_get_property_info(NM_SETTING_GET_CLASS(setting), key);
    if (!property) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_PROPERTY_NOT_FOUND,
                            _("secret not found"));
        g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), key);
        return NM_SETTING_UPDATE_SECRET_ERROR;
    }

    /* Silently ignore non-secrets */
    prop_spec = property->param_spec;
    if (!prop_spec || !(prop_spec->flags & NM_SETTING_PARAM_SECRET))
        return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

    if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING) && G_IS_PARAM_SPEC_STRING(prop_spec)) {
        /* String is expected to be a common case. Handle it specially and check
         * whether the value is already set. Otherwise, we just reset the
         * property and assume the value got modified.
         */
        char *v;

        g_object_get(G_OBJECT(setting), prop_spec->name, &v, NULL);
        if (g_strcmp0(v, g_variant_get_string(value, NULL)) == 0) {
            g_free(v);
            return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;
        }
        g_free(v);
    }

    g_value_init(&prop_value, prop_spec->value_type);
    set_property_from_dbus(property, value, &prop_value);
    g_object_set_property(G_OBJECT(setting), prop_spec->name, &prop_value);
    g_value_unset(&prop_value);

    return NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
}

/**
 * _nm_setting_update_secrets:
 * @setting: the #NMSetting
 * @secrets: a #GVariant of type #NM_VARIANT_TYPE_SETTING, mapping property
 *   names to secrets.
 * @error: location to store error, or %NULL
 *
 * Update the setting's secrets, given a dictionary of secrets intended for that
 * setting (deserialized from D-Bus for example).
 *
 * Returns: an #NMSettingUpdateSecretResult
 **/
NMSettingUpdateSecretResult
_nm_setting_update_secrets(NMSetting *setting, GVariant *secrets, GError **error)
{
    GVariantIter                iter;
    const char *                secret_key;
    GVariant *                  secret_value;
    GError *                    tmp_error = NULL;
    NMSettingUpdateSecretResult result    = NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

    g_return_val_if_fail(NM_IS_SETTING(setting), NM_SETTING_UPDATE_SECRET_ERROR);
    g_return_val_if_fail(g_variant_is_of_type(secrets, NM_VARIANT_TYPE_SETTING),
                         NM_SETTING_UPDATE_SECRET_ERROR);
    if (error)
        g_return_val_if_fail(*error == NULL, NM_SETTING_UPDATE_SECRET_ERROR);

    g_variant_iter_init(&iter, secrets);
    while (g_variant_iter_next(&iter, "{&sv}", &secret_key, &secret_value)) {
        int success;

        success = NM_SETTING_GET_CLASS(setting)->update_one_secret(setting,
                                                                   secret_key,
                                                                   secret_value,
                                                                   &tmp_error);
        nm_assert(!((success == NM_SETTING_UPDATE_SECRET_ERROR) ^ (!!tmp_error)));

        g_variant_unref(secret_value);

        if (success == NM_SETTING_UPDATE_SECRET_ERROR) {
            g_propagate_error(error, tmp_error);
            return NM_SETTING_UPDATE_SECRET_ERROR;
        }

        if (success == NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED)
            result = NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
    }

    return result;
}

static void
for_each_secret(NMSetting *                    setting,
                const char *                   secret_name,
                GVariant *                     val,
                gboolean                       remove_non_secrets,
                _NMConnectionForEachSecretFunc callback,
                gpointer                       callback_data,
                GVariantBuilder *              setting_builder)
{
    NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

    if (!nm_setting_get_secret_flags(setting, secret_name, &secret_flags, NULL)) {
        if (!remove_non_secrets)
            g_variant_builder_add(setting_builder, "{sv}", secret_name, val);
        return;
    }
    if (callback(secret_flags, callback_data))
        g_variant_builder_add(setting_builder, "{sv}", secret_name, val);
}

static void
_set_error_secret_property_not_found(GError **error, NMSetting *setting, const char *secret_name)
{
    g_set_error_literal(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_PROPERTY_NOT_FOUND,
                        _("not a secret property"));
    g_prefix_error(error, "%s.%s: ", nm_setting_get_name(setting), secret_name);
}

gboolean
_nm_setting_property_is_regular_secret(NMSetting *setting, const char *secret_name)
{
    const NMSettInfoProperty *property;

    nm_assert(NM_IS_SETTING(setting));
    nm_assert(secret_name);

    property = _nm_setting_class_get_property_info(NM_SETTING_GET_CLASS(setting), secret_name);
    return property && property->param_spec
           && NM_FLAGS_HAS(property->param_spec->flags, NM_SETTING_PARAM_SECRET);
}

gboolean
_nm_setting_property_is_regular_secret_flags(NMSetting *setting, const char *secret_flags_name)
{
    const NMSettInfoProperty *property;

    nm_assert(NM_IS_SETTING(setting));
    nm_assert(secret_flags_name);

    property =
        _nm_setting_class_get_property_info(NM_SETTING_GET_CLASS(setting), secret_flags_name);
    return property && property->param_spec
           && !NM_FLAGS_HAS(property->param_spec->flags, NM_SETTING_PARAM_SECRET)
           && G_PARAM_SPEC_VALUE_TYPE(property->param_spec) == NM_TYPE_SETTING_SECRET_FLAGS;
}

static gboolean
get_secret_flags(NMSetting *           setting,
                 const char *          secret_name,
                 NMSettingSecretFlags *out_flags,
                 GError **             error)
{
    gs_free char *       secret_flags_name_free = NULL;
    const char *         secret_flags_name;
    NMSettingSecretFlags flags;

    if (!_nm_setting_property_is_regular_secret(setting, secret_name)) {
        _set_error_secret_property_not_found(error, setting, secret_name);
        NM_SET_OUT(out_flags, NM_SETTING_SECRET_FLAG_NONE);
        return FALSE;
    }

    secret_flags_name = nm_construct_name_a("%s-flags", secret_name, &secret_flags_name_free);

    nm_assert(_nm_setting_property_is_regular_secret_flags(setting, secret_flags_name));

    g_object_get(G_OBJECT(setting), secret_flags_name, &flags, NULL);
    NM_SET_OUT(out_flags, flags);
    return TRUE;
}

/**
 * nm_setting_get_secret_flags:
 * @setting: the #NMSetting
 * @secret_name: the secret key name to get flags for
 * @out_flags: on success, the #NMSettingSecretFlags for the secret
 * @error: location to store error, or %NULL
 *
 * For a given secret, retrieves the #NMSettingSecretFlags describing how to
 * handle that secret.
 *
 * Returns: %TRUE on success (if the given secret name was a valid property of
 * this setting, and if that property is secret), %FALSE if not
 **/
gboolean
nm_setting_get_secret_flags(NMSetting *           setting,
                            const char *          secret_name,
                            NMSettingSecretFlags *out_flags,
                            GError **             error)
{
    g_return_val_if_fail(NM_IS_SETTING(setting), FALSE);
    g_return_val_if_fail(secret_name != NULL, FALSE);

    return NM_SETTING_GET_CLASS(setting)->get_secret_flags(setting, secret_name, out_flags, error);
}

static gboolean
set_secret_flags(NMSetting *          setting,
                 const char *         secret_name,
                 NMSettingSecretFlags flags,
                 GError **            error)
{
    gs_free char *secret_flags_name_free = NULL;
    const char *  secret_flags_name;

    if (!_nm_setting_property_is_regular_secret(setting, secret_name)) {
        _set_error_secret_property_not_found(error, setting, secret_name);
        return FALSE;
    }

    secret_flags_name = nm_construct_name_a("%s-flags", secret_name, &secret_flags_name_free);

    nm_assert(_nm_setting_property_is_regular_secret_flags(setting, secret_flags_name));

    if (!nm_g_object_set_property_flags(G_OBJECT(setting),
                                        secret_flags_name,
                                        NM_TYPE_SETTING_SECRET_FLAGS,
                                        flags,
                                        error))
        g_return_val_if_reached(FALSE);
    return TRUE;
}

/**
 * nm_setting_set_secret_flags:
 * @setting: the #NMSetting
 * @secret_name: the secret key name to set flags for
 * @flags: the #NMSettingSecretFlags for the secret
 * @error: location to store error, or %NULL
 *
 * For a given secret, stores the #NMSettingSecretFlags describing how to
 * handle that secret.
 *
 * Returns: %TRUE on success (if the given secret name was a valid property of
 * this setting, and if that property is secret), %FALSE if not
 **/
gboolean
nm_setting_set_secret_flags(NMSetting *          setting,
                            const char *         secret_name,
                            NMSettingSecretFlags flags,
                            GError **            error)
{
    g_return_val_if_fail(NM_IS_SETTING(setting), FALSE);
    g_return_val_if_fail(secret_name != NULL, FALSE);
    g_return_val_if_fail(_nm_setting_secret_flags_valid(flags), FALSE);

    return NM_SETTING_GET_CLASS(setting)->set_secret_flags(setting, secret_name, flags, error);
}

/**
 * nm_setting_to_string:
 * @setting: the #NMSetting
 *
 * Convert the setting (including secrets!) into a string. For debugging
 * purposes ONLY, should NOT be used for serialization of the setting,
 * or machine-parsed in any way. The output format is not guaranteed to
 * be stable and may change at any time.
 *
 * Returns: an allocated string containing a textual representation of the
 * setting's properties and values, which the caller should
 * free with g_free()
 **/
char *
nm_setting_to_string(NMSetting *setting)
{
    GString *        string;
    gs_unref_variant GVariant *variant = NULL;
    GVariant *                 child;
    GVariantIter               iter;

    string = g_string_new(nm_setting_get_name(setting));
    g_string_append_c(string, '\n');

    variant = _nm_setting_to_dbus(setting, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);

    g_variant_iter_init(&iter, variant);
    while ((child = g_variant_iter_next_value(&iter))) {
        gs_free char *   name            = NULL;
        gs_free char *   value_str       = NULL;
        gs_unref_variant GVariant *value = NULL;

        g_variant_get(child, "{sv}", &name, &value);
        value_str = g_variant_print(value, FALSE);

        g_string_append_printf(string, "\t%s : %s\n", name, value_str);
    }

    return g_string_free(string, FALSE);
}

static GVariant *
_nm_setting_get_deprecated_virtual_interface_name(const NMSettInfoSetting *      sett_info,
                                                  const NMSettInfoProperty *     property_info,
                                                  NMConnection *                 connection,
                                                  NMSetting *                    setting,
                                                  NMConnectionSerializationFlags flags,
                                                  const NMConnectionSerializationOptions *options)
{
    NMSettingConnection *s_con;

    if (!connection)
        return NULL;

    s_con = nm_connection_get_setting_connection(connection);
    if (!s_con)
        return NULL;

    if (nm_setting_connection_get_interface_name(s_con))
        return g_variant_new_string(nm_setting_connection_get_interface_name(s_con));
    else
        return NULL;
}

const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_interface_name =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(G_VARIANT_TYPE_STRING,
                                        .compare_fcn = _nm_setting_property_compare_fcn_ignore,
                                        .to_dbus_fcn =
                                            _nm_setting_get_deprecated_virtual_interface_name, );

const NMSettInfoPropertType nm_sett_info_propert_type_setting_name =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(G_VARIANT_TYPE_STRING,
                                        .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_ignore,
                                        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_ignore,
                                        .from_dbus_is_full = TRUE,
                                        .compare_fcn = _nm_setting_property_compare_fcn_ignore);

const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_i =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(
        G_VARIANT_TYPE_INT32,
        /* No functions set. This property type is to silently ignore the value on D-Bus. */
        .compare_fcn = _nm_setting_property_compare_fcn_ignore);

const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_u =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(
        G_VARIANT_TYPE_UINT32,
        /* No functions set. This property type is to silently ignore the value on D-Bus. */
        .compare_fcn = _nm_setting_property_compare_fcn_ignore);

const NMSettInfoPropertType nm_sett_info_propert_type_plain_i =
    NM_SETT_INFO_PROPERT_TYPE_GPROP_INIT(G_VARIANT_TYPE_INT32,
                                         .compare_fcn   = _nm_setting_property_compare_fcn_default,
                                         .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_gprop,
                                         .from_dbus_is_full = TRUE);

const NMSettInfoPropertType nm_sett_info_propert_type_plain_u =
    NM_SETT_INFO_PROPERT_TYPE_GPROP_INIT(G_VARIANT_TYPE_UINT32,
                                         .compare_fcn   = _nm_setting_property_compare_fcn_default,
                                         .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_gprop,
                                         .from_dbus_is_full = TRUE);

const NMSettInfoPropertType nm_sett_info_propert_type_direct_boolean =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(G_VARIANT_TYPE_BOOLEAN,
                                        .direct_type   = NM_VALUE_TYPE_BOOL,
                                        .compare_fcn   = _nm_setting_property_compare_fcn_direct,
                                        .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct,
                                        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct,
                                        .from_dbus_is_full                = TRUE,
                                        .from_dbus_direct_allow_transform = TRUE);

const NMSettInfoPropertType nm_sett_info_propert_type_direct_int32 =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(G_VARIANT_TYPE_INT32,
                                        .direct_type   = NM_VALUE_TYPE_INT32,
                                        .compare_fcn   = _nm_setting_property_compare_fcn_direct,
                                        .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct,
                                        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct,
                                        .from_dbus_is_full                = TRUE,
                                        .from_dbus_direct_allow_transform = TRUE);

const NMSettInfoPropertType nm_sett_info_propert_type_direct_uint32 =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(G_VARIANT_TYPE_UINT32,
                                        .direct_type   = NM_VALUE_TYPE_UINT32,
                                        .compare_fcn   = _nm_setting_property_compare_fcn_direct,
                                        .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct,
                                        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct,
                                        .from_dbus_is_full                = TRUE,
                                        .from_dbus_direct_allow_transform = TRUE);

const NMSettInfoPropertType nm_sett_info_propert_type_direct_string =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(G_VARIANT_TYPE_STRING,
                                        .direct_type   = NM_VALUE_TYPE_STRING,
                                        .compare_fcn   = _nm_setting_property_compare_fcn_direct,
                                        .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct,
                                        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct,
                                        .from_dbus_is_full                = TRUE,
                                        .from_dbus_direct_allow_transform = TRUE);

const NMSettInfoPropertType nm_sett_info_propert_type_direct_mac_address =
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(
        G_VARIANT_TYPE_BYTESTRING,
        .direct_type   = NM_VALUE_TYPE_STRING,
        .compare_fcn   = _nm_setting_property_compare_fcn_direct,
        .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct_mac_address,
        .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct_mac_address);

/*****************************************************************************/

static GenData *
_gendata_hash(NMSetting *setting, gboolean create_if_necessary)
{
    NMSettingPrivate *priv;

    nm_assert(NM_IS_SETTING(setting));

    priv = NM_SETTING_GET_PRIVATE(setting);

    if (G_UNLIKELY(!priv->gendata)) {
        if (!create_if_necessary)
            return NULL;
        priv->gendata         = g_slice_new(GenData);
        priv->gendata->hash   = g_hash_table_new_full(nm_str_hash,
                                                    g_str_equal,
                                                    g_free,
                                                    (GDestroyNotify) g_variant_unref);
        priv->gendata->names  = NULL;
        priv->gendata->values = NULL;
    }

    return priv->gendata;
}

GHashTable *
_nm_setting_option_hash(NMSetting *setting, gboolean create_if_necessary)
{
    GenData *gendata;

    gendata = _gendata_hash(setting, create_if_necessary);
    return gendata ? gendata->hash : NULL;
}

void
_nm_setting_option_notify(NMSetting *setting, gboolean names_changed)
{
    GenData *gendata;

    gendata = _gendata_hash(setting, FALSE);
    if (!gendata)
        goto out;

    nm_clear_g_free(&gendata->values);

    if (names_changed) {
        /* if only the values changed, it's sufficient to invalidate the
         * values cache. Otherwise, the names cache must be invalidated too. */
        nm_clear_g_free(&gendata->names);
    }

    /* Note, currently there is no way to notify the subclass when gendata changed.
     * gendata is only changed in two situations:
     *   1) from within NMSetting itself, for example when creating a NMSetting instance
     *      from keyfile or a D-Bus GVariant.
     *   2) actively from the subclass itself
     * For 2), we don't need the notification, because the subclass knows that something
     * changed.
     * For 1), we currently don't need the notification either, because all that the subclass
     * currently would do, is emit a g_object_notify() signal. However, 1) only happens when
     * the setting instance is newly created, at that point, nobody listens to the signal.
     *
     * If we ever need it, then we would need to call a virtual function to notify the subclass
     * that gendata changed. */

out:
    _nm_setting_emit_property_changed(setting);
}

guint
_nm_setting_option_get_all(NMSetting *         setting,
                           const char *const **out_names,
                           GVariant *const **  out_values)
{
    GenData *   gendata;
    GHashTable *hash;
    guint       i, len;

    nm_assert(NM_IS_SETTING(setting));

    gendata = _gendata_hash(setting, FALSE);
    if (!gendata)
        goto out_zero;

    hash = gendata->hash;
    len  = g_hash_table_size(hash);
    if (len == 0)
        goto out_zero;

    if (!out_names && !out_values)
        return len;

    if (G_UNLIKELY(!gendata->names)) {
        gendata->names = nm_utils_strdict_get_keys(hash, TRUE, NULL);
    }

    if (out_values) {
        if (G_UNLIKELY(!gendata->values)) {
            gendata->values = g_new(GVariant *, len + 1);
            for (i = 0; i < len; i++)
                gendata->values[i] = g_hash_table_lookup(hash, gendata->names[i]);
            gendata->values[i] = NULL;
        }
        *out_values = gendata->values;
    }

    NM_SET_OUT(out_names, (const char *const *) gendata->names);
    return len;

out_zero:
    NM_SET_OUT(out_names, NULL);
    NM_SET_OUT(out_values, NULL);
    return 0;
}

/**
 * nm_setting_option_get_all_names:
 * @setting: the #NMSetting
 * @out_len: (allow-none) (out):
 *
 * Gives the name of all set options.
 *
 * Returns: (array length=out_len zero-terminated=1) (transfer none):
 *   A %NULL terminated array of key names. If no names are present, this returns
 *   %NULL. The returned array and the names are owned by %NMSetting and might be invalidated
 *   by the next operation.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_option_get_all_names(NMSetting *setting, guint *out_len)
{
    const char *const *names;
    guint              len;

    g_return_val_if_fail(NM_IS_SETTING(setting), NULL);

    len = _nm_setting_option_get_all(setting, &names, NULL);
    NM_SET_OUT(out_len, len);
    return names;
}

gboolean
_nm_setting_option_clear(NMSetting *setting, const char *optname)
{
    GHashTable *ht;

    nm_assert(NM_IS_SETTING(setting));
    nm_assert(nm_str_not_empty(optname));

    ht = _nm_setting_option_hash(setting, FALSE);
    if (!ht)
        return FALSE;

    return g_hash_table_remove(ht, optname);
}

/**
 * nm_setting_option_clear_by_name:
 * @setting: the #NMSetting
 * @predicate: (allow-none) (scope call): the predicate for which names
 *   should be clear.
 *   If the predicate returns %TRUE for an option name, the option
 *   gets removed. If %NULL, all options will be removed.
 *
 * Since: 1.26
 */
void
nm_setting_option_clear_by_name(NMSetting *setting, NMUtilsPredicateStr predicate)
{
    GHashTable *   hash;
    GHashTableIter iter;
    const char *   name;
    gboolean       changed = FALSE;

    g_return_if_fail(NM_IS_SETTING(setting));

    hash = _nm_setting_option_hash(NM_SETTING(setting), FALSE);
    if (!hash)
        return;

    if (!predicate) {
        changed = (g_hash_table_size(hash) > 0);
        if (changed)
            g_hash_table_remove_all(hash);
    } else {
        g_hash_table_iter_init(&iter, hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) &name, NULL)) {
            if (predicate(name)) {
                g_hash_table_iter_remove(&iter);
                changed = TRUE;
            }
        }
    }

    if (changed)
        _nm_setting_option_notify(setting, TRUE);
}

/*****************************************************************************/

/**
 * nm_setting_option_get:
 * @setting: the #NMSetting
 * @opt_name: the option name to request.
 *
 * Returns: (transfer none): the #GVariant or %NULL if the option
 *   is not set.
 *
 * Since: 1.26.
 */
GVariant *
nm_setting_option_get(NMSetting *setting, const char *opt_name)
{
    GenData *gendata;

    g_return_val_if_fail(NM_IS_SETTING(setting), FALSE);
    g_return_val_if_fail(opt_name, FALSE);

    gendata = _gendata_hash(setting, FALSE);
    return gendata ? g_hash_table_lookup(gendata->hash, opt_name) : NULL;
}

/**
 * nm_setting_option_get_boolean:
 * @setting: the #NMSetting
 * @opt_name: the option to get
 * @out_value: (allow-none) (out): the optional output value.
 *   If the option is unset, %FALSE will be returned.
 *
 * Returns: %TRUE if @opt_name is set to a boolean variant.
 *
 * Since: 1.26
 */
gboolean
nm_setting_option_get_boolean(NMSetting *setting, const char *opt_name, gboolean *out_value)
{
    GVariant *v;

    v = nm_setting_option_get(NM_SETTING(setting), opt_name);
    if (v && g_variant_is_of_type(v, G_VARIANT_TYPE_BOOLEAN)) {
        NM_SET_OUT(out_value, g_variant_get_boolean(v));
        return TRUE;
    }
    NM_SET_OUT(out_value, FALSE);
    return FALSE;
}

/**
 * nm_setting_option_get_uint32:
 * @setting: the #NMSetting
 * @opt_name: the option to get
 * @out_value: (allow-none) (out): the optional output value.
 *   If the option is unset, 0 will be returned.
 *
 * Returns: %TRUE if @opt_name is set to a uint32 variant.
 *
 * Since: 1.26
 */
gboolean
nm_setting_option_get_uint32(NMSetting *setting, const char *opt_name, guint32 *out_value)
{
    GVariant *v;

    v = nm_setting_option_get(NM_SETTING(setting), opt_name);
    if (v && g_variant_is_of_type(v, G_VARIANT_TYPE_UINT32)) {
        NM_SET_OUT(out_value, g_variant_get_uint32(v));
        return TRUE;
    }
    NM_SET_OUT(out_value, 0);
    return FALSE;
}

/**
 * nm_setting_option_set:
 * @setting: the #NMSetting
 * @opt_name: the option name to set
 * @variant: (allow-none): the variant to set.
 *
 * If @variant is %NULL, this clears the option if it is set.
 * Otherwise, @variant is set as the option. If @variant is
 * a floating reference, it will be consumed.
 *
 * Note that not all setting types support options. It is a bug
 * setting a variant to a setting that doesn't support it.
 * Currently, only #NMSettingEthtool supports it.
 *
 * Since: 1.26
 */
void
nm_setting_option_set(NMSetting *setting, const char *opt_name, GVariant *variant)
{
    GVariant *  old_variant;
    gboolean    changed_name;
    gboolean    changed_value;
    GHashTable *hash;

    g_return_if_fail(NM_IS_SETTING(setting));
    g_return_if_fail(opt_name);

    hash = _nm_setting_option_hash(setting, variant != NULL);

    if (!variant) {
        if (hash) {
            if (g_hash_table_remove(hash, opt_name))
                _nm_setting_option_notify(setting, TRUE);
        }
        return;
    }

    /* Currently, it is a bug setting any option, unless the setting type supports it.
     * And currently, only NMSettingEthtool supports it.
     *
     * In the future, more setting types may support it. Or we may relax this so
     * that options can be attached to all setting types (to indicate "unsupported"
     * settings for forward compatibility).
     *
     * As it is today, internal code will only add gendata options to NMSettingEthtool,
     * and there exists not public API to add such options. Still, it is permissible
     * to call get(), clear() and set(variant=NULL) also on settings that don't support
     * it, as these operations don't add options.
     */
    g_return_if_fail(
        _nm_setting_class_get_sett_info(NM_SETTING_GET_CLASS(setting))->detail.gendata_info);

    old_variant = g_hash_table_lookup(hash, opt_name);

    changed_name  = (old_variant == NULL);
    changed_value = changed_name || !g_variant_equal(old_variant, variant);

    /* We always want to replace the variant, even if it has
     * the same value according to g_variant_equal(). The reason
     * is that we want to take a reference on @variant, because
     * that is what the user might expect. */
    g_hash_table_insert(hash, g_strdup(opt_name), g_variant_ref_sink(variant));

    if (changed_value)
        _nm_setting_option_notify(setting, !changed_name);
}

/**
 * nm_setting_option_set_boolean:
 * @setting: the #NMSetting
 * @value: the value to set.
 *
 * Like nm_setting_option_set() to set a boolean GVariant.
 *
 * Since: 1.26
 */
void
nm_setting_option_set_boolean(NMSetting *setting, const char *opt_name, gboolean value)
{
    GVariant *  old_variant;
    gboolean    changed_name;
    gboolean    changed_value;
    GHashTable *hash;

    g_return_if_fail(NM_IS_SETTING(setting));
    g_return_if_fail(opt_name);

    value = (!!value);

    hash = _nm_setting_option_hash(setting, TRUE);

    old_variant = g_hash_table_lookup(hash, opt_name);

    changed_name  = (old_variant == NULL);
    changed_value = changed_name
                    || (!g_variant_is_of_type(old_variant, G_VARIANT_TYPE_BOOLEAN)
                        || g_variant_get_boolean(old_variant) != value);

    g_hash_table_insert(hash, g_strdup(opt_name), g_variant_ref_sink(g_variant_new_boolean(value)));

    if (changed_value)
        _nm_setting_option_notify(setting, !changed_name);
}

/**
 * nm_setting_option_set_uint32:
 * @setting: the #NMSetting
 * @value: the value to set.
 *
 * Like nm_setting_option_set() to set a uint32 GVariant.
 *
 * Since: 1.26
 */
void
nm_setting_option_set_uint32(NMSetting *setting, const char *opt_name, guint32 value)
{
    GVariant *  old_variant;
    gboolean    changed_name;
    gboolean    changed_value;
    GHashTable *hash;

    g_return_if_fail(NM_IS_SETTING(setting));
    g_return_if_fail(opt_name);

    hash = _nm_setting_option_hash(setting, TRUE);

    old_variant = g_hash_table_lookup(hash, opt_name);

    changed_name  = (old_variant == NULL);
    changed_value = changed_name
                    || (!g_variant_is_of_type(old_variant, G_VARIANT_TYPE_UINT32)
                        || g_variant_get_uint32(old_variant) != value);

    g_hash_table_insert(hash, g_strdup(opt_name), g_variant_ref_sink(g_variant_new_uint32(value)));

    if (changed_value)
        _nm_setting_option_notify(setting, !changed_name);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSetting *setting = NM_SETTING(object);

    switch (prop_id) {
    case PROP_NAME:
        g_value_set_string(value, nm_setting_get_name(setting));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_init(NMSetting *setting)
{}

static void
constructed(GObject *object)
{
    NMSetting *     self  = NM_SETTING(object);
    NMSettingClass *klass = NM_SETTING_GET_CLASS(self);

    /* we don't support that NMSetting subclasses override constructed.
     * They all must have no G_PARAM_CONSTRUCT/G_PARAM_CONSTRUCT_ONLY
     * properties, otherwise the automatism of _init_direct() needs
     * careful adjustment. */
    nm_assert(G_OBJECT_CLASS(klass)->constructed == constructed);

    /* we always initialize the defaults of the (direct) properties. Note that:
     *
     * - we don't use CONSTRUCT properties, because they have an overhead during
     *   each object creation. Via _init_direct() we can do it more efficiently.
     *
     * - we always call this, because we want to get all default values right.
     *   We even call this for NMSetting subclasses that (historically) are not
     *   yet aware of this happening.
     */
    _init_direct(self);

    G_OBJECT_CLASS(nm_setting_parent_class)->constructed(object);
}

static void
finalize(GObject *object)
{
    NMSetting *       self  = NM_SETTING(object);
    NMSettingPrivate *priv  = NM_SETTING_GET_PRIVATE(self);
    NMSettingClass *  klass = NM_SETTING_GET_CLASS(self);

    if (priv->gendata) {
        g_free(priv->gendata->names);
        g_free(priv->gendata->values);
        g_hash_table_unref(priv->gendata->hash);
        g_slice_free(GenData, priv->gendata);
    }

    G_OBJECT_CLASS(nm_setting_parent_class)->finalize(object);

    if (klass->finalize_direct)
        _finalize_direct(self);
}

static void
nm_setting_class_init(NMSettingClass *setting_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(setting_class);

    g_type_class_add_private(setting_class, sizeof(NMSettingPrivate));

    object_class->constructed  = constructed;
    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    setting_class->update_one_secret         = update_one_secret;
    setting_class->get_secret_flags          = get_secret_flags;
    setting_class->set_secret_flags          = set_secret_flags;
    setting_class->clear_secrets             = clear_secrets;
    setting_class->for_each_secret           = for_each_secret;
    setting_class->duplicate_copy_properties = duplicate_copy_properties;
    setting_class->enumerate_values          = enumerate_values;
    setting_class->aggregate                 = aggregate;
    setting_class->init_from_dbus            = init_from_dbus;

    /**
     * NMSetting:name:
     *
     * The setting's name, which uniquely identifies the setting within the
     * connection.  Each setting type has a name unique to that type, for
     * example "ppp" or "802-11-wireless" or "802-3-ethernet".
     **/
    obj_properties[PROP_NAME] = g_param_spec_string(NM_SETTING_NAME,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
