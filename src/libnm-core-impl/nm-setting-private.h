/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NM_SETTING_PRIVATE_H__
#define __NM_SETTING_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
    #error Cannot use this header.
#endif

#include "nm-setting.h"
#include "nm-setting-bridge.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"

#include "libnm-core-intern/nm-core-internal.h"

/*****************************************************************************/

typedef struct {
    NMConnection *self;

    NMSetting *settings[_NM_META_SETTING_TYPE_NUM];

    /* D-Bus path of the connection, if any */
    char *path;
} NMConnectionPrivate;

extern GTypeClass *_nm_simple_connection_class_instance;
extern int         _nm_simple_connection_private_offset;

void _nm_connection_private_clear(NMConnectionPrivate *priv);

/*****************************************************************************/

/**
 * NMSetting:
 *
 * The NMSetting struct contains only private data.
 * It should only be accessed through the functions described below.
 */
struct _NMSetting {
    GObject parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingClass {
    GObjectClass parent;

    /* In the past, this struct was public API. Preserve ABI! */

    int (*verify)(NMSetting *setting, NMConnection *connection, GError **error);

    gboolean (*verify_secrets)(NMSetting *setting, NMConnection *connection, GError **error);

    GPtrArray *(*need_secrets)(NMSetting *setting);

    int (*update_one_secret)(NMSetting *setting, const char *key, GVariant *value, GError **error);

    gboolean (*get_secret_flags)(NMSetting *           setting,
                                 const char *          secret_name,
                                 NMSettingSecretFlags *out_flags,
                                 GError **             error);

    gboolean (*set_secret_flags)(NMSetting *          setting,
                                 const char *         secret_name,
                                 NMSettingSecretFlags flags,
                                 GError **            error);

    gboolean (*clear_secrets)(const struct _NMSettInfoSetting *sett_info,
                              guint                            property_idx,
                              NMSetting *                      setting,
                              NMSettingClearSecretsWithFlagsFn func,
                              gpointer                         user_data);

    /* compare_property() returns a ternary, where DEFAULT means that the property should not
     * be compared due to the compare @flags. A TRUE/FALSE result means that the property is
     * equal/not-equal.
     *
     * @other may be %NULL, in which case the function only determines whether
     * the setting should be compared (TRUE) or not (DEFAULT). */
    NMTernary (*compare_property)(const struct _NMSettInfoSetting *sett_info,
                                  guint                            property_idx,
                                  NMConnection *                   con_a,
                                  NMSetting *                      set_a,
                                  NMConnection *                   con_b,
                                  NMSetting *                      set_b,
                                  NMSettingCompareFlags            flags);

    void (*duplicate_copy_properties)(const struct _NMSettInfoSetting *sett_info,
                                      NMSetting *                      src,
                                      NMSetting *                      dst);

    void (*enumerate_values)(const struct _NMSettInfoProperty *property_info,
                             NMSetting *                       setting,
                             NMSettingValueIterFn              func,
                             gpointer                          user_data);

    gboolean (*aggregate)(NMSetting *setting, int type_i, gpointer arg);

    void (*for_each_secret)(NMSetting *                    setting,
                            const char *                   secret_name,
                            GVariant *                     val,
                            gboolean                       remove_non_secrets,
                            _NMConnectionForEachSecretFunc callback,
                            gpointer                       callback_data,
                            GVariantBuilder *              setting_builder);

    gboolean (*init_from_dbus)(NMSetting *                     setting,
                               GHashTable *                    keys,
                               GVariant *                      setting_dict,
                               GVariant *                      connection_dict,
                               guint /* NMSettingParseFlags */ parse_flags,
                               GError **                       error);

    gpointer padding[1];

    const struct _NMMetaSettingInfo *setting_info;
};

/*****************************************************************************/

/**
 * NMSettingIPConfig:
 */
struct _NMSettingIPConfig {
    NMSetting parent;
};

struct _NMSettingIPConfigClass {
    NMSettingClass parent;

    /* Padding for future expansion */
    gpointer padding[8];
};

/*****************************************************************************/

NMSettingPriority _nm_setting_get_base_type_priority(NMSetting *setting);
int               _nm_setting_compare_priority(gconstpointer a, gconstpointer b);

int _nmtst_nm_setting_sort(NMSetting *a, NMSetting *b);

/*****************************************************************************/

#define _nm_assert_setting_info(setting_info, gtype)                         \
    G_STMT_START                                                             \
    {                                                                        \
        const NMMetaSettingInfo *_setting_info = (setting_info);             \
                                                                             \
        if (NM_MORE_ASSERTS > 0) {                                           \
            GType _gtype = (gtype);                                          \
                                                                             \
            nm_assert(_setting_info);                                        \
            nm_assert(_NM_INT_NOT_NEGATIVE(_setting_info->meta_type));       \
            nm_assert(_setting_info->meta_type < _NM_META_SETTING_TYPE_NUM); \
            nm_assert(_setting_info->get_setting_gtype);                     \
            if (_gtype != 0)                                                 \
                nm_assert(_setting_info->get_setting_gtype() == _gtype);     \
            else                                                             \
                _gtype = _setting_info->get_setting_gtype();                 \
            nm_assert(g_type_is_a(_gtype, NM_TYPE_SETTING));                 \
        }                                                                    \
    }                                                                        \
    G_STMT_END

static inline const NMMetaSettingInfo *
_nm_meta_setting_info_from_class(NMSettingClass *klass)
{
    const NMMetaSettingInfo *setting_info;

    if (!NM_IS_SETTING_CLASS(klass))
        return NULL;

    setting_info = klass->setting_info;
    if (!setting_info)
        return NULL;

    _nm_assert_setting_info(setting_info, G_OBJECT_CLASS_TYPE(klass));
    return setting_info;
}

static inline const NMMetaSettingInfo *
_nm_meta_setting_info_from_gtype(GType gtype)
{
    const NMMetaSettingInfo *setting_info;

    setting_info = nm_meta_setting_infos_by_gtype(gtype);
    if (!setting_info)
        return NULL;

    _nm_assert_setting_info(setting_info, gtype);
    return setting_info;
}

/*****************************************************************************/

void _nm_setting_emit_property_changed(NMSetting *setting);

typedef enum NMSettingUpdateSecretResult {
    NM_SETTING_UPDATE_SECRET_ERROR             = FALSE,
    NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED  = TRUE,
    NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED = 2,
} NMSettingUpdateSecretResult;

NMSettingUpdateSecretResult
         _nm_setting_update_secrets(NMSetting *setting, GVariant *secrets, GError **error);
gboolean _nm_setting_clear_secrets(NMSetting *                      setting,
                                   NMSettingClearSecretsWithFlagsFn func,
                                   gpointer                         user_data);

/*****************************************************************************/

#define NM_SETTING_PARAM_NONE 0

/* The property of the #NMSetting should be considered during comparisons that
 * use the %NM_SETTING_COMPARE_FLAG_INFERRABLE flag. Properties that don't have
 * this flag, are ignored when doing an infrerrable comparison.  This flag should
 * be set on all properties that are read from the kernel or the system when a
 * connection is generated.  eg, IP addresses/routes can be read from the
 * kernel, but the 'autoconnect' property cannot, so
 * %NM_SETTING_IP4_CONFIG_ADDRESSES gets the INFERRABLE flag, but
 * %NM_SETTING_CONNECTION_AUTOCONNECT would not.
 *
 * This flag should not be used with properties where the default cannot be
 * read separately from the current value, like MTU or wired duplex mode.
 */
#define NM_SETTING_PARAM_INFERRABLE (1 << (4 + G_PARAM_USER_SHIFT))

/* This is a legacy property, which clients should not send to the daemon. */
#define NM_SETTING_PARAM_LEGACY (1 << (5 + G_PARAM_USER_SHIFT))

/* When a connection is active and gets modified, usually the change
 * to the settings-connection does not propagate automatically to the
 * applied-connection of the device. For certain properties like the
 * firewall zone and the metered property, this is different.
 *
 * Such fields can be ignored during nm_connection_compare() with the
 * NMSettingCompareFlag NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY.
 */
#define NM_SETTING_PARAM_REAPPLY_IMMEDIATELY (1 << (6 + G_PARAM_USER_SHIFT))

/* property_to_dbus() should ignore the property flags, and instead always calls to_dbus_fcn()
 */
#define NM_SETTING_PARAM_TO_DBUS_IGNORE_FLAGS (1 << (7 + G_PARAM_USER_SHIFT))

extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_interface_name;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_i;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_u;

extern const NMSettInfoPropertType nm_sett_info_propert_type_plain_i;
extern const NMSettInfoPropertType nm_sett_info_propert_type_plain_u;

extern const NMSettInfoPropertType nm_sett_info_propert_type_boolean;
extern const NMSettInfoPropertType nm_sett_info_propert_type_string;

NMSettingVerifyResult
_nm_setting_verify(NMSetting *setting, NMConnection *connection, GError **error);

gboolean _nm_setting_verify_secret_string(const char *str,
                                          const char *setting_name,
                                          const char *property,
                                          GError **   error);

gboolean _nm_setting_aggregate(NMSetting *setting, NMConnectionAggregateType type, gpointer arg);

gboolean _nm_setting_slave_type_is_valid(const char *slave_type, const char **out_port_type);

GVariant *_nm_setting_property_to_dbus_fcn_gprop(const NMSettInfoSetting *      sett_info,
                                                 guint                          property_idx,
                                                 NMConnection *                 connection,
                                                 NMSetting *                    setting,
                                                 NMConnectionSerializationFlags flags,
                                                 const NMConnectionSerializationOptions *options);

GVariant *
_nm_setting_property_to_dbus_fcn_get_boolean(const NMSettInfoSetting *               sett_info,
                                             guint                                   property_idx,
                                             NMConnection *                          connection,
                                             NMSetting *                             setting,
                                             NMConnectionSerializationFlags          flags,
                                             const NMConnectionSerializationOptions *options);

GVariant *
_nm_setting_property_to_dbus_fcn_get_string(const NMSettInfoSetting *               sett_info,
                                            guint                                   property_idx,
                                            NMConnection *                          connection,
                                            NMSetting *                             setting,
                                            NMConnectionSerializationFlags          flags,
                                            const NMConnectionSerializationOptions *options);

GVariant *_nm_setting_to_dbus(NMSetting *                             setting,
                              NMConnection *                          connection,
                              NMConnectionSerializationFlags          flags,
                              const NMConnectionSerializationOptions *options);

NMSetting *_nm_setting_new_from_dbus(GType               setting_type,
                                     GVariant *          setting_dict,
                                     GVariant *          connection_dict,
                                     NMSettingParseFlags parse_flags,
                                     GError **           error);

gboolean _nm_setting_property_is_regular_secret(NMSetting *setting, const char *secret_name);
gboolean _nm_setting_property_is_regular_secret_flags(NMSetting * setting,
                                                      const char *secret_flags_name);

/*****************************************************************************/

static inline GArray *
_nm_sett_info_property_override_create_array(void)
{
    return g_array_new(FALSE, FALSE, sizeof(NMSettInfoProperty));
}

GArray *_nm_sett_info_property_override_create_array_ip_config(void);

void _nm_setting_class_commit_full(NMSettingClass *            setting_class,
                                   NMMetaSettingType           meta_type,
                                   const NMSettInfoSettDetail *detail,
                                   GArray *                    properties_override);

static inline void
_nm_setting_class_commit(NMSettingClass *setting_class, NMMetaSettingType meta_type)
{
    _nm_setting_class_commit_full(setting_class, meta_type, NULL, NULL);
}

#define NM_SETT_INFO_SETT_GENDATA(...)                         \
    ({                                                         \
        static const NMSettInfoSettGendata _g = {__VA_ARGS__}; \
                                                               \
        &_g;                                                   \
    })

#define NM_SETT_INFO_SETT_DETAIL(...) (&((const NMSettInfoSettDetail){__VA_ARGS__}))

#define NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(_dbus_type, ...) \
    {                                                        \
        .dbus_type = _dbus_type, __VA_ARGS__                 \
    }

#define NM_SETT_INFO_PROPERT_TYPE_GPROP_INIT(_dbus_type, ...)                           \
    {                                                                                   \
        .dbus_type = _dbus_type, .to_dbus_fcn = _nm_setting_property_to_dbus_fcn_gprop, \
        __VA_ARGS__                                                                     \
    }

#define NM_SETT_INFO_PROPERT_TYPE(init)               \
    ({                                                \
        static const NMSettInfoPropertType _g = init; \
                                                      \
        &_g;                                          \
    })

#define NM_SETT_INFO_PROPERT_TYPE_DBUS(_dbus_type, ...) \
    NM_SETT_INFO_PROPERT_TYPE(NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(_dbus_type, __VA_ARGS__))

#define NM_SETT_INFO_PROPERT_TYPE_GPROP(_dbus_type, ...) \
    NM_SETT_INFO_PROPERT_TYPE(NM_SETT_INFO_PROPERT_TYPE_GPROP_INIT(_dbus_type, __VA_ARGS__))

#define NM_SETT_INFO_PROPERTY(...) (&((const NMSettInfoProperty){__VA_ARGS__}))

gboolean _nm_properties_override_assert(const NMSettInfoProperty *prop_info);

static inline void
_nm_properties_override(GArray *properties_override, const NMSettInfoProperty *prop_info)
{
    nm_assert(properties_override);
    nm_assert(_nm_properties_override_assert(prop_info));
    g_array_append_vals(properties_override, prop_info, 1);
}

#define _nm_properties_override_gobj(properties_override, p_param_spec, p_property_type, ...) \
    _nm_properties_override((properties_override),                                            \
                            NM_SETT_INFO_PROPERTY(.name          = NULL,                      \
                                                  .param_spec    = (p_param_spec),            \
                                                  .property_type = (p_property_type),         \
                                                  __VA_ARGS__))

#define _nm_properties_override_dbus(properties_override, p_name, p_property_type) \
    _nm_properties_override(                                                       \
        (properties_override),                                                     \
        NM_SETT_INFO_PROPERTY(.name = ("" p_name ""), .property_type = (p_property_type), ))

/*****************************************************************************/

#define _nm_setting_property_define_boolean_full(properties_override,                           \
                                                 obj_properties,                                \
                                                 prop_name,                                     \
                                                 prop_id,                                       \
                                                 default_value,                                 \
                                                 param_flags,                                   \
                                                 property_type,                                 \
                                                 get_fcn,                                       \
                                                 ...)                                           \
    G_STMT_START                                                                                \
    {                                                                                           \
        const gboolean                     _default_value = (default_value);                    \
        GParamSpec *                       _param_spec;                                         \
        const NMSettInfoPropertType *const _property_type = (property_type);                    \
                                                                                                \
        G_STATIC_ASSERT(                                                                        \
            !NM_FLAGS_ANY((param_flags),                                                        \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE         \
                            | NM_SETTING_PARAM_REAPPLY_IMMEDIATELY)));                          \
                                                                                                \
        nm_assert(_property_type);                                                              \
        nm_assert(_property_type->to_dbus_fcn == _nm_setting_property_to_dbus_fcn_get_boolean); \
                                                                                                \
        nm_assert(NM_IN_SET(_default_value, 0, 1));                                             \
                                                                                                \
        _param_spec =                                                                           \
            g_param_spec_boolean("" prop_name "",                                               \
                                 "",                                                            \
                                 "",                                                            \
                                 _default_value,                                                \
                                 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));   \
                                                                                                \
        (obj_properties)[(prop_id)] = _param_spec;                                              \
                                                                                                \
        _nm_properties_override_gobj((properties_override),                                     \
                                     _param_spec,                                               \
                                     _property_type,                                            \
                                     .to_dbus_data.get_boolean =                                \
                                         (gboolean(*)(NMSetting *)) (get_fcn),                  \
                                     __VA_ARGS__);                                              \
    }                                                                                           \
    G_STMT_END

#define _nm_setting_property_define_boolean(properties_override,                 \
                                            obj_properties,                      \
                                            prop_name,                           \
                                            prop_id,                             \
                                            default_value,                       \
                                            param_flags,                         \
                                            get_fcn,                             \
                                            ...)                                 \
    _nm_setting_property_define_boolean_full((properties_override),              \
                                             (obj_properties),                   \
                                             prop_name,                          \
                                             (prop_id),                          \
                                             (default_value),                    \
                                             (param_flags),                      \
                                             &nm_sett_info_propert_type_boolean, \
                                             (get_fcn),                          \
                                             __VA_ARGS__)

/*****************************************************************************/

#define _nm_setting_property_define_string_full(properties_override,                            \
                                                obj_properties,                                 \
                                                prop_name,                                      \
                                                prop_id,                                        \
                                                param_flags,                                    \
                                                property_type,                                  \
                                                get_fcn,                                        \
                                                ...)                                            \
    G_STMT_START                                                                                \
    {                                                                                           \
        GParamSpec *                       _param_spec;                                         \
        const NMSettInfoPropertType *const _property_type = (property_type);                    \
                                                                                                \
        G_STATIC_ASSERT(!NM_FLAGS_ANY((param_flags),                                            \
                                      ~(NM_SETTING_PARAM_SECRET | NM_SETTING_PARAM_FUZZY_IGNORE \
                                        | NM_SETTING_PARAM_INFERRABLE                           \
                                        | NM_SETTING_PARAM_REAPPLY_IMMEDIATELY)));              \
        nm_assert(_property_type);                                                              \
        nm_assert(_property_type->to_dbus_fcn == _nm_setting_property_to_dbus_fcn_get_string);  \
                                                                                                \
        _param_spec =                                                                           \
            g_param_spec_string("" prop_name "",                                                \
                                "",                                                             \
                                "",                                                             \
                                NULL,                                                           \
                                G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));    \
                                                                                                \
        (obj_properties)[(prop_id)] = _param_spec;                                              \
                                                                                                \
        _nm_properties_override_gobj((properties_override),                                     \
                                     _param_spec,                                               \
                                     _property_type,                                            \
                                     .to_dbus_data.get_string =                                 \
                                         (const char *(*) (NMSetting *) ) (get_fcn),            \
                                     __VA_ARGS__);                                              \
    }                                                                                           \
    G_STMT_END

#define _nm_setting_property_define_string(properties_override,                \
                                           obj_properties,                     \
                                           prop_name,                          \
                                           prop_id,                            \
                                           param_flags,                        \
                                           get_fcn,                            \
                                           ...)                                \
    _nm_setting_property_define_string_full((properties_override),             \
                                            (obj_properties),                  \
                                            prop_name,                         \
                                            (prop_id),                         \
                                            (param_flags),                     \
                                            &nm_sett_info_propert_type_string, \
                                            (get_fcn),                         \
                                            __VA_ARGS__)

/*****************************************************************************/

gboolean _nm_setting_use_legacy_property(NMSetting * setting,
                                         GVariant *  connection_dict,
                                         const char *legacy_property,
                                         const char *new_property);

GPtrArray *_nm_setting_need_secrets(NMSetting *setting);

gboolean _nm_setting_should_compare_secret_property(NMSetting *           setting,
                                                    NMSetting *           other,
                                                    const char *          secret_name,
                                                    NMSettingCompareFlags flags);

NMBridgeVlan *_nm_bridge_vlan_dup(const NMBridgeVlan *vlan);
NMBridgeVlan *_nm_bridge_vlan_dup_and_seal(const NMBridgeVlan *vlan);

/*****************************************************************************/

#endif /* NM_SETTING_PRIVATE_H */
