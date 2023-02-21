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
#include "nm-simple-connection.h"
#include "nm-core-enum-types.h"

#include "libnm-core-intern/nm-core-internal.h"

/*****************************************************************************/

struct _NMRefString;

typedef struct {
    NMConnection *self;

    NMSetting *settings[_NM_META_SETTING_TYPE_NUM];

    /* D-Bus path of the connection, if any */
    struct _NMRefString *path;
} NMConnectionPrivate;

extern GTypeClass *_nm_simple_connection_class_instance;
extern int         _nm_simple_connection_private_offset;

#undef NM_IS_SIMPLE_CONNECTION
#define NM_IS_SIMPLE_CONNECTION(self)                                                           \
    ({                                                                                          \
        gconstpointer _self1 = (self);                                                          \
        gboolean      _result;                                                                  \
                                                                                                \
        _result =                                                                               \
            (_self1                                                                             \
             && (((GTypeInstance *) _self1)->g_class == _nm_simple_connection_class_instance)); \
                                                                                                \
        nm_assert(_result == G_TYPE_CHECK_INSTANCE_TYPE(_self1, NM_TYPE_SIMPLE_CONNECTION));    \
                                                                                                \
        _result;                                                                                \
    })

#undef NM_IS_CONNECTION
#define NM_IS_CONNECTION(self)                                            \
    ({                                                                    \
        gconstpointer _self0 = (self);                                    \
                                                                          \
        (_self0                                                           \
         && (NM_IS_SIMPLE_CONNECTION(_self0)                              \
             || G_TYPE_CHECK_INSTANCE_TYPE(_self0, NM_TYPE_CONNECTION))); \
    })

#define _NM_SIMPLE_CONNECTION_GET_CONNECTION_PRIVATE(connection)                                \
    ({                                                                                          \
        gpointer             _connection_1 = (connection);                                      \
        NMConnectionPrivate *_priv_1;                                                           \
                                                                                                \
        nm_assert(NM_IS_SIMPLE_CONNECTION(_connection_1));                                      \
                                                                                                \
        _priv_1 = (void *) (&(((char *) _connection_1)[_nm_simple_connection_private_offset])); \
                                                                                                \
        nm_assert(_priv_1                                                                       \
                  == G_TYPE_INSTANCE_GET_PRIVATE(_connection_1,                                 \
                                                 NM_TYPE_SIMPLE_CONNECTION,                     \
                                                 NMConnectionPrivate));                         \
                                                                                                \
        _priv_1;                                                                                \
    })

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

    GPtrArray *(*need_secrets)(NMSetting *setting, gboolean check_rerequest);

    int (*update_one_secret)(NMSetting *setting, const char *key, GVariant *value, GError **error);

    gboolean (*get_secret_flags)(NMSetting            *setting,
                                 const char           *secret_name,
                                 NMSettingSecretFlags *out_flags,
                                 GError              **error);

    gboolean (*set_secret_flags)(NMSetting           *setting,
                                 const char          *secret_name,
                                 NMSettingSecretFlags flags,
                                 GError             **error);

    gboolean (*clear_secrets)(const struct _NMSettInfoSetting *sett_info,
                              const NMSettInfoProperty        *property_info,
                              NMSetting                       *setting,
                              NMSettingClearSecretsWithFlagsFn func,
                              gpointer                         user_data);

    void (*padding_1)(void);

    void (*duplicate_copy_properties)(const struct _NMSettInfoSetting *sett_info,
                                      NMSetting                       *src,
                                      NMSetting                       *dst);

    void (*enumerate_values)(const struct _NMSettInfoProperty *property_info,
                             NMSetting                        *setting,
                             NMSettingValueIterFn              func,
                             gpointer                          user_data);

    gboolean (*aggregate)(NMSetting *setting, int type_i, gpointer arg);

    void (*for_each_secret)(NMSetting                     *setting,
                            const char                    *secret_name,
                            GVariant                      *val,
                            gboolean                       remove_non_secrets,
                            _NMConnectionForEachSecretFunc callback,
                            gpointer                       callback_data,
                            GVariantBuilder               *setting_builder);

    gboolean (*init_from_dbus)(NMSetting                      *setting,
                               GHashTable                     *keys,
                               GVariant                       *setting_dict,
                               GVariant                       *connection_dict,
                               guint /* NMSettingParseFlags */ parse_flags,
                               GError                        **error);

    const struct _NMMetaSettingInfo *setting_info;
};

/*****************************************************************************/

/**
 * NMSettingIPConfig:
 */
struct _NMSettingIPConfig {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingIPConfigClass {
    NMSettingClass parent;

    /* In the past, this struct was public API. Preserve ABI! */

    union {
        gpointer _dummy1;
        int      private_offset;
    };

    union {
        gpointer _dummy2;
        gint8    addr_family;
    };

    union {
        gpointer _dummy3;
        bool     is_ipv4;
    };

    gpointer padding[5];
};

typedef struct {
    GPtrArray *dns;         /* array of IP address strings */
    GPtrArray *dns_search;  /* array of domain name strings */
    GPtrArray *dns_options; /* array of DNS options */
    GPtrArray *addresses;   /* array of NMIPAddress */
    GPtrArray *routes;      /* array of NMIPRoute */
    GPtrArray *routing_rules;
    GArray    *dhcp_reject_servers;
    char      *method;
    char      *gateway;
    char      *dhcp_hostname;
    char      *dhcp_iaid;
    gint64     route_metric;
    int        auto_route_ext_gw;
    int        replace_local_rule;
    gint32     required_timeout;
    gint32     dad_timeout;
    gint32     dhcp_timeout;
    gint32     dns_priority;
    guint32    route_table;
    guint32    dhcp_hostname_flags;
    bool       ignore_auto_routes;
    bool       ignore_auto_dns;
    bool       dhcp_send_hostname;
    bool       never_default;
    bool       may_fail;
} NMSettingIPConfigPrivate;

void _nm_setting_ip_config_private_init(gpointer self, NMSettingIPConfigPrivate *priv);

#define NM_SETTING_IP_CONFIG_GET_ADDR_FAMILY(setting) \
    (NM_SETTING_IP_CONFIG_GET_CLASS(setting)->addr_family)

#define NM_SETTING_IP_CONFIG_IS_IPv4(setting) (NM_SETTING_IP_CONFIG_GET_CLASS(setting)->is_ipv4)

/*****************************************************************************/

NMSettingPriority _nm_setting_get_base_type_priority(NMSetting *setting);
int               _nm_setting_compare_priority(gconstpointer a, gconstpointer b);

int _nm_setting_sort_for_nm_assert(NMSetting *a, NMSetting *b);

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
gboolean _nm_setting_clear_secrets(NMSetting                       *setting,
                                   NMSettingClearSecretsWithFlagsFn func,
                                   gpointer                         user_data);

/*****************************************************************************/

/* This holds a property of type NM_VALUE_TYPE_STRV. You probably want
 * to use nm_strvarray_*() API with this. */
typedef struct {
    GArray *arr;
} NMValueStrv;

/*****************************************************************************/

struct _NMRange {
    int     refcount;
    guint64 start;
    guint64 end;
};

/*****************************************************************************/

#define NM_SETTING_PARAM_NONE 0

/* The property of the #NMSetting should be considered during comparisons that
 * use the %NM_SETTING_COMPARE_FLAG_INFERRABLE flag. Properties that don't have
 * this flag, are ignored when doing an inferrable comparison.  This flag should
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

/* This flag has no meaning (anymore). It's only kept, because we used it
 * on some older versions of libnm. */
#define NM_SETTING_PARAM_UNUSED1 (1 << (5 + G_PARAM_USER_SHIFT))

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

extern const NMSettInfoPropertType nm_sett_info_propert_type_setting_name;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_interface_name;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_i;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_u;

extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_boolean;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_int32;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_uint32;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_int64;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_uint64;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_string;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_bytes;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_strv;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_enum;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_flags;
extern const NMSettInfoPropertType nm_sett_info_propert_type_direct_mac_address;

NMSettingVerifyResult
_nm_setting_verify(NMSetting *setting, NMConnection *connection, GError **error);

gboolean _nm_setting_verify_secret_string(const char *str,
                                          const char *setting_name,
                                          const char *property,
                                          GError    **error);

gboolean _nm_setting_aggregate(NMSetting *setting, NMConnectionAggregateType type, gpointer arg);

gboolean _nm_setting_slave_type_is_valid(const char *slave_type, const char **out_port_type);

gboolean _nm_setting_compare_flags_check(const GParamSpec     *param_spec,
                                         NMSettingCompareFlags flags,
                                         NMSetting            *set_a,
                                         NMSetting            *set_b);

NMTernary _nm_setting_property_compare_fcn_ignore(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

NMTernary _nm_setting_property_compare_fcn_direct(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

NMTernary _nm_setting_property_compare_fcn_default(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

void _nm_setting_property_get_property_direct(GObject    *object,
                                              guint       prop_id,
                                              GValue     *value,
                                              GParamSpec *pspec);

void _nm_setting_property_set_property_direct(GObject      *object,
                                              guint         prop_id,
                                              const GValue *value,
                                              GParamSpec   *pspec);

GVariant *_nm_setting_property_to_dbus_fcn_ignore(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

GVariant *_nm_setting_property_to_dbus_fcn_gprop(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

GVariant *_nm_setting_property_to_dbus_fcn_direct(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

GVariant *
_nm_setting_property_to_dbus_fcn_direct_mac_address(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

gboolean _nm_setting_property_from_dbus_fcn_ignore(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

gboolean _nm_setting_property_from_dbus_fcn_direct_ip_config_gateway(
    _NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

gboolean _nm_setting_property_from_dbus_fcn_direct_mac_address(
    _NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

gboolean _nm_setting_property_from_dbus_fcn_direct(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

gboolean _nm_setting_property_from_dbus_fcn_gprop(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

GVariant *_nm_setting_to_dbus(NMSetting                              *setting,
                              NMConnection                           *connection,
                              NMConnectionSerializationFlags          flags,
                              const NMConnectionSerializationOptions *options);

NMSetting *_nm_setting_new_from_dbus(GType               setting_type,
                                     GVariant           *setting_dict,
                                     GVariant           *connection_dict,
                                     NMSettingParseFlags parse_flags,
                                     GError            **error);

gboolean _nm_setting_property_is_regular_secret(NMSetting *setting, const char *secret_name);
gboolean _nm_setting_property_is_regular_secret_flags(NMSetting  *setting,
                                                      const char *secret_flags_name);

/*****************************************************************************/

const NMSettInfoProperty *
_nm_sett_info_property_lookup_by_param_spec(const NMSettInfoSetting *sett_info,
                                            const GParamSpec        *param_spec);

static inline GArray *
_nm_sett_info_property_override_create_array_sized(guint reserved_size)
{
    return g_array_sized_new(FALSE, FALSE, sizeof(NMSettInfoProperty), reserved_size);
}

static inline GArray *
_nm_sett_info_property_override_create_array(void)
{
    /* pre-allocate a relatively large buffer to avoid frequent re-allocations.
     * Note that the buffer is only short-lived and will be destroyed by
     * _nm_setting_class_commit(). */
    return _nm_sett_info_property_override_create_array_sized(20);
}

GArray *_nm_sett_info_property_override_create_array_ip_config(int addr_family);

void _nm_setting_class_commit(NMSettingClass             *setting_class,
                              NMMetaSettingType           meta_type,
                              const NMSettInfoSettDetail *detail,
                              GArray                     *properties_override,
                              gint16                      private_offset);

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

#define NM_SETT_INFO_PROPERT_TYPE_GPROP_INIT(_dbus_type, ...)                                  \
    NM_SETT_INFO_PROPERT_TYPE_DBUS_INIT(_dbus_type,                                            \
                                        .to_dbus_fcn = _nm_setting_property_to_dbus_fcn_gprop, \
                                        __VA_ARGS__)

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

#define _nm_properties_override_gobj(properties_override,                             \
                                     p_param_spec,                                    \
                                     p_property_type,                                 \
                                     ... /* extra NMSettInfoProperty fields */)       \
    _nm_properties_override((properties_override),                                    \
                            NM_SETT_INFO_PROPERTY(.name          = NULL,              \
                                                  .param_spec    = (p_param_spec),    \
                                                  .property_type = (p_property_type), \
                                                  __VA_ARGS__))

#define _nm_properties_override_dbus(properties_override,                             \
                                     p_name,                                          \
                                     p_property_type,                                 \
                                     ... /* extra NMSettInfoProperty fields */)       \
    _nm_properties_override((properties_override),                                    \
                            NM_SETT_INFO_PROPERTY(.name          = ("" p_name ""),    \
                                                  .property_type = (p_property_type), \
                                                  __VA_ARGS__))

/*****************************************************************************/

/* Define "direct" properties. These are properties that have a GParamSpec and
 * NMSettInfoPropertType.direct_type != NM_VALUE_TYPE_NONE.
 *
 * With this, the location of the data is known at
 *
 *    _nm_setting_get_private(setting, sett_info, property_info->direct_offset)
 *
 * which allows to generically handle the property operations (like get, set, compare).
 */

#define _nm_setting_property_define_direct_boolean(properties_override,                        \
                                                   obj_properties,                             \
                                                   prop_name,                                  \
                                                   prop_id,                                    \
                                                   default_value,                              \
                                                   param_flags,                                \
                                                   private_struct_type,                        \
                                                   private_struct_field,                       \
                                                   ... /* extra NMSettInfoProperty fields */)  \
    G_STMT_START                                                                               \
    {                                                                                          \
        const gboolean _default_value = (default_value);                                       \
        GParamSpec    *_param_spec;                                                            \
                                                                                               \
        G_STATIC_ASSERT(                                                                       \
            !NM_FLAGS_ANY((param_flags),                                                       \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE        \
                            | NM_SETTING_PARAM_REAPPLY_IMMEDIATELY)));                         \
                                                                                               \
        nm_assert(NM_IN_SET(_default_value, 0, 1));                                            \
                                                                                               \
        _param_spec =                                                                          \
            g_param_spec_boolean("" prop_name "",                                              \
                                 "",                                                           \
                                 "",                                                           \
                                 _default_value,                                               \
                                 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));  \
                                                                                               \
        (obj_properties)[(prop_id)] = _param_spec;                                             \
                                                                                               \
        _nm_properties_override_gobj(                                                          \
            (properties_override),                                                             \
            _param_spec,                                                                       \
            &nm_sett_info_propert_type_direct_boolean,                                         \
            .direct_offset =                                                                   \
                NM_STRUCT_OFFSET_ENSURE_TYPE(bool, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                      \
    }                                                                                          \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_uint32(properties_override,                            \
                                                  obj_properties,                                 \
                                                  prop_name,                                      \
                                                  prop_id,                                        \
                                                  min_value,                                      \
                                                  max_value,                                      \
                                                  default_value,                                  \
                                                  param_flags,                                    \
                                                  private_struct_type,                            \
                                                  private_struct_field,                           \
                                                  ... /* extra NMSettInfoProperty fields */)      \
    G_STMT_START                                                                                  \
    {                                                                                             \
        GParamSpec *_param_spec;                                                                  \
                                                                                                  \
        G_STATIC_ASSERT(                                                                          \
            !NM_FLAGS_ANY((param_flags),                                                          \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE)));       \
        G_STATIC_ASSERT((min_value) <= (guint64) (default_value));                                \
        G_STATIC_ASSERT((default_value) <= (guint64) (max_value));                                \
        G_STATIC_ASSERT((max_value) <= (guint64) G_MAXUINT32);                                    \
                                                                                                  \
        _param_spec =                                                                             \
            g_param_spec_uint("" prop_name "",                                                    \
                              "",                                                                 \
                              "",                                                                 \
                              (min_value),                                                        \
                              (max_value),                                                        \
                              (default_value),                                                    \
                              G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));        \
                                                                                                  \
        (obj_properties)[(prop_id)] = _param_spec;                                                \
                                                                                                  \
        _nm_properties_override_gobj(                                                             \
            (properties_override),                                                                \
            _param_spec,                                                                          \
            &nm_sett_info_propert_type_direct_uint32,                                             \
            .direct_offset =                                                                      \
                NM_STRUCT_OFFSET_ENSURE_TYPE(guint32, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                         \
    }                                                                                             \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_int32(properties_override,                            \
                                                 obj_properties,                                 \
                                                 prop_name,                                      \
                                                 prop_id,                                        \
                                                 min_value,                                      \
                                                 max_value,                                      \
                                                 default_value,                                  \
                                                 param_flags,                                    \
                                                 private_struct_type,                            \
                                                 private_struct_field,                           \
                                                 ... /* extra NMSettInfoProperty fields */)      \
    G_STMT_START                                                                                 \
    {                                                                                            \
        GParamSpec *_param_spec;                                                                 \
                                                                                                 \
        G_STATIC_ASSERT(                                                                         \
            !NM_FLAGS_ANY((param_flags),                                                         \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE)));      \
        G_STATIC_ASSERT((min_value) >= (gint64) (G_MININT32));                                   \
        G_STATIC_ASSERT((min_value) <= (gint64) (default_value));                                \
        G_STATIC_ASSERT((default_value) <= (gint64) (max_value));                                \
        G_STATIC_ASSERT((max_value) <= (gint64) G_MAXUINT32);                                    \
                                                                                                 \
        _param_spec =                                                                            \
            g_param_spec_int("" prop_name "",                                                    \
                             "",                                                                 \
                             "",                                                                 \
                             (min_value),                                                        \
                             (max_value),                                                        \
                             (default_value),                                                    \
                             G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));        \
                                                                                                 \
        (obj_properties)[(prop_id)] = _param_spec;                                               \
                                                                                                 \
        _nm_properties_override_gobj(                                                            \
            (properties_override),                                                               \
            _param_spec,                                                                         \
            &nm_sett_info_propert_type_direct_int32,                                             \
            .direct_offset =                                                                     \
                NM_STRUCT_OFFSET_ENSURE_TYPE(gint32, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                        \
    }                                                                                            \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_int64(properties_override,                            \
                                                 obj_properties,                                 \
                                                 prop_name,                                      \
                                                 prop_id,                                        \
                                                 min_value,                                      \
                                                 max_value,                                      \
                                                 default_value,                                  \
                                                 param_flags,                                    \
                                                 private_struct_type,                            \
                                                 private_struct_field,                           \
                                                 ... /* extra NMSettInfoProperty fields */)      \
    G_STMT_START                                                                                 \
    {                                                                                            \
        GParamSpec *_param_spec;                                                                 \
                                                                                                 \
        G_STATIC_ASSERT(                                                                         \
            !NM_FLAGS_ANY((param_flags),                                                         \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE)));      \
        G_STATIC_ASSERT((min_value) >= G_MININT64);                                              \
        G_STATIC_ASSERT((min_value) <= (default_value));                                         \
        G_STATIC_ASSERT((default_value) <= (max_value));                                         \
        G_STATIC_ASSERT((max_value) <= G_MAXINT64);                                              \
                                                                                                 \
        _param_spec =                                                                            \
            g_param_spec_int64("" prop_name "",                                                  \
                               "",                                                               \
                               "",                                                               \
                               (min_value),                                                      \
                               (max_value),                                                      \
                               (default_value),                                                  \
                               G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));      \
                                                                                                 \
        (obj_properties)[(prop_id)] = _param_spec;                                               \
                                                                                                 \
        _nm_properties_override_gobj(                                                            \
            (properties_override),                                                               \
            _param_spec,                                                                         \
            &nm_sett_info_propert_type_direct_int64,                                             \
            .direct_offset =                                                                     \
                NM_STRUCT_OFFSET_ENSURE_TYPE(gint64, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                        \
    }                                                                                            \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_uint64(properties_override,                            \
                                                  obj_properties,                                 \
                                                  prop_name,                                      \
                                                  prop_id,                                        \
                                                  min_value,                                      \
                                                  max_value,                                      \
                                                  default_value,                                  \
                                                  param_flags,                                    \
                                                  private_struct_type,                            \
                                                  private_struct_field,                           \
                                                  ... /* extra NMSettInfoProperty fields */)      \
    G_STMT_START                                                                                  \
    {                                                                                             \
        GParamSpec *_param_spec;                                                                  \
                                                                                                  \
        G_STATIC_ASSERT(                                                                          \
            !NM_FLAGS_ANY((param_flags),                                                          \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE)));       \
        G_STATIC_ASSERT((min_value) <= (default_value));                                          \
        G_STATIC_ASSERT((default_value) == 0 || (default_value) -1u < (max_value));               \
        G_STATIC_ASSERT((max_value) <= G_MAXUINT64);                                              \
                                                                                                  \
        _param_spec =                                                                             \
            g_param_spec_uint64("" prop_name "",                                                  \
                                "",                                                               \
                                "",                                                               \
                                (min_value),                                                      \
                                (max_value),                                                      \
                                (default_value),                                                  \
                                G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));      \
                                                                                                  \
        (obj_properties)[(prop_id)] = _param_spec;                                                \
                                                                                                  \
        _nm_properties_override_gobj(                                                             \
            (properties_override),                                                                \
            _param_spec,                                                                          \
            &nm_sett_info_propert_type_direct_uint64,                                             \
            .direct_offset =                                                                      \
                NM_STRUCT_OFFSET_ENSURE_TYPE(guint64, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                         \
    }                                                                                             \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_string_full(properties_override,                       \
                                                       obj_properties,                            \
                                                       prop_name,                                 \
                                                       prop_id,                                   \
                                                       param_flags,                               \
                                                       property_type,                             \
                                                       private_struct_type,                       \
                                                       private_struct_field,                      \
                                                       ... /* extra NMSettInfoProperty fields */) \
    G_STMT_START                                                                                  \
    {                                                                                             \
        GParamSpec                  *_param_spec;                                                 \
        const NMSettInfoPropertType *_property_type = (property_type);                            \
                                                                                                  \
        G_STATIC_ASSERT(!NM_FLAGS_ANY((param_flags),                                              \
                                      ~(NM_SETTING_PARAM_SECRET | NM_SETTING_PARAM_FUZZY_IGNORE   \
                                        | NM_SETTING_PARAM_INFERRABLE | NM_SETTING_PARAM_REQUIRED \
                                        | NM_SETTING_PARAM_REAPPLY_IMMEDIATELY)));                \
                                                                                                  \
        nm_assert(_property_type);                                                                \
        nm_assert(g_variant_type_equal(_property_type->dbus_type, "s"));                          \
        nm_assert(_property_type->direct_type == NM_VALUE_TYPE_STRING);                           \
        nm_assert(_property_type->to_dbus_fcn == _nm_setting_property_to_dbus_fcn_direct);        \
                                                                                                  \
        _param_spec =                                                                             \
            g_param_spec_string("" prop_name "",                                                  \
                                "",                                                               \
                                "",                                                               \
                                NULL,                                                             \
                                G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));      \
                                                                                                  \
        (obj_properties)[(prop_id)] = _param_spec;                                                \
                                                                                                  \
        _nm_properties_override_gobj(                                                             \
            (properties_override),                                                                \
            _param_spec,                                                                          \
            _property_type,                                                                       \
            .direct_offset =                                                                      \
                NM_STRUCT_OFFSET_ENSURE_TYPE(char *, private_struct_type, private_struct_field),  \
            __VA_ARGS__);                                                                         \
    }                                                                                             \
    G_STMT_END

#define _nm_setting_property_define_direct_string(properties_override,                       \
                                                  obj_properties,                            \
                                                  prop_name,                                 \
                                                  prop_id,                                   \
                                                  param_flags,                               \
                                                  private_struct_type,                       \
                                                  private_struct_field,                      \
                                                  ... /* extra NMSettInfoProperty fields */) \
    _nm_setting_property_define_direct_string_full((properties_override),                    \
                                                   (obj_properties),                         \
                                                   prop_name,                                \
                                                   (prop_id),                                \
                                                   (param_flags),                            \
                                                   &nm_sett_info_propert_type_direct_string, \
                                                   private_struct_type,                      \
                                                   private_struct_field,                     \
                                                   __VA_ARGS__)

/*****************************************************************************/

#define _nm_setting_property_define_direct_bytes(properties_override,                              \
                                                 obj_properties,                                   \
                                                 prop_name,                                        \
                                                 prop_id,                                          \
                                                 param_flags,                                      \
                                                 private_struct_type,                              \
                                                 private_struct_field,                             \
                                                 ... /* extra NMSettInfoProperty fields */)        \
    G_STMT_START                                                                                   \
    {                                                                                              \
        GParamSpec *_param_spec;                                                                   \
                                                                                                   \
        G_STATIC_ASSERT(!NM_FLAGS_ANY((param_flags),                                               \
                                      ~(NM_SETTING_PARAM_SECRET | NM_SETTING_PARAM_INFERRABLE      \
                                        | NM_SETTING_PARAM_FUZZY_IGNORE)));                        \
                                                                                                   \
        _param_spec =                                                                              \
            g_param_spec_boxed("" prop_name "",                                                    \
                               "",                                                                 \
                               "",                                                                 \
                               G_TYPE_BYTES,                                                       \
                               G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));        \
                                                                                                   \
        (obj_properties)[(prop_id)] = _param_spec;                                                 \
                                                                                                   \
        _nm_properties_override_gobj(                                                              \
            (properties_override),                                                                 \
            _param_spec,                                                                           \
            &nm_sett_info_propert_type_direct_bytes,                                               \
            .direct_offset =                                                                       \
                NM_STRUCT_OFFSET_ENSURE_TYPE(GBytes *, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                          \
    }                                                                                              \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_strv(properties_override,                         \
                                                obj_properties,                              \
                                                prop_name,                                   \
                                                prop_id,                                     \
                                                param_flags,                                 \
                                                private_struct_type,                         \
                                                private_struct_field,                        \
                                                ... /* extra NMSettInfoProperty fields */)   \
    G_STMT_START                                                                             \
    {                                                                                        \
        GParamSpec *_param_spec;                                                             \
                                                                                             \
        G_STATIC_ASSERT(!NM_FLAGS_ANY((param_flags), ~(NM_SETTING_PARAM_FUZZY_IGNORE)));     \
                                                                                             \
        _param_spec =                                                                        \
            g_param_spec_boxed("" prop_name "",                                              \
                               "",                                                           \
                               "",                                                           \
                               G_TYPE_STRV,                                                  \
                               G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));  \
                                                                                             \
        (obj_properties)[(prop_id)] = _param_spec;                                           \
                                                                                             \
        _nm_properties_override_gobj((properties_override),                                  \
                                     _param_spec,                                            \
                                     &nm_sett_info_propert_type_direct_strv,                 \
                                     .direct_offset =                                        \
                                         NM_STRUCT_OFFSET_ENSURE_TYPE(NMValueStrv,           \
                                                                      private_struct_type,   \
                                                                      private_struct_field), \
                                     __VA_ARGS__);                                           \
    }                                                                                        \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_enum(properties_override,                             \
                                                obj_properties,                                  \
                                                prop_name,                                       \
                                                prop_id,                                         \
                                                gtype_enum,                                      \
                                                default_value,                                   \
                                                param_flags,                                     \
                                                private_struct_type,                             \
                                                private_struct_field,                            \
                                                ... /* extra NMSettInfoProperty fields */)       \
    G_STMT_START                                                                                 \
    {                                                                                            \
        GParamSpec *_param_spec;                                                                 \
                                                                                                 \
        G_STATIC_ASSERT(                                                                         \
            !NM_FLAGS_ANY((param_flags),                                                         \
                          ~(NM_SETTING_PARAM_REAPPLY_IMMEDIATELY | NM_SETTING_PARAM_FUZZY_IGNORE \
                            | NM_SETTING_PARAM_INFERRABLE)));                                    \
                                                                                                 \
        _param_spec =                                                                            \
            g_param_spec_enum("" prop_name "",                                                   \
                              "",                                                                \
                              "",                                                                \
                              (gtype_enum),                                                      \
                              (default_value),                                                   \
                              G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));       \
                                                                                                 \
        (obj_properties)[(prop_id)] = _param_spec;                                               \
                                                                                                 \
        _nm_properties_override_gobj(                                                            \
            (properties_override),                                                               \
            _param_spec,                                                                         \
            &nm_sett_info_propert_type_direct_enum,                                              \
            .direct_offset =                                                                     \
                NM_STRUCT_OFFSET_ENSURE_TYPE(int, private_struct_type, private_struct_field),    \
            __VA_ARGS__);                                                                        \
    }                                                                                            \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_ternary_enum(properties_override,  \
                                                        obj_properties,       \
                                                        prop_name,            \
                                                        prop_id,              \
                                                        param_flags,          \
                                                        private_struct_type,  \
                                                        private_struct_field, \
                                                        ...)                  \
    _nm_setting_property_define_direct_enum((properties_override),            \
                                            (obj_properties),                 \
                                            prop_name,                        \
                                            (prop_id),                        \
                                            NM_TYPE_TERNARY,                  \
                                            NM_TERNARY_DEFAULT,               \
                                            (param_flags),                    \
                                            private_struct_type,              \
                                            private_struct_field,             \
                                            __VA_ARGS__)

/*****************************************************************************/

#define _nm_setting_property_define_direct_flags(properties_override,                           \
                                                 obj_properties,                                \
                                                 prop_name,                                     \
                                                 prop_id,                                       \
                                                 gtype_flags,                                   \
                                                 default_value,                                 \
                                                 param_flags,                                   \
                                                 private_struct_type,                           \
                                                 private_struct_field,                          \
                                                 ... /* extra NMSettInfoProperty fields */)     \
    G_STMT_START                                                                                \
    {                                                                                           \
        GParamSpec *_param_spec;                                                                \
                                                                                                \
        G_STATIC_ASSERT(                                                                        \
            !NM_FLAGS_ANY((param_flags),                                                        \
                          ~(NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE)));     \
                                                                                                \
        _param_spec =                                                                           \
            g_param_spec_flags("" prop_name "",                                                 \
                               "",                                                              \
                               "",                                                              \
                               (gtype_flags),                                                   \
                               (default_value),                                                 \
                               G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));     \
                                                                                                \
        (obj_properties)[(prop_id)] = _param_spec;                                              \
                                                                                                \
        _nm_properties_override_gobj(                                                           \
            (properties_override),                                                              \
            _param_spec,                                                                        \
            &nm_sett_info_propert_type_direct_flags,                                            \
            .direct_offset =                                                                    \
                NM_STRUCT_OFFSET_ENSURE_TYPE(guint, private_struct_type, private_struct_field), \
            __VA_ARGS__);                                                                       \
    }                                                                                           \
    G_STMT_END

/*****************************************************************************/

#define _nm_setting_property_define_direct_secret_flags(properties_override,                       \
                                                        obj_properties,                            \
                                                        prop_name,                                 \
                                                        prop_id,                                   \
                                                        private_struct_type,                       \
                                                        private_struct_field,                      \
                                                        ... /* extra NMSettInfoProperty fields */) \
    _nm_setting_property_define_direct_flags((properties_override),                                \
                                             (obj_properties),                                     \
                                             prop_name,                                            \
                                             (prop_id),                                            \
                                             NM_TYPE_SETTING_SECRET_FLAGS,                         \
                                             NM_SETTING_SECRET_FLAG_NONE,                          \
                                             NM_SETTING_PARAM_NONE,                                \
                                             private_struct_type,                                  \
                                             private_struct_field,                                 \
                                             ##__VA_ARGS__)

/*****************************************************************************/

#define _nm_setting_property_define_direct_mac_address(properties_override,                       \
                                                       obj_properties,                            \
                                                       prop_name,                                 \
                                                       prop_id,                                   \
                                                       param_flags,                               \
                                                       private_struct_type,                       \
                                                       private_struct_field,                      \
                                                       ... /* extra NMSettInfoProperty fields */) \
    G_STMT_START                                                                                  \
    {                                                                                             \
        GParamSpec *_param_spec;                                                                  \
                                                                                                  \
        G_STATIC_ASSERT(!NM_FLAGS_ANY((param_flags),                                              \
                                      ~(NM_SETTING_PARAM_SECRET | NM_SETTING_PARAM_FUZZY_IGNORE   \
                                        | NM_SETTING_PARAM_INFERRABLE                             \
                                        | NM_SETTING_PARAM_REAPPLY_IMMEDIATELY)));                \
                                                                                                  \
        _param_spec =                                                                             \
            g_param_spec_string("" prop_name "",                                                  \
                                "",                                                               \
                                "",                                                               \
                                NULL,                                                             \
                                G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | (param_flags));      \
                                                                                                  \
        (obj_properties)[(prop_id)] = _param_spec;                                                \
                                                                                                  \
        _nm_properties_override_gobj(                                                             \
            (properties_override),                                                                \
            _param_spec,                                                                          \
            &nm_sett_info_propert_type_direct_mac_address,                                        \
            .direct_offset =                                                                      \
                NM_STRUCT_OFFSET_ENSURE_TYPE(char *, private_struct_type, private_struct_field),  \
            __VA_ARGS__);                                                                         \
    }                                                                                             \
    G_STMT_END

/*****************************************************************************/

gboolean _nm_setting_use_legacy_property(NMSetting  *setting,
                                         GVariant   *connection_dict,
                                         const char *legacy_property,
                                         const char *new_property);

GPtrArray *_nm_setting_need_secrets(NMSetting *setting, gboolean check_rerequest);

gboolean _nm_setting_should_compare_secret_property(NMSetting            *setting,
                                                    NMSetting            *other,
                                                    const char           *secret_name,
                                                    NMSettingCompareFlags flags);

NMBridgeVlan *_nm_bridge_vlan_dup(const NMBridgeVlan *vlan);
NMBridgeVlan *_nm_bridge_vlan_dup_and_seal(const NMBridgeVlan *vlan);

gboolean _nm_utils_bridge_vlans_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

GVariant *_nm_utils_bridge_vlans_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

gboolean _nm_utils_ranges_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

NMTernary _nm_utils_ranges_cmp(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

GVariant *_nm_utils_ranges_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

NMTernary _nm_setting_ip_config_compare_fcn_addresses(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

NMTernary _nm_setting_ip_config_compare_fcn_routes(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

NMTernary _nm_setting_ip_config_compare_fcn_dns(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

gboolean _nm_sett_info_prop_missing_from_dbus_fcn_cloned_mac_address(
    _NM_SETT_INFO_PROP_MISSING_FROM_DBUS_FCN_ARGS _nm_nil);

GVariant *
_nm_sett_info_prop_to_dbus_fcn_cloned_mac_address(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

gboolean
_nm_sett_info_prop_from_dbus_fcn_cloned_mac_address(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

/*****************************************************************************/

#endif /* NM_SETTING_PRIVATE_H */
