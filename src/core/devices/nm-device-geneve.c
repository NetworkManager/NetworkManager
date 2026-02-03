/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-manager.h"
#include "nm-device-geneve.h"

#include "libnm-core-intern/nm-core-internal.h"
#include "nm-act-request.h"
#include "nm-device-private.h"
#include "nm-setting-geneve.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"

#define _NMLOG_DEVICE_TYPE NMDeviceGeneve
#include "nm-device-logging.h"

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceGeneve,
                             PROP_ID,
                             PROP_REMOTE,
                             PROP_TOS,
                             PROP_TTL,
                             PROP_DF,
                             PROP_DST_PORT, );

typedef struct {
    NMPlatformLnkGeneve props;
} NMDeviceGenevePrivate;

struct _NMDeviceGeneve {
    NMDevice              parent;
    NMDeviceGenevePrivate _priv;
};

struct _NMDeviceGeneveClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceGeneve, nm_device_geneve, NM_TYPE_DEVICE)

#define NM_DEVICE_GENEVE_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceGeneve, NM_IS_DEVICE_GENEVE, NMDevice)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
update_properties(NMDevice *device)
{
    NMDeviceGeneve            *self;
    NMDeviceGenevePrivate     *priv;
    const NMPlatformLink      *plink;
    const NMPlatformLnkGeneve *props;
    int                        ifindex;

    g_return_if_fail(NM_IS_DEVICE_GENEVE(device));
    self = NM_DEVICE_GENEVE(device);
    priv = NM_DEVICE_GENEVE_GET_PRIVATE(self);

    ifindex = nm_device_get_ifindex(device);
    g_return_if_fail(ifindex > 0);
    props = nm_platform_link_get_lnk_geneve(nm_device_get_platform(device), ifindex, &plink);

    if (!props) {
        _LOGW(LOGD_PLATFORM, "could not get GENEVE properties");
        return;
    }

    g_object_freeze_notify((GObject *) device);

#define CHECK_PROPERTY_CHANGED(field, prop)      \
    G_STMT_START                                 \
    {                                            \
        if (priv->props.field != props->field) { \
            priv->props.field = props->field;    \
            _notify(self, prop);                 \
        }                                        \
    }                                            \
    G_STMT_END

#define CHECK_PROPERTY_CHANGED_IN6ADDR(field, prop)                                 \
    G_STMT_START                                                                    \
    {                                                                               \
        if (memcmp(&priv->props.field, &props->field, sizeof(props->field)) != 0) { \
            priv->props.field = props->field;                                       \
            _notify(self, prop);                                                    \
        }                                                                           \
    }                                                                               \
    G_STMT_END

    CHECK_PROPERTY_CHANGED(id, PROP_ID);
    CHECK_PROPERTY_CHANGED(remote, PROP_REMOTE);
    CHECK_PROPERTY_CHANGED_IN6ADDR(remote6, PROP_REMOTE);
    CHECK_PROPERTY_CHANGED(tos, PROP_TOS);
    CHECK_PROPERTY_CHANGED(ttl, PROP_TTL);
    CHECK_PROPERTY_CHANGED(df, PROP_DF);
    CHECK_PROPERTY_CHANGED(dst_port, PROP_DST_PORT);

    g_object_thaw_notify((GObject *) device);
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NM_DEVICE_CLASS(nm_device_geneve_parent_class)->link_changed(device, pllink);
    update_properties(device);
}

static void
unrealize_notify(NMDevice *device)
{
    NMDeviceGeneve        *self = NM_DEVICE_GENEVE(device);
    NMDeviceGenevePrivate *priv = NM_DEVICE_GENEVE_GET_PRIVATE(self);
    guint                  i;

    NM_DEVICE_CLASS(nm_device_geneve_parent_class)->unrealize_notify(device);

    memset(&priv->props, 0, sizeof(NMPlatformLnkGeneve));

    for (i = 1; i < _PROPERTY_ENUMS_LAST; i++)
        g_object_notify_by_pspec(G_OBJECT(self), obj_properties[i]);
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char         *iface = nm_device_get_iface(device);
    NMPlatformLnkGeneve props = {};
    NMSettingGeneve    *s_geneve;
    const char         *str;
    int                 r;

    s_geneve = nm_connection_get_setting_geneve(connection);
    g_return_val_if_fail(s_geneve, FALSE);

    props.id = nm_setting_geneve_get_id(s_geneve);

    str = nm_setting_geneve_get_remote(s_geneve);
    if (!nm_inet_parse_bin(AF_INET, str, NULL, &props.remote)
        && !nm_inet_parse_bin(AF_INET6, str, NULL, &props.remote6)) {
        return nm_assert_unreachable_val(FALSE);
    }
    props.tos      = nm_setting_geneve_get_tos(s_geneve);
    props.ttl      = nm_setting_geneve_get_ttl(s_geneve);
    props.df       = nm_setting_geneve_get_df(s_geneve);
    props.dst_port = nm_setting_geneve_get_destination_port(s_geneve);

    r = nm_platform_link_geneve_add(nm_device_get_platform(device), iface, &props, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create geneve interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

static gboolean
address_matches(const char *candidate, in_addr_t addr4, struct in6_addr *addr6)
{
    NMIPAddr candidate_addr;
    int      addr_family;

    if (!candidate)
        return addr4 == 0u && IN6_IS_ADDR_UNSPECIFIED(addr6);

    if (!nm_inet_parse_bin(AF_UNSPEC, candidate, &addr_family, &candidate_addr))
        return FALSE;

    if (!nm_ip_addr_equal(addr_family,
                          &candidate_addr,
                          NM_IS_IPv4(addr_family) ? (gpointer) &addr4 : addr6))
        return FALSE;

    if (NM_IS_IPv4(addr_family))
        return IN6_IS_ADDR_UNSPECIFIED(addr6);
    else
        return addr4 == 0u;
}

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMDeviceGenevePrivate *priv = NM_DEVICE_GENEVE_GET_PRIVATE(device);
    NMSettingGeneve       *s_geneve;

    if (!NM_DEVICE_CLASS(nm_device_geneve_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    if (check_properties && nm_device_is_real(device)) {
        s_geneve = nm_connection_get_setting_geneve(connection);

        if (priv->props.id != nm_setting_geneve_get_id(s_geneve)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "geneve id mismatches");
            return FALSE;
        }

        if (!address_matches(nm_setting_geneve_get_remote(s_geneve),
                             priv->props.remote,
                             &priv->props.remote6)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "geneve remote address mismatches");
            return FALSE;
        }

        if (priv->props.dst_port != nm_setting_geneve_get_destination_port(s_geneve)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "geneve destination port mismatches");
            return FALSE;
        }

        if (priv->props.tos != nm_setting_geneve_get_tos(s_geneve)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "geneve TOS mismatches");
            return FALSE;
        }

        if (priv->props.ttl != nm_setting_geneve_get_ttl(s_geneve)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "geneve TTL mismatches");
            return FALSE;
        }

        if (priv->props.df != nm_setting_geneve_get_df(s_geneve)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "geneve DF mismatches");
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    NMSettingGeneve *s_geneve;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_GENEVE_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Geneve connection"),
                              NULL,
                              NULL);

    s_geneve = nm_connection_get_setting_geneve(connection);
    if (!s_geneve) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "A 'geneve' setting is required.");
        return FALSE;
    }

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceGenevePrivate *priv = NM_DEVICE_GENEVE_GET_PRIVATE(device);
    NMSettingGeneve *s_geneve   = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_GENEVE);
    char             sbuf[NM_INET_ADDRSTRLEN];

    if (priv->props.id != nm_setting_geneve_get_id(s_geneve))
        g_object_set(G_OBJECT(s_geneve), NM_SETTING_GENEVE_ID, priv->props.id, NULL);

    /* Handle remote (IPv4 or IPv6) */
    if (priv->props.remote) {
        g_object_set(s_geneve,
                     NM_SETTING_GENEVE_REMOTE,
                     nm_inet4_ntop(priv->props.remote, sbuf),
                     NULL);
    } else if (memcmp(&priv->props.remote6, &in6addr_any, sizeof(in6addr_any))) {
        g_object_set(s_geneve,
                     NM_SETTING_GENEVE_REMOTE,
                     nm_inet6_ntop(&priv->props.remote6, sbuf),
                     NULL);
    }

    if (priv->props.dst_port != nm_setting_geneve_get_destination_port(s_geneve))
        g_object_set(G_OBJECT(s_geneve),
                     NM_SETTING_GENEVE_DESTINATION_PORT,
                     priv->props.dst_port,
                     NULL);

    if (priv->props.tos != nm_setting_geneve_get_tos(s_geneve))
        g_object_set(G_OBJECT(s_geneve), NM_SETTING_GENEVE_TOS, priv->props.tos, NULL);

    if (priv->props.ttl != nm_setting_geneve_get_ttl(s_geneve))
        g_object_set(G_OBJECT(s_geneve), NM_SETTING_GENEVE_TTL, priv->props.ttl, NULL);

    if (priv->props.df != nm_setting_geneve_get_df(s_geneve))
        g_object_set(G_OBJECT(s_geneve), NM_SETTING_GENEVE_DF, priv->props.df, NULL);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceGenevePrivate *priv = NM_DEVICE_GENEVE_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_ID:
        g_value_set_uint(value, priv->props.id);
        break;
    case PROP_REMOTE:
        if (priv->props.remote)
            g_value_take_string(value, nm_inet4_ntop_dup(priv->props.remote));
        else if (!IN6_IS_ADDR_UNSPECIFIED(&priv->props.remote6))
            g_value_take_string(value, nm_inet6_ntop_dup(&priv->props.remote6));
        break;
    case PROP_TOS:
        g_value_set_uchar(value, priv->props.tos);
        break;
    case PROP_TTL:
        g_value_set_uchar(value, priv->props.ttl);
        break;
    case PROP_DF:
        g_value_set_uint(value, priv->props.df);
        break;
    case PROP_DST_PORT:
        g_value_set_uint(value, priv->props.dst_port);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_geneve_init(NMDeviceGeneve *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_geneve = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_GENEVE,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Id", "u", NM_DEVICE_GENEVE_ID),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Remote", "s", NM_DEVICE_GENEVE_REMOTE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Tos", "y", NM_DEVICE_GENEVE_TOS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ttl", "y", NM_DEVICE_GENEVE_TTL),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Df", "u", NM_DEVICE_GENEVE_DF),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DstPort",
                                                           "q",
                                                           NM_DEVICE_GENEVE_DST_PORT), ), ),
};

static void
nm_device_geneve_class_init(NMDeviceGeneveClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_geneve);

    device_class->connection_type_supported        = NM_SETTING_GENEVE_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_GENEVE_SETTING_NAME;
    device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_GENEVE);

    device_class->link_changed                = link_changed;
    device_class->unrealize_notify            = unrealize_notify;
    device_class->create_and_realize          = create_and_realize;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->complete_connection         = complete_connection;
    device_class->get_generic_capabilities    = get_generic_capabilities;
    device_class->update_connection           = update_connection;

    obj_properties[PROP_ID] = g_param_spec_uint(NM_DEVICE_GENEVE_ID,
                                                "",
                                                "",
                                                0,
                                                G_MAXUINT32,
                                                0,
                                                G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_REMOTE] = g_param_spec_string(NM_DEVICE_GENEVE_REMOTE,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_TOS] = g_param_spec_uchar(NM_DEVICE_GENEVE_TOS,
                                                  "",
                                                  "",
                                                  0,
                                                  255,
                                                  0,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_TTL] = g_param_spec_uchar(NM_DEVICE_GENEVE_TTL,
                                                  "",
                                                  "",
                                                  0,
                                                  255,
                                                  0,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_DF] = g_param_spec_uint(NM_DEVICE_GENEVE_DF,
                                                "",
                                                "",
                                                0,
                                                2,
                                                0,
                                                G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_DST_PORT] = g_param_spec_uint(NM_DEVICE_GENEVE_DST_PORT,
                                                      "",
                                                      "",
                                                      0,
                                                      65535,
                                                      0,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_GENEVE_DEVICE_FACTORY (nm_geneve_device_factory_get_type())
#define NM_GENEVE_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_GENEVE_DEVICE_FACTORY, NMGeneveDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_GENEVE,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Geneve",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_GENEVE,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_GENEVE,
                        NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    GENEVE,
    Geneve,
    geneve,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_GENEVE)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_GENEVE_SETTING_NAME),
    factory_class->create_device = create_device;);
