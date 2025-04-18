/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-vxlan.h"

#include "nm-device-private.h"
#include "nm-manager.h"
#include "libnm-platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-device-factory.h"
#include "nm-setting-vxlan.h"
#include "nm-setting-wired.h"
#include "settings/nm-settings.h"
#include "nm-act-request.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"

#define _NMLOG_DEVICE_TYPE NMDeviceVxlan
#include "nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceVxlan,
                             PROP_ID,
                             PROP_LOCAL,
                             PROP_GROUP,
                             PROP_TOS,
                             PROP_TTL,
                             PROP_LEARNING,
                             PROP_AGEING,
                             PROP_LIMIT,
                             PROP_SRC_PORT_MIN,
                             PROP_SRC_PORT_MAX,
                             PROP_DST_PORT,
                             PROP_PROXY,
                             PROP_RSC,
                             PROP_L2MISS,
                             PROP_L3MISS, );

typedef struct {
    NMPlatformLnkVxlan props;
} NMDeviceVxlanPrivate;

struct _NMDeviceVxlan {
    NMDevice             parent;
    NMDeviceVxlanPrivate _priv;
};

struct _NMDeviceVxlanClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceVxlan, nm_device_vxlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VXLAN_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceVxlan, NM_IS_DEVICE_VXLAN, NMDevice)

/*****************************************************************************/

static void
update_properties(NMDevice *device)
{
    NMDeviceVxlan            *self   = NM_DEVICE_VXLAN(device);
    NMDeviceVxlanPrivate     *priv   = NM_DEVICE_VXLAN_GET_PRIVATE(self);
    GObject                  *object = G_OBJECT(device);
    const NMPlatformLnkVxlan *props;

    props = nm_platform_link_get_lnk_vxlan(nm_device_get_platform(device),
                                           nm_device_get_ifindex(device),
                                           NULL);
    if (!props) {
        _LOGW(LOGD_PLATFORM, "could not get vxlan properties");
        return;
    }

    g_object_freeze_notify(object);

    if (priv->props.parent_ifindex != props->parent_ifindex)
        nm_device_parent_set_ifindex(device, props->parent_ifindex);

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
    CHECK_PROPERTY_CHANGED(local, PROP_LOCAL);
    CHECK_PROPERTY_CHANGED_IN6ADDR(local6, PROP_LOCAL);
    CHECK_PROPERTY_CHANGED(group, PROP_GROUP);
    CHECK_PROPERTY_CHANGED_IN6ADDR(group6, PROP_GROUP);
    CHECK_PROPERTY_CHANGED(tos, PROP_TOS);
    CHECK_PROPERTY_CHANGED(ttl, PROP_TTL);
    CHECK_PROPERTY_CHANGED(learning, PROP_LEARNING);
    CHECK_PROPERTY_CHANGED(ageing, PROP_AGEING);
    CHECK_PROPERTY_CHANGED(limit, PROP_LIMIT);
    CHECK_PROPERTY_CHANGED(src_port_min, PROP_SRC_PORT_MIN);
    CHECK_PROPERTY_CHANGED(src_port_max, PROP_SRC_PORT_MAX);
    CHECK_PROPERTY_CHANGED(dst_port, PROP_DST_PORT);
    CHECK_PROPERTY_CHANGED(proxy, PROP_PROXY);
    CHECK_PROPERTY_CHANGED(rsc, PROP_RSC);
    CHECK_PROPERTY_CHANGED(l2miss, PROP_L2MISS);
    CHECK_PROPERTY_CHANGED(l3miss, PROP_L3MISS);

    g_object_thaw_notify(object);
}

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NM_DEVICE_CLASS(nm_device_vxlan_parent_class)->link_changed(device, pllink);
    update_properties(device);
}

static void
unrealize_notify(NMDevice *device)
{
    NMDeviceVxlan        *self = NM_DEVICE_VXLAN(device);
    NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE(self);
    guint                 i;

    NM_DEVICE_CLASS(nm_device_vxlan_parent_class)->unrealize_notify(device);

    memset(&priv->props, 0, sizeof(NMPlatformLnkVxlan));

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
    const char        *iface = nm_device_get_iface(device);
    NMPlatformLnkVxlan props = {};
    NMSettingVxlan    *s_vxlan;
    const char        *str;
    int                r;

    s_vxlan = nm_connection_get_setting_vxlan(connection);
    g_return_val_if_fail(s_vxlan, FALSE);

    if (parent)
        props.parent_ifindex = nm_device_get_ifindex(parent);

    props.id = nm_setting_vxlan_get_id(s_vxlan);

    str = nm_setting_vxlan_get_local(s_vxlan);
    if (str) {
        if (!nm_inet_parse_bin(AF_INET, str, NULL, &props.local)
            && !nm_inet_parse_bin(AF_INET6, str, NULL, &props.local6))
            return FALSE;
    }

    str = nm_setting_vxlan_get_remote(s_vxlan);
    if (str) {
        if (!nm_inet_parse_bin(AF_INET, str, NULL, &props.group)
            && !nm_inet_parse_bin(AF_INET6, str, NULL, &props.group6))
            return FALSE;
    }

    props.tos          = nm_setting_vxlan_get_tos(s_vxlan);
    props.ttl          = nm_setting_vxlan_get_ttl(s_vxlan);
    props.learning     = nm_setting_vxlan_get_learning(s_vxlan);
    props.ageing       = nm_setting_vxlan_get_ageing(s_vxlan);
    props.limit        = nm_setting_vxlan_get_limit(s_vxlan);
    props.src_port_min = nm_setting_vxlan_get_source_port_min(s_vxlan);
    props.src_port_max = nm_setting_vxlan_get_source_port_max(s_vxlan);
    props.dst_port     = nm_setting_vxlan_get_destination_port(s_vxlan);
    props.proxy        = nm_setting_vxlan_get_proxy(s_vxlan);
    props.rsc          = nm_setting_vxlan_get_rsc(s_vxlan);
    props.l2miss       = nm_setting_vxlan_get_l2_miss(s_vxlan);
    props.l3miss       = nm_setting_vxlan_get_l3_miss(s_vxlan);

    r = nm_platform_link_vxlan_add(nm_device_get_platform(device), iface, &props, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create VXLAN interface '%s' for '%s': %s",
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
    NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE(device);
    NMSettingVxlan       *s_vxlan;
    const char           *parent;

    if (!NM_DEVICE_CLASS(nm_device_vxlan_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    if (check_properties && nm_device_is_real(device)) {
        s_vxlan = nm_connection_get_setting_vxlan(connection);

        parent = nm_setting_vxlan_get_parent(s_vxlan);
        if (parent && !nm_device_match_parent(device, parent)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan parent mismatches");
            return FALSE;
        }

        if (priv->props.id != nm_setting_vxlan_get_id(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan id mismatches");
            return FALSE;
        }

        if (!address_matches(nm_setting_vxlan_get_local(s_vxlan),
                             priv->props.local,
                             &priv->props.local6)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan local address mismatches");
            return FALSE;
        }

        if (!address_matches(nm_setting_vxlan_get_remote(s_vxlan),
                             priv->props.group,
                             &priv->props.group6)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan remote address mismatches");
            return FALSE;
        }

        if (priv->props.src_port_min != nm_setting_vxlan_get_source_port_min(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan source port min mismatches");
            return FALSE;
        }

        if (priv->props.src_port_max != nm_setting_vxlan_get_source_port_max(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan source port max mismatches");
            return FALSE;
        }

        if (priv->props.dst_port != nm_setting_vxlan_get_destination_port(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan destination port mismatches");
            return FALSE;
        }

        if (priv->props.tos != nm_setting_vxlan_get_tos(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan TOS mismatches");
            return FALSE;
        }

        if (priv->props.ttl != nm_setting_vxlan_get_ttl(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan TTL mismatches");
            return FALSE;
        }

        if (priv->props.learning != nm_setting_vxlan_get_learning(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan learning mismatches");
            return FALSE;
        }

        if (priv->props.ageing != nm_setting_vxlan_get_ageing(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan ageing mismatches");
            return FALSE;
        }

        if (priv->props.proxy != nm_setting_vxlan_get_proxy(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan proxy mismatches");
            return FALSE;
        }

        if (priv->props.rsc != nm_setting_vxlan_get_rsc(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan rsc mismatches");
            return FALSE;
        }

        if (priv->props.l2miss != nm_setting_vxlan_get_l2_miss(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan l2miss mismatches");
            return FALSE;
        }

        if (priv->props.l3miss != nm_setting_vxlan_get_l3_miss(s_vxlan)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vxlan l3miss mismatches");
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
    NMSettingVxlan *s_vxlan;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_VXLAN_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("VXLAN connection"),
                              NULL,
                              NULL);

    s_vxlan = nm_connection_get_setting_vxlan(connection);
    if (!s_vxlan) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "A 'vxlan' setting is required.");
        return FALSE;
    }

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE(device);
    NMSettingVxlan *s_vxlan    = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_VXLAN);
    char            sbuf[NM_INET_ADDRSTRLEN];

    if (priv->props.id != nm_setting_vxlan_get_id(s_vxlan))
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_ID, priv->props.id, NULL);

    g_object_set(s_vxlan,
                 NM_SETTING_VXLAN_PARENT,
                 nm_device_parent_find_for_connection(device, nm_setting_vxlan_get_parent(s_vxlan)),
                 NULL);

    if (!address_matches(nm_setting_vxlan_get_remote(s_vxlan),
                         priv->props.group,
                         &priv->props.group6)) {
        if (priv->props.group) {
            g_object_set(s_vxlan,
                         NM_SETTING_VXLAN_REMOTE,
                         nm_inet4_ntop(priv->props.group, sbuf),
                         NULL);
        } else {
            g_object_set(s_vxlan,
                         NM_SETTING_VXLAN_REMOTE,
                         nm_inet6_ntop(&priv->props.group6, sbuf),
                         NULL);
        }
    }

    if (!address_matches(nm_setting_vxlan_get_local(s_vxlan),
                         priv->props.local,
                         &priv->props.local6)) {
        if (priv->props.local) {
            g_object_set(s_vxlan,
                         NM_SETTING_VXLAN_LOCAL,
                         nm_inet4_ntop(priv->props.local, sbuf),
                         NULL);
        } else if (memcmp(&priv->props.local6, &in6addr_any, sizeof(in6addr_any))) {
            g_object_set(s_vxlan,
                         NM_SETTING_VXLAN_LOCAL,
                         nm_inet6_ntop(&priv->props.local6, sbuf),
                         NULL);
        }
    }

    if (priv->props.src_port_min != nm_setting_vxlan_get_source_port_min(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan),
                     NM_SETTING_VXLAN_SOURCE_PORT_MIN,
                     priv->props.src_port_min,
                     NULL);
    }

    if (priv->props.src_port_max != nm_setting_vxlan_get_source_port_max(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan),
                     NM_SETTING_VXLAN_SOURCE_PORT_MAX,
                     priv->props.src_port_max,
                     NULL);
    }

    if (priv->props.dst_port != nm_setting_vxlan_get_destination_port(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan),
                     NM_SETTING_VXLAN_DESTINATION_PORT,
                     priv->props.dst_port,
                     NULL);
    }

    if (priv->props.tos != nm_setting_vxlan_get_tos(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_TOS, priv->props.tos, NULL);
    }

    if (priv->props.ttl != nm_setting_vxlan_get_ttl(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_TTL, priv->props.ttl, NULL);
    }

    if (priv->props.learning != nm_setting_vxlan_get_learning(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_LEARNING, priv->props.learning, NULL);
    }

    if (priv->props.ageing != nm_setting_vxlan_get_ageing(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_AGEING, priv->props.ageing, NULL);
    }

    if (priv->props.proxy != nm_setting_vxlan_get_proxy(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_PROXY, priv->props.proxy, NULL);
    }

    if (priv->props.rsc != nm_setting_vxlan_get_rsc(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_RSC, priv->props.rsc, NULL);
    }

    if (priv->props.l2miss != nm_setting_vxlan_get_l2_miss(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_L2_MISS, priv->props.l2miss, NULL);
    }

    if (priv->props.l3miss != nm_setting_vxlan_get_l3_miss(s_vxlan)) {
        g_object_set(G_OBJECT(s_vxlan), NM_SETTING_VXLAN_L3_MISS, priv->props.l3miss, NULL);
    }
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_ID:
        g_value_set_uint(value, priv->props.id);
        break;
    case PROP_GROUP:
        if (priv->props.group)
            g_value_take_string(value, nm_inet4_ntop_dup(priv->props.group));
        else if (!IN6_IS_ADDR_UNSPECIFIED(&priv->props.group6))
            g_value_take_string(value, nm_inet6_ntop_dup(&priv->props.group6));
        break;
    case PROP_LOCAL:
        if (priv->props.local)
            g_value_take_string(value, nm_inet4_ntop_dup(priv->props.local));
        else if (!IN6_IS_ADDR_UNSPECIFIED(&priv->props.local6))
            g_value_take_string(value, nm_inet6_ntop_dup(&priv->props.local6));
        break;
    case PROP_TOS:
        g_value_set_uchar(value, priv->props.tos);
        break;
    case PROP_TTL:
        g_value_set_uchar(value, priv->props.ttl);
        break;
    case PROP_LEARNING:
        g_value_set_boolean(value, priv->props.learning);
        break;
    case PROP_AGEING:
        g_value_set_uint(value, priv->props.ageing);
        break;
    case PROP_LIMIT:
        g_value_set_uint(value, priv->props.limit);
        break;
    case PROP_DST_PORT:
        g_value_set_uint(value, priv->props.dst_port);
        break;
    case PROP_SRC_PORT_MIN:
        g_value_set_uint(value, priv->props.src_port_min);
        break;
    case PROP_SRC_PORT_MAX:
        g_value_set_uint(value, priv->props.src_port_max);
        break;
    case PROP_PROXY:
        g_value_set_boolean(value, priv->props.proxy);
        break;
    case PROP_RSC:
        g_value_set_boolean(value, priv->props.rsc);
        break;
    case PROP_L2MISS:
        g_value_set_boolean(value, priv->props.l2miss);
        break;
    case PROP_L3MISS:
        g_value_set_boolean(value, priv->props.l3miss);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_vxlan_init(NMDeviceVxlan *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_vxlan = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_VXLAN,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Parent", "o", NM_DEVICE_PARENT),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(
                "HwAddress",
                "s",
                NM_DEVICE_HW_ADDRESS,
                .annotations = NM_GDBUS_ANNOTATION_INFO_LIST_DEPRECATED(), ),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Id", "u", NM_DEVICE_VXLAN_ID),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Group", "s", NM_DEVICE_VXLAN_GROUP),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Local", "s", NM_DEVICE_VXLAN_LOCAL),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Tos", "y", NM_DEVICE_VXLAN_TOS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ttl", "y", NM_DEVICE_VXLAN_TTL),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Learning",
                                                           "b",
                                                           NM_DEVICE_VXLAN_LEARNING),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ageing", "u", NM_DEVICE_VXLAN_AGEING),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Limit", "u", NM_DEVICE_VXLAN_LIMIT),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DstPort",
                                                           "q",
                                                           NM_DEVICE_VXLAN_DST_PORT),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("SrcPortMin",
                                                           "q",
                                                           NM_DEVICE_VXLAN_SRC_PORT_MIN),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("SrcPortMax",
                                                           "q",
                                                           NM_DEVICE_VXLAN_SRC_PORT_MAX),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Proxy", "b", NM_DEVICE_VXLAN_PROXY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Rsc", "b", NM_DEVICE_VXLAN_RSC),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("L2miss", "b", NM_DEVICE_VXLAN_L2MISS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("L3miss",
                                                           "b",
                                                           NM_DEVICE_VXLAN_L3MISS), ), ),
};

static void
nm_device_vxlan_class_init(NMDeviceVxlanClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_vxlan);

    device_class->connection_type_supported        = NM_SETTING_VXLAN_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_VXLAN_SETTING_NAME;
    device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_VXLAN);

    device_class->link_changed                           = link_changed;
    device_class->unrealize_notify                       = unrealize_notify;
    device_class->create_and_realize                     = create_and_realize;
    device_class->check_connection_compatible            = check_connection_compatible;
    device_class->complete_connection                    = complete_connection;
    device_class->get_generic_capabilities               = get_generic_capabilities;
    device_class->update_connection                      = update_connection;
    device_class->act_stage1_prepare_set_hwaddr_ethernet = TRUE;
    device_class->get_configured_mtu                     = nm_device_get_configured_mtu_for_wired;

    obj_properties[PROP_ID] = g_param_spec_uint(NM_DEVICE_VXLAN_ID,
                                                "",
                                                "",
                                                0,
                                                G_MAXUINT32,
                                                0,
                                                G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_LOCAL] = g_param_spec_string(NM_DEVICE_VXLAN_LOCAL,
                                                     "",
                                                     "",
                                                     NULL,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_GROUP] = g_param_spec_string(NM_DEVICE_VXLAN_GROUP,
                                                     "",
                                                     "",
                                                     NULL,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_TOS] = g_param_spec_uchar(NM_DEVICE_VXLAN_TOS,
                                                  "",
                                                  "",
                                                  0,
                                                  255,
                                                  0,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_TTL] = g_param_spec_uchar(NM_DEVICE_VXLAN_TTL,
                                                  "",
                                                  "",
                                                  0,
                                                  255,
                                                  0,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_LEARNING] = g_param_spec_boolean(NM_DEVICE_VXLAN_LEARNING,
                                                         "",
                                                         "",
                                                         FALSE,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_AGEING] = g_param_spec_uint(NM_DEVICE_VXLAN_AGEING,
                                                    "",
                                                    "",
                                                    0,
                                                    G_MAXUINT32,
                                                    0,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_LIMIT] = g_param_spec_uint(NM_DEVICE_VXLAN_LIMIT,
                                                   "",
                                                   "",
                                                   0,
                                                   G_MAXUINT32,
                                                   0,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_SRC_PORT_MIN] =
        g_param_spec_uint(NM_DEVICE_VXLAN_SRC_PORT_MIN,
                          "",
                          "",
                          0,
                          65535,
                          0,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_SRC_PORT_MAX] =
        g_param_spec_uint(NM_DEVICE_VXLAN_SRC_PORT_MAX,
                          "",
                          "",
                          0,
                          65535,
                          0,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_DST_PORT] = g_param_spec_uint(NM_DEVICE_VXLAN_DST_PORT,
                                                      "",
                                                      "",
                                                      0,
                                                      65535,
                                                      0,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_PROXY] = g_param_spec_boolean(NM_DEVICE_VXLAN_PROXY,
                                                      "",
                                                      "",
                                                      FALSE,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_RSC] = g_param_spec_boolean(NM_DEVICE_VXLAN_RSC,
                                                    "",
                                                    "",
                                                    FALSE,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_L2MISS] = g_param_spec_boolean(NM_DEVICE_VXLAN_L2MISS,
                                                       "",
                                                       "",
                                                       FALSE,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_L3MISS] = g_param_spec_boolean(NM_DEVICE_VXLAN_L3MISS,
                                                       "",
                                                       "",
                                                       FALSE,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_VXLAN_DEVICE_FACTORY (nm_vxlan_device_factory_get_type())
#define NM_VXLAN_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_VXLAN_DEVICE_FACTORY, NMVxlanDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_VXLAN,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Vxlan",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_VXLAN,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_VXLAN,
                        NULL);
}

static const char *
get_connection_parent(NMDeviceFactory *factory, NMConnection *connection)
{
    NMSettingVxlan *s_vxlan;

    g_return_val_if_fail(nm_connection_is_type(connection, NM_SETTING_VXLAN_SETTING_NAME), NULL);

    s_vxlan = nm_connection_get_setting_vxlan(connection);
    if (s_vxlan)
        return nm_setting_vxlan_get_parent(s_vxlan);
    else
        return NULL;
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    VXLAN,
    Vxlan,
    vxlan,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_VXLAN)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_VXLAN_SETTING_NAME),
    factory_class->create_device         = create_device;
    factory_class->get_connection_parent = get_connection_parent;);
