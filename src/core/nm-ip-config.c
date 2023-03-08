/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ip-config.h"

#include <linux/rtnetlink.h>

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nm-l3cfg.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

GType nm_ip4_config_get_type(void);
GType nm_ip6_config_get_type(void);

/*****************************************************************************/

#define NM_IP_CONFIG_ADDRESS_DATA "address-data"
#define NM_IP_CONFIG_DNS_OPTIONS  "dns-options"
#define NM_IP_CONFIG_DNS_PRIORITY "dns-priority"
#define NM_IP_CONFIG_DOMAINS      "domains"
#define NM_IP_CONFIG_GATEWAY      "gateway"
#define NM_IP_CONFIG_ROUTE_DATA   "route-data"
#define NM_IP_CONFIG_SEARCHES     "searches"

/*****************************************************************************/

typedef struct _NMIPConfigPrivate NMIPConfigPrivate;

NM_GOBJECT_PROPERTIES_DEFINE_FULL(_ip,
                                  NMIPConfig,
                                  PROP_IP_L3CFG,
                                  PROP_IP_ADDRESS_DATA,
                                  PROP_IP_GATEWAY,
                                  PROP_IP_ROUTE_DATA,
                                  PROP_IP_DOMAINS,
                                  PROP_IP_SEARCHES,
                                  PROP_IP_DNS_PRIORITY,
                                  PROP_IP_DNS_OPTIONS, );

G_DEFINE_ABSTRACT_TYPE(NMIPConfig, nm_ip_config, NM_TYPE_DBUS_OBJECT)

#define NM_IP_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMIPConfig, NM_IS_IP_CONFIG)

/*****************************************************************************/

static void _handle_platform_change(NMIPConfig *self, guint32 obj_type_flags, gboolean is_init);
static void _handle_l3cd_changed(NMIPConfig *self, const NML3ConfigData *l3cd);

/*****************************************************************************/

static void
_value_set_variant_as(GValue *value, const char *const *strv, guint len)
{
    if (len > 0) {
        nm_assert(strv && strv[0]);
        g_value_set_variant(value, g_variant_new_strv((const char *const *) strv, len));
    } else
        g_value_set_variant(value, nm_g_variant_singleton_as());
}

/*****************************************************************************/

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMIPConfig *self)
{
    switch (notify_data->notify_type) {
    case NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED:
        if (notify_data->l3cd_changed.commited)
            _handle_l3cd_changed(self, notify_data->l3cd_changed.l3cd_new);
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE:
        _handle_platform_change(self, notify_data->platform_change_on_idle.obj_type_flags, FALSE);
        break;
    default:
        break;
    }
}

/*****************************************************************************/

static void
get_property_ip(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMIPConfig        *self        = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv        = NM_IP_CONFIG_GET_PRIVATE(self);
    const int          addr_family = nm_ip_config_get_addr_family(self);
    char               sbuf_addr[NM_INET_ADDRSTRLEN];
    const char *const *strv;
    guint              len;
    int                v_i;

    switch (prop_id) {
    case PROP_IP_ADDRESS_DATA:
        g_value_set_variant(value, priv->v_address_data);
        break;
    case PROP_IP_GATEWAY:
        if (priv->v_gateway.best_default_route) {
            const NMIPAddr *gateway;

            gateway = nm_platform_ip_route_get_gateway(
                addr_family,
                NMP_OBJECT_CAST_IP_ROUTE(priv->v_gateway.best_default_route));
            g_value_set_variant(
                value,
                g_variant_new_string(nm_inet_ntop(addr_family, gateway, sbuf_addr)));
        } else
            g_value_set_variant(value, nm_g_variant_singleton_s_empty());
        break;
    case PROP_IP_ROUTE_DATA:
        g_value_set_variant(value, priv->v_route_data);
        break;
    case PROP_IP_DOMAINS:
        strv = nm_l3_config_data_get_domains(priv->l3cd, addr_family, &len);
        _value_set_variant_as(value, strv, len);
        break;
    case PROP_IP_SEARCHES:
        strv = nm_l3_config_data_get_searches(priv->l3cd, addr_family, &len);
        _value_set_variant_as(value, strv, len);
        break;
    case PROP_IP_DNS_PRIORITY:
        v_i = nm_l3_config_data_get_dns_priority_or_default(priv->l3cd, addr_family);
        g_value_set_variant(value,
                            (v_i == 0) ? nm_g_variant_singleton_i_0() : g_variant_new_int32(v_i));
        break;
    case PROP_IP_DNS_OPTIONS:
        strv = nm_l3_config_data_get_dns_options(priv->l3cd, addr_family, &len);
        _value_set_variant_as(value, strv, len);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMIPConfig        *self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);
    gpointer           ptr;

    switch (prop_id) {
    case PROP_IP_L3CFG:
        /* construct-only */
        ptr = g_value_get_pointer(value);
        nm_assert(NM_IS_L3CFG(ptr));
        priv->l3cfg = g_object_ref(ptr);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_ip_config_init(NMIPConfig *self)
{}

NMIPConfig *
nm_ip_config_new(int addr_family, NML3Cfg *l3cfg)
{
    nm_assert_addr_family(addr_family);
    nm_assert(NM_L3CFG(l3cfg));

    return g_object_new(NM_IS_IPv4(addr_family) ? nm_ip4_config_get_type()
                                                : nm_ip6_config_get_type(),
                        NM_IP_CONFIG_L3CFG,
                        l3cfg,
                        NULL);
}

static void
constructed(GObject *object)
{
    NMIPConfig        *self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    priv->l3cfg_notify_id =
        g_signal_connect(priv->l3cfg, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self);

    priv->l3cd = nm_l3_config_data_ref(nm_l3cfg_get_combined_l3cd(priv->l3cfg, TRUE));

    _handle_platform_change(self, ~((guint32) 0u), TRUE);

    G_OBJECT_CLASS(nm_ip_config_parent_class)->constructed(object);
}

void
nm_ip_config_take_and_unexport_on_idle(NMIPConfig *self_take)
{
    if (self_take)
        nm_dbus_object_unexport_on_idle(g_steal_pointer(&self_take));
}

static void
finalize(GObject *object)
{
    NMIPConfig        *self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    nm_clear_g_signal_handler(priv->l3cfg, &priv->l3cfg_notify_id);

    g_object_unref(priv->l3cfg);

    nm_g_variant_unref(priv->v_address_data);
    nm_g_variant_unref(priv->v_addresses);
    nm_g_variant_unref(priv->v_route_data);
    nm_g_variant_unref(priv->v_routes);

    nmp_object_unref(priv->v_gateway.best_default_route);

    nm_l3_config_data_unref(priv->l3cd);

    G_OBJECT_CLASS(nm_ip_config_parent_class)->finalize(object);
}

static void
nm_ip_config_class_init(NMIPConfigClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);

    object_class->get_property = get_property_ip;
    object_class->set_property = set_property;
    object_class->constructed  = constructed;
    object_class->finalize     = finalize;

    dbus_object_class->export_on_construction = TRUE;

    obj_properties_ip[PROP_IP_L3CFG] =
        g_param_spec_pointer(NM_IP_CONFIG_L3CFG,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties_ip[PROP_IP_ADDRESS_DATA] =
        g_param_spec_variant(NM_IP_CONFIG_ADDRESS_DATA,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_GATEWAY] =
        g_param_spec_variant(NM_IP_CONFIG_GATEWAY,
                             "",
                             "",
                             G_VARIANT_TYPE("s"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_ROUTE_DATA] =
        g_param_spec_variant(NM_IP_CONFIG_ROUTE_DATA,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_DOMAINS] =
        g_param_spec_variant(NM_IP_CONFIG_DOMAINS,
                             "",
                             "",
                             G_VARIANT_TYPE("as"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_SEARCHES] =
        g_param_spec_variant(NM_IP_CONFIG_SEARCHES,
                             "",
                             "",
                             G_VARIANT_TYPE("as"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_DNS_PRIORITY] =
        g_param_spec_variant(NM_IP_CONFIG_DNS_PRIORITY,
                             "",
                             "",
                             G_VARIANT_TYPE("i"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_DNS_OPTIONS] =
        g_param_spec_variant(NM_IP_CONFIG_DNS_OPTIONS,
                             "",
                             "",
                             G_VARIANT_TYPE("as"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST_ip, obj_properties_ip);
}

/*****************************************************************************/

/* public */
#define NM_IP4_CONFIG_NAMESERVER_DATA  "nameserver-data"
#define NM_IP4_CONFIG_WINS_SERVER_DATA "wins-server-data"

/* deprecated */
#define NM_IP4_CONFIG_ADDRESSES    "addresses"
#define NM_IP4_CONFIG_NAMESERVERS  "nameservers"
#define NM_IP4_CONFIG_ROUTES       "routes"
#define NM_IP4_CONFIG_WINS_SERVERS "wins-servers"

typedef struct _NMIP4Config      NMIP4Config;
typedef struct _NMIP4ConfigClass NMIP4ConfigClass;

NM_GOBJECT_PROPERTIES_DEFINE_FULL(_ip4,
                                  NMIP4Config,
                                  PROP_IP4_ADDRESSES,
                                  PROP_IP4_NAMESERVERS,
                                  PROP_IP4_NAMESERVER_DATA,
                                  PROP_IP4_ROUTES,
                                  PROP_IP4_WINS_SERVERS,
                                  PROP_IP4_WINS_SERVER_DATA, );

struct _NMIP4Config {
    NMIPConfig parent;
};

struct _NMIP4ConfigClass {
    NMIPConfigClass parent;
};

G_DEFINE_TYPE(NMIP4Config, nm_ip4_config, NM_TYPE_IP_CONFIG)

static void
get_property_ip4(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMIPConfig        *self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);
    char               addr_str[NM_INET_ADDRSTRLEN];
    GVariantBuilder    builder;
    const in_addr_t   *addrs;
    const char *const *strarr;
    guint              len;
    guint              i;

    switch (prop_id) {
    case PROP_IP4_ADDRESSES:
        g_value_set_variant(value, priv->v_addresses);
        break;
    case PROP_IP4_ROUTES:
        g_value_set_variant(value, priv->v_routes);
        break;
    case PROP_IP4_NAMESERVERS:
    case PROP_IP4_NAMESERVER_DATA:
        strarr = nm_l3_config_data_get_nameservers(priv->l3cd, AF_INET, &len);
        if (len == 0) {
            g_value_set_variant(value,
                                (prop_id == PROP_IP4_NAMESERVERS)
                                    ? nm_g_variant_singleton_au()
                                    : nm_g_variant_singleton_aaLsvI());
        } else {
            if (prop_id == PROP_IP4_NAMESERVERS)
                g_variant_builder_init(&builder, G_VARIANT_TYPE("au"));
            else
                g_variant_builder_init(&builder, G_VARIANT_TYPE("aa{sv}"));
            for (i = 0; i < len; i++) {
                in_addr_t a;

                if (!nm_utils_dnsname_parse_assert(AF_INET, strarr[i], NULL, &a, NULL))
                    continue;

                if (prop_id == PROP_IP4_NAMESERVERS)
                    g_variant_builder_add(&builder, "u", a);
                else {
                    GVariantBuilder nested_builder;

                    nm_inet4_ntop(a, addr_str);
                    g_variant_builder_init(&nested_builder, G_VARIANT_TYPE("a{sv}"));
                    g_variant_builder_add(&nested_builder,
                                          "{sv}",
                                          "address",
                                          g_variant_new_string(addr_str));
                    g_variant_builder_add(&builder, "a{sv}", &nested_builder);
                }
            }

            g_value_take_variant(value, g_variant_builder_end(&builder));
        }
        break;
    case PROP_IP4_WINS_SERVERS:
        addrs = nm_l3_config_data_get_wins(priv->l3cd, &len);
        g_value_set_variant(value,
                            (len == 0) ? nm_g_variant_singleton_au()
                                       : nm_g_variant_new_au(addrs, len));
        break;
    case PROP_IP4_WINS_SERVER_DATA:
        addrs = nm_l3_config_data_get_wins(priv->l3cd, &len);
        if (len == 0)
            g_value_set_variant(value, nm_g_variant_singleton_as());
        else {
            g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));
            for (i = 0; i < len; i++)
                g_variant_builder_add(&builder, "s", nm_inet4_ntop(addrs[i], addr_str));
            g_value_take_variant(value, g_variant_builder_end(&builder));
        }
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static const NMDBusInterfaceInfoExtended interface_info_ip4_config = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_IP4_CONFIG,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Addresses",
                                                           "aau",
                                                           NM_IP4_CONFIG_ADDRESSES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("AddressData",
                                                           "aa{sv}",
                                                           NM_IP_CONFIG_ADDRESS_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Gateway", "s", NM_IP_CONFIG_GATEWAY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Routes", "aau", NM_IP4_CONFIG_ROUTES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("RouteData",
                                                           "aa{sv}",
                                                           NM_IP_CONFIG_ROUTE_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("NameserverData",
                                                           "aa{sv}",
                                                           NM_IP4_CONFIG_NAMESERVER_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Nameservers",
                                                           "au",
                                                           NM_IP4_CONFIG_NAMESERVERS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Domains", "as", NM_IP_CONFIG_DOMAINS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Searches", "as", NM_IP_CONFIG_SEARCHES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsOptions",
                                                           "as",
                                                           NM_IP_CONFIG_DNS_OPTIONS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsPriority",
                                                           "i",
                                                           NM_IP_CONFIG_DNS_PRIORITY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("WinsServerData",
                                                           "as",
                                                           NM_IP4_CONFIG_WINS_SERVER_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("WinsServers",
                                                           "au",
                                                           NM_IP4_CONFIG_WINS_SERVERS), ), ),
};

static void
nm_ip4_config_init(NMIP4Config *self)
{}

static void
nm_ip4_config_class_init(NMIP4ConfigClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMIPConfigClass   *ip_config_class   = NM_IP_CONFIG_CLASS(klass);

    ip_config_class->addr_family = AF_INET;

    dbus_object_class->export_path     = NM_DBUS_EXPORT_PATH_NUMBERED(NM_DBUS_PATH "/IP4Config");
    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_ip4_config);

    object_class->get_property = get_property_ip4;

    obj_properties_ip4[PROP_IP4_ADDRESSES] =
        g_param_spec_variant(NM_IP4_CONFIG_ADDRESSES,
                             "",
                             "",
                             G_VARIANT_TYPE("aau"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_ROUTES] =
        g_param_spec_variant(NM_IP4_CONFIG_ROUTES,
                             "",
                             "",
                             G_VARIANT_TYPE("aau"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_NAMESERVER_DATA] =
        g_param_spec_variant(NM_IP4_CONFIG_NAMESERVER_DATA,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_NAMESERVERS] =
        g_param_spec_variant(NM_IP4_CONFIG_NAMESERVERS,
                             "",
                             "",
                             G_VARIANT_TYPE("au"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_WINS_SERVER_DATA] =
        g_param_spec_variant(NM_IP4_CONFIG_WINS_SERVER_DATA,
                             "",
                             "",
                             G_VARIANT_TYPE("as"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_WINS_SERVERS] =
        g_param_spec_variant(NM_IP4_CONFIG_WINS_SERVERS,
                             "",
                             "",
                             G_VARIANT_TYPE("au"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST_ip4, obj_properties_ip4);
}

/*****************************************************************************/

/* public */
#define NM_IP6_CONFIG_NAMESERVERS "nameservers"

/* deprecated */
#define NM_IP6_CONFIG_ADDRESSES "addresses"
#define NM_IP6_CONFIG_ROUTES    "routes"

typedef struct _NMIP6Config      NMIP6Config;
typedef struct _NMIP6ConfigClass NMIP6ConfigClass;

NM_GOBJECT_PROPERTIES_DEFINE_FULL(_ip6,
                                  NMIP6Config,
                                  PROP_IP6_NAMESERVERS,
                                  PROP_IP6_ADDRESSES,
                                  PROP_IP6_ROUTES, );

struct _NMIP6Config {
    NMIPConfig parent;
};

struct _NMIP6ConfigClass {
    NMIPConfigClass parent;
};

G_DEFINE_TYPE(NMIP6Config, nm_ip6_config, NM_TYPE_IP_CONFIG)

static const NMDBusInterfaceInfoExtended interface_info_ip6_config = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_IP6_CONFIG,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Addresses",
                                                           "a(ayuay)",
                                                           NM_IP6_CONFIG_ADDRESSES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("AddressData",
                                                           "aa{sv}",
                                                           NM_IP_CONFIG_ADDRESS_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Gateway", "s", NM_IP_CONFIG_GATEWAY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Routes",
                                                           "a(ayuayu)",
                                                           NM_IP6_CONFIG_ROUTES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("RouteData",
                                                           "aa{sv}",
                                                           NM_IP_CONFIG_ROUTE_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Nameservers",
                                                           "aay",
                                                           NM_IP6_CONFIG_NAMESERVERS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Domains", "as", NM_IP_CONFIG_DOMAINS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Searches", "as", NM_IP_CONFIG_SEARCHES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsOptions",
                                                           "as",
                                                           NM_IP_CONFIG_DNS_OPTIONS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsPriority",
                                                           "i",
                                                           NM_IP_CONFIG_DNS_PRIORITY), ), ),
};

static void
get_property_ip6(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMIPConfig        *self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);
    GVariantBuilder    builder;
    guint              len;
    guint              i;
    const char *const *strarr;

    switch (prop_id) {
    case PROP_IP6_ADDRESSES:
        g_value_set_variant(value, priv->v_addresses);
        break;
    case PROP_IP6_ROUTES:
        g_value_set_variant(value, priv->v_routes);
        break;
    case PROP_IP6_NAMESERVERS:
        strarr = nm_l3_config_data_get_nameservers(priv->l3cd, AF_INET6, &len);
        if (len == 0)
            g_value_set_variant(value, nm_g_variant_singleton_aay());
        else {
            g_variant_builder_init(&builder, G_VARIANT_TYPE("aay"));
            for (i = 0; i < len; i++) {
                struct in6_addr a;

                if (!nm_utils_dnsname_parse_assert(AF_INET6, strarr[i], NULL, &a, NULL))
                    continue;

                g_variant_builder_add(&builder, "@ay", nm_g_variant_new_ay_in6addr(&a));
            }
            g_value_take_variant(value, g_variant_builder_end(&builder));
        }
        break;

    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_ip6_config_init(NMIP6Config *self)
{}

static void
nm_ip6_config_class_init(NMIP6ConfigClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMIPConfigClass   *ip_config_class   = NM_IP_CONFIG_CLASS(klass);

    ip_config_class->addr_family = AF_INET6;

    dbus_object_class->export_path     = NM_DBUS_EXPORT_PATH_NUMBERED(NM_DBUS_PATH "/IP6Config");
    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_ip6_config);

    object_class->get_property = get_property_ip6;

    obj_properties_ip6[PROP_IP6_ADDRESSES] =
        g_param_spec_variant(NM_IP6_CONFIG_ADDRESSES,
                             "",
                             "",
                             G_VARIANT_TYPE("a(ayuay)"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_ROUTES] =
        g_param_spec_variant(NM_IP6_CONFIG_ROUTES,
                             "",
                             "",
                             G_VARIANT_TYPE("a(ayuayu)"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_NAMESERVERS] =
        g_param_spec_variant(NM_IP6_CONFIG_NAMESERVERS,
                             "",
                             "",
                             G_VARIANT_TYPE("aay"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST_ip6, obj_properties_ip6);
}

/*****************************************************************************/

#define _notify_all(self, changed_params, n_changed_params)                     \
    G_STMT_START                                                                \
    {                                                                           \
        NMIPConfig *const        _self             = (self);                    \
        const guint              _n_changed_params = (n_changed_params);        \
        GParamSpec *const *const _changed_params   = (changed_params);          \
        guint                    _i;                                            \
                                                                                \
        if (_n_changed_params > 0) {                                            \
            nm_assert(_n_changed_params <= G_N_ELEMENTS(changed_params));       \
            if (_n_changed_params > 1)                                          \
                g_object_freeze_notify(G_OBJECT(_self));                        \
            for (_i = 0; _i < _n_changed_params; _i++)                          \
                g_object_notify_by_pspec(G_OBJECT(_self), _changed_params[_i]); \
            if (_n_changed_params > 1)                                          \
                g_object_thaw_notify(G_OBJECT(_self));                          \
        }                                                                       \
    }                                                                           \
    G_STMT_END

static void
_handle_l3cd_changed(NMIPConfig *self, const NML3ConfigData *l3cd)
{
    const int                                addr_family = nm_ip_config_get_addr_family(self);
    const int                                IS_IPv4     = NM_IS_IPv4(addr_family);
    NMIPConfigPrivate                       *priv        = NM_IP_CONFIG_GET_PRIVATE(self);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old    = NULL;
    GParamSpec                              *changed_params[8];
    guint                                    n_changed_params = 0;
    const char *const                       *strarr;
    const char *const                       *strarr_old;
    gconstpointer                            addrs;
    gconstpointer                            addrs_old;
    guint                                    len;
    guint                                    len_old;
    int                                      v_i;
    int                                      v_i_old;

    l3cd_old   = g_steal_pointer(&priv->l3cd);
    priv->l3cd = nm_l3_config_data_ref(l3cd);

    strarr_old = nm_l3_config_data_get_nameservers(l3cd_old, addr_family, &len_old);
    strarr     = nm_l3_config_data_get_nameservers(priv->l3cd, addr_family, &len);
    if (!nm_strv_equal_n(strarr_old, len_old, strarr, len)) {
        if (IS_IPv4) {
            changed_params[n_changed_params++] = obj_properties_ip4[PROP_IP4_NAMESERVER_DATA];
            changed_params[n_changed_params++] = obj_properties_ip4[PROP_IP4_NAMESERVERS];
        } else
            changed_params[n_changed_params++] = obj_properties_ip6[PROP_IP6_NAMESERVERS];
    }

    strarr_old = nm_l3_config_data_get_domains(l3cd_old, addr_family, &len_old);
    strarr     = nm_l3_config_data_get_domains(priv->l3cd, addr_family, &len);
    if (!nm_strv_equal_n(strarr, len, strarr_old, len_old))
        changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_DOMAINS];

    strarr_old = nm_l3_config_data_get_searches(l3cd_old, addr_family, &len_old);
    strarr     = nm_l3_config_data_get_searches(priv->l3cd, addr_family, &len);
    if (!nm_strv_equal_n(strarr, len, strarr_old, len_old))
        changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_SEARCHES];

    v_i_old = nm_l3_config_data_get_dns_priority_or_default(l3cd_old, addr_family);
    v_i     = nm_l3_config_data_get_dns_priority_or_default(priv->l3cd, addr_family);
    if (v_i != v_i_old)
        changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_DNS_PRIORITY];

    strarr_old = nm_l3_config_data_get_dns_options(l3cd_old, addr_family, &len);
    strarr     = nm_l3_config_data_get_dns_options(priv->l3cd, addr_family, &len);
    if (!nm_strv_equal_n(strarr, len, strarr_old, len_old))
        changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_DNS_OPTIONS];

    if (IS_IPv4) {
        addrs_old = nm_l3_config_data_get_wins(l3cd_old, &len_old);
        addrs     = nm_l3_config_data_get_wins(priv->l3cd, &len);
        if (!nm_memeq_n(addrs_old, len_old, addrs, len, sizeof(in_addr_t))) {
            changed_params[n_changed_params++] = obj_properties_ip4[PROP_IP4_WINS_SERVER_DATA];
            changed_params[n_changed_params++] = obj_properties_ip4[PROP_IP4_WINS_SERVERS];
        }
    }

    _notify_all(self, changed_params, n_changed_params);
}

static void
_handle_platform_change(NMIPConfig *self, guint32 obj_type_flags, gboolean is_init)
{
    const int                    addr_family = nm_ip_config_get_addr_family(self);
    const int                    IS_IPv4     = NM_IS_IPv4(addr_family);
    NMIPConfigPrivate           *priv        = NM_IP_CONFIG_GET_PRIVATE(self);
    GParamSpec                  *changed_params[5];
    guint                        n_changed_params           = 0;
    const NMDedupMultiHeadEntry *head_entry_routes          = NULL;
    gboolean                     best_default_route_changed = FALSE;

    if (NM_FLAGS_ANY(obj_type_flags,
                     (nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4))
                      | nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4))))) {
        const NMPObject *best_default_route = NULL;

        head_entry_routes = nm_platform_lookup_object(nm_l3cfg_get_platform(priv->l3cfg),
                                                      NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4),
                                                      nm_l3cfg_get_ifindex(priv->l3cfg));
        if (head_entry_routes) {
            NMDedupMultiIter iter;
            const NMPObject *obj;

            nm_dedup_multi_iter_init(&iter, head_entry_routes);
            while (nm_platform_dedup_multi_iter_next_obj(&iter,
                                                         &obj,
                                                         NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4))) {
                const NMPlatformIPXRoute *r = NMP_OBJECT_CAST_IPX_ROUTE(obj);

                /* Determine the gateway. That is the next hop of a route
                 *  - 0.0.0.0/0 or ::/0
                 *  - type=unicast
                 *  - table=main
                 */
                if (r->rx.plen != 0
                    || r->rx.type_coerced != nm_platform_route_type_coerce(RTN_UNICAST)
                    || r->rx.table_coerced != nm_platform_route_table_coerce(RT_TABLE_MAIN)
                    || !nm_ip_addr_is_null(addr_family, r->rx.network_ptr))
                    continue;

                if (!best_default_route
                    || NMP_OBJECT_CAST_IP_ROUTE(best_default_route)->metric > r->rx.metric)
                    best_default_route = obj;
            }
        }

        if (priv->v_gateway.best_default_route != best_default_route) {
            if (!nm_ip_addr_equal(
                    addr_family,
                    nm_platform_ip_route_get_gateway(
                        addr_family,
                        NMP_OBJECT_CAST_IP_ROUTE(priv->v_gateway.best_default_route)),
                    nm_platform_ip_route_get_gateway(addr_family,
                                                     NMP_OBJECT_CAST_IP_ROUTE(best_default_route))))
                best_default_route_changed = TRUE;

            nmp_object_ref_set(&priv->v_gateway.best_default_route, best_default_route);
        }
    }

    if (best_default_route_changed
        || NM_FLAGS_ANY(obj_type_flags,
                        nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)))) {
        gs_unref_variant GVariant *x_address_data = NULL;
        gs_unref_variant GVariant *x_addresses    = NULL;

        nm_utils_ip_addresses_to_dbus(addr_family,
                                      nm_platform_lookup_object(nm_l3cfg_get_platform(priv->l3cfg),
                                                                NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4),
                                                                nm_l3cfg_get_ifindex(priv->l3cfg)),
                                      priv->v_gateway.best_default_route,
                                      &x_address_data,
                                      &x_addresses);

        if (!nm_g_variant_equal(priv->v_address_data, x_address_data)) {
            changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_ADDRESS_DATA];
            g_variant_ref_sink(x_address_data);
            NM_SWAP(&priv->v_address_data, &x_address_data);
        }
        if (!nm_g_variant_equal(priv->v_addresses, x_addresses)) {
            changed_params[n_changed_params++] = IS_IPv4 ? obj_properties_ip4[PROP_IP4_ADDRESSES]
                                                         : obj_properties_ip6[PROP_IP6_ADDRESSES];
            g_variant_ref_sink(x_addresses);
            NM_SWAP(&priv->v_addresses, &x_addresses);
        }
    }

    if (best_default_route_changed)
        changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_GATEWAY];

    if (NM_FLAGS_ANY(obj_type_flags, nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)))) {
        gs_unref_variant GVariant *x_route_data = NULL;
        gs_unref_variant GVariant *x_routes     = NULL;

        nm_utils_ip_routes_to_dbus(addr_family, head_entry_routes, &x_route_data, &x_routes);

        if (!nm_g_variant_equal(priv->v_route_data, x_route_data)) {
            changed_params[n_changed_params++] = obj_properties_ip[PROP_IP_ROUTE_DATA];
            g_variant_ref_sink(x_route_data);
            NM_SWAP(&priv->v_route_data, &x_route_data);
        }
        if (!nm_g_variant_equal(priv->v_routes, x_routes)) {
            changed_params[n_changed_params++] =
                IS_IPv4 ? obj_properties_ip4[PROP_IP4_ROUTES] : obj_properties_ip6[PROP_IP6_ROUTES];
            g_variant_ref_sink(x_routes);
            NM_SWAP(&priv->v_routes, &x_routes);
        }
    }

    if (!is_init)
        _notify_all(self, changed_params, n_changed_params);
}
