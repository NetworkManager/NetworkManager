/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ip-config.h"

#include "nm-l3cfg.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

GType nm_ip4_config_get_type(void);
GType nm_ip6_config_get_type(void);

/*****************************************************************************/

#define NM_IP_CONFIG_ADDRESS_DATA "address-data"
#define NM_IP_CONFIG_ROUTE_DATA   "route-data"

/*****************************************************************************/

typedef struct _NMIPConfigPrivate NMIPConfigPrivate;

NM_GOBJECT_PROPERTIES_DEFINE_FULL(_ip,
                                  NMIPConfig,
                                  PROP_IP_L3CFG,
                                  PROP_IP_IS_VPN,
                                  PROP_IP_ADDRESS_DATA,
                                  PROP_IP_ROUTE_DATA, );

G_DEFINE_ABSTRACT_TYPE(NMIPConfig, nm_ip_config, NM_TYPE_DBUS_OBJECT)

#define NM_IP_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMIPConfig, NM_IS_IP_CONFIG)

/*****************************************************************************/

static void _handle_platform_change(NMIPConfig *self, guint32 obj_type_flags);

/*****************************************************************************/

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMIPConfig *self)
{
    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE) {
        _handle_platform_change(self, notify_data->platform_change_on_idle.obj_type_flags);
        return;
    }
}

/*****************************************************************************/

static void
get_property_ip(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_IP_ADDRESS_DATA:
        g_value_set_variant(value, priv->v_address_data);
        break;
    case PROP_IP_ROUTE_DATA:
        g_value_set_variant(value, priv->v_route_data);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);
    gpointer           ptr;

    switch (prop_id) {
    case PROP_IP_L3CFG:
        /* construct-only */
        ptr = g_value_get_pointer(value);
        nm_assert(NM_IS_L3CFG(ptr));
        priv->l3cfg = g_object_ref(ptr);
        break;
    case PROP_IP_IS_VPN:
        /* construct-only */
        priv->is_vpn = g_value_get_boolean(value);
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
nm_ip_config_new(int addr_family, NML3Cfg *l3cfg, gboolean is_vpn)
{
    nm_assert_addr_family(addr_family);
    nm_assert(NM_L3CFG(l3cfg));

    return g_object_new(NM_IS_IPv4(addr_family) ? nm_ip4_config_get_type()
                                                : nm_ip6_config_get_type(),
                        NM_IP_CONFIG_L3CFG,
                        l3cfg,
                        NM_IP_CONFIG_IS_VPN,
                        is_vpn,
                        NULL);
}

static void
constructed(GObject *object)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    priv->l3cfg_notify_id =
        g_signal_connect(priv->l3cfg, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self);

    _handle_platform_change(self, ~((guint32) 0u));

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
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    nm_clear_g_signal_handler(priv->l3cfg, &priv->l3cfg_notify_id);

    g_object_unref(priv->l3cfg);

    nm_g_variant_unref(priv->v_address_data);
    nm_g_variant_unref(priv->v_addresses);
    nm_g_variant_unref(priv->v_route_data);
    nm_g_variant_unref(priv->v_routes);

    G_OBJECT_CLASS(nm_ip_config_parent_class)->finalize(object);
}

static void
nm_ip_config_class_init(NMIPConfigClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
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

    obj_properties_ip[PROP_IP_IS_VPN] =
        g_param_spec_boolean(NM_IP_CONFIG_IS_VPN,
                             "",
                             "",
                             FALSE,
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties_ip[PROP_IP_ADDRESS_DATA] =
        g_param_spec_variant(NM_IP_CONFIG_ADDRESS_DATA,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip[PROP_IP_ROUTE_DATA] =
        g_param_spec_variant(NM_IP_CONFIG_ROUTE_DATA,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST_ip, obj_properties_ip);
}

/*****************************************************************************/

/* public*/
#define NM_IP4_CONFIG_DNS_OPTIONS      "dns-options"
#define NM_IP4_CONFIG_DNS_PRIORITY     "dns-priority"
#define NM_IP4_CONFIG_DOMAINS          "domains"
#define NM_IP4_CONFIG_GATEWAY          "gateway"
#define NM_IP4_CONFIG_NAMESERVER_DATA  "nameserver-data"
#define NM_IP4_CONFIG_SEARCHES         "searches"
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
                                  PROP_IP4_DNS_OPTIONS,
                                  PROP_IP4_DNS_PRIORITY,
                                  PROP_IP4_DOMAINS,
                                  PROP_IP4_GATEWAY,
                                  PROP_IP4_NAMESERVERS,
                                  PROP_IP4_NAMESERVER_DATA,
                                  PROP_IP4_ROUTES,
                                  PROP_IP4_SEARCHES,
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
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_IP4_ADDRESSES:
        g_value_set_variant(value, priv->v_addresses);
        break;
    case PROP_IP4_ROUTES:
        g_value_set_variant(value, priv->v_routes);
        break;
    default:
        return;  //XXX
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
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Gateway", "s", NM_IP4_CONFIG_GATEWAY),
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
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Domains", "as", NM_IP4_CONFIG_DOMAINS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Searches",
                                                           "as",
                                                           NM_IP4_CONFIG_SEARCHES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsOptions",
                                                           "as",
                                                           NM_IP4_CONFIG_DNS_OPTIONS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsPriority",
                                                           "i",
                                                           NM_IP4_CONFIG_DNS_PRIORITY),
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
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMIPConfigClass *  ip_config_class   = NM_IP_CONFIG_CLASS(klass);

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
    obj_properties_ip4[PROP_IP4_GATEWAY] =
        g_param_spec_string(NM_IP4_CONFIG_GATEWAY,
                            "",
                            "",
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
    obj_properties_ip4[PROP_IP4_DOMAINS] =
        g_param_spec_boxed(NM_IP4_CONFIG_DOMAINS,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_SEARCHES] =
        g_param_spec_boxed(NM_IP4_CONFIG_SEARCHES,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_DNS_OPTIONS] =
        g_param_spec_boxed(NM_IP4_CONFIG_DNS_OPTIONS,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip4[PROP_IP4_DNS_PRIORITY] =
        g_param_spec_int(NM_IP4_CONFIG_DNS_PRIORITY,
                         "",
                         "",
                         G_MININT32,
                         G_MAXINT32,
                         0,
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
#define NM_IP6_CONFIG_GATEWAY      "gateway"
#define NM_IP6_CONFIG_NAMESERVERS  "nameservers"
#define NM_IP6_CONFIG_DOMAINS      "domains"
#define NM_IP6_CONFIG_SEARCHES     "searches"
#define NM_IP6_CONFIG_DNS_OPTIONS  "dns-options"
#define NM_IP6_CONFIG_DNS_PRIORITY "dns-priority"

/* deprecated */
#define NM_IP6_CONFIG_ADDRESSES "addresses"
#define NM_IP6_CONFIG_ROUTES    "routes"

typedef struct _NMIP6Config      NMIP6Config;
typedef struct _NMIP6ConfigClass NMIP6ConfigClass;

NM_GOBJECT_PROPERTIES_DEFINE_FULL(_ip6,
                                  NMIP6Config,
                                  PROP_IP6_GATEWAY,
                                  PROP_IP6_NAMESERVERS,
                                  PROP_IP6_DOMAINS,
                                  PROP_IP6_SEARCHES,
                                  PROP_IP6_DNS_OPTIONS,
                                  PROP_IP6_DNS_PRIORITY,
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
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Gateway", "s", NM_IP6_CONFIG_GATEWAY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Routes",
                                                           "a(ayuayu)",
                                                           NM_IP6_CONFIG_ROUTES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("RouteData",
                                                           "aa{sv}",
                                                           NM_IP_CONFIG_ROUTE_DATA),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Nameservers",
                                                           "aay",
                                                           NM_IP6_CONFIG_NAMESERVERS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Domains", "as", NM_IP6_CONFIG_DOMAINS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Searches",
                                                           "as",
                                                           NM_IP6_CONFIG_SEARCHES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsOptions",
                                                           "as",
                                                           NM_IP6_CONFIG_DNS_OPTIONS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DnsPriority",
                                                           "i",
                                                           NM_IP6_CONFIG_DNS_PRIORITY), ), ),
};

static void
get_property_ip6(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMIPConfig *       self = NM_IP_CONFIG(object);
    NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_IP6_ADDRESSES:
        g_value_set_variant(value, priv->v_addresses);
        break;
    case PROP_IP6_ROUTES:
        g_value_set_variant(value, priv->v_routes);
        break;
    default:
        return;  //XXX
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
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMIPConfigClass *  ip_config_class   = NM_IP_CONFIG_CLASS(klass);

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
    obj_properties_ip6[PROP_IP6_GATEWAY] =
        g_param_spec_string(NM_IP6_CONFIG_GATEWAY,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_NAMESERVERS] =
        g_param_spec_variant(NM_IP6_CONFIG_NAMESERVERS,
                             "",
                             "",
                             G_VARIANT_TYPE("aay"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_DOMAINS] =
        g_param_spec_boxed(NM_IP6_CONFIG_DOMAINS,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_SEARCHES] =
        g_param_spec_boxed(NM_IP6_CONFIG_SEARCHES,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_DNS_OPTIONS] =
        g_param_spec_boxed(NM_IP6_CONFIG_DNS_OPTIONS,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties_ip6[PROP_IP6_DNS_PRIORITY] =
        g_param_spec_int(NM_IP6_CONFIG_DNS_PRIORITY,
                         "",
                         "",
                         G_MININT32,
                         G_MAXINT32,
                         0,
                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST_ip6, obj_properties_ip6);
}

/*****************************************************************************/

static void
_handle_platform_change(NMIPConfig *self, guint32 obj_type_flags)
{
    const int          addr_family = nm_ip_config_get_addr_family(self);
    const int          IS_IPv4     = NM_IS_IPv4(addr_family);
    NMIPConfigPrivate *priv        = NM_IP_CONFIG_GET_PRIVATE(self);
    GParamSpec *       changed_params[4];
    guint              n_changed_params = 0;
    guint              i;

    if (NM_FLAGS_ANY(obj_type_flags,
                     nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)))) {
        gs_unref_variant GVariant *x_address_data = NULL;
        gs_unref_variant GVariant *x_addresses    = NULL;

        nm_utils_ip_addresses_to_dbus(
            addr_family,
            nm_platform_lookup_object(nm_l3cfg_get_platform(priv->l3cfg),
                                      NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4),
                                      nm_l3cfg_get_ifindex(priv->l3cfg)),
            //XXX: use the proper gateway. The one which is also set to as NM_IP4_CONFIG_GATEWAY.
            //The problem is, what *is* the proper gateway anyway?
            nm_l3cfg_get_best_default_route(priv->l3cfg, addr_family, FALSE),
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
    if (NM_FLAGS_ANY(obj_type_flags, nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)))) {
        gs_unref_variant GVariant *x_route_data = NULL;
        gs_unref_variant GVariant *x_routes     = NULL;

        nm_utils_ip_routes_to_dbus(addr_family,
                                   nm_platform_lookup_object(nm_l3cfg_get_platform(priv->l3cfg),
                                                             NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4),
                                                             nm_l3cfg_get_ifindex(priv->l3cfg)),
                                   &x_route_data,
                                   &x_routes);

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

    if (n_changed_params > 0) {
        nm_assert(n_changed_params <= G_N_ELEMENTS(changed_params));
        g_object_freeze_notify(G_OBJECT(self));
        for (i = 0; i < n_changed_params; i++)
            g_object_notify_by_pspec(G_OBJECT(self), changed_params[i]);
        g_object_thaw_notify(G_OBJECT(self));
    }
}
