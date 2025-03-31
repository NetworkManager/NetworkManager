/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dns-dnsconfd.h"

#include "libnm-glib-aux/nm-dbus-aux.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-l3-config-data.h"
#include "nm-manager.h"
#include "devices/nm-device.h"
#include "nm-active-connection.h"
#include "nm-l3cfg.h"

typedef enum {
    DNSCONFD_PLUGIN_IDLE             = 0,
    DNSCONFD_PLUGIN_WAIT_CONNECT     = 1,
    DNSCONFD_PLUGIN_WAIT_UPDATE_DONE = 2,
    DNSCONFD_PLUGIN_WAIT_SERIAL      = 3
} DnsconfdPluginState;

typedef struct {
    GDBusConnection *dbus_connection;
    GCancellable    *update_cancellable;
    char            *name_owner;
    guint            name_owner_changed_id;
    GCancellable    *name_owner_cancellable;
    bool             was_start_tried;
    GCancellable    *start_cancellable;
    GVariant        *latest_update_args;

    guint         awaited_configuration_serial;
    guint         present_configuration_serial;
    guint         properties_changed_id;
    GCancellable *serial_cancellable;

    DnsconfdPluginState plugin_state;
} NMDnsDnsconfdPrivate;

struct _NMDnsDnsconfd {
    NMDnsPlugin          parent;
    NMDnsDnsconfdPrivate _priv;
};

struct _NMDnsDnsconfdClass {
    NMDnsPluginClass parent;
};

G_DEFINE_TYPE(NMDnsDnsconfd, nm_dns_dnsconfd, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSCONFD_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDnsDnsconfd, NM_IS_DNS_DNSCONFD, NMDnsPlugin)

#define _NMLOG_DOMAIN      LOGD_DNS
#define _NMLOG(level, ...) __NMLOG_DEFAULT(level, _NMLOG_DOMAIN, "dnsconfd", __VA_ARGS__)

#define DNSCONFD_DBUS_SERVICE "com.redhat.dnsconfd"

typedef enum {
    CONNECTION_FAIL,
    CONNECTION_SUCCESS,
    CONNECTION_WAIT,
} ConnectionState;

/*****************************************************************************/

static void
dnsconfd_change_plugin_state(NMDnsDnsconfd *self, DnsconfdPluginState new_state)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    priv->plugin_state = new_state;
    _nm_dns_plugin_update_pending_maybe_changed(NM_DNS_PLUGIN(self));
}

static void
dnsconfd_serial_changed(NMDnsDnsconfd *self, guint new_serial)
{
    NMDnsDnsconfdPrivate *priv         = NM_DNS_DNSCONFD_GET_PRIVATE(self);
    priv->present_configuration_serial = new_serial;
    if (priv->plugin_state == DNSCONFD_PLUGIN_WAIT_SERIAL
        && priv->awaited_configuration_serial == new_serial) {
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_IDLE);
        /* Update finished, serials match */
        _LOGT("serials match, update finished");
    }
}

static void
dnsconfd_properties_changed(GDBusConnection *connection,
                            const char      *sender_name,
                            const char      *object_path,
                            const char      *interface_name,
                            const char      *signal_name,
                            GVariant        *parameters,
                            gpointer         user_data)
{
    NMDnsDnsconfd             *self               = user_data;
    gs_unref_variant GVariant *updated_properties = NULL;
    guint                      new_serial;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sa{sv}as)"))) {
        _LOGW("received properties changed signal but the type is wrong");
        return;
    }

    g_variant_get(parameters, "(&s@a{sv}as)", NULL, &updated_properties, NULL);

    if (!g_variant_lookup(updated_properties, "configuration_serial", "u", &new_serial)) {
        _LOGT("properties changed but they do not contain new serial");
        return;
    }
    _LOGT("properties changed and contain new serial %u", new_serial);

    dnsconfd_serial_changed(self, new_serial);
}

static void
dnsconfd_serial_retrieval_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    NMDnsDnsconfd             *self;
    NMDnsDnsconfdPrivate      *priv;
    gs_free_error GError      *error              = NULL;
    gs_unref_variant GVariant *response           = NULL;
    gs_unref_variant GVariant *new_serial_variant = NULL;
    guint                      new_serial;

    response = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source_object), res, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    if (!response) {
        _LOGW("dnsconfd serial retrieval failed: %s", error->message);
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_IDLE);
        return;
    }

    nm_clear_g_cancellable(&priv->serial_cancellable);

    g_variant_get(response, "(v)", &new_serial_variant);

    g_variant_get(new_serial_variant, "u", &new_serial);

    _LOGT("serial retrieval done %u", new_serial);

    dnsconfd_serial_changed(self, new_serial);
}

static gboolean
subscribe_serial(NMDnsDnsconfd *self)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    priv->properties_changed_id =
        g_dbus_connection_signal_subscribe(priv->dbus_connection,
                                           priv->name_owner,
                                           "org.freedesktop.DBus.Properties",
                                           "PropertiesChanged",
                                           "/com/redhat/dnsconfd",
                                           "com.redhat.dnsconfd.Manager",
                                           G_DBUS_SIGNAL_FLAGS_NONE,
                                           dnsconfd_properties_changed,
                                           self,
                                           NULL);
    if (!priv->properties_changed_id) {
        return FALSE;
    }

    nm_clear_g_cancellable(&priv->serial_cancellable);

    g_dbus_connection_call(
        priv->dbus_connection,
        priv->name_owner,
        "/com/redhat/dnsconfd",
        "org.freedesktop.DBus.Properties",
        "Get",
        g_variant_new("(ss)", "com.redhat.dnsconfd.Manager", "configuration_serial"),
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        priv->serial_cancellable,
        dnsconfd_serial_retrieval_done,
        self);
    return TRUE;
}

static void
dnsconfd_update_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    NMDnsDnsconfd             *self;
    NMDnsDnsconfdPrivate      *priv;
    gs_free_error GError      *error    = NULL;
    gs_unref_variant GVariant *response = NULL;
    guint                      awaited_serial;
    char                      *dnsconfd_message;

    response = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source_object), res, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    nm_clear_g_cancellable(&priv->update_cancellable);

    if (!response) {
        _LOGW("dnsconfd update failed: %s", error->message);
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_IDLE);
        return;
    }

    /* By using &s we will get pointer to char data contained
     * in variant and thus no freing of dnsconfd_message is required */
    g_variant_get(response, "(u&s)", &awaited_serial, &dnsconfd_message);

    if (!awaited_serial) {
        _LOGW("dnsconfd refused update: %s", dnsconfd_message);
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_IDLE);
        return;
    }

    priv->awaited_configuration_serial = awaited_serial;
    _LOGT("dnsconfd accepted update, awaited serial is %u", awaited_serial);

    if (priv->awaited_configuration_serial == priv->present_configuration_serial) {
        /* Serials match, update finished */
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_IDLE);
        _LOGT("after update serials match");
    } else {
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_WAIT_SERIAL);
        _LOGT("after update serials don't match, waiting");
    }
}

static gboolean
is_default_interface_explicit(const CList *ip_data_lst_head)
{
    guint              n_domains;
    const char *const *strv_domains;
    NMDnsConfigIPData *ip_data;
    gboolean           is_routing;

    /* If there is "~." specified in any connection's active ipvX.search setting then default
     * interface is explicit */

    c_list_for_each_entry (ip_data, ip_data_lst_head, ip_data_lst) {
        strv_domains =
            nm_l3_config_data_get_searches(ip_data->l3cd, ip_data->addr_family, &n_domains);
        for (guint i = 0; i < n_domains; i++) {
            if (nm_streq(nm_utils_parse_dns_domain(strv_domains[i], &is_routing), ".")) {
                return TRUE;
            }
        }
    }
    /* AFAIK it should not be passible to pass "." through DHCP and thus we will check only
     * searches */
    return FALSE;
}

static void
gather_interface_domains(NMDnsConfigIPData *ip_data,
                         gboolean           is_default_explicit,
                         const char      ***routing_domains,
                         const char      ***search_domains)
{
    guint              n_domains;
    const char *const *strv_domains;
    gboolean           is_routing;
    const char        *cur_domain;
    GPtrArray         *routing_ptr_array = g_ptr_array_sized_new(5);
    GPtrArray         *search_ptr_array  = g_ptr_array_sized_new(5);

    /* Searches have higher priority than domains (dynamically retrieved) */
    strv_domains = nm_l3_config_data_get_searches(ip_data->l3cd, ip_data->addr_family, &n_domains);
    if (!n_domains) {
        strv_domains =
            nm_l3_config_data_get_domains(ip_data->l3cd, ip_data->addr_family, &n_domains);
    }

    for (int i = 0; i < n_domains; i++) {
        cur_domain = nm_utils_parse_dns_domain(strv_domains[i], &is_routing);
        g_ptr_array_add(routing_ptr_array, (char *) cur_domain);
        if (!is_routing) {
            g_ptr_array_add(search_ptr_array, (char *) cur_domain);
        }
    }

    /* If there has been specified search like "~." then we will not be adding "." and respect
     * users wishes */
    if (!is_default_explicit
        && nm_l3_config_data_get_best_default_route(ip_data->l3cd, ip_data->addr_family)) {
        g_ptr_array_add(routing_ptr_array, ".");
    }
    g_ptr_array_add(routing_ptr_array, NULL);
    g_ptr_array_add(search_ptr_array, NULL);

    /* When array would be empty we will simply return NULL */
    *routing_domains =
        (const char **) g_ptr_array_free(routing_ptr_array, (routing_ptr_array->len == 1));
    *search_domains =
        (const char **) g_ptr_array_free(search_ptr_array, (search_ptr_array->len == 1));
}

static void
get_networks(NMDnsConfigIPData *ip_data, char ***networks)
{
    NMDedupMultiIter ipconf_iter;
    const NMPObject *obj;
    char             s_address[INET6_ADDRSTRLEN];
    /* +4 because INET6_ADDRSTRLEN already contains byte for end of string and we need 4 bytes
     * to store max 3 characters of mask and slash (/128 for example) */
    char                     network_buffer[INET6_ADDRSTRLEN + 4];
    const NMPlatformIPRoute *route;
    GPtrArray               *ptr_array   = g_ptr_array_sized_new(5);
    int                      addr_family = ip_data->addr_family;
    guint                    IS_IPv4     = NM_IS_IPv4(addr_family);

    nm_l3_config_data_iter_obj_for_each (&ipconf_iter,
                                         ip_data->l3cd,
                                         &obj,
                                         NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
        route = NMP_OBJECT_CAST_IP_ROUTE(obj);
        if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route)
            || route->table_coerced == NM_DNS_ROUTES_FWMARK_TABLE_PRIO) {
            continue;
        }
        nm_inet_ntop(addr_family, route->network_ptr, s_address);
        nm_sprintf_buf(network_buffer, "%s/%u", s_address, route->plen);
        g_ptr_array_add(ptr_array, g_strdup(network_buffer));
    }

    g_ptr_array_add(ptr_array, NULL);
    /* If array would be empty then return NULL */
    *networks = (char **) g_ptr_array_free(ptr_array, ptr_array->len == 1);
}

static void
server_builder_append_interface_info(GVariantBuilder *argument_builder,
                                     const char      *interface,
                                     char           **networks)
{
    if (interface) {
        g_variant_builder_add(argument_builder, "{sv}", "interface", g_variant_new("s", interface));
    }
    if (networks) {
        g_variant_builder_add(argument_builder,
                              "{sv}",
                              "networks",
                              g_variant_new_strv((const char *const *) networks, -1));
    }
    g_variant_builder_close(argument_builder);
}

static gboolean
server_builder_append_base(GVariantBuilder   *argument_builder,
                           int                address_family,
                           const char        *address_string,
                           const char *const *routing_domains,
                           const char *const *search_domains,
                           const char        *ca)
{
    NMDnsServer dns_server;
    gsize       addr_size;

    if (!nm_dns_uri_parse(address_family, address_string, &dns_server))
        return FALSE;
    addr_size = nm_utils_addr_family_to_size(dns_server.addr_family);

    g_variant_builder_open(argument_builder, G_VARIANT_TYPE("a{sv}"));

    /* No freeing needed in this section as builder takes ownership of all data */

    g_variant_builder_add(argument_builder,
                          "{sv}",
                          "address",
                          nm_g_variant_new_ay((gconstpointer) &dns_server.addr, addr_size));
    if (dns_server.scheme == NM_DNS_URI_SCHEME_TLS)
        g_variant_builder_add(argument_builder, "{sv}", "protocol", g_variant_new("s", "dns+tls"));
    if (dns_server.servername)
        g_variant_builder_add(argument_builder,
                              "{sv}",
                              "name",
                              g_variant_new("s", dns_server.servername));
    if (routing_domains) {
        g_variant_builder_add(argument_builder,
                              "{sv}",
                              "routing_domains",
                              g_variant_new_strv(routing_domains, -1));
    }
    if (search_domains) {
        g_variant_builder_add(argument_builder,
                              "{sv}",
                              "search_domains",
                              g_variant_new_strv(search_domains, -1));
    }
    if (ca) {
        g_variant_builder_add(argument_builder, "{sv}", "ca", g_variant_new("s", ca));
    }
    return TRUE;
}

static void
parse_global_config(const NMGlobalDnsConfig *global_config,
                    GVariantBuilder         *argument_builder,
                    guint                   *resolve_mode,
                    const char             **ca)
{
    NMGlobalDnsDomain *domain;
    const char *const *servers;
    const char        *name;
    const char        *routing_domains[2] = {0};
    const char *const *searches           = nm_global_dns_config_get_searches(global_config);
    guint              num_domains        = nm_global_dns_config_get_num_domains(global_config);
    /* CA can be specified only in global config, but if it is, then we must set it for
     * all servers the same, because we do not support multiple certification authorities
     * (backend limitation) */
    *ca           = nm_global_dns_config_get_certification_authority(global_config);
    *resolve_mode = nm_global_dns_config_get_resolve_mode(global_config);

    for (guint i = 0; i < num_domains; i++) {
        domain  = nm_global_dns_config_get_domain(global_config, i);
        servers = nm_global_dns_domain_get_servers(domain);
        if (!servers) {
            continue;
        }
        name               = nm_global_dns_domain_get_name(domain);
        routing_domains[0] = nm_streq(name, "*") ? "." : name;

        for (gsize j = 0; servers[j]; j++) {
            if (server_builder_append_base(argument_builder,
                                           AF_UNSPEC,
                                           servers[j],
                                           routing_domains,
                                           searches,
                                           *ca)) {
                g_variant_builder_close(argument_builder);
            }
        }
    }
}

static void
send_dnsconfd_update(NMDnsDnsconfd *self)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    nm_clear_g_cancellable(&priv->update_cancellable);
    priv->update_cancellable = g_cancellable_new();

    g_dbus_connection_call(priv->dbus_connection,
                           priv->name_owner,
                           "/com/redhat/dnsconfd",
                           "com.redhat.dnsconfd.Manager",
                           "Update",
                           priv->latest_update_args,
                           NULL,
                           G_DBUS_CALL_FLAGS_NONE,
                           20000,
                           priv->update_cancellable,
                           dnsconfd_update_done,
                           self);
}

static void
name_owner_changed(NMDnsDnsconfd *self, const char *name_owner)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    name_owner = nm_str_not_empty(name_owner);

    if (nm_streq0(priv->name_owner, name_owner))
        return;

    g_free(priv->name_owner);
    priv->name_owner = g_strdup(name_owner);

    if (!name_owner) {
        _LOGD("D-Bus name for dnsconfd disappeared");
        if (priv->plugin_state == DNSCONFD_PLUGIN_WAIT_UPDATE_DONE
            || priv->plugin_state == DNSCONFD_PLUGIN_WAIT_SERIAL) {
            /* We were waiting for either serial or confirmation of update and name
             * disappeared, thus we need to retransmit */
            dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_WAIT_CONNECT);
        }
        return;
    }

    _LOGT("D-Bus name for dnsconfd got owner %s", name_owner);
    priv->was_start_tried = FALSE;

    if (!subscribe_serial(self)) {
        /* This means that in time between new name and subscribe serial call
         * we lost the name again thus wait again */
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_WAIT_CONNECT);
        _LOGT("subscription failed, waiting to connect");
    } else {
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_WAIT_UPDATE_DONE);
        _LOGT("sending update and waiting for its finish");
        send_dnsconfd_update(self);
    }
}

static void
name_owner_changed_cb(GDBusConnection *connection,
                      const char      *sender_name,
                      const char      *object_path,
                      const char      *interface_name,
                      const char      *signal_name,
                      GVariant        *parameters,
                      gpointer         user_data)
{
    NMDnsDnsconfd *self = user_data;
    const char    *new_owner;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);

    name_owner_changed(self, new_owner);
}

static void
get_name_owner_cb(const char *name_owner, GError *error, gpointer user_data)
{
    if (nm_utils_error_is_cancelled(error))
        return;

    name_owner_changed(user_data, name_owner);
}

static void
dnsconfd_start_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    NMDnsDnsconfd             *self;
    NMDnsDnsconfdPrivate      *priv;
    gs_free_error GError      *error    = NULL;
    gs_unref_variant GVariant *response = NULL;

    response = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source_object), res, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);
    nm_clear_g_cancellable(&priv->start_cancellable);

    if (!res) {
        g_dbus_error_strip_remote_error(error);
        _LOGW("failed to start Dnsconfd %s", error->message);
    } else {
        _LOGT("successfully started Dnsconfd");
    }

    /* No update maybe changed or state change, as this is handled by the name owner callbacks
     * which should be triggered right after this */
}

static ConnectionState
ensure_all_connected(NMDnsDnsconfd *self)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    if (!priv->dbus_connection) {
        priv->dbus_connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);
        if (!priv->dbus_connection) {
            return CONNECTION_FAIL;
        }
    }

    if (priv->name_owner) {
        return CONNECTION_SUCCESS;
    }

    if (!priv->name_owner_changed_id) {
        priv->name_owner_changed_id =
            nm_dbus_connection_signal_subscribe_name_owner_changed(priv->dbus_connection,
                                                                   DNSCONFD_DBUS_SERVICE,
                                                                   name_owner_changed_cb,
                                                                   self,
                                                                   NULL);
    }

    if (!priv->name_owner_cancellable) {
        nm_clear_g_cancellable(&priv->name_owner_cancellable);
        priv->name_owner_cancellable = g_cancellable_new();

        nm_dbus_connection_call_get_name_owner(priv->dbus_connection,
                                               DNSCONFD_DBUS_SERVICE,
                                               -1,
                                               priv->name_owner_cancellable,
                                               get_name_owner_cb,
                                               self);
    }

    if (!priv->was_start_tried) {
        _LOGT("attempting to start Dnsconfd via DBus");
        priv->was_start_tried = TRUE;
        nm_clear_g_cancellable(&priv->start_cancellable);
        priv->start_cancellable = g_cancellable_new();
        nm_dbus_connection_call_start_service_by_name(priv->dbus_connection,
                                                      DNSCONFD_DBUS_SERVICE,
                                                      -1,
                                                      priv->start_cancellable,
                                                      dnsconfd_start_done,
                                                      self);
    }

    return CONNECTION_WAIT;
}

static void
parse_all_interface_config(GVariantBuilder *argument_builder,
                           const CList     *ip_data_lst_head,
                           const char      *ca)
{
    NMDnsConfigIPData *ip_data;
    const char *const *dns_server_strings;
    guint              nameserver_count;
    const char        *ifname;
    gboolean           explicit_default = is_default_interface_explicit(ip_data_lst_head);

    c_list_for_each_entry (ip_data, ip_data_lst_head, ip_data_lst) {
        /* No need to free insides of routing and search domains, as they point to data
         * owned elsewhere on the other hand networks are created by us and thus we need to also
         * free the data */
        gs_free const char **routing_domains = NULL;
        gs_free const char **search_domains  = NULL;
        gs_strfreev char   **networks        = NULL;

        dns_server_strings = nm_l3_config_data_get_nameservers(ip_data->l3cd,
                                                               ip_data->addr_family,
                                                               &nameserver_count);
        if (!nameserver_count)
            continue;
        ifname = nm_platform_link_get_name(NM_PLATFORM_GET, ip_data->data->ifindex);

        gather_interface_domains(ip_data, explicit_default, &routing_domains, &search_domains);
        get_networks(ip_data, &networks);

        for (guint i = 0; i < nameserver_count; i++) {
            if (server_builder_append_base(argument_builder,
                                           ip_data->addr_family,
                                           dns_server_strings[i],
                                           routing_domains,
                                           search_domains,
                                           ca)) {
                server_builder_append_interface_info(argument_builder, ifname, networks);
            }
        }
    }
}

static gboolean
update(NMDnsPlugin             *plugin,
       const NMGlobalDnsConfig *global_config,
       const CList             *ip_data_lst_head,
       const char              *hostdomain,
       GError                 **error)
{
    NMDnsDnsconfd        *self = NM_DNS_DNSCONFD(plugin);
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);
    GVariantBuilder       argument_builder;
    GVariant             *args;

    ConnectionState all_connected;
    const char     *ca           = NULL;
    guint           resolve_mode = 0;
    gs_free char   *debug_string = NULL;

    g_variant_builder_init(&argument_builder, G_VARIANT_TYPE("(aa{sv}u)"));
    g_variant_builder_open(&argument_builder, G_VARIANT_TYPE("aa{sv}"));

    if (global_config) {
        _LOGT("parsing global configuration");
        parse_global_config(global_config, &argument_builder, &resolve_mode, &ca);
    }
    _LOGT("parsing configuration of interfaces");
    parse_all_interface_config(&argument_builder, ip_data_lst_head, ca);

    g_variant_builder_close(&argument_builder);
    g_variant_builder_add(&argument_builder, "u", resolve_mode);

    args = g_variant_builder_end(&argument_builder);

    /* Knowing how the update looks will be immensely helpful during debugging */
    _LOGT("arguments variant is composed like: %s", (debug_string = g_variant_print(args, TRUE)));

    nm_clear_pointer(&priv->latest_update_args, g_variant_unref);
    priv->latest_update_args = g_variant_ref_sink(args);

    all_connected = ensure_all_connected(self);

    /* We need to consider only whether we are connected, because newer update call
     * overrides the old one */
    if (all_connected == CONNECTION_FAIL) {
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_IDLE);
        _LOGT("failed to connect");
    } else if (all_connected == CONNECTION_WAIT) {
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_WAIT_CONNECT);
        _LOGT("not connected, waiting to connect");
    } else {
        dnsconfd_change_plugin_state(self, DNSCONFD_PLUGIN_WAIT_UPDATE_DONE);
        _LOGT("connected, waiting for update to finish");
    }

    if (all_connected == CONNECTION_FAIL) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "no D-Bus connection available to talk to dnsconfd");
        /* Not connected to dbus, can do nothing here */
        return FALSE;
    } else if (all_connected == CONNECTION_WAIT) {
        /* We do not have name owner yet, and have to wait */
        return TRUE;
    }

    send_dnsconfd_update(self);

    return TRUE;
}

static void
stop(NMDnsPlugin *plugin)
{
    NMDnsDnsconfd        *self = NM_DNS_DNSCONFD(plugin);
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    nm_clear_g_cancellable(&priv->update_cancellable);
    nm_clear_g_cancellable(&priv->name_owner_cancellable);
    nm_clear_g_cancellable(&priv->serial_cancellable);
    nm_clear_g_cancellable(&priv->start_cancellable);
    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->name_owner_changed_id);
    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->properties_changed_id);
}

static gboolean
_update_pending_detect(NMDnsDnsconfd *self)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(self);

    if (priv->plugin_state == DNSCONFD_PLUGIN_IDLE) {
        /* We are waiting for nothing */
        return FALSE;
    }

    /* Update in progress */
    return TRUE;
}

static gboolean
get_update_pending(NMDnsPlugin *plugin)
{
    NMDnsDnsconfd *self = NM_DNS_DNSCONFD(plugin);
    return _update_pending_detect(self);
}

static void
nm_dns_dnsconfd_init(NMDnsDnsconfd *self)
{}

NMDnsPlugin *
nm_dns_dnsconfd_new(void)
{
    return g_object_new(NM_TYPE_DNS_DNSCONFD, NULL);
}

static void
dispose(GObject *object)
{
    NMDnsDnsconfdPrivate *priv = NM_DNS_DNSCONFD_GET_PRIVATE(NM_DNS_DNSCONFD(object));

    _LOGT("disposing of Dnsconfd plugin");

    stop(NM_DNS_PLUGIN(object));
    if (priv->name_owner) {
        nm_clear_g_free(&priv->name_owner);
    }
    if (priv->latest_update_args) {
        nm_clear_pointer(&priv->latest_update_args, g_variant_unref);
    }

    G_OBJECT_CLASS(nm_dns_dnsconfd_parent_class)->dispose(object);

    g_clear_object(&priv->dbus_connection);
}

static void
nm_dns_dnsconfd_class_init(NMDnsDnsconfdClass *dns_class)
{
    NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS(dns_class);
    GObjectClass     *object_class = G_OBJECT_CLASS(dns_class);

    object_class->dispose = dispose;

    plugin_class->plugin_name        = "dnsconfd";
    plugin_class->is_caching         = TRUE;
    plugin_class->stop               = stop;
    plugin_class->update             = update;
    plugin_class->get_update_pending = get_update_pending;
}
