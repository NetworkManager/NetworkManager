/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2016 Sjoerd Simons <sjoerd@luon.net>
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dns-systemd-resolved.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <linux/if.h>

#include "libnm-glib-aux/nm-c-list.h"
#include "libnm-glib-aux/nm-dbus-aux.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-manager.h"
#include "nm-l3-config-data.h"
#include "nm-setting-connection.h"
#include "devices/nm-device.h"
#include "NetworkManagerUtils.h"
#include "libnm-std-aux/nm-dbus-compat.h"

#define SYSTEMD_RESOLVED_DBUS_SERVICE  "org.freedesktop.resolve1"
#define SYSTEMD_RESOLVED_MANAGER_IFACE "org.freedesktop.resolve1.Manager"
#define SYSTEMD_RESOLVED_DBUS_PATH     "/org/freedesktop/resolve1"

/* define a variable, so that we can compare the operation with pointer equality. */
static const char *const DBUS_OP_SET_LINK_DEFAULT_ROUTE = "SetLinkDefaultRoute";
static const char *const DBUS_OP_SET_LINK_DNS_OVER_TLS  = "SetLinkDNSOverTLS";
static const char *const DBUS_OP_SET_LINK_DNS_EX        = "SetLinkDNSEx";

/*****************************************************************************/

typedef struct {
    int        ifindex;
    GPtrArray *ip_data_list;
} InterfaceConfig;

typedef struct {
    CList                 request_queue_lst;
    const char           *operation;
    GVariant             *argument;
    NMDnsSystemdResolved *self;
    int                   ifindex;
    int                   ref_count;
} RequestItem;

struct _NMDnsSystemdResolvedResolveHandle {
    CList                 handle_lst;
    NMDnsSystemdResolved *self;
    GSource              *timeout_source;
    GCancellable         *handle_cancellable;
    gpointer              callback_user_data;
    guint                 timeout_msec;
    bool                  is_failing_on_idle;
    union {
        struct {
            NMDnsSystemdResolvedResolveAddressCallback callback;
            guint64                                    flags;
            int                                        ifindex;
            int                                        addr_family;
            NMIPAddr                                   addr;
        } r_address;
    };
};

/*****************************************************************************/

typedef struct {
    GDBusConnection *dbus_connection;
    GHashTable      *dirty_interfaces;
    GCancellable    *cancellable;
    GCancellable    *service_start_cancellable;
    CList            request_queue_lst_head;
    char            *dbus_owner;
    CList            handle_lst_head;
    guint            name_owner_changed_id;
    guint            n_pending;
    bool             send_updates_warn_ratelimited : 1;
    bool             try_start_blocked : 1;
    bool             stopped : 1;
    bool             dbus_initied : 1;
    bool             send_updates_waiting : 1;
    bool             update_pending : 1;

    /* Detect support for the respective D-Bus API. */
    NMTernary has_set_link_default_route : 3;
    NMTernary has_set_link_dns_over_tls : 3;
    NMTernary has_set_link_dns_ex : 3;
} NMDnsSystemdResolvedPrivate;

struct _NMDnsSystemdResolved {
    NMDnsPlugin                 parent;
    NMDnsSystemdResolvedPrivate _priv;
};

struct _NMDnsSystemdResolvedClass {
    NMDnsPluginClass parent;
};

G_DEFINE_TYPE(NMDnsSystemdResolved, nm_dns_systemd_resolved, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDnsSystemdResolved, NM_IS_DNS_SYSTEMD_RESOLVED, NMDnsPlugin)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_DNS
#define _NMLOG_PREFIX_NAME "dns-sd-resolved"

#define _NMLOG(level, ...) \
    __NMLOG_DEFAULT_WITH_ADDR(level, _NMLOG_DOMAIN, _NMLOG_PREFIX_NAME, __VA_ARGS__)

#define _NMLOG2(level, handle, ...)                                                         \
    G_STMT_START                                                                            \
    {                                                                                       \
        const NMLogLevel _level = (level);                                                  \
                                                                                            \
        if (nm_logging_enabled(_level, (_NMLOG_DOMAIN))) {                                  \
            const NMDnsSystemdResolvedResolveHandle *const _handle = (handle);              \
                                                                                            \
            _nm_log(_level,                                                                 \
                    (_NMLOG_DOMAIN),                                                        \
                    0,                                                                      \
                    NULL,                                                                   \
                    NULL,                                                                   \
                    "%s[" NM_HASH_OBFUSCATE_PTR_FMT "]: request[" NM_HASH_OBFUSCATE_PTR_FMT \
                    "]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                               \
                    _NMLOG_PREFIX_NAME,                                                     \
                    NM_HASH_OBFUSCATE_PTR(self),                                            \
                    NM_HASH_OBFUSCATE_PTR(_handle) _NM_UTILS_MACRO_REST(__VA_ARGS__));      \
        }                                                                                   \
    }                                                                                       \
    G_STMT_END

/*****************************************************************************/

static void _resolve_complete_error(NMDnsSystemdResolvedResolveHandle *handle, GError *error);

static void _resolve_start(NMDnsSystemdResolved *self, NMDnsSystemdResolvedResolveHandle *handle);

static void send_updates(NMDnsSystemdResolved *self);

/*****************************************************************************/

static gboolean
_update_pending_detect(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    if (priv->n_pending > 0) {
        /* we have pending calls. We definitely want to wait for them to complete. */
        return TRUE;
    }
    if (!priv->dbus_initied) {
        if (!priv->dbus_connection)
            return FALSE;
        /* D-Bus not yet initialized (and we don't know the name owner yet). Pending. */
        return TRUE;
    }
    if (priv->service_start_cancellable) {
        /* We are waiting to D-Bus activate resolved. Pending. */
        return TRUE;
    }
    if (priv->try_start_blocked) {
        /* We earlier tried to start resolved, but are rate limited. We are not pending an update
         * (that we expect to complete any time soon). */
        return FALSE;
    }
    if (priv->send_updates_waiting) {
        /* we wait to send updates. We are pending. */
        return TRUE;
    }
    return FALSE;
}

static void
_update_pending_maybe_changed(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    gboolean                     update_pending;

    /* Important: we need to make sure that we call _update_pending_maybe_changed(), when
     * the state changes. */

    update_pending = _update_pending_detect(self);
    if (priv->update_pending != update_pending) {
        priv->update_pending = update_pending;
        _nm_dns_plugin_update_pending_maybe_changed(NM_DNS_PLUGIN(self));
    }
}

static gboolean
get_update_pending(NMDnsPlugin *plugin)
{
    NMDnsSystemdResolved        *self = NM_DNS_SYSTEMD_RESOLVED(plugin);
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    nm_assert(priv->update_pending == _update_pending_detect(self));
    return priv->update_pending;
}

/*****************************************************************************/

static RequestItem *
_request_item_ref(RequestItem *request_item)
{
    nm_assert(request_item);
    nm_assert(request_item->ref_count > 0);
    nm_assert(request_item->ref_count < G_MAXINT);
    nm_assert(!c_list_is_empty(&request_item->request_queue_lst));

    request_item->ref_count++;
    return request_item;
}

static void
_request_item_unref(RequestItem *request_item)
{
    nm_assert(request_item);
    nm_assert(request_item->ref_count > 0);

    if (--request_item->ref_count > 0)
        return;

    nm_assert(c_list_is_empty(&request_item->request_queue_lst));

    g_variant_unref(request_item->argument);
    nm_g_slice_free(request_item);
}

static void
_request_item_append(NMDnsSystemdResolved *self,
                     const char           *operation,
                     int                   ifindex,
                     GVariant             *argument)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    RequestItem                 *request_item;

    request_item  = g_slice_new(RequestItem);
    *request_item = (RequestItem){
        .ref_count = 1,
        .operation = operation,
        .argument  = g_variant_ref_sink(argument),
        .self      = self,
        .ifindex   = ifindex,
    };
    c_list_link_tail(&priv->request_queue_lst_head, &request_item->request_queue_lst);
}

/*****************************************************************************/

static void
_interface_config_free(InterfaceConfig *config)
{
    nm_g_ptr_array_unref(config->ip_data_list);
    nm_g_slice_free(config);
}

static void
call_done(GObject *source, GAsyncResult *r, gpointer user_data)
{
    gs_unref_variant GVariant   *v     = NULL;
    gs_free_error GError        *error = NULL;
    NMDnsSystemdResolved        *self;
    NMDnsSystemdResolvedPrivate *priv;
    RequestItem                 *request_item;
    NMLogLevel                   log_level;
    const char                  *operation;
    int                          ifindex;
    gboolean                     reconfigure = FALSE;

    request_item = user_data;
    self         = request_item->self;
    operation    = request_item->operation;
    ifindex      = request_item->ifindex;
    _request_item_unref(request_item);

    priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    v = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), r, &error);
    if (nm_utils_error_is_cancelled(error))
        goto out_dec_pending;

    if (v) {
        if (operation == DBUS_OP_SET_LINK_DEFAULT_ROUTE) {
            if (priv->has_set_link_default_route == NM_TERNARY_DEFAULT) {
                priv->has_set_link_default_route = NM_TERNARY_TRUE;
                _LOGD("systemd-resolved support for SetLinkDefaultRoute(): API supported");
            }
        } else if (operation == DBUS_OP_SET_LINK_DNS_OVER_TLS) {
            if (priv->has_set_link_dns_over_tls == NM_TERNARY_DEFAULT) {
                priv->has_set_link_dns_over_tls = NM_TERNARY_TRUE;
                _LOGD("systemd-resolved support for SetLinkDNSOverTLS(): API supported");
            }
        } else if (operation == DBUS_OP_SET_LINK_DNS_EX) {
            if (priv->has_set_link_dns_ex == NM_TERNARY_DEFAULT) {
                priv->has_set_link_dns_ex = NM_TERNARY_TRUE;
                _LOGD("systemd-resolved support for SetLinkDNSEx(): API supported");
            }
        }
        priv->send_updates_warn_ratelimited = FALSE;
        goto out_dec_pending;
    }

    if (nm_g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD)) {
        if (operation == DBUS_OP_SET_LINK_DEFAULT_ROUTE) {
            if (priv->has_set_link_default_route == NM_TERNARY_DEFAULT) {
                priv->has_set_link_default_route = NM_TERNARY_FALSE;
                _LOGD("systemd-resolved support for SetLinkDefaultRoute(): API not supported");
            }
        } else if (operation == DBUS_OP_SET_LINK_DNS_OVER_TLS) {
            if (priv->has_set_link_dns_over_tls == NM_TERNARY_DEFAULT) {
                priv->has_set_link_dns_over_tls = NM_TERNARY_FALSE;
                _LOGD("systemd-resolved support for SetLinkDNSOverTLS(): API not supported");
            }
        } else if (operation == DBUS_OP_SET_LINK_DNS_EX) {
            if (priv->has_set_link_dns_ex == NM_TERNARY_DEFAULT) {
                priv->has_set_link_dns_ex = NM_TERNARY_FALSE;
                _LOGD("systemd-resolved support for SetLinkDNSEx(): API not supported");

                _LOGW("systemd-resolved does not support SetLinkDNSEx API (v246). "
                      "Cannot set DoT server name (SNI)");

                /* We need to reconfigure with the SetLinkDNS fallback.
                 *
                 * In the other cases above, there is no need to reconfigure anything.
                 * We won't retry SetLinkDefaultRoute/SetLinkDNSOverTLS anymore, but there
                 * is nothing else we can do about that. */
                reconfigure = TRUE;
            }
        }
        goto out_dec_pending;
    }

    log_level = LOGL_DEBUG;
    if (!priv->send_updates_warn_ratelimited) {
        priv->send_updates_warn_ratelimited = TRUE;
        log_level                           = LOGL_WARN;
    }
    _NMLOG(log_level, "send-updates %s@%d failed: %s", operation, ifindex, error->message);

out_dec_pending:
    nm_assert(priv->n_pending > 0);
    if (--priv->n_pending <= 0) {
        _update_pending_maybe_changed(self);
        /* We keep @self alive while pending operations are in progress. It's simpler
         * to implement. But this requires that we implement "stop()" signal to cancel
         * all pending requests. Cancelling is necessary, because during shutdown,
         * we must wrap up fast, and not hang an undefined amount time. */
        g_object_unref(self);
    }

    if (reconfigure) {
        priv->send_updates_waiting = TRUE;
        send_updates(self);
    }
}

static gboolean
update_add_ip_config(NMDnsSystemdResolved    *self,
                     const NMDnsConfigIPData *ip_data,
                     GVariantBuilder         *dns,
                     GVariantBuilder         *dns_ex,
                     GVariantBuilder         *domains,
                     gboolean                *out_require_dns_ex)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    gsize                        addr_size;
    guint                        n;
    guint                        i;
    gboolean                     is_routing;
    const char                  *domain;
    gboolean                     has_config = FALSE;
    const char *const           *strarr;

    addr_size = nm_utils_addr_family_to_size(ip_data->addr_family);

    if ((!ip_data->domains.search || !ip_data->domains.search[0])
        && !ip_data->domains.has_default_route_exclusive && !ip_data->domains.has_default_route) {
        /* we have no search domain (which systemd-resolved uses to routing the request), but
         * also the "DefaultRoute" is not set on the interface. This setting has no effect and
         * gets ignored. */
        return FALSE;
    }

    strarr = nm_l3_config_data_get_nameservers(ip_data->l3cd, ip_data->addr_family, &n);
    for (i = 0; i < n; i++) {
        const char *server_name;
        NMIPAddr    a;

        if (!nm_utils_dnsname_parse_assert(ip_data->addr_family, strarr[i], NULL, &a, &server_name))
            continue;

        if (server_name) {
            NM_SET_OUT(out_require_dns_ex, TRUE);
            if (priv->has_set_link_dns_ex == FALSE) {
                /* The caller won't care about this result anymore. We can skip setting it. */
                dns = NULL;
            }
        }

        if (dns_ex) {
            g_variant_builder_open(dns_ex, G_VARIANT_TYPE("(iayqs)"));
            g_variant_builder_add(dns_ex, "i", ip_data->addr_family);
            g_variant_builder_add_value(dns_ex, nm_g_variant_new_ay((gconstpointer) &a, addr_size));
            g_variant_builder_add(dns_ex, "q", 0);
            g_variant_builder_add(dns_ex, "s", server_name ?: "");
            g_variant_builder_close(dns_ex);
        }
        if (dns) {
            g_variant_builder_open(dns, G_VARIANT_TYPE("(iay)"));
            g_variant_builder_add(dns, "i", ip_data->addr_family);
            g_variant_builder_add_value(dns, nm_g_variant_new_ay((gconstpointer) &a, addr_size));
            g_variant_builder_close(dns);
        }
        has_config = TRUE;
    }

    if (!has_config || domains) {
        if (!ip_data->domains.has_default_route_explicit
            && ip_data->domains.has_default_route_exclusive) {
            g_variant_builder_add(domains, "(sb)", ".", TRUE);
            has_config = TRUE;
        }
        if (ip_data->domains.search) {
            for (i = 0; ip_data->domains.search[i]; i++) {
                domain = nm_utils_parse_dns_domain(ip_data->domains.search[i], &is_routing);
                g_variant_builder_add(domains, "(sb)", domain[0] ? domain : ".", is_routing);
                has_config = TRUE;
            }
        }
    }

    return has_config;
}

static void
free_pending_updates(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    RequestItem                 *request_item;

    while (
        (request_item =
             c_list_first_entry(&priv->request_queue_lst_head, RequestItem, request_queue_lst))) {
        c_list_unlink(&request_item->request_queue_lst);
        _request_item_unref(request_item);
    }
}

static gboolean
prepare_one_interface(NMDnsSystemdResolved *self, const InterfaceConfig *ic)
{
    NMDnsSystemdResolvedPrivate  *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    GVariantBuilder               dns;
    GVariantBuilder               dns_ex;
    GVariantBuilder               domains;
    NMSettingConnectionMdns       mdns              = NM_SETTING_CONNECTION_MDNS_DEFAULT;
    NMSettingConnectionLlmnr      llmnr             = NM_SETTING_CONNECTION_LLMNR_DEFAULT;
    NMSettingConnectionDnsOverTls dns_over_tls      = NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT;
    const char                   *mdns_arg          = NULL;
    const char                   *llmnr_arg         = NULL;
    const char                   *dns_over_tls_arg  = NULL;
    gboolean                      has_config        = FALSE;
    gboolean                      has_default_route = FALSE;
    guint                         i;
    gboolean                      require_dns_ex = FALSE;

    nm_assert(ic->ifindex != NM_LOOPBACK_IFINDEX);

    g_variant_builder_init(&dns, G_VARIANT_TYPE("(ia(iay))"));
    g_variant_builder_add(&dns, "i", ic->ifindex);
    g_variant_builder_open(&dns, G_VARIANT_TYPE("a(iay)"));

    g_variant_builder_init(&domains, G_VARIANT_TYPE("(ia(sb))"));
    g_variant_builder_add(&domains, "i", ic->ifindex);
    g_variant_builder_open(&domains, G_VARIANT_TYPE("a(sb)"));

    if (ic->ip_data_list) {
        for (i = 0; i < ic->ip_data_list->len; i++) {
            const NMDnsConfigIPData *ip_data = ic->ip_data_list->pdata[i];

            if (update_add_ip_config(self, ip_data, &dns, NULL, &domains, &require_dns_ex))
                has_config = TRUE;

            if (ip_data->domains.has_default_route)
                has_default_route = TRUE;

            if (NM_IS_IPv4(ip_data->addr_family)) {
                mdns  = NM_MAX(mdns, nm_l3_config_data_get_mdns(ip_data->l3cd));
                llmnr = NM_MAX(llmnr, nm_l3_config_data_get_llmnr(ip_data->l3cd));
                dns_over_tls =
                    NM_MAX(dns_over_tls, nm_l3_config_data_get_dns_over_tls(ip_data->l3cd));
            }
        }
    }

    g_variant_builder_close(&dns);
    g_variant_builder_close(&domains);

    if (!require_dns_ex) {
        /* No need to use the new API. SetLinkDNS() is sufficient. */
    } else if (!priv->has_set_link_dns_ex) {
        /* API to set server name is not supported. Nothing we can do. */
        require_dns_ex = FALSE;
    } else {
        g_variant_builder_init(&dns_ex, G_VARIANT_TYPE("(ia(iayqs))"));
        g_variant_builder_add(&dns_ex, "i", ic->ifindex);
        g_variant_builder_open(&dns_ex, G_VARIANT_TYPE("a(iayqs)"));
        for (i = 0; i < ic->ip_data_list->len; i++) {
            const NMDnsConfigIPData *ip_data = ic->ip_data_list->pdata[i];

            update_add_ip_config(self, ip_data, NULL, &dns_ex, NULL, NULL);
        }
        g_variant_builder_close(&dns_ex);
    }

    switch (mdns) {
    case NM_SETTING_CONNECTION_MDNS_NO:
        mdns_arg = "no";
        break;
    case NM_SETTING_CONNECTION_MDNS_RESOLVE:
        mdns_arg = "resolve";
        break;
    case NM_SETTING_CONNECTION_MDNS_YES:
        mdns_arg = "yes";
        break;
    case NM_SETTING_CONNECTION_MDNS_DEFAULT:
        mdns_arg = "";
        break;
    }
    nm_assert(mdns_arg);

    switch (llmnr) {
    case NM_SETTING_CONNECTION_LLMNR_NO:
        llmnr_arg = "no";
        break;
    case NM_SETTING_CONNECTION_LLMNR_RESOLVE:
        llmnr_arg = "resolve";
        break;
    case NM_SETTING_CONNECTION_LLMNR_YES:
        llmnr_arg = "yes";
        break;
    case NM_SETTING_CONNECTION_LLMNR_DEFAULT:
        llmnr_arg = "";
        break;
    }
    nm_assert(llmnr_arg);

    switch (dns_over_tls) {
    case NM_SETTING_CONNECTION_DNS_OVER_TLS_NO:
        dns_over_tls_arg = "no";
        break;
    case NM_SETTING_CONNECTION_DNS_OVER_TLS_OPPORTUNISTIC:
        dns_over_tls_arg = "opportunistic";
        break;
    case NM_SETTING_CONNECTION_DNS_OVER_TLS_YES:
        dns_over_tls_arg = "yes";
        break;
    case NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT:
        dns_over_tls_arg = "";
        break;
    }
    nm_assert(dns_over_tls_arg);

    if (!nm_str_is_empty(mdns_arg) || !nm_str_is_empty(llmnr_arg)
        || !nm_str_is_empty(dns_over_tls_arg))
        has_config = TRUE;

    _request_item_append(self, "SetLinkDomains", ic->ifindex, g_variant_builder_end(&domains));
    _request_item_append(self,
                         DBUS_OP_SET_LINK_DEFAULT_ROUTE,
                         ic->ifindex,
                         g_variant_new("(ib)", ic->ifindex, has_default_route));
    _request_item_append(self,
                         "SetLinkMulticastDNS",
                         ic->ifindex,
                         g_variant_new("(is)", ic->ifindex, mdns_arg ?: ""));
    _request_item_append(self,
                         "SetLinkLLMNR",
                         ic->ifindex,
                         g_variant_new("(is)", ic->ifindex, llmnr_arg ?: ""));
    if (require_dns_ex) {
        _request_item_append(self,
                             DBUS_OP_SET_LINK_DNS_EX,
                             ic->ifindex,
                             g_variant_builder_end(&dns_ex));
        g_variant_builder_clear(&dns);
    } else
        _request_item_append(self, "SetLinkDNS", ic->ifindex, g_variant_builder_end(&dns));
    _request_item_append(self,
                         DBUS_OP_SET_LINK_DNS_OVER_TLS,
                         ic->ifindex,
                         g_variant_new("(is)", ic->ifindex, dns_over_tls_arg ?: ""));

    return has_config;
}

static void
start_resolved_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_variant GVariant         *res   = NULL;
    gs_free_error GError              *error = NULL;
    NMDnsSystemdResolved              *self;
    NMDnsSystemdResolvedPrivate       *priv;
    NMDnsSystemdResolvedResolveHandle *handle;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    nm_clear_g_cancellable(&priv->service_start_cancellable);

    if (!res) {
        g_dbus_error_strip_remote_error(error);
        _LOGD("error activating systemd-resolved: %s", error->message);

again:
        c_list_for_each_entry (handle, &priv->handle_lst_head, handle_lst) {
            gs_free_error GError *local = NULL;

            if (handle->is_failing_on_idle)
                continue;

            nm_utils_error_set(&local,
                               NM_UTILS_ERROR_NOT_READY,
                               "error activating systemd-resolved: %s",
                               error->message);
            _resolve_complete_error(handle, local);
            goto again;
        }
    } else
        _LOGD("systemd-resolved successfully started");

    _update_pending_maybe_changed(self);
}

static NMTernary
ensure_resolved_running(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    if (priv->stopped)
        return NM_TERNARY_FALSE;

    if (!priv->dbus_initied)
        return NM_TERNARY_DEFAULT;

    if (!priv->dbus_owner) {
        if (priv->try_start_blocked) {
            /* we have no name owner and we already tried poking the service to
             * autostart. */
            return NM_TERNARY_FALSE;
        }

        _LOGT("try D-Bus activating systemd-resolved...");
        priv->try_start_blocked = TRUE;
        nm_clear_g_cancellable(&priv->service_start_cancellable);
        priv->service_start_cancellable = g_cancellable_new();
        nm_dbus_connection_call_start_service_by_name(priv->dbus_connection,
                                                      SYSTEMD_RESOLVED_DBUS_SERVICE,
                                                      4000,
                                                      priv->service_start_cancellable,
                                                      start_resolved_cb,
                                                      self);
        _update_pending_maybe_changed(self);
        return NM_TERNARY_DEFAULT;
    }

    return NM_TERNARY_TRUE;
}

static void
send_updates(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate       *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    RequestItem                       *request_item;
    NMDnsSystemdResolvedResolveHandle *handle;

    if (!priv->send_updates_waiting) {
        /* nothing to do. */
        return;
    }

    if (ensure_resolved_running(self) != NM_TERNARY_TRUE)
        return;

    nm_clear_g_cancellable(&priv->cancellable);

    if (c_list_is_empty(&priv->request_queue_lst_head)) {
        _LOGT("send-updates: no requests to send");
        priv->send_updates_waiting = FALSE;
        goto start_resolve;
    }

    priv->cancellable = g_cancellable_new();

    priv->send_updates_waiting = FALSE;

    _LOGT("send-updates: start %zu requests", c_list_length(&priv->request_queue_lst_head));

    c_list_for_each_entry (request_item, &priv->request_queue_lst_head, request_queue_lst) {
        gs_free char *ss = NULL;

        if ((request_item->operation == DBUS_OP_SET_LINK_DEFAULT_ROUTE
             && priv->has_set_link_default_route == NM_TERNARY_FALSE)
            || (request_item->operation == DBUS_OP_SET_LINK_DNS_OVER_TLS
                && priv->has_set_link_dns_over_tls == NM_TERNARY_FALSE)) {
            /* The "SetLinkDefaultRoute" API is only supported since v240.
             * The "SetLinkDNSOverTLS" API is only supported since v239.
             * We detected whether they are supported, and skip the calls. There
             * is no special workaround, because in this case we rely on systemd-resolved
             * to do the right thing automatically. */
            continue;
        }

        _LOGT("send-updates: %s ( %s )",
              request_item->operation,
              (ss = g_variant_print(request_item->argument, FALSE)));

        if (priv->n_pending++ == 0) {
            /* We are inside send_updates(). All callers are already calling
             * _update_pending_maybe_changed() afterwards. */
            g_object_ref(self);
        }

        g_dbus_connection_call(priv->dbus_connection,
                               priv->dbus_owner,
                               SYSTEMD_RESOLVED_DBUS_PATH,
                               SYSTEMD_RESOLVED_MANAGER_IFACE,
                               request_item->operation,
                               request_item->argument,
                               NULL,
                               G_DBUS_CALL_FLAGS_NONE,
                               -1,
                               priv->cancellable,
                               call_done,
                               _request_item_ref(request_item));
    }

start_resolve:
    c_list_for_each_entry (handle, &priv->handle_lst_head, handle_lst) {
        if (handle->handle_cancellable)
            continue;
        if (handle->is_failing_on_idle)
            continue;
        _resolve_start(self, handle);
    }
}

static gboolean
update(NMDnsPlugin             *plugin,
       const NMGlobalDnsConfig *global_config,
       const CList             *ip_data_lst_head,
       const char              *hostdomain,
       GError                 **error)
{
    NMDnsSystemdResolved          *self       = NM_DNS_SYSTEMD_RESOLVED(plugin);
    NMDnsSystemdResolvedPrivate   *priv       = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    gs_unref_hashtable GHashTable *interfaces = NULL;
    const NMUtilsNamedValue       *interfaces_arr;
    NMUtilsNamedValue              interfaces_arr_stack[50];
    gs_free NMUtilsNamedValue     *interfaces_arr_heap = NULL;
    guint                          interfaces_len;
    gpointer                       pointer;
    NMDnsConfigIPData             *ip_data;
    GHashTableIter                 iter;
    gs_unref_array GArray         *dirty_array = NULL;
    guint                          i;

    nm_assert(!priv->stopped);

    /* Group configs by ifindex/interfaces. */
    interfaces =
        g_hash_table_new_full(nm_direct_hash, NULL, NULL, (GDestroyNotify) _interface_config_free);

    c_list_for_each_entry (ip_data, ip_data_lst_head, ip_data_lst) {
        InterfaceConfig *ic      = NULL;
        int              ifindex = ip_data->data->ifindex;

        nm_assert(ifindex == nm_l3_config_data_get_ifindex(ip_data->l3cd));

        if (ifindex == NM_LOOPBACK_IFINDEX) {
            /* systemd-resolved API is per-link, and loopback is not supported.
             * Unclear what to do about DNS configuration on loopback. Just skip
             * it here. */
            continue;
        }

        ic = g_hash_table_lookup(interfaces, GINT_TO_POINTER(ifindex));
        if (!ic) {
            ic  = g_slice_new(InterfaceConfig);
            *ic = (InterfaceConfig){
                .ifindex      = ifindex,
                .ip_data_list = g_ptr_array_sized_new(4),
            };
            g_hash_table_insert(interfaces, GINT_TO_POINTER(ifindex), ic);
        }

        g_ptr_array_add(ic->ip_data_list, ip_data);
    }

    free_pending_updates(self);

    interfaces_arr = nm_utils_hash_to_array_with_buffer(interfaces,
                                                        &interfaces_len,
                                                        nm_cmp_int2ptr_p_with_data,
                                                        NULL,
                                                        interfaces_arr_stack,
                                                        &interfaces_arr_heap);
    for (i = 0; i < interfaces_len; i++) {
        const InterfaceConfig *ic = interfaces_arr[i].value_ptr;

        if (prepare_one_interface(self, ic))
            g_hash_table_add(priv->dirty_interfaces, GINT_TO_POINTER(ic->ifindex));
        else
            g_hash_table_remove(priv->dirty_interfaces, GINT_TO_POINTER(ic->ifindex));
    }

    /* If we previously configured an ifindex with non-empty values in
     * resolved, and the current update doesn't contain that interface,
     * reset the resolved configuration for that ifindex. */
    g_hash_table_iter_init(&iter, priv->dirty_interfaces);
    while (g_hash_table_iter_next(&iter, &pointer, NULL)) {
        int ifindex = GPOINTER_TO_INT(pointer);

        if (g_hash_table_contains(interfaces, GINT_TO_POINTER(ifindex))) {
            /* the interface is still tracked and still dirty. Keep. */
            continue;
        }

        if (!dirty_array)
            dirty_array = g_array_new(FALSE, FALSE, sizeof(int));
        g_array_append_val(dirty_array, ifindex);

        g_hash_table_iter_remove(&iter);
    }
    if (dirty_array) {
        g_array_sort_with_data(dirty_array, nm_cmp_int2ptr_p_with_data, NULL);
        for (i = 0; i < dirty_array->len; i++) {
            int             ifindex = nm_g_array_index(dirty_array, int, i);
            InterfaceConfig ic;

            _LOGT("clear previously configured ifindex %d", ifindex);
            ic = (InterfaceConfig){
                .ifindex      = ifindex,
                .ip_data_list = NULL,
            };
            prepare_one_interface(self, &ic);
        }
    }

    priv->send_updates_waiting = TRUE;
    send_updates(self);
    _update_pending_maybe_changed(self);
    return TRUE;
}

/*****************************************************************************/

static void
name_owner_changed(NMDnsSystemdResolved *self, const char *owner)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    owner = nm_str_not_empty(owner);

    if (!owner)
        _LOGT("D-Bus name for systemd-resolved has no owner");
    else
        _LOGT("D-Bus name for systemd-resolved has owner %s", owner);

    nm_clear_g_cancellable(&priv->service_start_cancellable);
    nm_strdup_reset(&priv->dbus_owner, owner);

    if (owner) {
        priv->try_start_blocked    = FALSE;
        priv->send_updates_waiting = TRUE;
    } else {
        priv->has_set_link_default_route = NM_TERNARY_DEFAULT;
        priv->has_set_link_dns_over_tls  = NM_TERNARY_DEFAULT;
        priv->has_set_link_dns_ex        = NM_TERNARY_DEFAULT;
    }

    send_updates(self);
    _update_pending_maybe_changed(self);
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
    NMDnsSystemdResolved        *self = user_data;
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    const char                  *new_owner;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);

    if (!priv->dbus_initied) {
        /* There was a race and we got a NameOwnerChanged signal before GetNameOwner
         * returns. */
        priv->dbus_initied = TRUE;
        nm_clear_g_cancellable(&priv->cancellable);
        _LOGT("D-Bus connection is ready");
    }

    name_owner_changed(user_data, new_owner);
}

static void
get_name_owner_cb(const char *name_owner, GError *error, gpointer user_data)
{
    NMDnsSystemdResolved        *self;
    NMDnsSystemdResolvedPrivate *priv;

    if (!name_owner && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = user_data;
    priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    g_clear_object(&priv->cancellable);

    priv->dbus_initied = TRUE;
    _LOGT("D-Bus connection is ready");

    name_owner_changed(self, name_owner);
}

/*****************************************************************************/

gboolean
nm_dns_systemd_resolved_is_running(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate *priv;

    g_return_val_if_fail(NM_IS_DNS_SYSTEMD_RESOLVED(self), FALSE);

    priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    return priv->dbus_initied && (priv->dbus_owner || !priv->try_start_blocked);
}

/*****************************************************************************/

static void
_resolve_complete(NMDnsSystemdResolvedResolveHandle       *handle,
                  const NMDnsSystemdResolvedAddressResult *names,
                  guint                                    names_len,
                  guint64                                  flags,
                  GError                                  *error)
{
    NMDnsSystemdResolved        *self;
    NMDnsSystemdResolvedPrivate *priv;

    g_return_if_fail(handle && NM_IS_DNS_SYSTEMD_RESOLVED(handle->self));

    self = handle->self;
    priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    nm_assert(c_list_contains(&priv->handle_lst_head, &handle->handle_lst));

    c_list_unlink(&handle->handle_lst);

    handle->self = NULL;

    nm_clear_g_source_inst(&handle->timeout_source);
    nm_clear_g_cancellable(&handle->handle_cancellable);

    handle->r_address
        .callback(self, handle, names, names_len, flags, error, handle->callback_user_data);

    nm_g_slice_free(handle);
}

static void
_resolve_complete_error(NMDnsSystemdResolvedResolveHandle *handle, GError *error)
{
    NMDnsSystemdResolved *self = handle->self;

    nm_assert(error);
    _LOG2T(handle, "request failed: %s", error->message);
    _resolve_complete(handle, NULL, 0, 0, error);
}

static void
_resolve_handle_call_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_variant GVariant         *v     = NULL;
    gs_free_error GError              *error = NULL;
    NMDnsSystemdResolvedResolveHandle *handle;
    NMDnsSystemdResolved              *self;
    GVariantIter                      *v_names_iter;
    guint64                            v_flags;
    int                                v_ifindex;
    char                              *v_name;
    gs_unref_array GArray             *v_names = NULL;
    gs_free char                      *ss      = NULL;

    v = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    handle = user_data;
    self   = handle->self;

    if (error) {
        gs_free char *remote_error = NULL;

        remote_error = g_dbus_error_get_remote_error(error);
        if (nm_streq0(remote_error, "org.freedesktop.DBus.Error.ServiceUnknown")) {
            _LOG2T(handle, "request failed due to service stop. Retry");
            g_clear_object(&handle->handle_cancellable);
            _resolve_start(self, handle);
            return;
        }

        _resolve_complete_error(handle, error);
        return;
    }

    _LOG2T(handle, "request completed: %s", (ss = g_variant_print(v, FALSE)));

    v_names = g_array_new(FALSE, FALSE, sizeof(NMDnsSystemdResolvedAddressResult));

    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(NMDnsSystemdResolvedAddressResult, name) == 0);
    g_array_set_clear_func(v_names, nm_indirect_g_free);

    g_variant_get(v, "(a(is)t)", &v_names_iter, &v_flags);

    while (g_variant_iter_next(v_names_iter, "(is)", &v_ifindex, &v_name)) {
        NMDnsSystemdResolvedAddressResult *n;

        n  = nm_g_array_append_new(v_names, NMDnsSystemdResolvedAddressResult);
        *n = (NMDnsSystemdResolvedAddressResult){
            .name    = g_steal_pointer(&v_name),
            .ifindex = v_ifindex,
        };
    }
    g_variant_iter_free(v_names_iter);

    _resolve_complete(handle,
                      nm_g_array_first_p(v_names, NMDnsSystemdResolvedAddressResult),
                      v_names->len,
                      v_flags,
                      NULL);
}

static gboolean
_resolve_failing_on_idle(gpointer user_data)
{
    NMDnsSystemdResolvedResolveHandle *handle = user_data;
    gs_free_error GError              *error  = NULL;

    nm_utils_error_set_literal(&error,
                               NM_UTILS_ERROR_NOT_READY,
                               "systemd-resolved is not available");
    _resolve_complete_error(handle, error);
    return G_SOURCE_CONTINUE;
}

static gboolean
_resolve_handle_timeout(gpointer user_data)
{
    NMDnsSystemdResolvedResolveHandle *handle = user_data;
    gs_free_error GError              *error  = NULL;

    nm_utils_error_set_literal(&error, NM_UTILS_ERROR_UNKNOWN, "timeout for request");
    _resolve_complete_error(handle, error);
    return G_SOURCE_CONTINUE;
}

static void
_resolve_start(NMDnsSystemdResolved *self, NMDnsSystemdResolvedResolveHandle *handle)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    NMTernary                    is_running;

    nm_assert(!handle->handle_cancellable);
    nm_assert(!handle->is_failing_on_idle);

    is_running = ensure_resolved_running(self);

    if (is_running == NM_TERNARY_FALSE) {
        /* Systemd-resolved is not is_running and shall not be used. We fail
         * on an idle handler. */
        _LOG2T(handle, "systemd-resolved not running. Failing on idle...");
        nm_assert(!handle->timeout_source);
        handle->is_failing_on_idle = TRUE;
        handle->timeout_source     = nm_g_idle_add_source(_resolve_failing_on_idle, handle);
        return;
    }

    if (!handle->timeout_source) {
        handle->timeout_source =
            nm_g_timeout_add_source(handle->timeout_msec, _resolve_handle_timeout, handle);
    }

    if (is_running == NM_TERNARY_DEFAULT) {
        /* we are D-Bus activating systemd-resolved. Wait for it... */
        _LOG2T(handle, "waiting for systemd-resolved to start...");
        return;
    }

    nm_assert(!priv->send_updates_waiting);

    handle->handle_cancellable = g_cancellable_new();

    _LOG2T(handle, "start D-Bus request...");
    g_dbus_connection_call(priv->dbus_connection,
                           priv->dbus_owner,
                           SYSTEMD_RESOLVED_DBUS_PATH,
                           SYSTEMD_RESOLVED_MANAGER_IFACE,
                           "ResolveAddress",
                           g_variant_new("(ii@ayt)",
                                         handle->r_address.ifindex,
                                         handle->r_address.addr_family,
                                         nm_g_variant_new_ay_inaddr(handle->r_address.addr_family,
                                                                    &handle->r_address.addr),
                                         handle->r_address.flags),
                           G_VARIANT_TYPE("(a(is)t)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           handle->timeout_msec + 1000u,
                           handle->handle_cancellable,
                           _resolve_handle_call_cb,
                           handle);
}

NMDnsSystemdResolvedResolveHandle *
nm_dns_systemd_resolved_resolve_address(NMDnsSystemdResolved                      *self,
                                        int                                        ifindex,
                                        int                                        addr_family,
                                        const NMIPAddr                            *addr,
                                        guint64                                    flags,
                                        guint                                      timeout_msec,
                                        NMDnsSystemdResolvedResolveAddressCallback callback,
                                        gpointer                                   user_data)
{
    NMDnsSystemdResolvedPrivate       *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    NMDnsSystemdResolvedResolveHandle *handle;
    char                               addr_str[NM_INET_ADDRSTRLEN];

    g_return_val_if_fail(NM_IS_DNS_SYSTEMD_RESOLVED(self), NULL);
    nm_assert_addr_family(addr_family);
    nm_assert(addr);
    nm_assert(callback);

    handle  = g_slice_new(NMDnsSystemdResolvedResolveHandle);
    *handle = (NMDnsSystemdResolvedResolveHandle){
        .self               = self,
        .timeout_msec       = timeout_msec,
        .callback_user_data = user_data,
        .r_address =
            {
                .ifindex     = ifindex,
                .addr_family = addr_family,
                .addr        = *addr,
                .flags       = flags,
                .callback    = callback,
            },
    };
    c_list_link_tail(&priv->handle_lst_head, &handle->handle_lst);

    _LOG2T(handle,
           "resolve-address(ifindex=%d, %s, flags=%" G_GINT64_MODIFIER "x): new request",
           handle->r_address.ifindex,
           nm_inet_ntop(handle->r_address.addr_family, &handle->r_address.addr, addr_str),
           handle->r_address.flags);

    _resolve_start(self, handle);

    return handle;
}

void
nm_dns_systemd_resolved_resolve_cancel(NMDnsSystemdResolvedResolveHandle *handle)
{
    gs_free_error GError *error = NULL;

    nm_utils_error_set_cancelled(&error, FALSE, "NMDnsSystemdResolved");
    _resolve_complete_error(handle, error);
}

/*****************************************************************************/

static void
stop(NMDnsPlugin *plugin)
{
    NMDnsSystemdResolved              *self = NM_DNS_SYSTEMD_RESOLVED(plugin);
    NMDnsSystemdResolvedPrivate       *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);
    NMDnsSystemdResolvedResolveHandle *handle;

    /* This function must be re-entrant!!
     *
     * Currently there is no concept of unregistering/shutting down. It's not
     * clear whether we should de-configure anything in systemd-resolved, we
     * don't.
     *
     * Implementing stop() is important because pending operations take a
     * reference on @self. We can only cancel (fast shutdown) the instance
     * by cancelling those requests. */

    priv->stopped           = TRUE;
    priv->try_start_blocked = TRUE;

    nm_clear_g_cancellable(&priv->cancellable);

    nm_clear_g_free(&priv->dbus_owner);

    while ((handle = c_list_first_entry(&priv->handle_lst_head,
                                        NMDnsSystemdResolvedResolveHandle,
                                        handle_lst))) {
        gs_free_error GError *error = NULL;

        nm_utils_error_set_cancelled(&error, TRUE, "NMDnsSystemdResolved");
        _resolve_complete_error(handle, error);
    }

    free_pending_updates(self);

    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->name_owner_changed_id);

    nm_clear_g_cancellable(&priv->service_start_cancellable);
}

/*****************************************************************************/

static void
nm_dns_systemd_resolved_init(NMDnsSystemdResolved *self)
{
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    priv->has_set_link_default_route = NM_TERNARY_DEFAULT;
    priv->has_set_link_dns_over_tls  = NM_TERNARY_DEFAULT;
    priv->has_set_link_dns_ex        = NM_TERNARY_DEFAULT;

    c_list_init(&priv->request_queue_lst_head);
    c_list_init(&priv->handle_lst_head);
    priv->dirty_interfaces = g_hash_table_new(nm_direct_hash, NULL);

    priv->dbus_connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);
    if (!priv->dbus_connection) {
        _LOGD("no D-Bus connection");
        return;
    }

    priv->update_pending = TRUE;

    priv->name_owner_changed_id =
        nm_dbus_connection_signal_subscribe_name_owner_changed(priv->dbus_connection,
                                                               SYSTEMD_RESOLVED_DBUS_SERVICE,
                                                               name_owner_changed_cb,
                                                               self,
                                                               NULL);
    priv->cancellable = g_cancellable_new();
    nm_dbus_connection_call_get_name_owner(priv->dbus_connection,
                                           SYSTEMD_RESOLVED_DBUS_SERVICE,
                                           -1,
                                           priv->cancellable,
                                           get_name_owner_cb,
                                           self);
}

NMDnsPlugin *
nm_dns_systemd_resolved_new(void)
{
    return g_object_new(NM_TYPE_DNS_SYSTEMD_RESOLVED, NULL);
}

static void
dispose(GObject *object)
{
    NMDnsSystemdResolved        *self = NM_DNS_SYSTEMD_RESOLVED(object);
    NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self);

    stop(NM_DNS_PLUGIN(self));

    g_clear_object(&priv->dbus_connection);
    nm_clear_pointer(&priv->dirty_interfaces, g_hash_table_destroy);

    G_OBJECT_CLASS(nm_dns_systemd_resolved_parent_class)->dispose(object);
}

static void
nm_dns_systemd_resolved_class_init(NMDnsSystemdResolvedClass *dns_class)
{
    NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS(dns_class);
    GObjectClass     *object_class = G_OBJECT_CLASS(dns_class);

    object_class->dispose = dispose;

    plugin_class->plugin_name        = "systemd-resolved";
    plugin_class->is_caching         = TRUE;
    plugin_class->stop               = stop;
    plugin_class->update             = update;
    plugin_class->get_update_pending = get_update_pending;
}
