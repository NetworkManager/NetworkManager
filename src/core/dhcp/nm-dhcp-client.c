/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dhcp-client.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-glib-aux/nm-random-utils.h"

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-l3cfg.h"
#include "nm-l3-config-data.h"
#include "nm-dhcp-utils.h"
#include "nm-dhcp-options.h"
#include "libnm-platform/nm-platform.h"
#include "nm-hostname-manager.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "nm-dhcp-client-logging.h"

/*****************************************************************************/

enum { SIGNAL_NOTIFY, LAST_SIGNAL };

static guint signals[LAST_SIGNAL] = {0};

NM_GOBJECT_PROPERTIES_DEFINE(NMDhcpClient, PROP_CONFIG, );

typedef struct _NMDhcpClientPrivate {
    NMDhcpClientConfig    config;
    const NML3ConfigData *l3cd;
    GSource              *no_lease_timeout_source;
    GSource              *ipv6_lladdr_timeout_source;
    GBytes               *effective_client_id;
    pid_t                 pid;
    guint                 watch_id;
    NMDhcpState           state;
    bool                  iaid_explicit : 1;
    bool                  is_stopped : 1;
    struct {
        gulong id;
        bool   wait_dhcp_commit : 1;
        bool   wait_ll_address : 1;
    } l3cfg_notify;
} NMDhcpClientPrivate;

G_DEFINE_ABSTRACT_TYPE(NMDhcpClient, nm_dhcp_client, G_TYPE_OBJECT)

#define NM_DHCP_CLIENT_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDhcpClient, NM_IS_DHCP_CLIENT)

/*****************************************************************************/

static void
l3_cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMDhcpClient *self);

/*****************************************************************************/

/* we use pid=-1 for invalid PIDs. Ensure that pid_t can hold negative values. */
G_STATIC_ASSERT(!(((pid_t) -1) > 0));

/*****************************************************************************/

static void
_emit_notify(NMDhcpClient *self, const NMDhcpClientNotifyData *notify_data)
{
    g_signal_emit(G_OBJECT(self), signals[SIGNAL_NOTIFY], 0, notify_data);
}

/*****************************************************************************/

static void
connect_l3cfg_notify(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    gboolean             do_connect;

    do_connect = priv->l3cfg_notify.wait_dhcp_commit | priv->l3cfg_notify.wait_ll_address;

    if (!do_connect) {
        nm_clear_g_signal_handler(priv->config.l3cfg, &priv->l3cfg_notify.id);
        return;
    }

    if (priv->l3cfg_notify.id == 0) {
        priv->l3cfg_notify.id = g_signal_connect(priv->config.l3cfg,
                                                 NM_L3CFG_SIGNAL_NOTIFY,
                                                 G_CALLBACK(l3_cfg_notify_cb),
                                                 self);
    }
}

pid_t
nm_dhcp_client_get_pid(NMDhcpClient *self)
{
    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), -1);

    return NM_DHCP_CLIENT_GET_PRIVATE(self)->pid;
}

void
nm_dhcp_client_set_effective_client_id(NMDhcpClient *self, GBytes *client_id)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_if_fail(NM_IS_DHCP_CLIENT(self));
    g_return_if_fail(!client_id || g_bytes_get_size(client_id) >= 2);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (nm_g_bytes_equal0(priv->effective_client_id, client_id))
        return;

    g_bytes_unref(priv->effective_client_id);
    priv->effective_client_id = client_id;
    if (client_id)
        g_bytes_ref(client_id);

    {
        gs_free char *s = NULL;

        _LOGT("%s: set %s",
              priv->config.addr_family == AF_INET6 ? "duid" : "client-id",
              priv->effective_client_id
                  ? (s = nm_dhcp_utils_duid_to_string(priv->effective_client_id))
                  : "default");
    }
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(nm_dhcp_state_to_string,
                           NMDhcpState,
                           NM_UTILS_LOOKUP_DEFAULT(NULL),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_BOUND, "bound"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_DONE, "done"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_EXPIRE, "expire"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_EXTENDED, "extended"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_FAIL, "fail"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_NOOP, "noop"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_TERMINATED, "terminated"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_TIMEOUT, "timeout"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_STATE_UNKNOWN, "unknown"), );

static NMDhcpState
reason_to_state(const char *reason)
{
    if (NM_IN_STRSET_ASCII_CASE(reason, "bound", "bound6", "static"))
        return NM_DHCP_STATE_BOUND;
    if (NM_IN_STRSET_ASCII_CASE(reason, "renew", "renew6", "reboot", "rebind", "rebind6"))
        return NM_DHCP_STATE_EXTENDED;
    if (NM_IN_STRSET_ASCII_CASE(reason, "timeout"))
        return NM_DHCP_STATE_TIMEOUT;
    if (NM_IN_STRSET_ASCII_CASE(reason, "nak", "expire", "expire6"))
        return NM_DHCP_STATE_EXPIRE;
    if (NM_IN_STRSET_ASCII_CASE(reason, "end", "stop", "stopped"))
        return NM_DHCP_STATE_DONE;
    if (NM_IN_STRSET_ASCII_CASE(reason, "fail", "abend"))
        return NM_DHCP_STATE_FAIL;
    if (NM_IN_STRSET_ASCII_CASE(reason, "preinit"))
        return NM_DHCP_STATE_NOOP;

    return NM_DHCP_STATE_UNKNOWN;
}

/*****************************************************************************/

static void
watch_cleanup(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source(&priv->watch_id);
}

void
nm_dhcp_client_stop_pid(pid_t pid, const char *iface)
{
    char *name = iface ? g_strdup_printf("dhcp-client-%s", iface) : NULL;

    g_return_if_fail(pid > 1);

    nm_utils_kill_child_sync(pid,
                             SIGTERM,
                             LOGD_DHCP,
                             name ?: "dhcp-client",
                             NULL,
                             1000 / 2,
                             1000 / 20);
    g_free(name);
}

static void
stop(NMDhcpClient *self, gboolean release)
{
    NMDhcpClientPrivate *priv;

    g_return_if_fail(NM_IS_DHCP_CLIENT(self));

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (priv->pid > 0) {
        /* Clean up the watch handler since we're explicitly killing the daemon */
        watch_cleanup(self);
        nm_dhcp_client_stop_pid(priv->pid, priv->config.iface);
    }
    priv->pid = -1;
}

static gboolean
_no_lease_timeout(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->no_lease_timeout_source);

    _emit_notify(self,
                 &((NMDhcpClientNotifyData){
                     .notify_type = NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT,
                 }));
    return G_SOURCE_CONTINUE;
}

const NMDhcpClientConfig *
nm_dhcp_client_get_config(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return &priv->config;
}

static void
schedule_no_lease_timeout(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (priv->no_lease_timeout_source)
        return;

    if (priv->config.timeout == NM_DHCP_TIMEOUT_INFINITY) {
        _LOGI("activation: beginning transaction (no timeout)");
        priv->no_lease_timeout_source = g_source_ref(nm_g_source_sentinel_get(0));
    } else {
        _LOGI("activation: beginning transaction (timeout in %u seconds)",
              (guint) priv->config.timeout);
        priv->no_lease_timeout_source =
            nm_g_timeout_add_seconds_source(priv->config.timeout, _no_lease_timeout, self);
    }
}

void
nm_dhcp_client_set_state(NMDhcpClient *self, NMDhcpState new_state, const NML3ConfigData *l3cd)
{
    NMDhcpClientPrivate                     *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    GHashTable                              *options;
    const int                                IS_IPv4     = NM_IS_IPv4(priv->config.addr_family);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_merged = NULL;

    g_return_if_fail(NM_IS_DHCP_CLIENT(self));

    if (NM_IN_SET(new_state, NM_DHCP_STATE_BOUND, NM_DHCP_STATE_EXTENDED)) {
        g_return_if_fail(NM_IS_L3_CONFIG_DATA(l3cd));
        g_return_if_fail(nm_l3_config_data_get_dhcp_lease(l3cd, priv->config.addr_family));
    } else
        g_return_if_fail(!l3cd);

    if (l3cd)
        nm_l3_config_data_seal(l3cd);

    if (new_state >= NM_DHCP_STATE_TIMEOUT)
        watch_cleanup(self);

    if (!IS_IPv4 && l3cd) {
        if (nm_dhcp_utils_merge_new_dhcp6_lease(priv->l3cd, l3cd, &l3cd_merged)) {
            _LOGD("lease merged with existing one");
            l3cd = nm_l3_config_data_seal(l3cd_merged);
        }
    }

    if (priv->l3cd == l3cd)
        return;

    if (l3cd) {
        nm_clear_g_source_inst(&priv->no_lease_timeout_source);
    } else {
        if (priv->l3cd)
            schedule_no_lease_timeout(self);
    }

    /* FIXME(l3cfg:dhcp): the API of NMDhcpClient is changing to expose a simpler API.
     * The internals like NMDhcpState should not be exposed (or possibly dropped in large
     * parts). */

    nm_l3_config_data_reset(&priv->l3cd, l3cd);

    options = l3cd ? nm_dhcp_lease_get_options(
                  nm_l3_config_data_get_dhcp_lease(l3cd, priv->config.addr_family))
                   : NULL;

    if (_LOGD_ENABLED()) {
        if (options) {
            gs_free const char **keys = NULL;
            guint                nkeys;
            guint                i;

            keys = nm_strdict_get_keys(options, TRUE, &nkeys);
            for (i = 0; i < nkeys; i++) {
                _LOGD("option %-20s => '%s'",
                      keys[i],
                      (char *) g_hash_table_lookup(options, keys[i]));
            }
        }
    }

    if (_LOGI_ENABLED()) {
        const char *req_str =
            IS_IPv4 ? nm_dhcp_option_request_string(AF_INET, NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS)
                    : nm_dhcp_option_request_string(AF_INET6, NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS);
        const char *addr = nm_g_hash_table_lookup(options, req_str);

        _LOGI("state changed %s%s%s%s",
              priv->l3cd ? "new lease" : "no lease",
              NM_PRINT_FMT_QUOTED(addr, ", address=", addr, "", ""));
    }

    /* FIXME(l3cfg:dhcp:acd): NMDhcpClient must also do ACD. It needs acd_timeout_msec
     * as a configuration parameter (in NMDhcpClientConfig). When ACD is enabled,
     * when a new lease gets announced, it must first use NML3Cfg to run ACD on the
     * interface (the previous lease -- if any -- will still be used at that point).
     * If ACD fails, we call nm_dhcp_client_decline() and try to get a different
     * lease.
     * If ACD passes, we need to notify the new lease, and the user (NMDevice) may
     * then configure the address. We need to watch the configured addresses (in NML3Cfg),
     * and if the address appears there, we need to accept the lease. That is complicated
     * but necessary, because we can only accept the lease after we configured the
     * address.
     *
     * As a whole, ACD is transparent for the user (NMDevice). It's entirely managed
     * by NMDhcpClient. Note that we do ACD through NML3Cfg, which centralizes IP handling
     * for one interface, so for example if the same address happens to be configured
     * as a static address (bypassing ACD), then NML3Cfg is aware of that and signals
     * immediate success. */

    if (nm_dhcp_client_can_accept(self) && new_state == NM_DHCP_STATE_BOUND && priv->l3cd
        && nm_l3_config_data_get_num_addresses(priv->l3cd, priv->config.addr_family) > 0) {
        priv->l3cfg_notify.wait_dhcp_commit = TRUE;
    } else {
        priv->l3cfg_notify.wait_dhcp_commit = FALSE;
    }
    connect_l3cfg_notify(self);

    {
        const NMDhcpClientNotifyData notify_data = {
            .notify_type = NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE,
            .lease_update =
                {
                    .l3cd     = priv->l3cd,
                    .accepted = !priv->l3cfg_notify.wait_dhcp_commit,
                },
        };

        _emit_notify(self, &notify_data);
    }
}

static void
daemon_watch_cb(GPid pid, int status, gpointer user_data)
{
    NMDhcpClient        *self = NM_DHCP_CLIENT(user_data);
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    gs_free char        *desc = NULL;

    g_return_if_fail(priv->watch_id);
    priv->watch_id = 0;

    _LOGI("client pid %d %s", pid, (desc = nm_utils_get_process_exit_status_desc(status)));

    priv->pid = -1;

    nm_dhcp_client_set_state(self, NM_DHCP_STATE_TERMINATED, NULL);
}

void
nm_dhcp_client_watch_child(NMDhcpClient *self, pid_t pid)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_if_fail(priv->pid == -1);
    priv->pid = pid;

    g_return_if_fail(priv->watch_id == 0);
    priv->watch_id = g_child_watch_add(pid, daemon_watch_cb, self);
}

void
nm_dhcp_client_stop_watch_child(NMDhcpClient *self, pid_t pid)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_if_fail(priv->pid == pid);
    priv->pid = -1;

    watch_cleanup(self);
}

gboolean
nm_dhcp_client_start_ip4(NMDhcpClient *self, GError **error)
{
    NMDhcpClientPrivate *priv;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    g_return_val_if_fail(priv->pid == -1, FALSE);
    g_return_val_if_fail(priv->config.addr_family == AF_INET, FALSE);
    g_return_val_if_fail(priv->config.uuid, FALSE);

    schedule_no_lease_timeout(self);

    return NM_DHCP_CLIENT_GET_CLASS(self)->ip4_start(self, error);
}

gboolean
nm_dhcp_client_accept(NMDhcpClient *self, GError **error)
{
    NMDhcpClientPrivate *priv;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_val_if_fail(priv->l3cd, FALSE);

    if (NM_DHCP_CLIENT_GET_CLASS(self)->accept) {
        return NM_DHCP_CLIENT_GET_CLASS(self)->accept(self, error);
    }

    return TRUE;
}

gboolean
nm_dhcp_client_can_accept(NMDhcpClient *self)
{
    gboolean can_accept;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);

    can_accept = !!(NM_DHCP_CLIENT_GET_CLASS(self)->accept);

    nm_assert(can_accept == (!!(NM_DHCP_CLIENT_GET_CLASS(self)->decline)));

    return can_accept;
}

gboolean
nm_dhcp_client_decline(NMDhcpClient *self, const char *error_message, GError **error)
{
    NMDhcpClientPrivate *priv;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_val_if_fail(priv->l3cd, FALSE);

    if (NM_DHCP_CLIENT_GET_CLASS(self)->decline) {
        return NM_DHCP_CLIENT_GET_CLASS(self)->decline(self, error_message, error);
    }

    return TRUE;
}

static GBytes *
get_duid(NMDhcpClient *self)
{
    return NULL;
}

static gboolean
ipv6_lladdr_timeout(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->ipv6_lladdr_timeout_source);

    _emit_notify(
        self,
        &((NMDhcpClientNotifyData){
            .notify_type         = NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
            .it_looks_bad.reason = "timeout reached while waiting for an IPv6 link-local address",
        }));
    return G_SOURCE_CONTINUE;
}

static const NMPlatformIP6Address *
ipv6_lladdr_find(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    NML3Cfg             *l3cfg;
    NMPLookup            lookup;
    NMDedupMultiIter     iter;
    const NMPObject     *obj;

    l3cfg = priv->config.l3cfg;
    nmp_lookup_init_object(&lookup, NMP_OBJECT_TYPE_IP6_ADDRESS, nm_l3cfg_get_ifindex(l3cfg));

    nm_platform_iter_obj_for_each (&iter, nm_l3cfg_get_platform(l3cfg), &lookup, &obj) {
        const NMPlatformIP6Address *pladdr = NMP_OBJECT_CAST_IP6_ADDRESS(obj);

        if (!IN6_IS_ADDR_LINKLOCAL(&pladdr->address))
            continue;
        if (NM_FLAGS_HAS(pladdr->n_ifa_flags, IFA_F_TENTATIVE)
            && !NM_FLAGS_HAS(pladdr->n_ifa_flags, IFA_F_OPTIMISTIC))
            continue;
        return pladdr;
    }
    return NULL;
}

static void
l3_cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_assert(l3cfg == priv->config.l3cfg);

    switch (notify_data->notify_type) {
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE:
    {
        const NMPlatformIP6Address *addr;
        gs_free_error GError       *error = NULL;

        if (!priv->l3cfg_notify.wait_ll_address)
            return;

        addr = ipv6_lladdr_find(self);
        if (addr) {
            _LOGD("got IPv6LL address, starting transaction");
            priv->l3cfg_notify.wait_ll_address = FALSE;
            connect_l3cfg_notify(self);
            nm_clear_g_source_inst(&priv->ipv6_lladdr_timeout_source);

            schedule_no_lease_timeout(self);

            if (!NM_DHCP_CLIENT_GET_CLASS(self)->ip6_start(self, &addr->address, &error)) {
                _emit_notify(self,
                             &((NMDhcpClientNotifyData){
                                 .notify_type         = NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                                 .it_looks_bad.reason = error->message,
                             }));
            }
        }

        break;
    }
    case NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT:
    {
        const NML3ConfigData      *committed_l3cd;
        NMDedupMultiIter           ipconf_iter;
        const NMPlatformIPAddress *lease_address;
        gs_free_error GError      *error = NULL;

        /* A new configuration was committed to the interface. If we previously
         * got a lease, check whether we are waiting for the address to be
         * configured. If the address was added, we can proceed accepting the
         * lease and notifying NMDevice. */

        if (!priv->l3cfg_notify.wait_dhcp_commit)
            return;

        nm_l3_config_data_iter_ip_address_for_each (&ipconf_iter,
                                                    priv->l3cd,
                                                    priv->config.addr_family,
                                                    &lease_address)
            break;
        nm_assert(lease_address);
        committed_l3cd = nm_l3cfg_get_combined_l3cd(l3cfg, TRUE);

        if (priv->config.addr_family == AF_INET) {
            const NMPlatformIP4Address *address4 = (const NMPlatformIP4Address *) lease_address;

            if (!nm_l3_config_data_lookup_address_4(committed_l3cd,
                                                    address4->address,
                                                    address4->plen,
                                                    address4->peer_address))
                return;
        } else {
            const NMPlatformIP6Address *address6 = (const NMPlatformIP6Address *) lease_address;

            if (!nm_l3_config_data_lookup_address_6(committed_l3cd, &address6->address))
                return;
        }

        priv->l3cfg_notify.wait_dhcp_commit = FALSE;
        connect_l3cfg_notify(self);

        _LOGD("accept address");

        if (!nm_dhcp_client_accept(self, &error)) {
            gs_free char *reason = g_strdup_printf("error accepting lease: %s", error->message);

            _emit_notify(self,
                         &((NMDhcpClientNotifyData){
                             .notify_type         = NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                             .it_looks_bad.reason = reason,
                         }));
            return;
        }

        _emit_notify(
            self,
            &((NMDhcpClientNotifyData){.notify_type  = NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE,
                                       .lease_update = {
                                           .l3cd     = priv->l3cd,
                                           .accepted = TRUE,
                                       }}));
        break;
    };
    default:
        /* ignore */;
    }
}

gboolean
nm_dhcp_client_start_ip6(NMDhcpClient *self, GError **error)
{
    NMDhcpClientPrivate        *priv;
    gs_unref_bytes GBytes      *own_client_id = NULL;
    const NMPlatformIP6Address *addr;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);
    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_val_if_fail(priv->pid == -1, FALSE);
    g_return_val_if_fail(priv->config.addr_family == AF_INET6, FALSE);
    g_return_val_if_fail(priv->config.uuid, FALSE);
    g_return_val_if_fail(!priv->effective_client_id, FALSE);

    if (!priv->config.v6.enforce_duid)
        own_client_id = NM_DHCP_CLIENT_GET_CLASS(self)->get_duid(self);

    nm_dhcp_client_set_effective_client_id(self, own_client_id ?: priv->config.client_id);

    addr = ipv6_lladdr_find(self);
    if (!addr) {
        _LOGD("waiting for IPv6LL address");
        priv->l3cfg_notify.wait_ll_address = TRUE;
        connect_l3cfg_notify(self);
        priv->ipv6_lladdr_timeout_source =
            nm_g_timeout_add_seconds_source(10, ipv6_lladdr_timeout, self);
        return TRUE;
    }

    schedule_no_lease_timeout(self);

    return NM_DHCP_CLIENT_GET_CLASS(self)->ip6_start(self, &addr->address, error);
}

void
nm_dhcp_client_stop_existing(const char *pid_file, const char *binary_name)
{
    guint64       start_time;
    pid_t         pid, ppid;
    const char   *exe;
    char          proc_path[NM_STRLEN("/proc/%lu/cmdline") + 100];
    gs_free char *pid_contents = NULL, *proc_contents = NULL;

    /* Check for an existing instance and stop it */
    if (!g_file_get_contents(pid_file, &pid_contents, NULL, NULL))
        return;

    pid = _nm_utils_ascii_str_to_int64(pid_contents, 10, 1, G_MAXINT64, 0);
    if (pid <= 0)
        goto out;

    start_time = nm_utils_get_start_time_for_pid(pid, NULL, &ppid);
    if (start_time == 0)
        goto out;

    nm_sprintf_buf(proc_path, "/proc/%lu/cmdline", (unsigned long) pid);
    if (!g_file_get_contents(proc_path, &proc_contents, NULL, NULL))
        goto out;

    exe = strrchr(proc_contents, '/');
    if (exe)
        exe++;
    else
        exe = proc_contents;
    if (!nm_streq0(exe, binary_name))
        goto out;

    if (ppid == getpid()) {
        /* the process is our own child. */
        nm_utils_kill_child_sync(pid, SIGTERM, LOGD_DHCP, "dhcp-client", NULL, 1000 / 2, 1000 / 20);
    } else {
        nm_utils_kill_process_sync(pid,
                                   start_time,
                                   SIGTERM,
                                   LOGD_DHCP,
                                   "dhcp-client",
                                   1000 / 2,
                                   1000 / 20,
                                   2000);
    }

out:
    if (remove(pid_file) == -1) {
        int errsv = errno;

        nm_log_dbg(LOGD_DHCP,
                   "dhcp: could not remove pid file \"%s\": %s (%d)",
                   pid_file,
                   nm_strerror_native(errsv),
                   errsv);
    }
}

void
nm_dhcp_client_stop(NMDhcpClient *self, gboolean release)
{
    NMDhcpClientPrivate *priv;
    pid_t                old_pid = 0;

    g_return_if_fail(NM_IS_DHCP_CLIENT(self));

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (priv->is_stopped)
        return;

    priv->is_stopped = TRUE;

    priv->l3cfg_notify.wait_dhcp_commit = FALSE;
    priv->l3cfg_notify.wait_ll_address  = FALSE;
    connect_l3cfg_notify(self);

    /* Kill the DHCP client */
    old_pid = priv->pid;
    NM_DHCP_CLIENT_GET_CLASS(self)->stop(self, release);
    if (old_pid > 0)
        _LOGI("canceled DHCP transaction, DHCP client pid %d", old_pid);
    else
        _LOGI("canceled DHCP transaction");
    nm_assert(priv->pid == -1);

    nm_dhcp_client_set_state(self, NM_DHCP_STATE_TERMINATED, NULL);
}

/*****************************************************************************/

static char *
bytearray_variant_to_string(NMDhcpClient *self, GVariant *value, const char *key)
{
    const guint8 *array;
    gsize         length;
    GString      *str;
    int           i;
    unsigned char c;
    char         *converted = NULL;

    g_return_val_if_fail(value != NULL, NULL);

    array = g_variant_get_fixed_array(value, &length, 1);

    /* Since the DHCP options come through environment variables, they should
     * already be UTF-8 safe, but just make sure.
     */
    str = g_string_sized_new(length);
    for (i = 0; i < length; i++) {
        c = array[i];

        /* Convert NULLs to spaces and non-ASCII characters to ? */
        if (c == '\0')
            c = ' ';
        else if (c > 127)
            c = '?';
        str = g_string_append_c(str, c);
    }
    str = g_string_append_c(str, '\0');

    converted = str->str;
    if (!g_utf8_validate(converted, -1, NULL))
        _LOGW("option '%s' couldn't be converted to UTF-8", key);
    g_string_free(str, FALSE);
    return converted;
}

static int
label_is_unknown_xyz(const char *label)
{
    if (!NM_STR_HAS_PREFIX(label, "unknown_"))
        return -EINVAL;

    label += NM_STRLEN("unknown_");
    if (label[0] != '2' || !g_ascii_isdigit(label[1]) || !g_ascii_isdigit(label[2])
        || label[3] != '\0')
        return -EINVAL;

    return _nm_utils_ascii_str_to_int64(label, 10, 224, 254, -EINVAL);
}

#define OLD_TAG "old_"
#define NEW_TAG "new_"

static void
maybe_add_option(NMDhcpClient *self, GHashTable *hash, const char *key, GVariant *value)
{
    char *str_value = NULL;

    g_return_if_fail(g_variant_is_of_type(value, G_VARIANT_TYPE_BYTESTRING));

    if (g_str_has_prefix(key, OLD_TAG))
        return;

    /* Filter out stuff that's not actually new DHCP options */
    if (NM_IN_STRSET(key, "interface", "pid", "reason", "dhcp_message_type"))
        return;

    if (NM_STR_HAS_PREFIX(key, NEW_TAG))
        key += NM_STRLEN(NEW_TAG);
    if (NM_STR_HAS_PREFIX(key, "private_") || !key[0])
        return;

    str_value = bytearray_variant_to_string(self, value, key);
    if (str_value) {
        int priv_opt_num;

        g_hash_table_insert(hash, g_strdup(key), str_value);

        /* dhclient has no special labels for private dhcp options: it uses "unknown_xyz"
         * labels for that. We need to identify those to alias them to our "private_xyz"
         * format unused in the internal dchp plugins.
         */
        if ((priv_opt_num = label_is_unknown_xyz(key)) > 0) {
            gs_free guint8 *check_val = NULL;
            char           *hex_str   = NULL;
            gsize           len;

            /* dhclient passes values from dhcp private options in its own "string" format:
             * if the raw values are printable as ascii strings, it will pass the string
             * representation; if the values are not printable as an ascii string, it will
             * pass a string displaying the hex values (hex string). Try to enforce passing
             * always an hex string, converting string representation if needed.
             */
            check_val = nm_utils_hexstr2bin_alloc(str_value, FALSE, TRUE, ":", 0, &len);
            hex_str   = nm_utils_bin2hexstr_full(check_val ?: (guint8 *) str_value,
                                               check_val ? len : strlen(str_value),
                                               ':',
                                               FALSE,
                                               NULL);
            g_hash_table_insert(hash, g_strdup_printf("private_%d", priv_opt_num), hex_str);
        }
    }
}

void
nm_dhcp_client_emit_ipv6_prefix_delegated(NMDhcpClient *self, const NMPlatformIP6Address *prefix)
{
    const NMDhcpClientNotifyData notify_data = {
        .notify_type = NM_DHCP_CLIENT_NOTIFY_TYPE_PREFIX_DELEGATED,
        .prefix_delegated =
            {
                .prefix = prefix,
            },
    };

    _emit_notify(self, &notify_data);
}

gboolean
nm_dhcp_client_handle_event(gpointer      unused,
                            const char   *iface,
                            int           pid,
                            GVariant     *options,
                            const char   *reason,
                            NMDhcpClient *self)
{
    NMDhcpClientPrivate                    *priv;
    guint32                                 new_state;
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd   = NULL;
    NMPlatformIP6Address                    prefix = {
        0,
    };

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);
    g_return_val_if_fail(iface != NULL, FALSE);
    g_return_val_if_fail(pid > 0, FALSE);
    g_return_val_if_fail(g_variant_is_of_type(options, G_VARIANT_TYPE_VARDICT), FALSE);
    g_return_val_if_fail(reason != NULL, FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (!nm_streq0(priv->config.iface, iface))
        return FALSE;
    if (priv->pid != pid)
        return FALSE;

    new_state = reason_to_state(reason);

    if (new_state == NM_DHCP_STATE_UNKNOWN)
        _LOGD("unmapped DHCP state '%s'", reason);

    if (new_state == NM_DHCP_STATE_NOOP)
        return TRUE;

    _LOGD("DHCP state '%s' -> '%s' (reason: '%s')",
          nm_dhcp_state_to_string(priv->state),
          nm_dhcp_state_to_string(new_state),
          reason);
    priv->state = new_state;

    if (NM_IN_SET(new_state, NM_DHCP_STATE_BOUND, NM_DHCP_STATE_EXTENDED)) {
        gs_unref_hashtable GHashTable *str_options = NULL;
        GVariantIter                   iter;
        const char                    *name;
        GVariant                      *value;

        /* Copy options */
        str_options = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
        g_variant_iter_init(&iter, options);
        while (g_variant_iter_next(&iter, "{&sv}", &name, &value)) {
            maybe_add_option(self, str_options, name, value);
            g_variant_unref(value);
        }

        /* Create the IP config */
        if (g_hash_table_size(str_options) > 0) {
            if (priv->config.addr_family == AF_INET) {
                l3cd = nm_dhcp_utils_ip4_config_from_options(
                    nm_l3cfg_get_multi_idx(priv->config.l3cfg),
                    nm_l3cfg_get_ifindex(priv->config.l3cfg),
                    priv->config.iface,
                    str_options);
            } else {
                prefix = nm_dhcp_utils_ip6_prefix_from_options(str_options);
                l3cd   = nm_dhcp_utils_ip6_config_from_options(
                    nm_l3cfg_get_multi_idx(priv->config.l3cfg),
                    nm_l3cfg_get_ifindex(priv->config.l3cfg),
                    priv->config.iface,
                    str_options,
                    priv->config.v6.info_only);
            }
        } else
            g_warn_if_reached();

        if (l3cd) {
            nm_l3_config_data_set_dhcp_lease_from_options(l3cd,
                                                          priv->config.addr_family,
                                                          g_steal_pointer(&str_options));
        }
    }

    if (!IN6_IS_ADDR_UNSPECIFIED(&prefix.address)) {
        /* If we got an IPv6 prefix to delegate, we don't change the state
         * of the DHCP client instance. Instead, we just signal the prefix
         * to the device. */
        nm_dhcp_client_emit_ipv6_prefix_delegated(self, &prefix);
        return TRUE;
    }

    /* Fail if no valid IP config was received */
    if (NM_IN_SET(new_state, NM_DHCP_STATE_BOUND, NM_DHCP_STATE_EXTENDED) && !l3cd) {
        _LOGW("client bound but IP config not received");
        new_state = NM_DHCP_STATE_FAIL;
    }

    nm_dhcp_client_set_state(self, new_state, l3cd);
    return TRUE;
}

gboolean
nm_dhcp_client_server_id_is_rejected(NMDhcpClient *self, gconstpointer addr)
{
    NMDhcpClientPrivate *priv  = NM_DHCP_CLIENT_GET_PRIVATE(self);
    in_addr_t            addr4 = *(in_addr_t *) addr;
    guint                i;

    /* IPv6 not implemented yet */
    nm_assert(priv->config.addr_family == AF_INET);

    if (!priv->config.reject_servers || !priv->config.reject_servers[0])
        return FALSE;

    for (i = 0; priv->config.reject_servers[i]; i++) {
        in_addr_t r_addr;
        in_addr_t mask;
        int       r_prefix;

        if (!nm_utils_parse_inaddr_prefix_bin(AF_INET,
                                              priv->config.reject_servers[i],
                                              NULL,
                                              &r_addr,
                                              &r_prefix))
            nm_assert_not_reached();
        mask = _nm_utils_ip4_prefix_to_netmask(r_prefix < 0 ? 32 : r_prefix);
        if ((addr4 & mask) == (r_addr & mask))
            return TRUE;
    }

    return FALSE;
}

static void
config_init(NMDhcpClientConfig *config, const NMDhcpClientConfig *src)
{
    *config = *src;

    g_object_ref(config->l3cfg);

    if (config->hwaddr)
        g_bytes_ref(config->hwaddr);
    if (config->bcast_hwaddr)
        g_bytes_ref(config->bcast_hwaddr);
    if (config->vendor_class_identifier)
        g_bytes_ref(config->vendor_class_identifier);
    if (config->client_id)
        g_bytes_ref(config->client_id);

    config->iface           = g_strdup(config->iface);
    config->uuid            = g_strdup(config->uuid);
    config->anycast_address = g_strdup(config->anycast_address);
    config->hostname        = g_strdup(config->hostname);
    config->mud_url         = g_strdup(config->mud_url);

    config->reject_servers = (const char *const *) nm_strv_dup(config->reject_servers, -1, TRUE);

    if (config->addr_family == AF_INET) {
        config->v4.last_address = g_strdup(config->v4.last_address);
    } else if (config->addr_family == AF_INET6) {
        config->hwaddr       = NULL;
        config->bcast_hwaddr = NULL;
        config->use_fqdn     = TRUE;
    } else {
        nm_assert_not_reached();
    }

    if (!config->hostname && config->send_hostname) {
        const char   *hostname;
        gs_free char *hostname_tmp = NULL;

        hostname = nm_hostname_manager_get_static_hostname(nm_hostname_manager_get());

        if (nm_utils_is_specific_hostname(hostname)) {
            if (config->addr_family == AF_INET) {
                char *dot;

                hostname_tmp = g_strdup(hostname);
                dot          = strchr(hostname_tmp, '.');
                if (dot)
                    *dot = '\0';
            }
            config->hostname = hostname_tmp ? g_steal_pointer(&hostname_tmp) : g_strdup(hostname);
        }
    }

    if (config->hostname) {
        if (!config->send_hostname) {
            nm_clear_g_free((gpointer *) &config->hostname);
        } else if ((config->use_fqdn && !nm_sd_dns_name_is_valid(config->hostname))
                   || (!config->use_fqdn && !nm_hostname_is_valid(config->hostname, FALSE))) {
            nm_log_warn(LOGD_DHCP,
                        "dhcp%c: %s '%s' is invalid, will be ignored",
                        nm_utils_addr_family_to_char(config->addr_family),
                        config->use_fqdn ? "FQDN" : "hostname",
                        config->hostname);
            nm_clear_g_free((gpointer *) &config->hostname);
        }
    }
}

static void
config_clear(NMDhcpClientConfig *config)
{
    g_object_unref(config->l3cfg);

    nm_clear_pointer(&config->hwaddr, g_bytes_unref);
    nm_clear_pointer(&config->bcast_hwaddr, g_bytes_unref);
    nm_clear_pointer(&config->vendor_class_identifier, g_bytes_unref);
    nm_clear_pointer(&config->client_id, g_bytes_unref);

    nm_clear_g_free((gpointer *) &config->iface);
    nm_clear_g_free((gpointer *) &config->uuid);
    nm_clear_g_free((gpointer *) &config->anycast_address);
    nm_clear_g_free((gpointer *) &config->hostname);
    nm_clear_g_free((gpointer *) &config->mud_url);

    nm_clear_pointer((gpointer *) &config->reject_servers, g_strfreev);

    if (config->addr_family == AF_INET) {
        nm_clear_g_free((gpointer *) &config->v4.last_address);
    }
}

int
nm_dhcp_client_get_addr_family(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return priv->config.addr_family;
}

const char *
nm_dhcp_client_get_iface(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return priv->config.iface;
}

NMDedupMultiIndex *
nm_dhcp_client_get_multi_idx(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return nm_l3cfg_get_multi_idx(priv->config.l3cfg);
}

int
nm_dhcp_client_get_ifindex(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return nm_l3cfg_get_ifindex(priv->config.l3cfg);
}

GBytes *
nm_dhcp_client_get_effective_client_id(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return priv->effective_client_id;
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_CONFIG:
        /* construct-only */
        config_init(&priv->config, g_value_get_pointer(value));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_dhcp_client_init(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv;

    priv        = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_DHCP_CLIENT, NMDhcpClientPrivate);
    self->_priv = priv;

    priv->pid = -1;
}

static void
dispose(GObject *object)
{
    NMDhcpClient        *self = NM_DHCP_CLIENT(object);
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_dhcp_client_stop(self, FALSE);

    watch_cleanup(self);

    nm_clear_g_source_inst(&priv->no_lease_timeout_source);
    nm_clear_g_source_inst(&priv->ipv6_lladdr_timeout_source);
    nm_clear_pointer(&priv->effective_client_id, g_bytes_unref);

    G_OBJECT_CLASS(nm_dhcp_client_parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
    NMDhcpClient        *self = NM_DHCP_CLIENT(object);
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    config_clear(&priv->config);

    G_OBJECT_CLASS(nm_dhcp_client_parent_class)->finalize(object);
}

static void
nm_dhcp_client_class_init(NMDhcpClientClass *client_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(client_class);

    g_type_class_add_private(client_class, sizeof(NMDhcpClientPrivate));

    object_class->dispose      = dispose;
    object_class->finalize     = finalize;
    object_class->set_property = set_property;

    client_class->stop     = stop;
    client_class->get_duid = get_duid;

    obj_properties[PROP_CONFIG] =
        g_param_spec_pointer(NM_DHCP_CLIENT_CONFIG,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[SIGNAL_NOTIFY] =
        g_signal_new(NM_DHCP_CLIENT_NOTIFY,
                     G_OBJECT_CLASS_TYPE(object_class),
                     G_SIGNAL_RUN_FIRST,
                     0,
                     NULL,
                     NULL,
                     g_cclosure_marshal_VOID__POINTER,
                     G_TYPE_NONE,
                     1,
                     G_TYPE_POINTER /* const NMDhcpClientNotifyData *notify_data */);
}
