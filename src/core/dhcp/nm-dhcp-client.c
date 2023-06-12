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

/* This is how long we do ACD for each entry and reject new offers for
 * the same address. Note that the maximum ACD timeout is limited to 30 seconds
 * (NM_ACD_TIMEOUT_MAX_MSEC).
 **/
#define ACD_REGLIST_GRACE_PERIOD_MSEC 300000u

G_STATIC_ASSERT(ACD_REGLIST_GRACE_PERIOD_MSEC > (NM_ACD_TIMEOUT_MAX_MSEC + 1000));

#define ACD_REGLIST_MAX_ENTRIES 30

/* To do ACD for an address (new lease), we will register a NML3ConfigData
 * with l3cfg. After ACD completes, we still continue having NML3Cfg
 * watch that address, for ACD_REGLIST_GRACE_PERIOD_MSEC. The reasons are:
 *
 * - the caller is supposed to actually configure the address right after
 *   ACD passed. We would not want to drop the ACD state before the caller
 *   got a chance to do that.
 * - when ACD fails, we decline the address and expect the DHCP client
 *   to present a new lease. We may want to outright reject the address,
 *   if ACD is bad. Thus, we want to keep running ACD for the address a bit
 *   longer, so that future requests for the same address can be rejected.
 *
 * This data structure is used for tracking the registered ACD address.
 */
typedef struct {
    const NML3ConfigData *l3cd;
    gint64                expiry_msec;
    in_addr_t             addr;
} AcdRegListData;

/*****************************************************************************/

enum {
    SIGNAL_NOTIFY,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

NM_GOBJECT_PROPERTIES_DEFINE(NMDhcpClient, PROP_CONFIG, );

typedef struct _NMDhcpClientPrivate {
    NMDhcpClientConfig config;

    /* This is the "next" data. That is, the one what was received last via
     * _nm_dhcp_client_notify(), but which is currently pending on ACD. */
    const NML3ConfigData *l3cd_next;

    /* This is the currently exposed data. It passed ACD (or no ACD was performed),
     * and is set from l3cd_next. */
    const NML3ConfigData *l3cd_curr;

    GSource *previous_lease_timeout_source;
    GSource *no_lease_timeout_source;
    GSource *watch_source;
    GBytes  *effective_client_id;

    union {
        struct {
            struct {
                NML3CfgCommitTypeHandle *l3cfg_commit_handle;
                GSource                 *done_source;

                /* When we do ACD for a l3cd lease, we will keep running ACD for
                 * the grace period ACD_REGLIST_GRACE_PERIOD_MSEC, even if we already
                 * determined the state. There are two reasons for that:
                 *
                 * - after ACD completes we notify the lease to the user, who is supposed
                 *   to configure the address in NML3Cfg. If we were already removing the
                 *   ACD state from NML3Cfg, ACD might need to start over. Instead, when
                 *   the caller tries to configure the address, ACD state is already good.
                 *
                 * - if we decline on ACD offer, we may want to keep running and
                 *   select other offers. Offers for which we just failed ACD (within
                 *   ACD_REGLIST_GRACE_PERIOD_MSEC) are rejected. See _nm_dhcp_client_accept_offer().
                 *   For that, we keep monitoring the ACD state for up to ACD_REGLIST_MAX_ENTRIES
                 *   addresses, to not restart and select the same lease twice in a row.
                 */
                GArray  *reglist;
                GSource *reglist_timeout_source;

                in_addr_t    addr;
                NMOptionBool state;
            } acd;
        } v4;
        struct {
            GSource *lladdr_timeout_source;
            GSource *dad_timeout_source;
        } v6;
    };

    GDBusMethodInvocation *invocation;

    struct {
        gulong id;
        bool   wait_dhcp_commit : 1;
        bool   wait_ipv6_dad : 1;
        bool   wait_ll_address : 1;
    } l3cfg_notify;

    pid_t pid;
    bool  is_stopped : 1;
} NMDhcpClientPrivate;

G_DEFINE_ABSTRACT_TYPE(NMDhcpClient, nm_dhcp_client, G_TYPE_OBJECT)

#define NM_DHCP_CLIENT_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDhcpClient, NM_IS_DHCP_CLIENT)

/*****************************************************************************/

#define L3CD_ACD_TAG(priv) (&(priv)->v4.acd.addr)

static gboolean _dhcp_client_accept(NMDhcpClient *self, const NML3ConfigData *l3cd, GError **error);

static gboolean _dhcp_client_decline(NMDhcpClient         *self,
                                     const NML3ConfigData *l3cd,
                                     const char           *error_message,
                                     GError              **error);

static void
l3_cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMDhcpClient *self);

static void _acd_reglist_timeout_reschedule(NMDhcpClient *self, gint64 now_msec);

static void _acd_reglist_data_remove(NMDhcpClient *self, guint idx, gboolean do_log);

/*****************************************************************************/

/* we use pid=-1 for invalid PIDs. Ensure that pid_t can hold negative values. */
G_STATIC_ASSERT(!(((pid_t) -1) > 0));

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(nm_dhcp_client_event_type_to_string,
                           NMDhcpClientEventType,
                           NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT(NULL),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_BOUND, "bound"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_EXPIRE, "expire"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED, "extended"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_FAIL, "fail"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_TERMINATED,
                                                    "terminated"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT, "timeout"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DHCP_CLIENT_EVENT_TYPE_UNSPECIFIED,
                                                    "unspecified"), );

/*****************************************************************************/

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

const char *
nm_dhcp_client_get_iface_type_for_log(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return priv->config.iface_type_log;
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

const NMDhcpClientConfig *
nm_dhcp_client_get_config(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return &priv->config;
}

GBytes *
nm_dhcp_client_get_effective_client_id(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return priv->effective_client_id;
}

NML3ConfigData *
nm_dhcp_client_create_l3cd(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    return nm_l3_config_data_new(nm_l3cfg_get_multi_idx(priv->config.l3cfg),
                                 nm_l3cfg_get_ifindex(priv->config.l3cfg),
                                 NM_IP_CONFIG_SOURCE_DHCP);
}

GHashTable *
nm_dhcp_client_create_options_dict(NMDhcpClient *self, gboolean static_keys)
{
    NMDhcpClientPrivate *priv    = NM_DHCP_CLIENT_GET_PRIVATE(self);
    const int            IS_IPv4 = NM_IS_IPv4(priv->config.addr_family);
    GHashTable          *options;
    GBytes              *effective_client_id;

    options = nm_dhcp_option_create_options_dict(static_keys);

    effective_client_id = nm_dhcp_client_get_effective_client_id(self);
    if (effective_client_id) {
        guint option = IS_IPv4 ? NM_DHCP_OPTION_DHCP4_CLIENT_ID : NM_DHCP_OPTION_DHCP6_CLIENT_ID;
        gs_free char *str = nm_dhcp_utils_duid_to_string(effective_client_id);

        /* Note that for the nm-dhcp-helper based plugins (dhclient), the plugin
         * may send the used client-id/DUID via the environment variables and
         * overwrite them yet again. */

        nm_dhcp_option_take_option(options,
                                   static_keys,
                                   priv->config.addr_family,
                                   option,
                                   g_steal_pointer(&str));
    }

    return options;
}

const NML3ConfigData *
nm_dhcp_client_get_lease(NMDhcpClient *self)
{
    return NM_DHCP_CLIENT_GET_PRIVATE(self)->l3cd_curr;
}

/*****************************************************************************/

gboolean
nm_dhcp_client_set_effective_client_id(NMDhcpClient *self, GBytes *client_id)
{
    NMDhcpClientPrivate   *priv              = NM_DHCP_CLIENT_GET_PRIVATE(self);
    gs_free char          *tmp_str           = NULL;
    gs_unref_bytes GBytes *client_id_to_free = NULL;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);
    g_return_val_if_fail(!client_id || g_bytes_get_size(client_id) >= 2, FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (nm_g_bytes_equal0(priv->effective_client_id, client_id))
        return FALSE;

    client_id_to_free         = g_steal_pointer(&priv->effective_client_id);
    priv->effective_client_id = nm_g_bytes_ref(client_id);

    _LOGT("%s: set effective %s",
          priv->config.addr_family == AF_INET6 ? "duid" : "client-id",
          priv->effective_client_id
              ? (tmp_str = nm_dhcp_utils_duid_to_string(priv->effective_client_id))
              : "default");

    return TRUE;
}

/*****************************************************************************/

static void
_emit_notify_data(NMDhcpClient *self, const NMDhcpClientNotifyData *notify_data)
{
    g_signal_emit(G_OBJECT(self), signals[SIGNAL_NOTIFY], 0, notify_data);
}

#define _emit_notify(self, _notify_type, ...) \
    _emit_notify_data(                        \
        (self),                               \
        &((const NMDhcpClientNotifyData){.notify_type = (_notify_type), __VA_ARGS__}))

/*****************************************************************************/

static void
l3_cfg_notify_check_connected(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    gboolean             do_connect;

    do_connect = priv->l3cfg_notify.wait_dhcp_commit | priv->l3cfg_notify.wait_ll_address
                 | priv->l3cfg_notify.wait_ipv6_dad
                 | (NM_IS_IPv4(priv->config.addr_family) && priv->v4.acd.l3cfg_commit_handle);

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

/*****************************************************************************/

pid_t
nm_dhcp_client_get_pid(NMDhcpClient *self)
{
    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), -1);

    return NM_DHCP_CLIENT_GET_PRIVATE(self)->pid;
}

static void
watch_cleanup(NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->watch_source);
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

/*****************************************************************************/

static gboolean
_no_lease_timeout(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->no_lease_timeout_source);
    _emit_notify(self, NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT);
    return G_SOURCE_CONTINUE;
}

static void
_no_lease_timeout_schedule(NMDhcpClient *self)
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

/*****************************************************************************/

static void
_acd_state_reset(NMDhcpClient *self, gboolean forget_addr, gboolean forget_reglist)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (!NM_IS_IPv4(priv->config.addr_family))
        return;

    if (priv->v4.acd.addr != INADDR_ANY) {
        nm_l3cfg_commit_type_clear(priv->config.l3cfg, &priv->v4.acd.l3cfg_commit_handle);
        l3_cfg_notify_check_connected(self);
        nm_clear_g_source_inst(&priv->v4.acd.done_source);
        if (forget_addr) {
            priv->v4.acd.addr  = INADDR_ANY;
            priv->v4.acd.state = NM_OPTION_BOOL_DEFAULT;
        }
    } else
        nm_assert(priv->v4.acd.state == NM_OPTION_BOOL_DEFAULT);

    if (forget_reglist) {
        guint n;

        while ((n = nm_g_array_len(priv->v4.acd.reglist)) > 0)
            _acd_reglist_data_remove(self, n - 1, TRUE);
    }

    nm_assert(!priv->v4.acd.l3cfg_commit_handle);
    nm_assert(!priv->v4.acd.done_source);
    nm_assert(!forget_reglist
              || !nm_l3cfg_remove_config_all(priv->config.l3cfg, L3CD_ACD_TAG(priv)));
}

static gboolean
_acd_complete_on_idle_cb(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_assert(NM_IS_IPv4(priv->config.addr_family));
    nm_assert(priv->v4.acd.addr != INADDR_ANY);
    nm_assert(!priv->v4.acd.l3cfg_commit_handle);
    nm_assert(priv->l3cd_next);

    _acd_state_reset(self, FALSE, FALSE);

    _nm_dhcp_client_notify(self, NM_DHCP_CLIENT_EVENT_TYPE_BOUND, priv->l3cd_next);

    return G_SOURCE_CONTINUE;
}

#define _acd_reglist_data_get(priv, idx) \
    (&nm_g_array_index((priv)->v4.acd.reglist, AcdRegListData, (idx)))

static guint
_acd_reglist_data_find(NMDhcpClientPrivate *priv, in_addr_t addr_needle)
{
    const guint n = nm_g_array_len(priv->v4.acd.reglist);
    guint       i;

    nm_assert(addr_needle != INADDR_ANY);

    for (i = 0; i < n; i++) {
        AcdRegListData *reglist_data = _acd_reglist_data_get(priv, i);

        if (reglist_data->addr == addr_needle)
            return i;
    }
    return G_MAXUINT;
}

static void
_acd_reglist_data_remove(NMDhcpClient *self, guint idx, gboolean do_log)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    AcdRegListData      *reglist_data;

    nm_assert(idx < nm_g_array_len(priv->v4.acd.reglist));

    reglist_data = _acd_reglist_data_get(priv, idx);

    if (do_log) {
        char sbuf_addr[NM_INET_ADDRSTRLEN];

        _LOGD("acd: drop check for address %s (l3cd " NM_HASH_OBFUSCATE_PTR_FMT ")",
              nm_inet4_ntop(reglist_data->addr, sbuf_addr),
              NM_HASH_OBFUSCATE_PTR(reglist_data->l3cd));
    }

    if (!nm_l3cfg_remove_config(priv->config.l3cfg, L3CD_ACD_TAG(priv), reglist_data->l3cd))
        nm_assert_not_reached();

    nm_clear_l3cd(&reglist_data->l3cd);

    nm_l3cfg_commit_on_idle_schedule(priv->config.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);

    g_array_remove_index(priv->v4.acd.reglist, idx);

    if (priv->v4.acd.reglist->len == 0) {
        nm_clear_pointer(&priv->v4.acd.reglist, g_array_unref);
        nm_clear_g_source_inst(&priv->v4.acd.reglist_timeout_source);
    }
}

static gboolean
_acd_reglist_timeout_cb(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    gint64               now_msec;

    nm_clear_g_source_inst(&priv->v4.acd.reglist_timeout_source);

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    while (nm_g_array_len(priv->v4.acd.reglist) > 0) {
        AcdRegListData *reglist_data = _acd_reglist_data_get(priv, 0);

        if (reglist_data->expiry_msec > now_msec)
            break;

        _acd_reglist_data_remove(self, 0, TRUE);
    }

    _acd_reglist_timeout_reschedule(self, now_msec);

    return G_SOURCE_CONTINUE;
}

static void
_acd_reglist_timeout_reschedule(NMDhcpClient *self, gint64 now_msec)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    AcdRegListData      *reglist_data;

    if (nm_g_array_len(priv->v4.acd.reglist) == 0) {
        nm_assert(!priv->v4.acd.reglist_timeout_source);
        return;
    }

    if (priv->v4.acd.reglist_timeout_source) {
        /* already pending. As we only add new elements with a *later*
          * expiry, we don't need to ever cancel a pending timer. Worst
          * case, the timer fires, and there is nothing to do and we
          * reschedule. */
        return;
    }

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    reglist_data = _acd_reglist_data_get(priv, 0);

    nm_assert(reglist_data->expiry_msec > now_msec);

    priv->v4.acd.reglist_timeout_source =
        nm_g_timeout_add_source(reglist_data->expiry_msec - now_msec,
                                _acd_reglist_timeout_cb,
                                self);
}

static void
_acd_check_lease(NMDhcpClient *self, NMOptionBool *out_acd_state)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    char                 sbuf_addr[NM_INET_ADDRSTRLEN];
    in_addr_t            addr;
    gboolean             addr_changed = FALSE;
    guint                idx;
    gint64               now_msec;

    if (!NM_IS_IPv4(priv->config.addr_family))
        goto handle_no_acd;

    if (!priv->l3cd_next)
        goto handle_no_acd;

    /* an IPv4 lease is always expected to have exactly one address. */
    nm_assert(nm_l3_config_data_get_num_addresses(priv->l3cd_next, AF_INET) == 1);

    if (priv->config.v4.acd_timeout_msec == 0)
        goto handle_no_acd;

    addr = NMP_OBJECT_CAST_IP4_ADDRESS(
               nm_l3_config_data_get_first_obj(priv->l3cd_next, NMP_OBJECT_TYPE_IP4_ADDRESS, NULL))
               ->address;
    nm_assert(addr != INADDR_ANY);

    nm_clear_g_source_inst(&priv->v4.acd.done_source);

    if (priv->v4.acd.state != NM_OPTION_BOOL_DEFAULT && priv->v4.acd.addr == addr) {
        /* the ACD state is already determined. Return right away. */
        nm_assert(!priv->v4.acd.l3cfg_commit_handle);
        *out_acd_state = !!priv->v4.acd.state;
        return;
    }

    if (priv->v4.acd.addr != addr) {
        addr_changed      = TRUE;
        priv->v4.acd.addr = addr;
    }

    _LOGD("acd: %s check for address %s (timeout %u msec, l3cd " NM_HASH_OBFUSCATE_PTR_FMT ")",
          addr_changed ? "add" : "update",
          nm_inet4_ntop(addr, sbuf_addr),
          priv->config.v4.acd_timeout_msec,
          NM_HASH_OBFUSCATE_PTR(priv->l3cd_next));

    priv->v4.acd.state = NM_OPTION_BOOL_DEFAULT;

    if (nm_l3cfg_add_config(priv->config.l3cfg,
                            L3CD_ACD_TAG(priv),
                            FALSE,
                            priv->l3cd_next,
                            NM_L3CFG_CONFIG_PRIORITY_IPV4LL,
                            0,
                            0,
                            NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
                            NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                            0,
                            0,
                            NM_DNS_PRIORITY_DEFAULT_NORMAL,
                            NM_DNS_PRIORITY_DEFAULT_NORMAL,
                            NM_L3_ACD_DEFEND_TYPE_ONCE,
                            NM_MIN(priv->config.v4.acd_timeout_msec, NM_ACD_TIMEOUT_MAX_MSEC),
                            NM_L3CFG_CONFIG_FLAGS_ONLY_FOR_ACD,
                            NM_L3_CONFIG_MERGE_FLAGS_NONE))
        addr_changed = TRUE;

    if (!priv->v4.acd.reglist)
        priv->v4.acd.reglist = g_array_new(FALSE, FALSE, sizeof(AcdRegListData));

    idx = _acd_reglist_data_find(priv, addr);

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    g_array_append_val(priv->v4.acd.reglist,
                       ((AcdRegListData){
                           .l3cd        = nm_l3_config_data_ref(priv->l3cd_next),
                           .addr        = addr,
                           .expiry_msec = now_msec + ACD_REGLIST_GRACE_PERIOD_MSEC,
                       }));

    if (idx != G_MAXUINT) {
        /* we already tracked this "addr". We don't need to track it twice,
         * forget about this one. This also has the effect, that we will
         * always append the new entry to the list (so the list
         * stays sorted by the increasing timestamp). */
        _acd_reglist_data_remove(self, idx, FALSE);
    }

    if (priv->v4.acd.reglist->len > ACD_REGLIST_MAX_ENTRIES) {
        /* rate limit how many addresses we track for ACD. */
        _acd_reglist_data_remove(self, 0, TRUE);
    }

    _acd_reglist_timeout_reschedule(self, now_msec);

    if (!priv->v4.acd.l3cfg_commit_handle) {
        priv->v4.acd.l3cfg_commit_handle =
            nm_l3cfg_commit_type_register(priv->config.l3cfg,
                                          NM_L3_CFG_COMMIT_TYPE_UPDATE,
                                          NULL,
                                          "dhcp4-acd");
        l3_cfg_notify_check_connected(self);
    }

    if (addr_changed)
        nm_l3cfg_commit_on_idle_schedule(priv->config.l3cfg, NM_L3_CFG_COMMIT_TYPE_AUTO);

    /* ACD is started/pending... */
    nm_assert(priv->v4.acd.addr != INADDR_ANY);
    nm_assert(priv->v4.acd.state == NM_OPTION_BOOL_DEFAULT);
    nm_assert(priv->v4.acd.l3cfg_commit_handle);
    nm_assert(priv->l3cfg_notify.id);
    *out_acd_state = NM_OPTION_BOOL_DEFAULT;
    return;

handle_no_acd:
    /* Indicate that ACD is good (or disabled) by returning TRUE. */
    _acd_state_reset(self, TRUE, FALSE);
    *out_acd_state = NM_OPTION_BOOL_TRUE;
    return;
}

/*****************************************************************************/

gboolean
_nm_dhcp_client_accept_offer(NMDhcpClient *self, gconstpointer p_yiaddr)
{
    NMDhcpClientPrivate   *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    char                   sbuf_addr[NM_INET_ADDRSTRLEN];
    NMIPAddr               yiaddr;
    const NML3AcdAddrInfo *acd_info;

    if (!NM_IS_IPv4(priv->config.addr_family))
        return nm_assert_unreachable_val(FALSE);

    if (priv->config.v4.acd_timeout_msec == 0) {
        /* ACD is disabled. Note that we might track the address for other
         * reasons and have information about the ACD state below. But
         * with ACD disabled, we always ignore that information. */
        return TRUE;
    }

    nm_ip_addr_set(priv->config.addr_family, &yiaddr, p_yiaddr);

    /* Note that once we do ACD for a certain address, even after completing
     * it, we keep the l3cd registered in NML3Cfg for ACD_REGLIST_GRACE_PERIOD_MSEC
     * The idea is, that we don't yet turn off ACD for a grace period, so that
     * we can avoid selecting the same lease again.
     *
     * Note that we even check whether we have an ACD state if priv->v4.acd.reglist
     * is empty. Maybe for odd reasons, we track ACD for the address already. */

    acd_info = nm_l3cfg_get_acd_addr_info(priv->config.l3cfg, yiaddr.addr4);

    if (!acd_info)
        return TRUE;

    if (!NM_IN_SET(acd_info->state, NM_L3_ACD_ADDR_STATE_USED, NM_L3_ACD_ADDR_STATE_CONFLICT))
        return TRUE;

    _LOGD("offered lease rejected: address %s failed ACD check",
          nm_inet4_ntop(yiaddr.addr4, sbuf_addr));

    return FALSE;
}

void
_nm_dhcp_client_notify(NMDhcpClient         *self,
                       NMDhcpClientEventType client_event_type,
                       const NML3ConfigData *l3cd)
{
    NMDhcpClientPrivate                     *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    GHashTable                              *options;
    gboolean                                 l3cd_changed;
    NMOptionBool                             acd_state;
    const int                                IS_IPv4     = NM_IS_IPv4(priv->config.addr_family);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_merged = NULL;
    char                                     sbuf1[NM_HASH_OBFUSCATE_PTR_STR_BUF_SIZE];

    nm_assert(NM_IN_SET(client_event_type,
                        NM_DHCP_CLIENT_EVENT_TYPE_UNSPECIFIED,
                        NM_DHCP_CLIENT_EVENT_TYPE_BOUND,
                        NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED,
                        NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT,
                        NM_DHCP_CLIENT_EVENT_TYPE_EXPIRE,
                        NM_DHCP_CLIENT_EVENT_TYPE_FAIL,
                        NM_DHCP_CLIENT_EVENT_TYPE_TERMINATED));
    nm_assert((client_event_type >= NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT)
              == NM_IN_SET(client_event_type,
                           NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT,
                           NM_DHCP_CLIENT_EVENT_TYPE_EXPIRE,
                           NM_DHCP_CLIENT_EVENT_TYPE_FAIL,
                           NM_DHCP_CLIENT_EVENT_TYPE_TERMINATED));
    nm_assert((!!l3cd)
              == NM_IN_SET(client_event_type,
                           NM_DHCP_CLIENT_EVENT_TYPE_BOUND,
                           NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED));

    nm_assert(!l3cd || NM_IS_L3_CONFIG_DATA(l3cd));
    nm_assert(!l3cd || nm_l3_config_data_get_dhcp_lease(l3cd, priv->config.addr_family));

    _LOGT("notify: event=%s%s%s",
          nm_dhcp_client_event_type_to_string(client_event_type),
          NM_PRINT_FMT_QUOTED2(l3cd, ", l3cd=", NM_HASH_OBFUSCATE_PTR_STR(l3cd, sbuf1), ""));

    nm_l3_config_data_seal(l3cd);

    if (client_event_type >= NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT)
        watch_cleanup(self);

    if (!IS_IPv4 && l3cd) {
        /* nm_dhcp_utils_merge_new_dhcp6_lease() relies on "life_starts" option
         * for merging, which is only set by dhclient. Internal client never sets that,
         * but it supports multiple IP addresses per lease. */
        if (nm_dhcp_utils_merge_new_dhcp6_lease(priv->l3cd_next, l3cd, &l3cd_merged)) {
            _LOGD("lease merged with existing one");
            l3cd = nm_l3_config_data_seal(l3cd_merged);
        }
    }

    if (l3cd) {
        nm_clear_g_source_inst(&priv->no_lease_timeout_source);
    } else
        _no_lease_timeout_schedule(self);

    l3cd_changed = nm_l3_config_data_reset(&priv->l3cd_next, l3cd);

    _acd_check_lease(self, &acd_state);

    options = priv->l3cd_next ? nm_dhcp_lease_get_options(
                  nm_l3_config_data_get_dhcp_lease(priv->l3cd_next, priv->config.addr_family))
                              : NULL;

    if (_LOGI_ENABLED()) {
        const char *req_str =
            IS_IPv4 ? nm_dhcp_option_request_string(AF_INET, NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS)
                    : nm_dhcp_option_request_string(AF_INET6, NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS);
        const char *addr = nm_g_hash_table_lookup(options, req_str);

        _LOGI("state changed %s%s%s%s",
              priv->l3cd_next ? "new lease" : "no lease",
              NM_PRINT_FMT_QUOTED2(addr, ", address=", addr, ""),
              acd_state == NM_OPTION_BOOL_DEFAULT ? ", acd pending"
                                                  : (acd_state ? "" : ", acd conflict"));
    }

    if (_LOGD_ENABLED()) {
        if (l3cd_changed && options) {
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

    if (acd_state == NM_OPTION_BOOL_DEFAULT) {
        /* ACD is in progress... */
        return;
    }

    if (!acd_state) {
        gs_free_error GError *error = NULL;

        /* We only decline. We don't actually emit to the caller that
         * something is wrong (like NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD).
         * If we would, NMDevice might decide to tear down the device, when
         * we actually should continue trying to get a better lease. There
         * is already "ipv4.dhcp-timeout" which will handle the failure if
         * we don't get a good lease. */
        if (!_dhcp_client_decline(self, priv->l3cd_next, "acd failed", &error))
            _LOGD("decline failed: %s", error->message);
        return;
    }

    if (priv->l3cd_next)
        nm_clear_g_source_inst(&priv->previous_lease_timeout_source);

    nm_l3_config_data_reset(&priv->l3cd_curr, priv->l3cd_next);
    priv->l3cfg_notify.wait_ipv6_dad = FALSE;

    if (client_event_type == NM_DHCP_CLIENT_EVENT_TYPE_BOUND && priv->l3cd_curr
        && nm_l3_config_data_get_num_addresses(priv->l3cd_curr, priv->config.addr_family) > 0)
        priv->l3cfg_notify.wait_dhcp_commit = TRUE;
    else
        priv->l3cfg_notify.wait_dhcp_commit = FALSE;

    if (!priv->l3cfg_notify.wait_dhcp_commit && priv->l3cd_curr) {
        gs_free_error GError *error = NULL;

        _LOGD("accept lease right away");
        if (!_dhcp_client_accept(self, priv->l3cd_curr, &error)) {
            _LOGD("accept failed: %s", error->message);
            /* Unclear why this happened, or what to do about it. Just proceed. */
        }
    }

    l3_cfg_notify_check_connected(self);

    _emit_notify(self,
                 NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE,
                 .lease_update = {
                     .l3cd     = priv->l3cd_curr,
                     .accepted = !priv->l3cfg_notify.wait_dhcp_commit,
                 });
}

static void
daemon_watch_cb(GPid pid, int status, gpointer user_data)
{
    NMDhcpClient        *self = NM_DHCP_CLIENT(user_data);
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    gs_free char        *desc = NULL;

    g_return_if_fail(priv->watch_source);

    priv->watch_source = NULL;

    _LOGI("client pid %d %s", pid, (desc = nm_utils_get_process_exit_status_desc(status)));

    priv->pid = -1;

    _nm_dhcp_client_notify(self, NM_DHCP_CLIENT_EVENT_TYPE_TERMINATED, NULL);
}

void
nm_dhcp_client_watch_child(NMDhcpClient *self, pid_t pid)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_if_fail(priv->pid == -1);
    priv->pid = pid;

    g_return_if_fail(!priv->watch_source);
    priv->watch_source = nm_g_child_watch_add_source(pid, daemon_watch_cb, self);
}

void
nm_dhcp_client_stop_watch_child(NMDhcpClient *self, pid_t pid)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_if_fail(priv->pid == pid);
    priv->pid = -1;

    watch_cleanup(self);
}

static gboolean
_accept(NMDhcpClient *self, const NML3ConfigData *l3cd, GError **error)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (!priv->invocation)
        return TRUE;

    g_dbus_method_invocation_return_value(g_steal_pointer(&priv->invocation), NULL);
    return TRUE;
}

static gboolean
_dhcp_client_accept(NMDhcpClient *self, const NML3ConfigData *l3cd, GError **error)
{
    NMDhcpClientClass *klass;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);
    nm_assert(l3cd);

    klass = NM_DHCP_CLIENT_GET_CLASS(self);

    g_return_val_if_fail(NM_DHCP_CLIENT_GET_PRIVATE(self)->l3cd_curr, FALSE);

    return klass->accept(self, l3cd, error);
}

static gboolean
decline(NMDhcpClient *self, const NML3ConfigData *l3cd, const char *error_message, GError **error)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    if (!priv->invocation) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "calling decline in unexpected script state");
        return FALSE;
    }
    g_dbus_method_invocation_return_error(g_steal_pointer(&priv->invocation),
                                          NM_DEVICE_ERROR,
                                          NM_DEVICE_ERROR_FAILED,
                                          NM_IS_IPv4(priv->config.addr_family) ? "ACD failed"
                                                                               : "DAD failed");
    return TRUE;
}

static gboolean
_dhcp_client_decline(NMDhcpClient         *self,
                     const NML3ConfigData *l3cd,
                     const char           *error_message,
                     GError              **error)
{
    NMDhcpClientClass *klass;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);
    nm_assert(l3cd);

    klass = NM_DHCP_CLIENT_GET_CLASS(self);

    g_return_val_if_fail(NM_DHCP_CLIENT_GET_PRIVATE(self)->l3cd_next, FALSE);

    return klass->decline(self, l3cd, error_message, error);
}

static gboolean
ipv6_lladdr_timeout(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->v6.lladdr_timeout_source);

    _emit_notify(self,
                 NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                 .it_looks_bad.reason =
                     "timeout reached while waiting for an IPv6 link-local address");
    return G_SOURCE_CONTINUE;
}

static gboolean
ipv6_dad_timeout(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->v6.dad_timeout_source);

    _emit_notify(self,
                 NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                 .it_looks_bad.reason = "timeout reached while waiting for IPv6 DAD to complete");
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

    nm_assert(!NM_IS_IPv4(priv->config.addr_family));

    l3cfg = priv->config.l3cfg;
    nmp_lookup_init_object_by_ifindex(&lookup,
                                      NMP_OBJECT_TYPE_IP6_ADDRESS,
                                      nm_l3cfg_get_ifindex(l3cfg));

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
ipv6_tentative_addr_check(NMDhcpClient                *self,
                          GPtrArray                  **tentative,
                          GPtrArray                  **dadfailed,
                          const NMPlatformIP6Address **valid)
{
    NMDhcpClientPrivate        *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    NMDedupMultiIter            iter;
    const NMPlatformIP6Address *addr;
    NML3Cfg                    *l3cfg    = priv->config.l3cfg;
    NMPlatform                 *platform = nm_l3cfg_get_platform(l3cfg);
    int                         ifindex  = nm_l3cfg_get_ifindex(l3cfg);

    /* For each address in the lease, check whether it's tentative
     * or dad-failed in platform. */
    nm_l3_config_data_iter_ip6_address_for_each (&iter, priv->l3cd_curr, &addr) {
        const NMPlatformIP6Address *pladdr;

        pladdr = nm_platform_ip6_address_get(platform, ifindex, &addr->address);
        if ((pladdr && NM_FLAGS_HAS(pladdr->n_ifa_flags, IFA_F_DADFAILED))
            || (!pladdr && nm_platform_ip6_dadfailed_check(platform, ifindex, &addr->address))) {
            if (dadfailed) {
                if (!*dadfailed)
                    *dadfailed = g_ptr_array_new();
                g_ptr_array_add(*dadfailed, (gpointer) addr);
            }
            continue;
        }

        if (pladdr && NM_FLAGS_HAS(pladdr->n_ifa_flags, IFA_F_TENTATIVE)
            && !NM_FLAGS_HAS(pladdr->n_ifa_flags, IFA_F_OPTIMISTIC)) {
            if (tentative) {
                if (!*tentative)
                    *tentative = g_ptr_array_new();
                g_ptr_array_add(*tentative, (gpointer) addr);
            }
        }

        /* Here the address is non-tentative or it was removed externally by the user.
         * In both cases it has completed DAD.
         */
        NM_SET_OUT(valid, addr);
    }
}

static void
l3_cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMDhcpClient *self)
{
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);
    char                 sbuf_addr[NM_INET_ADDRSTRLEN];

    nm_assert(l3cfg == priv->config.l3cfg);

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE
        && priv->l3cfg_notify.wait_ll_address) {
        const NMPlatformIP6Address *addr;
        gs_free_error GError       *error = NULL;

        addr = ipv6_lladdr_find(self);
        if (addr) {
            _LOGD("got IPv6LL address, starting transaction");
            priv->l3cfg_notify.wait_ll_address = FALSE;
            l3_cfg_notify_check_connected(self);
            nm_clear_g_source_inst(&priv->v6.lladdr_timeout_source);

            _no_lease_timeout_schedule(self);

            if (!NM_DHCP_CLIENT_GET_CLASS(self)->ip6_start(self, &addr->address, &error)) {
                _emit_notify(self,
                             NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                             .it_looks_bad.reason = error->message);
            }
        }
    }

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE
        && priv->l3cfg_notify.wait_ipv6_dad) {
        gs_unref_ptrarray GPtrArray *tentative = NULL;
        gs_unref_ptrarray GPtrArray *dadfailed = NULL;
        const NMPlatformIP6Address  *valid     = NULL;
        char                         str[NM_UTILS_TO_STRING_BUFFER_SIZE];
        guint                        i;
        gs_free_error GError        *error = NULL;

        ipv6_tentative_addr_check(self, &tentative, &dadfailed, &valid);
        if (tentative) {
            for (i = 0; i < tentative->len; i++) {
                _LOGD("still waiting DAD for address: %s",
                      nm_platform_ip6_address_to_string(tentative->pdata[i], str, sizeof(str)));
            }
        } else {
            /* done */

            priv->l3cfg_notify.wait_ipv6_dad = FALSE;
            nm_clear_g_source_inst(&priv->v6.dad_timeout_source);
            l3_cfg_notify_check_connected(self);

            if (dadfailed) {
                for (i = 0; i < dadfailed->len; i++) {
                    _LOGE("DAD failed for address: %s",
                          nm_platform_ip6_address_to_string(dadfailed->pdata[i], str, sizeof(str)));
                }
            }

            if (valid) {
                /* at least one non-duplicate address */
                _LOGD("addresses in the lease completed DAD: accept the lease");

                if (_dhcp_client_accept(self, priv->l3cd_curr, &error)) {
                    _emit_notify(self,
                                 NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE,
                                 .lease_update = {
                                     .l3cd     = priv->l3cd_curr,
                                     .accepted = TRUE,
                                 });
                } else {
                    gs_free char *reason =
                        g_strdup_printf("error accepting lease: %s", error->message);

                    _LOGD("accept failed: %s", error->message);
                    _emit_notify(self,
                                 NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                                 .it_looks_bad.reason = reason);
                }
            } else {
                _LOGD("decline the lease");
                if (!_dhcp_client_decline(self, priv->l3cd_curr, "DAD failed", &error))
                    _LOGD("decline failed: %s", error->message);
            }
        }
    }

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT
        && priv->l3cfg_notify.wait_dhcp_commit) {
        const NML3ConfigData      *committed_l3cd;
        NMDedupMultiIter           ipconf_iter;
        const NMPlatformIPAddress *lease_address;
        gs_free_error GError      *error = NULL;

        /* A new configuration was committed to the interface. If we previously
         * got a lease, check whether we are waiting for the address to be
         * configured. If the address was added, we can proceed accepting the
         * lease and notifying NMDevice. */

        nm_l3_config_data_iter_ip_address_for_each (&ipconf_iter,
                                                    priv->l3cd_curr,
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
                goto wait_dhcp_commit_done;
        } else {
            const NMPlatformIP6Address  *address6  = (const NMPlatformIP6Address *) lease_address;
            gs_unref_ptrarray GPtrArray *tentative = NULL;
            char                         str[NM_UTILS_TO_STRING_BUFFER_SIZE];
            guint                        i;

            if (!nm_l3_config_data_lookup_address_6(committed_l3cd, &address6->address))
                goto wait_dhcp_commit_done;

            ipv6_tentative_addr_check(self, &tentative, NULL, NULL);
            if (tentative) {
                priv->l3cfg_notify.wait_ipv6_dad = TRUE;
                priv->v6.dad_timeout_source =
                    nm_g_timeout_add_seconds_source(30, ipv6_dad_timeout, self);
                for (i = 0; i < tentative->len; i++) {
                    _LOGD("wait DAD for address %s",
                          nm_platform_ip6_address_to_string(tentative->pdata[i], str, sizeof(str)));
                }
            } else {
                priv->l3cfg_notify.wait_ipv6_dad = FALSE;
                nm_clear_g_source_inst(&priv->v6.dad_timeout_source);
            }
        }

        priv->l3cfg_notify.wait_dhcp_commit = FALSE;

        l3_cfg_notify_check_connected(self);

        if (priv->config.addr_family == AF_INET || !priv->l3cfg_notify.wait_ipv6_dad) {
            _LOGD("accept lease");

            if (!_dhcp_client_accept(self, priv->l3cd_curr, &error)) {
                gs_free char *reason = g_strdup_printf("error accepting lease: %s", error->message);

                _LOGD("accept failed: %s", error->message);

                _emit_notify(self,
                             NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,
                             .it_looks_bad.reason = reason, );
                goto wait_dhcp_commit_done;
            }

            _emit_notify(self,
                         NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE,
                         .lease_update = {
                             .l3cd     = priv->l3cd_curr,
                             .accepted = TRUE,
                         });
        }
    }
wait_dhcp_commit_done:

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT
        && priv->v4.acd.l3cfg_commit_handle) {
        nm_assert(priv->v4.acd.addr != INADDR_ANY);
        nm_assert(priv->v4.acd.state == NM_OPTION_BOOL_DEFAULT);
        nm_assert(!priv->v4.acd.done_source);

        if (priv->v4.acd.addr == notify_data->acd_event.info.addr
            && nm_l3_acd_addr_info_find_track_info(&notify_data->acd_event.info,
                                                   L3CD_ACD_TAG(priv),
                                                   NULL,
                                                   NULL)) {
            NMOptionBool acd_state;

            switch (notify_data->acd_event.info.state) {
            default:
                nm_assert_not_reached();
                /* fall-through */
            case NM_L3_ACD_ADDR_STATE_INIT:
            case NM_L3_ACD_ADDR_STATE_PROBING:
                acd_state = NM_OPTION_BOOL_DEFAULT;
                break;
            case NM_L3_ACD_ADDR_STATE_USED:
            case NM_L3_ACD_ADDR_STATE_CONFLICT:
            case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
                acd_state = NM_OPTION_BOOL_FALSE;
                break;
            case NM_L3_ACD_ADDR_STATE_READY:
            case NM_L3_ACD_ADDR_STATE_DEFENDING:
                acd_state = NM_OPTION_BOOL_TRUE;
                break;
            }
            if (acd_state != NM_OPTION_BOOL_DEFAULT) {
                _LOGD("acd: acd %s for %s",
                      acd_state ? "ready" : "conflict",
                      nm_inet4_ntop(priv->v4.acd.addr, sbuf_addr));
                nm_l3cfg_commit_type_clear(priv->config.l3cfg, &priv->v4.acd.l3cfg_commit_handle);
                priv->v4.acd.state       = acd_state;
                priv->v4.acd.done_source = nm_g_idle_add_source(_acd_complete_on_idle_cb, self);
            }
        }
    }
}

static gboolean
_previous_lease_timeout_cb(gpointer user_data)
{
    NMDhcpClient        *self = user_data;
    NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->previous_lease_timeout_source);

    _nm_dhcp_client_notify(self, NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT, NULL);

    return G_SOURCE_CONTINUE;
}

gboolean
nm_dhcp_client_start(NMDhcpClient *self, GError **error)
{
    NMDhcpClientPrivate        *priv;
    const NMPlatformIP6Address *addr = NULL;
    int                         IS_IPv4;

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_val_if_fail(priv->pid == -1, FALSE);
    g_return_val_if_fail(priv->config.uuid, FALSE);
    nm_assert(!priv->effective_client_id);

    IS_IPv4 = NM_IS_IPv4(priv->config.addr_family);

    if (!IS_IPv4) {
        addr = ipv6_lladdr_find(self);
        if (!addr) {
            _LOGD("waiting for IPv6LL address");
            priv->l3cfg_notify.wait_ll_address = TRUE;
            l3_cfg_notify_check_connected(self);
            priv->v6.lladdr_timeout_source =
                nm_g_timeout_add_seconds_source(10, ipv6_lladdr_timeout, self);
            return TRUE;
        }
    }

    _no_lease_timeout_schedule(self);

    if (priv->config.previous_lease) {
        /* We got passed a previous lease (during a reapply). For a few seconds, we
         * will pretend that this is current lease. */
        priv->l3cd_curr = g_steal_pointer(&priv->config.previous_lease);

        /* Schedule a timeout for when we give up using this lease. Note
         * that then we will emit a NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE event
         * and the lease is gone. Note that NMDevice ignores that and will
         * keep using the lease.
         *
         * At the same time, we have _no_lease_timeout_schedule() ticking, when
         * that expires, we will emit a NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT
         * signal, which causes NMDevice to clear the lease. */
        priv->previous_lease_timeout_source =
            nm_g_timeout_add_seconds_source(15, _previous_lease_timeout_cb, self);
    }

    if (IS_IPv4)
        return NM_DHCP_CLIENT_GET_CLASS(self)->ip4_start(self, error);

    return NM_DHCP_CLIENT_GET_CLASS(self)->ip6_start(self, &addr->address, error);
}

/*****************************************************************************/

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

    nm_clear_g_source_inst(&priv->previous_lease_timeout_source);

    priv->is_stopped = TRUE;

    if (priv->invocation) {
        g_dbus_method_invocation_return_error(g_steal_pointer(&priv->invocation),
                                              NM_DEVICE_ERROR,
                                              NM_DEVICE_ERROR_FAILED,
                                              "dhcp stopping");
    }

    _acd_state_reset(self, TRUE, TRUE);

    priv->l3cfg_notify.wait_dhcp_commit = FALSE;
    priv->l3cfg_notify.wait_ll_address  = FALSE;
    priv->l3cfg_notify.wait_ipv6_dad    = FALSE;
    l3_cfg_notify_check_connected(self);

    /* Kill the DHCP client */
    old_pid = priv->pid;
    NM_DHCP_CLIENT_GET_CLASS(self)->stop(self, release);
    if (old_pid > 0)
        _LOGI("canceled DHCP transaction, DHCP client pid %d", old_pid);
    else
        _LOGI("canceled DHCP transaction");
    nm_assert(priv->pid == -1);

    nm_clear_l3cd(&priv->l3cd_next);
    nm_clear_l3cd(&priv->l3cd_curr);

    _nm_dhcp_client_notify(self, NM_DHCP_CLIENT_EVENT_TYPE_TERMINATED, NULL);
}

/*****************************************************************************/

static char *
bytearray_variant_to_string(GVariant *value)
{
    const guint8 *array;
    char         *str;
    gsize         length;
    gsize         i;

    nm_assert(value);

    array = g_variant_get_fixed_array(value, &length, 1);

    /* Since the DHCP options come originally came as environment variables, they
     * have not guaranteed encoding. Let's only accept ASCII here.
     */
    str = g_malloc(length + 1);
    for (i = 0; i < length; i++) {
        guint8 c = array[i];

        if (c == '\0')
            str[i] = ' ';
        else if (c > 127)
            str[i] = '?';
        else
            str[i] = (char) c;
    }
    str[i] = '\0';

    return str;
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
    const int IS_IPv4 = NM_IS_IPv4(NM_DHCP_CLIENT_GET_PRIVATE(self)->config.addr_family);
    char     *str_value;
    int       priv_opt_num;

    if (!g_variant_is_of_type(value, G_VARIANT_TYPE_BYTESTRING))
        return;

    if (NM_STR_HAS_PREFIX(key, OLD_TAG))
        return;

    /* Filter out stuff that's not actually new DHCP options */
    if (NM_IN_STRSET(key, "interface", "pid", "reason", "dhcp_message_type"))
        return;

    if (NM_STR_HAS_PREFIX(key, NEW_TAG))
        key += NM_STRLEN(NEW_TAG);
    if (NM_STR_HAS_PREFIX(key, "private_") || !key[0])
        return;

    str_value = bytearray_variant_to_string(value);
    if (!str_value)
        return;

    if ((IS_IPv4 && nm_streq(key, "dhcp_client_identifier"))
        || (!IS_IPv4 && nm_streq(key, "dhcp6_client_id"))) {
        gs_free char          *str   = g_steal_pointer(&str_value);
        gs_unref_bytes GBytes *bytes = NULL;

        /* Validate and normalize the client-id/DUID. */

        bytes = nm_utils_hexstr2bin(str);
        if (!bytes || g_bytes_get_size(bytes) < 2) {
            /* Seems invalid. Ignore */
            return;
        }

        if (!nm_dhcp_client_set_effective_client_id(self, bytes)) {
            /* the client-id is identical and we already set it. Nothing to do. */
            return;
        }

        /* The effective-client-id was (re)set. Update "hash" with the new value... */
        str_value = nm_dhcp_utils_duid_to_string(bytes);
    }

    if (!IS_IPv4 && nm_streq(key, "iaid")) {
        gs_free char *str = g_steal_pointer(&str_value);
        guint32       iaid;

        /* Validate and normalize the iaid. */

        if (!nm_dhcp_iaid_from_hexstr(str, &iaid)) {
            /* Seems invalid. Ignore */
            return;
        }

        str_value = nm_dhcp_iaid_to_hexstr(iaid, g_malloc(NM_DHCP_IAID_TO_HEXSTR_BUF_LEN));
    }

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

void
nm_dhcp_client_emit_ipv6_prefix_delegated(NMDhcpClient *self, const NMPlatformIP6Address *prefix)
{
    _emit_notify(self,
                 NM_DHCP_CLIENT_NOTIFY_TYPE_PREFIX_DELEGATED,
                 .prefix_delegated = {
                     .prefix = prefix,
                 });
}

gboolean
nm_dhcp_client_handle_event(gpointer               unused,
                            const char            *iface,
                            int                    pid,
                            GVariant              *options,
                            const char            *reason,
                            GDBusMethodInvocation *invocation,
                            NMDhcpClient          *self)
{
    NMDhcpClientPrivate                    *priv;
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    NMDhcpClientEventType                   client_event_type;
    NMPlatformIP6Address                    prefix = {
        0,
    };

    g_return_val_if_fail(NM_IS_DHCP_CLIENT(self), FALSE);
    g_return_val_if_fail(iface != NULL, FALSE);
    g_return_val_if_fail(pid > 0, FALSE);
    g_return_val_if_fail(g_variant_is_of_type(options, G_VARIANT_TYPE_VARDICT), FALSE);
    g_return_val_if_fail(reason != NULL, FALSE);
    g_return_val_if_fail(G_IS_DBUS_METHOD_INVOCATION(invocation), FALSE);

    priv = NM_DHCP_CLIENT_GET_PRIVATE(self);

    g_return_val_if_fail(!priv->is_stopped, FALSE);

    if (!nm_streq0(priv->config.iface, iface))
        return FALSE;
    if (priv->pid != pid)
        return FALSE;

    _LOGD("DHCP event (reason: '%s')", reason);

    if (NM_IN_STRSET_ASCII_CASE(reason, "preinit"))
        goto out_handled;

    if (NM_IN_STRSET_ASCII_CASE(reason, "bound", "bound6", "static"))
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_BOUND;
    else if (NM_IN_STRSET_ASCII_CASE(reason, "renew", "renew6", "reboot", "rebind", "rebind6"))
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED;
    else if (NM_IN_STRSET_ASCII_CASE(reason, "timeout"))
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT;
    else if (NM_IN_STRSET_ASCII_CASE(reason, "nak", "expire", "expire6"))
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_EXPIRE;
    else if (NM_IN_STRSET_ASCII_CASE(reason, "end", "stop", "stopped"))
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_TERMINATED;
    else if (NM_IN_STRSET_ASCII_CASE(reason, "fail", "abend"))
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_FAIL;
    else
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_UNSPECIFIED;

    if (NM_IN_SET(client_event_type,
                  NM_DHCP_CLIENT_EVENT_TYPE_BOUND,
                  NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED)) {
        gs_unref_hashtable GHashTable *str_options = NULL;
        GVariantIter                   iter;
        const char                    *name;
        GVariant                      *value;

        /* Copy options */
        str_options = nm_dhcp_client_create_options_dict(self, FALSE);
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
        }

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
        goto out_handled;
    }

    if (NM_IN_SET(client_event_type,
                  NM_DHCP_CLIENT_EVENT_TYPE_BOUND,
                  NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED)
        && !l3cd) {
        /* Fail if no valid IP config was received */
        _LOGW("client bound but IP config not received");
        client_event_type = NM_DHCP_CLIENT_EVENT_TYPE_FAIL;
    }

    if (priv->invocation)
        g_dbus_method_invocation_return_value(g_steal_pointer(&priv->invocation), NULL);

    if (NM_IN_SET(client_event_type,
                  NM_DHCP_CLIENT_EVENT_TYPE_BOUND,
                  NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED))
        priv->invocation = g_steal_pointer(&invocation);

    _nm_dhcp_client_notify(self, client_event_type, l3cd);

out_handled:
    if (invocation)
        g_dbus_method_invocation_return_value(invocation, NULL);
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

    if (priv->config.reject_servers) {
        for (i = 0; priv->config.reject_servers[i]; i++) {
            in_addr_t r_addr;
            in_addr_t mask;
            int       r_prefix;

            if (!nm_inet_parse_with_prefix_bin(AF_INET,
                                               priv->config.reject_servers[i],
                                               NULL,
                                               &r_addr,
                                               &r_prefix))
                nm_assert_not_reached();

            mask = nm_ip4_addr_netmask_from_prefix(r_prefix < 0 ? 32 : r_prefix);
            if ((addr4 & mask) == (r_addr & mask))
                return TRUE;
        }
    }

    return FALSE;
}

/*****************************************************************************/

static void
config_init(NMDhcpClientConfig *config, const NMDhcpClientConfig *src)
{
    nm_assert(config);
    nm_assert(src);
    nm_assert(config != src);
    nm_assert_addr_family(src->addr_family);

    *config = *src;

    /* We must not return before un-aliasing all pointers in @config! */

    g_object_ref(config->l3cfg);

    nm_l3_config_data_ref_and_seal(config->previous_lease);

    nm_g_bytes_ref(config->hwaddr);
    nm_g_bytes_ref(config->bcast_hwaddr);
    nm_g_bytes_ref(config->vendor_class_identifier);
    nm_g_bytes_ref(config->client_id);

    config->iface           = g_strdup(config->iface);
    config->iface_type_log  = g_strdup(config->iface_type_log);
    config->uuid            = g_strdup(config->uuid);
    config->anycast_address = g_strdup(config->anycast_address);
    config->hostname        = g_strdup(config->hostname);
    config->mud_url         = g_strdup(config->mud_url);

    config->reject_servers = nm_strv_dup_packed(config->reject_servers, -1);

    if (NM_IS_IPv4(config->addr_family))
        config->v4.last_address = g_strdup(config->v4.last_address);
    else {
        config->hwaddr       = NULL;
        config->bcast_hwaddr = NULL;
        config->use_fqdn     = TRUE;
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

    nm_clear_l3cd(&config->previous_lease);

    nm_clear_pointer(&config->hwaddr, g_bytes_unref);
    nm_clear_pointer(&config->bcast_hwaddr, g_bytes_unref);
    nm_clear_pointer(&config->vendor_class_identifier, g_bytes_unref);
    nm_clear_pointer(&config->client_id, g_bytes_unref);

    nm_clear_g_free((gpointer *) &config->iface);
    nm_clear_g_free((gpointer *) &config->iface_type_log);
    nm_clear_g_free((gpointer *) &config->uuid);
    nm_clear_g_free((gpointer *) &config->anycast_address);
    nm_clear_g_free((gpointer *) &config->hostname);
    nm_clear_g_free((gpointer *) &config->mud_url);
    nm_clear_g_free((gpointer *) &config->reject_servers);

    if (config->addr_family == AF_INET) {
        nm_clear_g_free((gpointer *) &config->v4.last_address);
    }
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

        /* I know, this is technically not necessary. It just feels nicer to
         * explicitly initialize the respective union member. */
        if (NM_IS_IPv4(priv->config.addr_family)) {
            priv->v4 = (typeof(priv->v4)){
                .acd =
                    {
                        .addr                = INADDR_ANY,
                        .state               = NM_OPTION_BOOL_DEFAULT,
                        .l3cfg_commit_handle = NULL,
                        .done_source         = NULL,
                    },
            };
        } else {
            priv->v6 = (typeof(priv->v6)){
                .lladdr_timeout_source = NULL,
            };
        }
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

    nm_clear_g_source_inst(&priv->previous_lease_timeout_source);
    nm_clear_g_source_inst(&priv->no_lease_timeout_source);

    if (!NM_IS_IPv4(priv->config.addr_family)) {
        nm_clear_g_source_inst(&priv->v6.lladdr_timeout_source);
        nm_clear_g_source_inst(&priv->v6.dad_timeout_source);
    }

    nm_clear_pointer(&priv->effective_client_id, g_bytes_unref);

    nm_assert(!priv->watch_source);
    nm_assert(!priv->l3cd_next);
    nm_assert(!priv->l3cd_curr);
    nm_assert(priv->l3cfg_notify.id == 0);

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
    client_class->accept       = _accept;
    client_class->decline      = decline;

    client_class->stop = stop;

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
