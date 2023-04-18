/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-ppp-mgr.h"

#include <net/if.h>

#include "NetworkManagerUtils.h"
#include "devices/nm-device-utils.h"
#include "nm-act-request.h"
#include "nm-netns.h"
#include "nm-ppp-manager-call.h"
#include "nm-ppp-status.h"

/*****************************************************************************/

struct _NMPppMgr {
    NMPppMgrConfig config;
    NMPPPManager  *ppp_manager;
    GSource       *idle_start;
    GSource       *connect_timeout_source;
    union {
        struct {
            NMPppMgrIPData ip_data_6;
            NMPppMgrIPData ip_data_4;
        };
        NMPppMgrIPData ip_data_x[2];
    };
    int                ifindex;
    NMPppMgrStatsData  stats_data;
    NMPppMgrState      state;
    NMUtilsIPv6IfaceId ipv6_iid;
    bool               ppp_started : 1;
};

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PPP
#define _NMLOG_PREFIX_NAME "ppp-mgr"
#define _NMLOG(level, ...) \
    __NMLOG_DEFAULT_WITH_ADDR(level, _NMLOG_DOMAIN, _NMLOG_PREFIX_NAME, __VA_ARGS__)

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(
    nm_ppp_mgr_state_to_string,
    NMPppMgrState,
    NM_UTILS_LOOKUP_DEFAULT_WARN("???"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_STARTING, "starting"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX, "waiting-for-ifindex"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_HAVE_IFINDEX, "have-ifindex"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_HAVE_IP_CONFIG, "have-ip-config"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_FAILED_TO_START, "failed-to-start"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_FAILED_TO_IFINDEX, "failed-to-ifindex"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_STATE_FAILED, "failed"));

NM_UTILS_LOOKUP_STR_DEFINE(nm_ppp_mgr_callback_type_to_string,
                           NMPppMgrCallbackType,
                           NM_UTILS_LOOKUP_DEFAULT_WARN("???"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                                    "state-changed"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_PPP_MGR_CALLBACK_TYPE_STATS_CHANGED,
                                                    "stats-changed"));

/*****************************************************************************/

#define SELF_TO_USERDATA(self) (&(self)->idle_start)

#define SELF_FROM_USERDATA(user_data) \
    NM_CAST_ALIGN(NMPppMgr, (((char *) (user_data)) - G_STRUCT_OFFSET(NMPppMgr, idle_start)))

/*****************************************************************************/

gboolean
_nm_assert_is_ppp_mgr(const NMPppMgr *self)
{
    nm_assert(G_IS_OBJECT(self->ppp_manager));
    nm_assert(NM_IS_NETNS(self->config.netns));
    nm_assert(self->config.parent_iface);

    return TRUE;
}

/*****************************************************************************/

static void
_callback_emit_with_data(NMPppMgr *self, const NMPppMgrCallbackData *callback_data)
{
    char sbuf_int[30];

    switch (callback_data->callback_type) {
    case NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED:
        _LOGT("emit signal: %s, state=%s%s%s%s%s, reason=%s",
              nm_ppp_mgr_callback_type_to_string(callback_data->callback_type),
              nm_ppp_mgr_state_to_string(callback_data->data.state),
              NM_PRINT_FMT_QUOTED2(callback_data->data.state != callback_data->data.old_state,
                                   ", old-state=",
                                   nm_ppp_mgr_state_to_string(callback_data->data.old_state),
                                   ""),
              NM_PRINT_FMT_QUOTED2(callback_data->data.ifindex > 0,
                                   ", ifindex=",
                                   nm_sprintf_buf(sbuf_int, "%d", callback_data->data.ifindex),
                                   ""),
              callback_data->data.reason_msg);
        break;
    case NM_PPP_MGR_CALLBACK_TYPE_STATS_CHANGED:
        /* This signal might be emitted every 5 seconds. It's too verbose for logging.
         * Be silent. */
        break;
    default:
        nm_assert_not_reached();
    }

    self->config.callback(self, callback_data, self->config.user_data);
}

static void
_callback_emit_state_change(NMPppMgr            *self,
                            NMPppMgrCallbackType callback_type,
                            NMPppMgrState        old_state,
                            gboolean             ip_changed_4,
                            gboolean             ip_changed_6,
                            NMDeviceStateReason  reason,
                            const char          *reason_msg)
{
    const NMPppMgrCallbackData callback_data = {
        .callback_type = callback_type,
        .data =
            {
                .old_state    = old_state,
                .state        = self->state,
                .ifindex      = self->ifindex,
                .reason       = reason,
                .reason_msg   = reason_msg,
                .ip_data_4    = &self->ip_data_4,
                .ip_data_6    = &self->ip_data_6,
                .stats_data   = &self->stats_data,
                .ip_changed_4 = ip_changed_4,
                .ip_changed_6 = ip_changed_6,
            },
    };

    _callback_emit_with_data(self, &callback_data);
}

/*****************************************************************************/

NMPppMgrState
nm_ppp_mgr_get_state(const NMPppMgr *self)
{
    g_return_val_if_fail(NM_IS_PPP_MGR(self), NM_PPP_MGR_STATE_FAILED);

    return self->state;
}

int
nm_ppp_mgr_get_ifindex(const NMPppMgr *self)
{
    g_return_val_if_fail(NM_IS_PPP_MGR(self), 0);

    return self->ifindex;
}

const NMPppMgrIPData *
nm_ppp_mgr_get_ip_data(const NMPppMgr *self, int addr_family)
{
    const int IS_IPv4 = NM_IS_IPv4(addr_family);

    g_return_val_if_fail(NM_IS_PPP_MGR(self), NULL);

    return &self->ip_data_x[IS_IPv4];
}

const NMPppMgrStatsData *
nm_ppp_mgr_get_stats(const NMPppMgr *self)
{
    g_return_val_if_fail(NM_IS_PPP_MGR(self), NULL);

    return &self->stats_data;
}

/*****************************************************************************/

static void
_set_state(NMPppMgr *self, NMPppMgrState state, NMPppMgrState *out_old_state)
{
    if (state >= NM_PPP_MGR_STATE_HAVE_IP_CONFIG)
        nm_clear_g_source_inst(&self->connect_timeout_source);

    NM_SET_OUT(out_old_state, self->state);
    if (self->state != state) {
        _LOGT("set state: %s (was %s)",
              nm_ppp_mgr_state_to_string(state),
              nm_ppp_mgr_state_to_string(self->state));
        self->state = state;
    }
}

static void
_set_state_failed(NMPppMgr *self, NMPppMgrState state, NMPppMgrState *out_old_state)
{
    nm_assert(state >= _NM_PPP_MGR_STATE_FAILED_START);
    nm_assert(self->state < _NM_PPP_MGR_STATE_FAILED_START);

    _set_state(self, state, out_old_state);

    self->ifindex = 0;
    nm_clear_l3cd(&self->ip_data_4.l3cd);
    nm_clear_l3cd(&self->ip_data_6.l3cd);
    self->ip_data_4 = (NMPppMgrIPData){
        .ip_received = FALSE,
        .ip_enabled  = FALSE,
    };
    self->ip_data_6 = (NMPppMgrIPData){
        .ip_received = FALSE,
        .ip_enabled  = FALSE,
    };

    if (self->ppp_manager) {
        g_signal_handlers_disconnect_by_data(self->ppp_manager, SELF_TO_USERDATA(self));
        if (self->ppp_started) {
            self->ppp_started = FALSE;
            nm_ppp_manager_stop(self->ppp_manager, NULL, NULL, NULL);
        }
        g_object_unref(self->ppp_manager);
    }
}

static gboolean
_state_ready_for_have_ifindex(NMPppMgr *self)
{
    if (self->ip_data_4.ip_received) {
        /* once we receive an IPv4 config, we consider this as ready.
         *
         * The problem is that we don't know when we can expect an IPv6 config
         * too, so we cannot just keep waiting. I don't know how to solve this, but
         * it means IPv4+IPv6 together doesn't work well (because we would not
         * wait for IPv6, once IPv4 config is received. */
        return TRUE;
    }

    return ((!self->ip_data_4.ip_enabled || self->ip_data_4.ip_received)
            && (!self->ip_data_6.ip_enabled || self->ip_data_6.ip_received));
}

/*****************************************************************************/

static void
_ppp_signal_state_changed(NMPPPManager *ppp_manager, guint ppp_state_u, gpointer user_data)
{
    NMPppMgr           *self      = SELF_FROM_USERDATA(user_data);
    NMPPPStatus         ppp_state = ppp_state_u;
    NMPppMgrState       state;
    NMPppMgrState       old_state;
    NMDeviceStateReason reason;
    const char         *reason_msg;

    if ((guint) ppp_state != ppp_state_u)
        ppp_state = NM_PPP_STATUS_INTERN_UNKNOWN;

    switch (ppp_state) {
    case NM_PPP_STATUS_DISCONNECT:
        state      = NM_PPP_MGR_STATE_FAILED;
        reason     = NM_DEVICE_STATE_REASON_PPP_DISCONNECT;
        reason_msg = "ppp signals disconnect";
        break;
    case NM_PPP_STATUS_DEAD:
    case NM_PPP_STATUS_INTERN_DEAD:
        state      = NM_PPP_MGR_STATE_FAILED;
        reason     = NM_DEVICE_STATE_REASON_PPP_FAILED;
        reason_msg = "ppp signals disconnect";
        break;
    default:
        _LOGT("ppp signal about state changed: #%u signal (ignored)", ppp_state_u);
        return;
    }

    _LOGT("ppp signal about state changed: #%u signal, new-state %s, state-reason=%s, %s",
          ppp_state_u,
          nm_ppp_mgr_state_to_string(state),
          nm_device_state_reason_to_string(reason),
          reason_msg);

    _set_state_failed(self, state, &old_state);
    _callback_emit_state_change(self,
                                NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                old_state,
                                FALSE,
                                FALSE,
                                reason,
                                reason_msg);
}

static void
_ppp_signal_ifindex_set(NMPPPManager *ppp_manager,
                        int           ifindex,
                        const char   *ifname,
                        gpointer      user_data)
{
    NMPppMgr     *self = SELF_FROM_USERDATA(user_data);
    NMPppMgrState old_state;
    NMPppMgrState new_state;
    gboolean      ip_changed_4;
    gboolean      ip_changed_6;

    if (ifindex <= 0) {
        nm_assert(self->state == NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX);
        _LOGT("ifindex set: invalid ifindex received");
        _set_state_failed(self, NM_PPP_MGR_STATE_FAILED_TO_IFINDEX, &old_state);
        _callback_emit_state_change(self,
                                    NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                    old_state,
                                    FALSE,
                                    FALSE,
                                    NM_DEVICE_STATE_REASON_PPP_FAILED,
                                    "invalid ifindex provided by ppp plugin");
        return;
    }

    if (self->ifindex > 0) {
        nm_assert(self->state > NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX);
        nm_assert(self->state < _NM_PPP_MGR_STATE_FAILED_START);

        _LOGT("ifindex set: ignore ifindex %d, already set to %d", ifindex, self->ifindex);
        return;
    }

    nm_assert(self->state == NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX);
    self->ifindex = ifindex;

    if (_state_ready_for_have_ifindex(self)) {
        new_state    = NM_PPP_MGR_STATE_HAVE_IP_CONFIG;
        ip_changed_4 = self->ip_data_4.ip_received;
        ip_changed_6 = self->ip_data_6.ip_received;
    } else {
        new_state    = NM_PPP_MGR_STATE_HAVE_IFINDEX;
        ip_changed_4 = FALSE;
        ip_changed_6 = FALSE;
    }

    _LOGT("ifindex set: ifindex %d", ifindex);

    _set_state(self, new_state, &old_state);
    _callback_emit_state_change(self,
                                NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                old_state,
                                ip_changed_4,
                                ip_changed_6,
                                NM_DEVICE_STATE_REASON_PPP_FAILED,
                                "invalid ifindex provided by ppp plugin");
}

static void
_ppp_signal_new_config(NMPPPManager             *ppp_manager,
                       int                       addr_family,
                       const NML3ConfigData     *l3cd,
                       const NMUtilsIPv6IfaceId *iid,
                       gpointer                  user_data)
{
    NMPppMgr     *self    = SELF_FROM_USERDATA(user_data);
    const int     IS_IPv4 = NM_IS_IPv4(addr_family);
    NMPppMgrState old_state;
    gboolean      ip_changed_4;
    gboolean      ip_changed_6;

    nm_assert(self->state >= NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX);
    nm_assert(self->state < _NM_PPP_MGR_STATE_FAILED_START);

    if (nm_l3_config_data_equal(self->ip_data_x[IS_IPv4].l3cd, l3cd))
        l3cd = self->ip_data_x[IS_IPv4].l3cd;

    nm_l3_config_data_reset(&self->ip_data_x[IS_IPv4].l3cd, l3cd);
    if (!IS_IPv4) {
        if (iid)
            self->ipv6_iid = *iid;
        else
            self->ipv6_iid = (NMUtilsIPv6IfaceId) NM_UTILS_IPV6_IFACE_ID_INIT;
        self->ip_data_6.ipv6_iid =
            nm_utils_memeqzero(&self->ipv6_iid, sizeof(self->ipv6_iid)) ? NULL : &self->ipv6_iid;
    }
    self->ip_data_x[IS_IPv4].ip_received = TRUE;

    if (self->state == NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX) {
        /* we still wait for the ifindex. We just cache the IP configuration,
         * but leave the state unchanged. */
        _LOGT("ip-config v%c received (still waiting for ifindex)",
              nm_utils_addr_family_to_char(addr_family));
        old_state = NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX;
    } else {
        NMPppMgrState new_state;

        _LOGT("ip-config v%c received", nm_utils_addr_family_to_char(addr_family));
        new_state = _state_ready_for_have_ifindex(self) ? NM_PPP_MGR_STATE_HAVE_IP_CONFIG
                                                        : NM_PPP_MGR_STATE_HAVE_IFINDEX;
        nm_assert((self->state == NM_PPP_MGR_STATE_HAVE_IFINDEX)
                  || (self->state == NM_PPP_MGR_STATE_HAVE_IP_CONFIG
                      && new_state == NM_PPP_MGR_STATE_HAVE_IP_CONFIG));
        _set_state(self, new_state, &old_state);
    }

    ip_changed_4 = IS_IPv4;
    ip_changed_6 = !IS_IPv4;

    _callback_emit_state_change(self,
                                NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                old_state,
                                ip_changed_4,
                                ip_changed_6,
                                NM_DEVICE_STATE_REASON_NONE,
                                "ip config received");
}

static void
_ppp_signal_stats(NMPPPManager *ppp_manager, guint in_bytes, guint out_bytes, gpointer user_data)
{
    NMPppMgr *self = SELF_FROM_USERDATA(user_data);

    if (self->stats_data.in_bytes == in_bytes && self->stats_data.out_bytes == out_bytes)
        return;

    self->stats_data.in_bytes  = in_bytes;
    self->stats_data.out_bytes = out_bytes;

    _callback_emit_state_change(self,
                                NM_PPP_MGR_CALLBACK_TYPE_STATS_CHANGED,
                                self->state,
                                FALSE,
                                FALSE,
                                NM_DEVICE_STATE_REASON_NONE,
                                "stats update");
}

/*****************************************************************************/

static gboolean
_ifindex_timeout_cb(gpointer user_data)
{
    NMPppMgr     *self = user_data;
    NMPppMgrState old_state;

    nm_clear_g_source_inst(&self->connect_timeout_source);

    _set_state_failed(self, NM_PPP_MGR_STATE_FAILED_TO_IFINDEX, &old_state);
    _callback_emit_state_change(self,
                                NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                old_state,
                                FALSE,
                                FALSE,
                                NM_DEVICE_STATE_REASON_PPP_FAILED,
                                "timeout connecting");
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

static gboolean
_idle_start_cb(gpointer user_data)
{
    NMPppMgr             *self  = user_data;
    gs_free_error GError *error = NULL;
    NMPppMgrState         old_state;
    gboolean              ip4_enabled;
    gboolean              ip6_enabled;
    NMPlatform           *platform;
    const NMPlatformLink *plink;

    nm_clear_g_source_inst(&self->idle_start);

    /* We only evaluate ipx_enabled here. That is because nm_ppp_manager_start()
     * will evaluate it based on act_req's applied connection (like we do now),
     * but as the applied connection can be reapplied, let's do it at the
     * same time to be sure we agree.
     *
     * This should be nicer solved by NMPPPManager not accessing the NMConnection
     * or make little/no use of NMActRequest. */
    nm_utils_ppp_ip_methods_enabled(nm_act_request_get_applied_connection(self->config.act_req),
                                    &ip4_enabled,
                                    &ip6_enabled);
    self->ip_data_4.ip_enabled = !!ip4_enabled;
    self->ip_data_6.ip_enabled = !!ip6_enabled;

    g_signal_connect(self->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_STATE_CHANGED,
                     G_CALLBACK(_ppp_signal_state_changed),
                     SELF_TO_USERDATA(self));
    g_signal_connect(self->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_IFINDEX_SET,
                     G_CALLBACK(_ppp_signal_ifindex_set),
                     SELF_TO_USERDATA(self));
    g_signal_connect(self->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_NEW_CONFIG,
                     G_CALLBACK(_ppp_signal_new_config),
                     SELF_TO_USERDATA(self));
    g_signal_connect(self->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_STATS,
                     G_CALLBACK(_ppp_signal_stats),
                     SELF_TO_USERDATA(self));

    platform = nm_netns_get_platform(self->config.netns);
    plink    = nm_platform_link_get_by_ifname(platform, self->config.parent_iface);
    if (plink && !NM_FLAGS_HAS(plink->n_ifi_flags, IFF_UP)) {
        nm_platform_link_change_flags(platform, plink->ifindex, IFF_UP, TRUE);
    }

    self->ppp_started = TRUE;
    if (!nm_ppp_manager_start(self->ppp_manager,
                              self->config.act_req,
                              self->config.ppp_username,
                              0,
                              self->config.baud_override,
                              &error)) {
        gs_free char *reason_msg = NULL;

        _set_state_failed(self, NM_PPP_MGR_STATE_FAILED_TO_START, &old_state);
        reason_msg = g_strdup_printf("failed to start: %s", error->message);
        _callback_emit_state_change(self,
                                    NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                    old_state,
                                    FALSE,
                                    FALSE,
                                    NM_DEVICE_STATE_REASON_PPP_START_FAILED,
                                    reason_msg);
        return G_SOURCE_CONTINUE;
    }

    nm_assert(self->state == NM_PPP_MGR_STATE_STARTING);
    _set_state(self, NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX, &old_state);

    self->connect_timeout_source =
        nm_g_timeout_add_seconds_source(self->config.timeout_secs, _ifindex_timeout_cb, self);

    _callback_emit_state_change(self,
                                NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
                                old_state,
                                FALSE,
                                FALSE,
                                NM_DEVICE_STATE_REASON_NONE,
                                "pppd is starting");

    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

NMPppMgr *
nm_ppp_mgr_start(const NMPppMgrConfig *config, GError **error)
{
    NMPppMgr     *self;
    NMPPPManager *ppp_manager;

    g_return_val_if_fail(config, NULL);
    g_return_val_if_fail(NM_IS_NETNS(config->netns), NULL);
    g_return_val_if_fail(config->parent_iface, NULL);
    g_return_val_if_fail(NM_IS_ACT_REQUEST(config->act_req), NULL);
    g_return_val_if_fail(config->callback, NULL);
    g_return_val_if_fail(!error || !*error, NULL);

    ppp_manager = nm_ppp_manager_create(config->parent_iface, error);

    if (!ppp_manager)
        return NULL;

    self = g_slice_new(NMPppMgr);

    *self = (NMPppMgr){
        .config      = *config,
        .ppp_manager = ppp_manager,
        .idle_start  = nm_g_idle_add_source(_idle_start_cb, self),
        .state       = NM_PPP_MGR_STATE_STARTING,
        .ip_data_4 =
            {
                .ip_received = FALSE,
                .ip_enabled  = NM_OPTION_BOOL_DEFAULT,
            },
        .ip_data_6 =
            {
                .ip_received = FALSE,
                .ip_enabled  = NM_OPTION_BOOL_DEFAULT,
            },
        .stats_data =
            {
                .in_bytes  = 0,
                .out_bytes = 0,
            },
    };

    g_object_ref(self->config.act_req);
    g_object_ref(self->config.netns);
    self->config.parent_iface = g_strdup(self->config.parent_iface);
    self->config.ppp_username = g_strdup(self->config.ppp_username);

    _LOGD("created");

    return self;
}

void
nm_ppp_mgr_destroy(NMPppMgr *self)
{
    if (!self)
        return;

    _LOGD("destroying");

    if (self->state < _NM_PPP_MGR_STATE_FAILED_START)
        _set_state_failed(self, NM_PPP_MGR_STATE_FAILED, NULL);

    nm_clear_g_source_inst(&self->idle_start);
    nm_clear_g_source_inst(&self->connect_timeout_source);

    g_object_unref(self->config.act_req);

    g_free((char *) self->config.parent_iface);
    g_free((char *) self->config.ppp_username);

    g_object_unref(self->config.netns);

    nm_g_slice_free(self);
}
