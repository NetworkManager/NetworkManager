/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-l3-ipv6ll.h"

#include "nm-compat-headers/linux/if_addr.h"

#include "nm-core-utils.h"

/*****************************************************************************/

/* FIXME(l3cfg): ensure that NML3IPv6LL generates the same stable privacy addresses
 *  as previous implementation. */

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(nm_l3_ipv6ll_state_to_string,
                           NML3IPv6LLState,
                           NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT("???"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_L3_IPV6LL_STATE_NONE, "none"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_L3_IPV6LL_STATE_DEFUNCT, "defunct"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_L3_IPV6LL_STATE_STARTING, "starting"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS,
                                                    "dad-in-progress"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_L3_IPV6LL_STATE_READY, "ready"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_L3_IPV6LL_STATE_DAD_FAILED, "dad-failed"), );

/*****************************************************************************/

struct _NML3IPv6LL {
    NML3Cfg                 *l3cfg;
    NML3CfgCommitTypeHandle *l3cfg_commit_handle;
    NML3IPv6LLNotifyFcn      notify_fcn;
    gpointer                 user_data;
    GSource                 *starting_on_idle_source;
    GSource                 *wait_for_addr_source;
    GSource                 *emit_changed_idle_source;
    gulong                   l3cfg_signal_notify_id;
    NML3IPv6LLState          state;

    /* if we have cur_lladdr set, then this might cache the last
     * matching NMPObject from the platform cache. This only serves
     * for optimizing the lookup to the platform cache. */
    const NMPlatformIP6Address *cur_lladdr_obj;

    struct in6_addr cur_lladdr;

    /* if we have cur_lladdr and _state_has_lladdr() indicates that
     * the LL address is suitable, this is a NML3ConfigData instance
     * with the configuration. */
    const NML3ConfigData *l3cd;

    guint32 route_table;

    /* "assume" means that we first look whether there is any suitable
     * IPv6 address on the device, and in that case, try to use that
     * instead of generating a new one. Otherwise, we always try to
     * generate a new LL address. */
    bool assume : 1;

    struct {
        NMUtilsStableType stable_type;
        guint32           dad_counter;
        struct {
            const char *ifname;
            const char *network_id;
        } stable_privacy;
        struct {
            NMUtilsIPv6IfaceId iid;
        } token;
    } addrgen;
};

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_IP6
#define _NMLOG_PREFIX_NAME "ipv6ll"
#define _NMLOG(level, ...)                                                             \
    G_STMT_START                                                                       \
    {                                                                                  \
        nm_log((level),                                                                \
               (_NMLOG_DOMAIN),                                                        \
               NULL,                                                                   \
               NULL,                                                                   \
               _NMLOG_PREFIX_NAME "[" NM_HASH_OBFUSCATE_PTR_FMT                        \
                                  ",ifindex=%d]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
               NM_HASH_OBFUSCATE_PTR(self),                                            \
               nm_l3cfg_get_ifindex((self)->l3cfg) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                                                  \
    G_STMT_END

/*****************************************************************************/

#define L3CD_TAG(self) (&(self)->notify_fcn)

/*****************************************************************************/

#define _ASSERT(self)                      \
    G_STMT_START                           \
    {                                      \
        NML3IPv6LL *const _self = (self);  \
                                           \
        nm_assert(NM_IS_L3_IPV6LL(_self)); \
    }                                      \
    G_STMT_END

/*****************************************************************************/

static void _check(NML3IPv6LL *self);

/*****************************************************************************/

NML3Cfg *
nm_l3_ipv6ll_get_l3cfg(NML3IPv6LL *self)
{
    nm_assert(NM_IS_L3_IPV6LL(self));

    return self->l3cfg;
}

int
nm_l3_ipv6ll_get_ifindex(NML3IPv6LL *self)
{
    nm_assert(NM_IS_L3_IPV6LL(self));

    return nm_l3cfg_get_ifindex(self->l3cfg);
}

NMPlatform *
nm_l3_ipv6ll_get_platform(NML3IPv6LL *self)
{
    nm_assert(NM_IS_L3_IPV6LL(self));

    return nm_l3cfg_get_platform(self->l3cfg);
}

/*****************************************************************************/

static gboolean
_state_has_lladdr(NML3IPv6LLState state)
{
    return NM_IN_SET(state, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS, NM_L3_IPV6LL_STATE_READY);
}

NML3IPv6LLState
nm_l3_ipv6ll_get_state(NML3IPv6LL *self, const struct in6_addr **out_lladdr)
{
    nm_assert(NM_IS_L3_IPV6LL(self));

    NM_SET_OUT(out_lladdr, _state_has_lladdr(self->state) ? &self->cur_lladdr : NULL);
    return self->state;
}

static const NML3ConfigData *
_l3cd_config_create(int ifindex, const struct in6_addr *lladdr, NMDedupMultiIndex *multi_idx)
{
    NML3ConfigData *l3cd;

    nm_assert(ifindex > 0);
    nm_assert(lladdr);
    nm_assert(IN6_IS_ADDR_LINKLOCAL(lladdr));

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_IP6LL);

    nm_l3_config_data_add_address_6(
        l3cd,
        NM_PLATFORM_IP6_ADDRESS_INIT(.address     = *lladdr,
                                     .plen        = 64,
                                     .addr_source = NM_IP_CONFIG_SOURCE_IP6LL));

    nm_l3_config_data_add_route_6(
        l3cd,
        NM_PLATFORM_IP6_ROUTE_INIT(.network.s6_addr16[0] = htons(0xfe80u),
                                   .plen                 = 64,
                                   .metric_any           = TRUE,
                                   .table_any            = TRUE,
                                   .rt_source            = NM_IP_CONFIG_SOURCE_IP6LL));

    return nm_l3_config_data_seal(l3cd);
}

const NML3ConfigData *
nm_l3_ipv6ll_get_l3cd(NML3IPv6LL *self)
{
    nm_assert(NM_IS_L3_IPV6LL(self));

    if (!_state_has_lladdr(self->state)) {
        nm_assert(!self->l3cd);
        return NULL;
    }

    if (!self->l3cd) {
        self->l3cd = _l3cd_config_create(nm_l3_ipv6ll_get_ifindex(self),
                                         &self->cur_lladdr,
                                         nm_l3cfg_get_multi_idx(self->l3cfg));
    }

    return self->l3cd;
}

/*****************************************************************************/

static gboolean
_emit_changed_on_idle_cb(gpointer user_data)
{
    NML3IPv6LL            *self = user_data;
    const struct in6_addr *lladdr;
    NML3IPv6LLState        state;
    char                   sbuf[INET6_ADDRSTRLEN];

    nm_clear_g_source_inst(&self->emit_changed_idle_source);

    state = nm_l3_ipv6ll_get_state(self, &lladdr);

    _LOGT("emit changed signal (state=%s%s%s)",
          nm_l3_ipv6ll_state_to_string(state),
          lladdr ? ", " : "",
          lladdr ? nm_inet6_ntop(lladdr, sbuf) : "");

    self->notify_fcn(self, state, lladdr, self->user_data);

    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

static gboolean
_generate_new_address(NML3IPv6LL *self, struct in6_addr *out_lladdr)
{
    struct in6_addr lladdr;

    memset(&lladdr, 0, sizeof(struct in6_addr));
    lladdr.s6_addr16[0] = htons(0xfe80u);

    if (self->addrgen.stable_type == NM_UTILS_STABLE_TYPE_NONE) {
        if (self->addrgen.dad_counter > 0)
            return FALSE;
        self->addrgen.dad_counter++;
        nm_utils_ipv6_addr_set_interface_identifier(&lladdr, &self->addrgen.token.iid);
    } else {
        /* RFC7217 says we MUST limit the number of retries, and it SHOULD try
         * at least IDGEN_RETRIES times (that is, 3 times).
         *
         * 3 times seems really low. Instead, let's try 6 times. */
        G_STATIC_ASSERT(NM_STABLE_PRIVACY_RFC7217_IDGEN_RETRIES == 3);
        if (self->addrgen.dad_counter >= NM_STABLE_PRIVACY_RFC7217_IDGEN_RETRIES + 3)
            return FALSE;

        nm_utils_ipv6_addr_set_stable_privacy(self->addrgen.stable_type,
                                              &lladdr,
                                              self->addrgen.stable_privacy.ifname,
                                              self->addrgen.stable_privacy.network_id,
                                              self->addrgen.dad_counter++);
    }

    *out_lladdr = lladdr;
    return TRUE;
}

/*****************************************************************************/

static gboolean
_pladdr_is_ll_failed(const NMPlatformIP6Address *addr)
{
    nm_assert(addr);
    nm_assert(IN6_IS_ADDR_LINKLOCAL(&addr->address));

    return NM_FLAGS_ANY(addr->n_ifa_flags, IFA_F_DADFAILED | IFA_F_DEPRECATED);
}

static gboolean
_pladdr_is_ll_tentative(const NMPlatformIP6Address *addr)
{
    nm_assert(addr);
    nm_assert(IN6_IS_ADDR_LINKLOCAL(&addr->address));
    nm_assert(!_pladdr_is_ll_failed(addr));

    return NM_FLAGS_HAS(addr->n_ifa_flags, IFA_F_TENTATIVE)
           && !NM_FLAGS_HAS(addr->n_ifa_flags, IFA_F_OPTIMISTIC);
}

static const NMPlatformIP6Address *
_pladdr_find_ll(NML3IPv6LL *self, gboolean *out_cur_addr_failed)
{
    NMDedupMultiIter            iter;
    NMPLookup                   lookup;
    const NMPlatformIP6Address *pladdr1 = NULL;
    const NMPObject            *obj;
    const NMPlatformIP6Address *pladdr_ready      = NULL;
    const NMPlatformIP6Address *pladdr_tentative  = NULL;
    gboolean                    cur_addr_check    = TRUE;
    gboolean                    cur_addr_failed   = FALSE;
    gboolean                    pladdr1_looked_up = FALSE;

    nm_assert(!self->cur_lladdr_obj
              || IN6_ARE_ADDR_EQUAL(&self->cur_lladdr, &self->cur_lladdr_obj->address));

    *out_cur_addr_failed = FALSE;

    if (self->state == NM_L3_IPV6LL_STATE_READY && self->cur_lladdr_obj) {
        nm_assert(!_pladdr_is_ll_tentative(self->cur_lladdr_obj));
        pladdr1 = NMP_OBJECT_CAST_IP6_ADDRESS(
            nm_platform_lookup_obj(nm_l3_ipv6ll_get_platform(self),
                                   NMP_CACHE_ID_TYPE_OBJECT_TYPE,
                                   NMP_OBJECT_UP_CAST(self->cur_lladdr_obj)));
        if (self->cur_lladdr_obj == pladdr1) {
            /* Fast-path. We are ready and the cur_lladdr_obj is still in the cache. We
             * got the result with a dictionary lookup without need to iterate over
             * all addresses. */
            return self->cur_lladdr_obj;
        }
        pladdr1_looked_up = TRUE;
    }

    if (!self->assume) {
        /* We don't accept any suitable LL address, only he one we are waiting for.
         * Let's do a dictionary lookup. */

        if (IN6_IS_ADDR_LINKLOCAL(&self->cur_lladdr)) {
            if (!pladdr1_looked_up) {
                NMPObject needle;

                nmp_object_stackinit_id_ip6_address(&needle,
                                                    nm_l3_ipv6ll_get_ifindex(self),
                                                    &self->cur_lladdr);
                pladdr1 = NMP_OBJECT_CAST_IP6_ADDRESS(
                    nm_platform_lookup_obj(nm_l3_ipv6ll_get_platform(self),
                                           NMP_CACHE_ID_TYPE_OBJECT_TYPE,
                                           &needle));
            }
            if (pladdr1) {
                if (!_pladdr_is_ll_failed(pladdr1))
                    return pladdr1;
                *out_cur_addr_failed = TRUE;
            }
        } else
            nm_assert(!pladdr1_looked_up);

        return NULL;
    }

    if (!NM_IN_SET(self->state, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS, NM_L3_IPV6LL_STATE_READY))
        cur_addr_check = FALSE;

    nmp_lookup_init_object_by_ifindex(&lookup,
                                      NMP_OBJECT_TYPE_IP6_ADDRESS,
                                      nm_l3_ipv6ll_get_ifindex(self));

    nm_platform_iter_obj_for_each (&iter, nm_l3_ipv6ll_get_platform(self), &lookup, &obj) {
        const NMPlatformIP6Address *pladdr = NMP_OBJECT_CAST_IP6_ADDRESS(obj);

        if (!IN6_IS_ADDR_LINKLOCAL(&pladdr->address))
            continue;

        if (_pladdr_is_ll_failed(pladdr)) {
            if (cur_addr_check && IN6_ARE_ADDR_EQUAL(&self->cur_lladdr, &pladdr->address)) {
                /* "pladdr" is the address we are currently doing DAD for. But it failed.
                 * We need to recognize and report to the caller, to stop waiting for this
                 * address. */
                cur_addr_failed = TRUE;
                cur_addr_check  = FALSE;
            }
            continue;
        }

        if (_pladdr_is_ll_tentative(pladdr)) {
            if (!pladdr_tentative)
                pladdr_tentative = pladdr;
            else if (pladdr == self->cur_lladdr_obj)
                pladdr_tentative = pladdr;
            else if (IN6_ARE_ADDR_EQUAL(&self->cur_lladdr, &pladdr->address))
                pladdr_tentative = pladdr;
            continue;
        }

        if (pladdr == self->cur_lladdr_obj) {
            /* it doesn't get any better. We have our best address. */
            return pladdr;
        }
        if (!pladdr_ready)
            pladdr_ready = pladdr;
        else if (IN6_ARE_ADDR_EQUAL(&self->cur_lladdr, &pladdr->address))
            pladdr_ready = pladdr;
    }

    *out_cur_addr_failed = cur_addr_failed;
    return pladdr_ready ?: pladdr_tentative;
}

/*****************************************************************************/

static void
_lladdr_handle_changed(NML3IPv6LL *self, gboolean force_commit)
{
    const NML3ConfigData *l3cd;
    gboolean              changed = FALSE;

    /* We register the l3cd with l3cfg to start DAD. That is different from
     * NML3IPv4LL, where we use NM_L3_CONFIG_MERGE_FLAGS_ONLY_FOR_ACD. The difference
     * is that for IPv6 we let kernel do DAD, so we need to actually configure the
     * address. For IPv4, we can run ACD without configuring anything in kernel,
     * and let the user decide how to proceed. */

    l3cd = nm_l3_ipv6ll_get_l3cd(self);

    if (l3cd) {
        if (nm_l3cfg_add_config(self->l3cfg,
                                L3CD_TAG(self),
                                TRUE,
                                l3cd,
                                NM_L3CFG_CONFIG_PRIORITY_IPV6LL,
                                0,
                                self->route_table,
                                NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
                                NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                                0,
                                0,
                                NM_DNS_PRIORITY_DEFAULT_NORMAL,
                                NM_DNS_PRIORITY_DEFAULT_NORMAL,
                                NM_L3_ACD_DEFEND_TYPE_ALWAYS,
                                0,
                                NM_L3CFG_CONFIG_FLAGS_NONE,
                                NM_L3_CONFIG_MERGE_FLAGS_NONE))
            changed = TRUE;
    } else {
        if (nm_l3cfg_remove_config_all(self->l3cfg, L3CD_TAG(self)))
            changed = TRUE;
    }

    self->l3cfg_commit_handle = nm_l3cfg_commit_type_register(self->l3cfg,
                                                              l3cd ? NM_L3_CFG_COMMIT_TYPE_UPDATE
                                                                   : NM_L3_CFG_COMMIT_TYPE_NONE,
                                                              self->l3cfg_commit_handle,
                                                              "ipv6ll");

    if (changed || force_commit)
        nm_l3cfg_commit_on_idle_schedule(self->l3cfg, NM_L3_CFG_COMMIT_TYPE_AUTO);

    if (!self->emit_changed_idle_source) {
        _LOGT("schedule changed signal on idle");
        self->emit_changed_idle_source = nm_g_idle_add_source(_emit_changed_on_idle_cb, self);
    }
}

/*****************************************************************************/

static gboolean
_set_cur_lladdr(NML3IPv6LL *self, NML3IPv6LLState state, const struct in6_addr *lladdr)
{
    gboolean changed = FALSE;

    if (lladdr) {
        nm_assert(IN6_IS_ADDR_LINKLOCAL(lladdr));
        if (!IN6_ARE_ADDR_EQUAL(&self->cur_lladdr, lladdr)) {
            self->cur_lladdr = *lladdr;
            nm_clear_l3cd(&self->l3cd);
            changed = TRUE;
        }
    } else {
        if (!nm_ip_addr_is_null(AF_INET6, &self->cur_lladdr)) {
            nm_clear_l3cd(&self->l3cd);
            self->cur_lladdr = nm_ip_addr_zero.addr6;
            changed          = TRUE;
        }
        nm_assert(!self->l3cd);
        nm_assert(!_state_has_lladdr(state));
    }

    if (self->state != state) {
        if (!_state_has_lladdr(state))
            nm_clear_l3cd(&self->l3cd);
        self->state = state;
        changed     = TRUE;
    }

    return changed;
}

static gboolean
_set_cur_lladdr_obj(NML3IPv6LL *self, NML3IPv6LLState state, const NMPlatformIP6Address *lladdr_obj)
{
    nm_assert(lladdr_obj);
    nm_assert(_state_has_lladdr(state));

    nmp_object_ref_set_up_cast(&self->cur_lladdr_obj, lladdr_obj);
    return _set_cur_lladdr(self, state, &lladdr_obj->address);
}

static gboolean
_set_cur_lladdr_bin(NML3IPv6LL *self, NML3IPv6LLState state, const struct in6_addr *lladdr)
{
    nmp_object_ref_set_up_cast(&self->cur_lladdr_obj, NULL);
    return _set_cur_lladdr(self, state, lladdr);
}

static gboolean
_wait_for_addr_timeout_cb(gpointer user_data)
{
    NML3IPv6LL *self = user_data;

    nm_clear_g_source_inst(&self->wait_for_addr_source);

    nm_assert(
        NM_IN_SET(self->state, NM_L3_IPV6LL_STATE_DAD_FAILED, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS));

    _check(self);

    return G_SOURCE_CONTINUE;
}

static void
_check(NML3IPv6LL *self)
{
    const NMPlatformIP6Address *pladdr;
    char                        sbuf[INET6_ADDRSTRLEN];
    gboolean                    cur_addr_failed;
    gboolean                    restarted = FALSE;
    struct in6_addr             lladdr;

    pladdr = _pladdr_find_ll(self, &cur_addr_failed);

    if (pladdr) {
        nm_clear_g_source_inst(&self->wait_for_addr_source);

        if (_pladdr_is_ll_tentative(pladdr)) {
            if (_set_cur_lladdr_obj(self, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS, pladdr)) {
                _LOGT("changed: waiting for address %s to complete DAD",
                      nm_inet6_ntop(&self->cur_lladdr, sbuf));
                _lladdr_handle_changed(self, FALSE);
            }
            return;
        }

        if (_set_cur_lladdr_obj(self, NM_L3_IPV6LL_STATE_READY, pladdr)) {
            _LOGT("changed: address %s is ready", nm_inet6_ntop(&self->cur_lladdr, sbuf));
            _lladdr_handle_changed(self, FALSE);
        }
        return;
    }

    if (self->cur_lladdr_obj || cur_addr_failed) {
        /* we were doing DAD, but the address is no longer a suitable candidate.
         * Prematurely abort DAD to generate a new address below. */
        nm_assert(
            NM_IN_SET(self->state, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS, NM_L3_IPV6LL_STATE_READY));

        if (cur_addr_failed) {
            /* On DAD failure, we always try to regenerate a new address. */
            _LOGT("changed: address %s failed", nm_inet6_ntop(&self->cur_lladdr, sbuf));
        } else {
            _LOGT("changed: address %s is gone", nm_inet6_ntop(&self->cur_lladdr, sbuf));
            /* When the address is removed, we always try to re-add it. */
            nm_clear_g_source_inst(&self->wait_for_addr_source);
            lladdr    = self->cur_lladdr;
            restarted = TRUE;
            goto commit;
        }

        /* reset the state here, so that we are sure that the following
         * _set_cur_lladdr_bin() calls (below) will notice the change
         * and trigger a _lladdr_handle_changed(). */
        _set_cur_lladdr_bin(self, NM_L3_IPV6LL_STATE_STARTING, NULL);
        nm_clear_g_source_inst(&self->wait_for_addr_source);
    } else if (self->wait_for_addr_source) {
        /* we are waiting. Nothing to do for now. */
        return;
    }

    if (!_generate_new_address(self, &lladdr)) {
        /* our DAD counter expired. We reset it, and start a timer to retry
         * and recover. */
        self->addrgen.dad_counter = 0;
        self->wait_for_addr_source =
            nm_g_timeout_add_source(10000, _wait_for_addr_timeout_cb, self);
        if (_set_cur_lladdr_bin(self, NM_L3_IPV6LL_STATE_DAD_FAILED, NULL)) {
            _LOGW("changed: no IPv6 link local address to retry after Duplicate Address Detection "
                  "failures (back off)");
            _lladdr_handle_changed(self, FALSE);
        }
        return;
    }

commit:
    /* we give NML3Cfg 2 seconds to configure the address on the interface. We
     * thus very soon expect to see this address configured (and kernel started DAD).
     * If that does not happen within timeout, we assume that this address failed DAD. */
    self->wait_for_addr_source = nm_g_timeout_add_source(2000, _wait_for_addr_timeout_cb, self);
    if (_set_cur_lladdr_bin(self, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS, &lladdr) || restarted) {
        _LOGT("changed: starting DAD for address %s", nm_inet6_ntop(&self->cur_lladdr, sbuf));
        _lladdr_handle_changed(self, restarted);
    }
    return;
}

/*****************************************************************************/

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NML3IPv6LL *self)
{
    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE) {
        if (NM_FLAGS_ANY(notify_data->platform_change_on_idle.obj_type_flags,
                         nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP6_ADDRESS)))
            _check(self);
        return;
    }
}

/*****************************************************************************/

static gboolean
_starting_on_idle_cb(gpointer user_data)
{
    NML3IPv6LL *self = user_data;

    nm_clear_g_source_inst(&self->starting_on_idle_source);

    self->l3cfg_signal_notify_id =
        g_signal_connect(self->l3cfg, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self);

    _check(self);

    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

NML3IPv6LL *
_nm_l3_ipv6ll_new(NML3Cfg                  *l3cfg,
                  gboolean                  assume,
                  NMUtilsStableType         stable_type,
                  const char               *ifname,
                  const char               *network_id,
                  const NMUtilsIPv6IfaceId *token_iid,
                  guint32                   route_table,
                  NML3IPv6LLNotifyFcn       notify_fcn,
                  gpointer                  user_data)
{
    NML3IPv6LL *self;

    g_return_val_if_fail(NM_IS_L3CFG(l3cfg), NULL);
    g_return_val_if_fail(notify_fcn, NULL);
    g_return_val_if_fail(
        (stable_type == NM_UTILS_STABLE_TYPE_NONE && !ifname && !network_id && token_iid)
            || (stable_type != NM_UTILS_STABLE_TYPE_NONE && ifname && network_id && !token_iid),
        NULL);

    self  = g_slice_new(NML3IPv6LL);
    *self = (NML3IPv6LL){
        .l3cfg                   = g_object_ref(l3cfg),
        .notify_fcn              = notify_fcn,
        .user_data               = user_data,
        .state                   = NM_L3_IPV6LL_STATE_STARTING,
        .starting_on_idle_source = nm_g_idle_add_source(_starting_on_idle_cb, self),
        .l3cfg_signal_notify_id  = 0,
        .cur_lladdr_obj          = NULL,
        .cur_lladdr              = IN6ADDR_ANY_INIT,
        .assume                  = assume,
        .route_table             = route_table,
        .addrgen =
            {
                .stable_type = stable_type,
                .dad_counter = 0,
            },
    };

    if (self->addrgen.stable_type == NM_UTILS_STABLE_TYPE_NONE) {
        char sbuf_token[INET6_ADDRSTRLEN];

        self->addrgen.token.iid = *token_iid;
        _LOGT("created: l3cfg=" NM_HASH_OBFUSCATE_PTR_FMT ", ifindex=%d, token=%s%s",
              NM_HASH_OBFUSCATE_PTR(l3cfg),
              nm_l3cfg_get_ifindex(l3cfg),
              nm_utils_inet6_interface_identifier_to_token(&self->addrgen.token.iid, sbuf_token),
              self->assume ? ", assume" : "");
    } else {
        self->addrgen.stable_privacy.ifname     = g_strdup(ifname);
        self->addrgen.stable_privacy.network_id = g_strdup(network_id);
        _LOGT("created: l3cfg=" NM_HASH_OBFUSCATE_PTR_FMT
              ", ifindex=%d, stable-type=%u, ifname=%s, network_id=%s%s",
              NM_HASH_OBFUSCATE_PTR(l3cfg),
              nm_l3cfg_get_ifindex(l3cfg),
              (unsigned) self->addrgen.stable_type,
              self->addrgen.stable_privacy.ifname,
              self->addrgen.stable_privacy.network_id,
              self->assume ? ", assume" : "");
    }

    return self;
}

void
nm_l3_ipv6ll_destroy(NML3IPv6LL *self)
{
    if (!self)
        return;

    _ASSERT(self);

    _LOGT("finalize");

    nm_l3cfg_commit_type_unregister(self->l3cfg, g_steal_pointer(&self->l3cfg_commit_handle));

    nm_l3cfg_remove_config_all(self->l3cfg, L3CD_TAG(self));

    nm_clear_g_source_inst(&self->starting_on_idle_source);
    nm_clear_g_source_inst(&self->wait_for_addr_source);
    nm_clear_g_source_inst(&self->emit_changed_idle_source);
    nm_clear_g_signal_handler(self->l3cfg, &self->l3cfg_signal_notify_id);

    g_clear_object(&self->l3cfg);

    nm_clear_l3cd(&self->l3cd);

    nm_clear_nmp_object_up_cast(&self->cur_lladdr_obj);

    if (self->addrgen.stable_type != NM_UTILS_STABLE_TYPE_NONE) {
        g_free((char *) self->addrgen.stable_privacy.ifname);
        g_free((char *) self->addrgen.stable_privacy.network_id);
    }

    nm_g_slice_free(self);
}
