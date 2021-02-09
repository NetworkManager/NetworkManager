/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-l3-ipv4ll.h"

#include <net/if.h>
#include <linux/if_ether.h>

#include "n-acd/src/n-acd.h"
#include "nm-core-utils.h"

#define ADDR_IPV4LL_PREFIX_LEN 16

#define TIMED_OUT_TIME_FACTOR 5u

/*****************************************************************************/

typedef enum {
    TIMED_OUT_STATE_IS_NOT_TIMED_OUT,
    TIMED_OUT_STATE_IS_TIMED_OUT,
    TIMED_OUT_STATE_HAVE_TIMER_RUNNING,
} TimedOutState;

struct _NML3IPv4LLRegistration {
    NML3IPv4LL *self;
    CList       reg_lst;
    guint       timeout_msec;
};

G_STATIC_ASSERT(G_STRUCT_OFFSET(NML3IPv4LLRegistration, self) == 0);

struct _NML3IPv4LL {
    NML3Cfg *                l3cfg;
    int                      ref_count;
    in_addr_t                addr;
    guint                    reg_timeout_msec;
    CList                    reg_lst_head;
    NML3CfgCommitTypeHandle *l3cfg_commit_handle;
    GSource *                state_change_on_idle_source;
    GSource *                timed_out_source;
    const NML3ConfigData *   l3cd;
    const NMPObject *        plobj;
    struct {
        nm_le64_t value;
        nm_le64_t generation;
    } seed;
    gint64          timed_out_expiry_msec;
    gulong          l3cfg_signal_notify_id;
    NML3IPv4LLState state;
    NMEtherAddr     seed_mac;
    NMEtherAddr     mac;
    bool            seed_set : 1;
    bool            mac_set : 1;
    bool            notify_on_idle : 1;
    bool            reg_changed : 1;
    bool            l3cd_timeout_msec_changed : 1;

    /* not yet used. */
    bool seed_reset_generation : 1;
};

G_STATIC_ASSERT(G_STRUCT_OFFSET(NML3IPv4LL, ref_count) == sizeof(gpointer));

#define L3CD_TAG(self) (&(((const char *) self)[1]))

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_IP4
#define _NMLOG_PREFIX_NAME "ipv4ll"
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

static void _ipv4ll_state_change_on_idle(NML3IPv4LL *self);

static void _ipv4ll_state_change(NML3IPv4LL *self, gboolean is_on_idle_handler);

static void _ipv4ll_set_timed_out_update(NML3IPv4LL *self, TimedOutState new_state);

/*****************************************************************************/

NM_UTILS_ENUM2STR_DEFINE(nm_l3_ipv4ll_state_to_string,
                         NML3IPv4LLState,
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_UNKNOWN, "unknown"),
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_DISABLED, "disabled"),
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_WAIT_FOR_LINK, "wait-for-link"),
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_EXTERNAL, "external"),
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_PROBING, "probing"),
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_DEFENDING, "defending"),
                         NM_UTILS_ENUM2STR(NM_L3_IPV4LL_STATE_READY, "ready"), );

/*****************************************************************************/

#define _ASSERT(self)                                                                        \
    G_STMT_START                                                                             \
    {                                                                                        \
        NML3IPv4LL *const _self = (self);                                                    \
                                                                                             \
        nm_assert(NM_IS_L3_IPV4LL(_self));                                                   \
        if (NM_MORE_ASSERTS > 5) {                                                           \
            nm_assert(_self->addr == 0u || nm_utils_ip4_address_is_link_local(_self->addr)); \
            nm_assert(!_self->l3cd || NM_IS_L3_CONFIG_DATA(_self->l3cd));                    \
        }                                                                                    \
    }                                                                                        \
    G_STMT_END

/*****************************************************************************/

NML3Cfg *
nm_l3_ipv4ll_get_l3cfg(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->l3cfg;
}

int
nm_l3_ipv4ll_get_ifindex(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return nm_l3cfg_get_ifindex(self->l3cfg);
}

NMPlatform *
nm_l3_ipv4ll_get_platform(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return nm_l3cfg_get_platform(self->l3cfg);
}

/*****************************************************************************/

NML3IPv4LLState
nm_l3_ipv4ll_get_state(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->state;
}

static gboolean
_ipv4ll_is_timed_out(NML3IPv4LL *self)
{
    _ASSERT(self);

    return self->timed_out_expiry_msec != 0 && !self->timed_out_source;
}

gboolean
nm_l3_ipv4ll_is_timed_out(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return _ipv4ll_is_timed_out(self);
}

in_addr_t
nm_l3_ipv4ll_get_addr(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->addr;
}

const NML3ConfigData *
nm_l3_ipv4ll_get_l3cd(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->l3cd;
}

static void
_ipv4ll_emit_signal_notify(NML3IPv4LL *self)
{
    NML3ConfigNotifyData notify_data;

    self->notify_on_idle = FALSE;

    notify_data.notify_type  = NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT;
    notify_data.ipv4ll_event = (typeof(notify_data.ipv4ll_event)){
        .ipv4ll = self,
    };
    _nm_l3cfg_emit_signal_notify(self->l3cfg, &notify_data);
}

/*****************************************************************************/

static NML3IPv4LLRegistration *
_registration_update(NML3IPv4LL *            self,
                     NML3IPv4LLRegistration *reg,
                     gboolean                add,
                     guint                   timeout_msec)
{
    nm_auto_unref_l3ipv4ll NML3IPv4LL *self_unref_on_exit = NULL;
    gboolean                           changed            = FALSE;

    if (reg) {
        nm_assert(!self);
        _ASSERT(reg->self);
        self = reg->self;
        nm_assert(c_list_contains(&self->reg_lst_head, &reg->reg_lst));
        nm_assert(self == nm_l3_ipv4ll_register_get_instance(reg));
    } else {
        nm_assert(add);
        _ASSERT(self);
    }

    if (!add) {
        _LOGT("registration[" NM_HASH_OBFUSCATE_PTR_FMT "]: remove", NM_HASH_OBFUSCATE_PTR(reg));
        c_list_unlink_stale(&reg->reg_lst);
        if (c_list_is_empty(&self->reg_lst_head))
            self_unref_on_exit = self;
        nm_g_slice_free(reg);
        reg = NULL;
        goto out;
    }

    if (!reg) {
        reg  = g_slice_new(NML3IPv4LLRegistration);
        *reg = (NML3IPv4LLRegistration){
            .self         = self,
            .timeout_msec = timeout_msec,
        };

        if (c_list_is_empty(&self->reg_lst_head))
            nm_l3_ipv4ll_ref(self);
        c_list_link_tail(&self->reg_lst_head, &reg->reg_lst);
        changed = TRUE;
        _LOGT("registration[" NM_HASH_OBFUSCATE_PTR_FMT "]: add (timeout_msec=%u)",
              NM_HASH_OBFUSCATE_PTR(reg),
              timeout_msec);
    } else {
        if (reg->timeout_msec != timeout_msec) {
            reg->timeout_msec = timeout_msec;
            changed           = TRUE;
        }
        if (changed) {
            _LOGT("registration[" NM_HASH_OBFUSCATE_PTR_FMT "]: update (timeout_msec=%u)",
                  NM_HASH_OBFUSCATE_PTR(reg),
                  timeout_msec);
        }
    }

out:
    if (changed) {
        self->reg_changed = TRUE;
        _ipv4ll_state_change(self, FALSE);
    }
    return reg;
}

NML3IPv4LLRegistration *
nm_l3_ipv4ll_register_new(NML3IPv4LL *self, guint timeout_msec)
{
    return _registration_update(self, NULL, TRUE, timeout_msec);
}

NML3IPv4LLRegistration *
nm_l3_ipv4ll_register_update(NML3IPv4LLRegistration *reg, guint timeout_msec)
{
    return _registration_update(NULL, reg, TRUE, timeout_msec);
}

NML3IPv4LLRegistration *
nm_l3_ipv4ll_register_remove(NML3IPv4LLRegistration *reg)
{
    return _registration_update(NULL, reg, FALSE, 0);
}

/*****************************************************************************/

static gboolean
_ip4_address_is_link_local(const NMPlatformIP4Address *a)
{
    nm_assert(a);

    return nm_utils_ip4_address_is_link_local(a->address) && a->plen == ADDR_IPV4LL_PREFIX_LEN
           && a->address == a->peer_address;
}

static gboolean
_acd_info_is_good(const NML3AcdAddrInfo *acd_info)
{
    if (!acd_info)
        return TRUE;

    switch (acd_info->state) {
    case NM_L3_ACD_ADDR_STATE_INIT:
    case NM_L3_ACD_ADDR_STATE_PROBING:
    case NM_L3_ACD_ADDR_STATE_READY:
    case NM_L3_ACD_ADDR_STATE_DEFENDING:
    case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
        return TRUE;
    case NM_L3_ACD_ADDR_STATE_USED:
    case NM_L3_ACD_ADDR_STATE_CONFLICT:
        return FALSE;
    }
    nm_assert_not_reached();
    return FALSE;
}

/*****************************************************************************/

static NMPlatformIP4Address *
_l3cd_config_plat_init_addr(NMPlatformIP4Address *a, int ifindex, in_addr_t addr)
{
    nm_assert(nm_utils_ip4_address_is_link_local(addr));

    *a = (NMPlatformIP4Address){
        .ifindex      = ifindex,
        .address      = addr,
        .peer_address = addr,
        .plen         = ADDR_IPV4LL_PREFIX_LEN,
        .addr_source  = NM_IP_CONFIG_SOURCE_IP4LL,
    };
    return a;
}

static NMPlatformIP4Route *
_l3cd_config_plat_init_route(NMPlatformIP4Route *r, int ifindex)
{
    *r = (NMPlatformIP4Route){
        .ifindex    = ifindex,
        .network    = htonl(0xE0000000u),
        .plen       = 4,
        .rt_source  = NM_IP_CONFIG_SOURCE_IP4LL,
        .table_any  = TRUE,
        .metric_any = TRUE,
    };
    return r;
}

static const NML3ConfigData *
_l3cd_config_create(int ifindex, in_addr_t addr, NMDedupMultiIndex *multi_idx)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    NMPlatformIP4Address                    a;
    NMPlatformIP4Route                      r;

    nm_assert(nm_utils_ip4_address_is_link_local(addr));
    nm_assert(ifindex > 0);
    nm_assert(multi_idx);

    l3cd = nm_l3_config_data_new(multi_idx, ifindex);
    nm_l3_config_data_set_source(l3cd, NM_IP_CONFIG_SOURCE_IP4LL);

    nm_l3_config_data_add_address_4(l3cd, _l3cd_config_plat_init_addr(&a, ifindex, addr));
    nm_l3_config_data_add_route_4(l3cd, _l3cd_config_plat_init_route(&r, ifindex));

    return nm_l3_config_data_seal(g_steal_pointer(&l3cd));
}

static in_addr_t
_l3cd_config_get_addr(const NML3ConfigData *l3cd)
{
    NMDedupMultiIter            iter;
    const NMPlatformIP4Address *pladdr;

    if (!l3cd)
        return 0u;

    nm_l3_config_data_iter_ip4_address_for_each (&iter, l3cd, &pladdr) {
        const in_addr_t addr = pladdr->address;

        nm_assert(_ip4_address_is_link_local(pladdr));
#if NM_MORE_ASSERTS > 10
        {
            nm_auto_unref_l3cd const NML3ConfigData *l3cd2 = NULL;

            l3cd2 = _l3cd_config_create(nm_l3_config_data_get_ifindex(l3cd),
                                        addr,
                                        nm_l3_config_data_get_multi_idx(l3cd));
            nm_assert(nm_l3_config_data_equal(l3cd2, l3cd));
        }
#endif
        return addr;
    }

    return nm_assert_unreachable_val(0u);
}

/*****************************************************************************/

static void
_ipv4ll_addrgen(NML3IPv4LL *self, gboolean generate_new_addr)
{
    CSipHash  state;
    char      sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];
    gboolean  seed_changed = FALSE;
    in_addr_t addr_new;
    guint64   h;

    _ASSERT(self);

    /* MAC_HASH_KEY is the same as used by systemd. */
#define MAC_HASH_KEY          \
    ((const guint8[16]){0xdf, \
                        0x04, \
                        0x22, \
                        0x98, \
                        0x3f, \
                        0xad, \
                        0x14, \
                        0x52, \
                        0xf9, \
                        0x87, \
                        0x2e, \
                        0xd1, \
                        0x9c, \
                        0x70, \
                        0xe2, \
                        0xf2})

    if (self->mac_set && (!self->seed_set || !nm_ether_addr_equal(&self->mac, &self->seed_mac))) {
        /* systemd's ipv4ll library by default only hashes the MAC address (as we do here).
         * This is also what previous versions of NetworkManager did (whenn using sd_ipv4ll).
         *
         * On the other hand, systemd-networkd uses net_get_name_persistent() of the device
         * mixed with /etc/machine-id.
         *
         * See also: https://tools.ietf.org/html/rfc3927#section-2.1
         *
         * FIXME(l3cfg): At this point, maybe we should also mix it with nm_utils_host_id_get().
         * This would get the behavior closer to what systemd-networkd does.
         * Don't do that for now, because it would be a change in behavior compared
         * to earlier versions of NetworkManager.  */

        c_siphash_init(&state, MAC_HASH_KEY);
        c_siphash_append(&state, self->mac.ether_addr_octet, ETH_ALEN);
        h = c_siphash_finalize(&state);

        _LOGT("addr-gen: %sset seed (for " NM_ETHER_ADDR_FORMAT_STR ")",
              self->seed_set ? "re" : "",
              NM_ETHER_ADDR_FORMAT_VAL(&self->mac));

        self->seed_set              = TRUE;
        self->seed_mac              = self->mac;
        self->seed.generation       = htole64(0);
        self->seed.value            = htole64(h);
        self->seed_reset_generation = FALSE;
        self->addr                  = 0u;

        seed_changed = TRUE;
    }

    if (!self->seed_set) {
        /* we have no seed set (and consequently no MAC address set either).
         * We cannot generate an address. */
        nm_assert(self->addr == 0u);
        return;
    }

    nm_assert(seed_changed || self->seed.generation != htole64(0u));

    if (self->seed_reset_generation) {
        _LOGT("addr-gen: reset seed (generation only)");
        self->seed.generation = htole64(0);
        self->addr            = 0u;
        seed_changed          = TRUE;
    }

    if (!seed_changed && !generate_new_addr) {
        /* neither did the caller request a new address, nor was the seed changed. The current
         * address is still to be used. */
        nm_assert(nm_utils_ip4_address_is_link_local(self->addr));
        return;
    }

gen_addr:

#define PICK_HASH_KEY         \
    ((const guint8[16]){0x15, \
                        0xac, \
                        0x82, \
                        0xa6, \
                        0xd6, \
                        0x3f, \
                        0x49, \
                        0x78, \
                        0x98, \
                        0x77, \
                        0x5d, \
                        0x0c, \
                        0x69, \
                        0x02, \
                        0x94, \
                        0x0b})

    h = c_siphash_hash(PICK_HASH_KEY, (const guint8 *) &self->seed, sizeof(self->seed));

    self->seed.generation = htole64(le64toh(self->seed.generation) + 1u);

    addr_new = htonl(h & UINT32_C(0x0000FFFF)) | NM_IPV4LL_NETWORK;

    if (self->addr == addr_new || NM_IN_SET(ntohl(addr_new) & 0x0000FF00u, 0x0000u, 0xFF00u))
        goto gen_addr;

    nm_assert(nm_utils_ip4_address_is_link_local(addr_new));

    _LOGT("addr-gen: set address %s", _nm_utils_inet4_ntop(addr_new, sbuf_addr));
    self->addr = addr_new;
}

/*****************************************************************************/

static void
_ipv4ll_update_link(NML3IPv4LL *self, const NMPObject *plobj)
{
    char                 sbuf[ETH_ALEN * 3];
    nm_auto_nmpobj const NMPObject *pllink_old = NULL;
    const NMEtherAddr *             mac_new;
    gboolean                        changed;

    if (self->plobj == plobj)
        return;

    pllink_old  = g_steal_pointer(&self->plobj);
    self->plobj = nmp_object_ref(plobj);

    mac_new = NULL;
    if (plobj) {
        const NMPlatformLink *pllink = NMP_OBJECT_CAST_LINK(plobj);

        if (pllink->l_address.len == ETH_ALEN)
            mac_new = &pllink->l_address.ether_addr;
    }

    changed = FALSE;
    if (!mac_new) {
        if (self->mac_set) {
            changed       = TRUE;
            self->mac_set = FALSE;
        }
    } else {
        if (!self->mac_set || !nm_ether_addr_equal(mac_new, &self->mac)) {
            changed       = TRUE;
            self->mac_set = TRUE;
            self->mac     = *mac_new;
        }
    }

    if (changed) {
        _LOGT("mac changed: %s",
              self->mac_set ? _nm_utils_hwaddr_ntoa(&self->mac, ETH_ALEN, TRUE, sbuf, sizeof(sbuf))
                            : "unset");
    }
}

/*****************************************************************************/

static void
_l3cd_config_add(NML3IPv4LL *self)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;
    char                                     sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];
    gboolean                                 changed;

    _ASSERT(self);
    nm_assert(self->addr != 0u);
    nm_assert(self->reg_timeout_msec > 0u);

    if (_l3cd_config_get_addr(self->l3cd) != self->addr) {
        l3cd = _l3cd_config_create(nm_l3_ipv4ll_get_ifindex(self),
                                   self->addr,
                                   nm_l3cfg_get_multi_idx(self->l3cfg));
        nm_assert(!nm_l3_config_data_equal(l3cd, self->l3cd));
        changed = TRUE;
    } else
        changed = FALSE;

    if (!changed && !self->l3cd_timeout_msec_changed)
        return;

    self->l3cd_timeout_msec_changed = FALSE;

    _LOGT("add l3cd config with %s (acd-timeout %u msec%s)",
          _nm_utils_inet4_ntop(self->addr, sbuf_addr),
          self->reg_timeout_msec,
          changed ? "" : " changed");

    if (changed) {
        NM_SWAP(&l3cd, &self->l3cd);
        self->notify_on_idle = TRUE;
    }

    if (!nm_l3cfg_add_config(self->l3cfg,
                             L3CD_TAG(self),
                             TRUE,
                             self->l3cd,
                             NM_L3CFG_CONFIG_PRIORITY_IPV4LL,
                             0,
                             0,
                             NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
                             NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                             0,
                             0,
                             NM_L3_ACD_DEFEND_TYPE_ONCE,
                             self->reg_timeout_msec,
                             NM_L3_CONFIG_MERGE_FLAGS_ONLY_FOR_ACD))
        nm_assert_not_reached();

    self->l3cfg_commit_handle = nm_l3cfg_commit_type_register(self->l3cfg,
                                                              NM_L3_CFG_COMMIT_TYPE_ASSUME,
                                                              self->l3cfg_commit_handle);
    nm_l3cfg_commit_on_idle_schedule(self->l3cfg);
}

static gboolean
_l3cd_config_remove(NML3IPv4LL *self)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;

    nm_assert(NM_IS_L3_IPV4LL(self));

    if (!self->l3cd)
        return FALSE;

    _LOGT("remove l3cd config");

    self->notify_on_idle = TRUE;

    l3cd = g_steal_pointer(&self->l3cd);
    if (!nm_l3cfg_remove_config(self->l3cfg, L3CD_TAG(self), l3cd))
        nm_assert_not_reached();

    nm_l3cfg_commit_type_unregister(self->l3cfg, g_steal_pointer(&self->l3cfg_commit_handle));
    nm_l3cfg_commit_on_idle_schedule(self->l3cfg);
    return TRUE;
}

/*****************************************************************************/

static const NMPlatformIP4Address *
_ipv4ll_platform_ip4_address_lookup(NML3IPv4LL *self, in_addr_t addr)
{
    const NMPlatformIP4Address *pladdr;

    if (addr == 0u)
        return NULL;

    nm_assert(nm_utils_ip4_address_is_link_local(addr));

    pladdr = nm_platform_ip4_address_get(nm_l3_ipv4ll_get_platform(self),
                                         nm_l3_ipv4ll_get_ifindex(self),
                                         addr,
                                         ADDR_IPV4LL_PREFIX_LEN,
                                         addr);

    nm_assert(!pladdr || pladdr->address == addr);
    nm_assert(!pladdr || _ip4_address_is_link_local(pladdr));
    return pladdr;
}

static const NML3AcdAddrInfo *
_ipv4ll_l3cfg_get_acd_addr_info(NML3IPv4LL *self, in_addr_t addr)
{
    if (addr == 0u)
        return NULL;

    nm_assert(nm_utils_ip4_address_is_link_local(addr));
    return nm_l3cfg_get_acd_addr_info(self->l3cfg, addr);
}

static const NMPlatformIP4Address *
_ipv4ll_platform_find_addr(NML3IPv4LL *self, const NML3AcdAddrInfo **out_acd_info)
{
    const NMPlatformIP4Address *addr_without_acd_info = NULL;
    NMDedupMultiIter            iter;
    NMPLookup                   lookup;
    const NMPObject *           obj;
    const NML3AcdAddrInfo *     acd_info;
    const NMPlatformIP4Address *addr;

    nmp_lookup_init_object(&lookup, NMP_OBJECT_TYPE_IP4_ADDRESS, nm_l3_ipv4ll_get_ifindex(self));
    nm_platform_iter_obj_for_each (&iter, nm_l3_ipv4ll_get_platform(self), &lookup, &obj) {
        addr = NMP_OBJECT_CAST_IP4_ADDRESS(obj);
        if (!_ip4_address_is_link_local(addr))
            continue;

        acd_info = _ipv4ll_l3cfg_get_acd_addr_info(self, addr->address);
        if (!_acd_info_is_good(acd_info))
            continue;

        if (acd_info) {
            /* We have a good acd_info. We won't find a better one. Return it. */
            NM_SET_OUT(out_acd_info, acd_info);
            return addr;
        }

        if (!addr_without_acd_info) {
            /* remember a potential candidate address that has no acd_info. */
            addr_without_acd_info = addr;
        }
    }

    if (addr_without_acd_info) {
        NM_SET_OUT(out_acd_info, NULL);
        return addr_without_acd_info;
    }

    return NULL;
}

/*****************************************************************************/

static gboolean
_ipv4ll_set_timed_out_timeout_cb(gpointer user_data)
{
    NML3IPv4LL *self = user_data;

    _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_IS_TIMED_OUT);
    if (self->notify_on_idle)
        _ipv4ll_emit_signal_notify(self);
    return G_SOURCE_REMOVE;
}

static void
_ipv4ll_set_timed_out_update(NML3IPv4LL *self, TimedOutState new_state)
{
    gboolean before;

    before = _ipv4ll_is_timed_out(self);

    switch (new_state) {
    case TIMED_OUT_STATE_IS_TIMED_OUT:
        if (self->timed_out_expiry_msec == 0) {
            nm_assert(!self->timed_out_source);
            self->timed_out_expiry_msec = 1;
        }
        nm_clear_g_source_inst(&self->timed_out_source);
        break;
    case TIMED_OUT_STATE_IS_NOT_TIMED_OUT:
        self->timed_out_expiry_msec = 0;
        nm_clear_g_source_inst(&self->timed_out_source);
        break;
    case TIMED_OUT_STATE_HAVE_TIMER_RUNNING:
    {
        gint64 now_msec = nm_utils_get_monotonic_timestamp_msec();
        guint  timeout_msec;
        gint64 expiry_msec;

        nm_assert(self->reg_timeout_msec > 0u);

        timeout_msec = nm_mult_clamped_u(TIMED_OUT_TIME_FACTOR, self->reg_timeout_msec);
        expiry_msec  = now_msec + timeout_msec;

        if (self->timed_out_expiry_msec == 0 || self->timed_out_expiry_msec < expiry_msec) {
            self->timed_out_expiry_msec = expiry_msec;
            nm_clear_g_source_inst(&self->timed_out_source);
            self->timed_out_source = nm_g_timeout_source_new(timeout_msec,
                                                             G_PRIORITY_DEFAULT,
                                                             _ipv4ll_set_timed_out_timeout_cb,
                                                             self,
                                                             NULL);
            g_source_attach(self->timed_out_source, NULL);
        }
        break;
    }
    }

    if (before != _ipv4ll_is_timed_out(self)) {
        self->notify_on_idle = TRUE;
        _LOGT("state: set timed-out-is-bad=%d", (!before));
    }
}

static gboolean
_ipv4ll_set_state(NML3IPv4LL *self, NML3IPv4LLState state)
{
    char sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];
    char sbuf100[100];

    if (self->state == state)
        return FALSE;
    self->state          = state;
    self->notify_on_idle = TRUE;
    _LOGT("state: set state %s (addr=%s)",
          nm_l3_ipv4ll_state_to_string(state, sbuf100, sizeof(sbuf100)),
          _nm_utils_inet4_ntop(self->addr, sbuf_addr));
    return TRUE;
}

static void
_ipv4ll_state_change(NML3IPv4LL *self, gboolean is_on_idle_handler)
{
    nm_auto_unref_l3ipv4ll NML3IPv4LL *self_keep_alive = NULL;
    const NMPlatformIP4Address *       pladdr;
    const NML3AcdAddrInfo *            acd_info;
    gboolean                           generate_new_addr;
    NML3IPv4LLState                    new_state;
    in_addr_t                          addr0;
    NML3IPv4LLRegistration *           reg;

    _ASSERT(self);

    self_keep_alive = nm_l3_ipv4ll_ref(self);

    nm_clear_g_source_inst(&self->state_change_on_idle_source);

    addr0 = self->addr;

    if (self->reg_changed) {
        guint timeout_msec = self->reg_timeout_msec;

        self->reg_changed = FALSE;

        if (c_list_is_empty(&self->reg_lst_head))
            timeout_msec = 0;
        else {
            timeout_msec = G_MAXUINT;
            c_list_for_each_entry (reg, &self->reg_lst_head, reg_lst) {
                if (reg->timeout_msec < timeout_msec)
                    timeout_msec = reg->timeout_msec;
                if (reg->timeout_msec == 0)
                    break;
            }
        }
        if (self->reg_timeout_msec != timeout_msec) {
            self->reg_timeout_msec          = timeout_msec;
            self->l3cd_timeout_msec_changed = TRUE;
        }
    }

    if (self->reg_timeout_msec == 0) {
        _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_IS_NOT_TIMED_OUT);
        if (_ipv4ll_set_state(self, NM_L3_IPV4LL_STATE_DISABLED))
            _l3cd_config_remove(self);
        goto out_notify;
    }

    if (!self->mac_set) {
        _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_HAVE_TIMER_RUNNING);
        if (_ipv4ll_set_state(self, NM_L3_IPV4LL_STATE_WAIT_FOR_LINK))
            _l3cd_config_remove(self);
        else
            nm_assert(!self->l3cd);
        goto out_notify;
    }

    if (self->state <= NM_L3_IPV4LL_STATE_EXTERNAL) {
        pladdr = _ipv4ll_platform_ip4_address_lookup(self, self->addr);
        if (pladdr) {
            if (!_acd_info_is_good(_ipv4ll_l3cfg_get_acd_addr_info(self, self->addr)))
                pladdr = NULL;
        }
        if (!pladdr)
            pladdr = _ipv4ll_platform_find_addr(self, NULL);

        if (pladdr) {
            /* we have an externally configured address. Check whether we can use it. */
            self->addr           = pladdr->address;
            self->notify_on_idle = TRUE;
            _ipv4ll_set_state(self, NM_L3_IPV4LL_STATE_EXTERNAL);
            _l3cd_config_add(self);
            _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_IS_NOT_TIMED_OUT);
            goto out_notify;
        }
    }

    generate_new_addr = FALSE;
    while (TRUE) {
        _ipv4ll_addrgen(self, generate_new_addr);
        acd_info = _ipv4ll_l3cfg_get_acd_addr_info(self, self->addr);
        if (_acd_info_is_good(acd_info))
            break;
        generate_new_addr = TRUE;
    }

    nm_assert(_acd_info_is_good(acd_info));
    switch (acd_info ? acd_info->state : NM_L3_ACD_ADDR_STATE_INIT) {
    case NM_L3_ACD_ADDR_STATE_INIT:
    case NM_L3_ACD_ADDR_STATE_PROBING:
        new_state = NM_L3_IPV4LL_STATE_PROBING;
        _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_HAVE_TIMER_RUNNING);
        goto out_is_good_1;
    case NM_L3_ACD_ADDR_STATE_READY:
        new_state = NM_L3_IPV4LL_STATE_READY;
        _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_HAVE_TIMER_RUNNING);
        goto out_is_good_1;
    case NM_L3_ACD_ADDR_STATE_DEFENDING:
        new_state = NM_L3_IPV4LL_STATE_DEFENDING;
        _ipv4ll_set_timed_out_update(self, TIMED_OUT_STATE_IS_NOT_TIMED_OUT);
        goto out_is_good_1;
    case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
    case NM_L3_ACD_ADDR_STATE_USED:
    case NM_L3_ACD_ADDR_STATE_CONFLICT:
        nm_assert_not_reached();
        goto out_notify;
    }
    nm_assert_not_reached();
    goto out_notify;
out_is_good_1:
    _ipv4ll_set_state(self, new_state);
    _l3cd_config_add(self);
    if (self->addr != addr0)
        self->notify_on_idle = TRUE;
    goto out_notify;

out_notify:
    if (self->notify_on_idle) {
        if (is_on_idle_handler)
            _ipv4ll_emit_signal_notify(self);
        else
            _ipv4ll_state_change_on_idle(self);
    }
}

static gboolean
_ipv4ll_state_change_on_idle_cb(gpointer user_data)
{
    NML3IPv4LL *self = user_data;

    _ipv4ll_state_change(self, TRUE);
    return G_SOURCE_REMOVE;
}

static void
_ipv4ll_state_change_on_idle(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    if (!self->state_change_on_idle_source) {
        self->state_change_on_idle_source =
            nm_g_idle_source_new(G_PRIORITY_DEFAULT, _ipv4ll_state_change_on_idle_cb, self, NULL);
        g_source_attach(self->state_change_on_idle_source, NULL);
    }
}

/*****************************************************************************/

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NML3IPv4LL *self)
{
    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE) {
        /* NMl3Cfg only reloads the platform link during the idle handler. Pick it up now. */
        _ipv4ll_update_link(self, nm_l3cfg_get_plobj(l3cfg, FALSE));

        /* theoretically, this even is already on an idle handler. However, we share
         * the call with other signal handlers, so at this point we don't want to
         * emit additional signals. Thus pass %FALSE to _ipv4ll_state_change(). */
        _ipv4ll_state_change(self, FALSE);
        return;
    }

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT) {
        if (self->l3cd
            && nm_l3_acd_addr_info_find_track_info(&notify_data->acd_event.info,
                                                   L3CD_TAG(self),
                                                   self->l3cd,
                                                   NULL)) {
            _ipv4ll_state_change(self, FALSE);
        }
        return;
    }
}

/*****************************************************************************/

NML3IPv4LL *
nm_l3_ipv4ll_new(NML3Cfg *l3cfg)
{
    NML3IPv4LL *self;

    g_return_val_if_fail(NM_IS_L3CFG(l3cfg), NULL);

    self  = g_slice_new(NML3IPv4LL);
    *self = (NML3IPv4LL){
        .l3cfg                       = g_object_ref(l3cfg),
        .ref_count                   = 1,
        .reg_lst_head                = C_LIST_INIT(self->reg_lst_head),
        .l3cfg_commit_handle         = NULL,
        .state_change_on_idle_source = NULL,
        .l3cd                        = NULL,
        .plobj                       = NULL,
        .addr                        = 0u,
        .state                       = NM_L3_IPV4LL_STATE_DISABLED,
        .reg_timeout_msec            = 0,
        .notify_on_idle              = TRUE,
        .l3cfg_signal_notify_id =
            g_signal_connect(l3cfg, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self),
        .seed_set              = FALSE,
        .seed_reset_generation = FALSE,
    };

    _LOGT("created: l3cfg=" NM_HASH_OBFUSCATE_PTR_FMT, NM_HASH_OBFUSCATE_PTR(l3cfg));

    _ipv4ll_update_link(self, nm_l3cfg_get_plobj(l3cfg, FALSE));
    _ipv4ll_state_change(self, FALSE);
    return self;
}

NML3IPv4LL *
nm_l3_ipv4ll_ref(NML3IPv4LL *self)
{
    if (!self)
        return NULL;

    _ASSERT(self);

    nm_assert(self->ref_count < G_MAXINT);
    self->ref_count++;
    return self;
}

void
nm_l3_ipv4ll_unref(NML3IPv4LL *self)
{
    if (!self)
        return;

    _ASSERT(self);

    if (--self->ref_count > 0)
        return;

    if (nm_l3cfg_get_ipv4ll(self->l3cfg) == self)
        _nm_l3cfg_unregister_ipv4ll(self->l3cfg);

    _LOGT("finalize");

    nm_assert(c_list_is_empty(&self->reg_lst_head));

    if (self->l3cd) {
        nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;

        l3cd = g_steal_pointer(&self->l3cd);
        if (!nm_l3cfg_remove_config(self->l3cfg, L3CD_TAG(self), l3cd))
            nm_assert_not_reached();

        nm_l3cfg_commit_type_unregister(self->l3cfg, g_steal_pointer(&self->l3cfg_commit_handle));
        nm_l3cfg_commit_on_idle_schedule(self->l3cfg);
    } else
        nm_assert(!self->l3cfg_commit_handle);

    nm_clear_g_source_inst(&self->state_change_on_idle_source);
    nm_clear_g_source_inst(&self->timed_out_source);

    nm_clear_g_signal_handler(self->l3cfg, &self->l3cfg_signal_notify_id);

    g_clear_object(&self->l3cfg);
    nmp_object_unref(self->plobj);
    nm_g_slice_free(self);
}
