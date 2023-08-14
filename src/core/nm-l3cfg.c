/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-l3cfg.h"

#include "libnm-std-aux/nm-linux-compat.h"

#include <net/if.h>
#include "nm-compat-headers/linux/if_addr.h"
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include "libnm-glib-aux/nm-prioq.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-object.h"
#include "libnm-platform/nmp-global-tracker.h"
#include "nm-netns.h"
#include "n-acd/src/n-acd.h"
#include "nm-l3-ipv4ll.h"
#include "nm-ip-config.h"

/*****************************************************************************/

#define ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC ((gint64) 20000)

/* When a ObjStateData becomes a "zombie", we aim to delete it from platform
 * on the next commit (until it disappears from platform). But we might have
 * a bug, so that we fail to delete the platform (for example, related to
 * IPv6 multicast routes). We thus rate limit how often we try to do this,
 * before giving up. */
#define ZOMBIE_COUNT_START 5

/*****************************************************************************/

G_STATIC_ASSERT(NM_ACD_TIMEOUT_RFC5227_MSEC == N_ACD_TIMEOUT_RFC5227);

#define ACD_SUPPORTED_ETH_ALEN                  ETH_ALEN
#define ACD_ENSURE_RATELIMIT_MSEC               ((guint32) 4000u)
#define ACD_WAIT_PROBING_EXTRA_TIME_MSEC        ((guint32) (1000u + ACD_ENSURE_RATELIMIT_MSEC))
#define ACD_WAIT_PROBING_EXTRA_TIME2_MSEC       ((guint32) 1000u)
#define ACD_WAIT_TIME_PROBING_FULL_RESTART_MSEC ((guint32) 30000u)
#define ACD_WAIT_TIME_CONFLICT_RESTART_MSEC     ((guint32) 120000u)
#define ACD_WAIT_TIME_ANNOUNCE_RESTART_MSEC     ((guint32) 30000u)
#define ACD_DEFENDCONFLICT_INFO_RATELIMIT_MSEC  ((guint32) 30000u)

static gboolean
ACD_ADDR_SKIP(in_addr_t addr)
{
    return addr == 0u;
}

#define ACD_TRACK_FMT                                                    \
    "[l3cd=" NM_HASH_OBFUSCATE_PTR_FMT ",obj=" NM_HASH_OBFUSCATE_PTR_FMT \
    ",tag=" NM_HASH_OBFUSCATE_PTR_FMT "]"
#define ACD_TRACK_PTR2(l3cd, obj, tag) \
    NM_HASH_OBFUSCATE_PTR(l3cd), NM_HASH_OBFUSCATE_PTR(obj), NM_HASH_OBFUSCATE_PTR(tag)
#define ACD_TRACK_PTR(acd_track) \
    ACD_TRACK_PTR2((acd_track)->l3cd, (acd_track)->obj, (acd_track)->tag)

typedef enum {
    ACD_STATE_CHANGE_MODE_NACD_CONFLICT = N_ACD_EVENT_CONFLICT,
    ACD_STATE_CHANGE_MODE_NACD_DEFENDED = N_ACD_EVENT_DEFENDED,
    ACD_STATE_CHANGE_MODE_NACD_DOWN     = N_ACD_EVENT_DOWN,
    ACD_STATE_CHANGE_MODE_NACD_READY    = N_ACD_EVENT_READY,
    ACD_STATE_CHANGE_MODE_NACD_USED     = N_ACD_EVENT_USED,

    ACD_STATE_CHANGE_MODE_INIT = _N_ACD_EVENT_N,
    ACD_STATE_CHANGE_MODE_INIT_REAPPLY,
    ACD_STATE_CHANGE_MODE_POST_COMMIT,

    ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED,
    ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED,
    ACD_STATE_CHANGE_MODE_LINK_NOW_UP,
    ACD_STATE_CHANGE_MODE_INSTANCE_RESET,
    ACD_STATE_CHANGE_MODE_TIMEOUT,
} AcdStateChangeMode;

G_STATIC_ASSERT(G_STRUCT_OFFSET(NML3AcdAddrInfo, addr) == 0);

typedef struct {
    NML3AcdAddrInfo info;

    CList acd_lst;
    CList acd_event_notify_lst;

    NAcdProbe *nacd_probe;

    GSource *acd_data_timeout_source;

    /* see probing_timeout_msec. */
    gint64 probing_timestamp_msec;

    gint64 last_defendconflict_timestamp_msec;

    guint n_track_infos_alloc;

    /* This is only relevant while in state NM_L3_ACD_ADDR_STATE_PROBING. It's the
     * duration for how long we probe, and @probing_timestamp_msec is the
     * timestamp when we start probing. */
    guint32 probing_timeout_msec;

    NML3AcdDefendType acd_defend_type_desired : 3;
    NML3AcdDefendType acd_defend_type_current : 3;
    bool              acd_defend_type_is_active : 1;

    bool track_infos_changed : 1;
} AcdData;

G_STATIC_ASSERT(G_STRUCT_OFFSET(AcdData, info.addr) == 0);

typedef struct {
    const NMPObject *obj;

    /* Whether obj is currently in the platform cache or not.
     * Since "obj" is the NMPObject from the merged NML3ConfigData,
     * the object in platform has the same ID (but may otherwise not
     * be identical). If this is not NULL, then currently the object
     * is configured in kernel. */
    const NMPObject *os_plobj;

    CList os_lst;

    /* If a NMPObject is no longer to be configured (but was configured
     * during a previous commit), then we need to remember it so that the
     * next commit can delete the address/route in kernel. It becomes a zombie. */
    CList os_zombie_lst;

    /* Used by _handle_routes_failed() mechanism. If "os_plobj" is set, then
     * this is meaningless but should be set to zero.
     *
     * If set to a non-zero value, this means adding the object failed.  Until
     * "os_failedobj_expiry_msec" we are still waiting whether we would be able to
     * configure the object. Afterwards, we consider the element failed.
     *
     * Depending on "os_failedobj_prioq_idx", we are currently waiting whether the
     * condition can resolve itself or becomes a failure. */
    gint64 os_failedobj_expiry_msec;

    /* The index into the "priv->failedobj_prioq" queue for objects that are failed.
     * - this field is meaningless in case "os_plobj" is set (but it should be
     *   set to NM_PRIOQ_IDX_NULL).
     * - otherwise, if "os_failedobj_expiry_msec" is 0, no error was detected so
     *   far. The index should be set to NM_PRIOQ_IDX_NULL.
     * - otherwise, if the index is NM_PRIOQ_IDX_NULL it means that the object
     *   is not tracked by the queue, no grace timer is pending, and the object
     *   is considered failed.
     * - otherwise, the index is used for tracking the element in the queue.
     *   It means, we are currently waiting to decide whether this will be a
     *   failure or not. */
    guint os_failedobj_prioq_idx;

    /* When the obj is a zombie (that means, it was previously configured by NML3Cfg, but
     * now no longer), it needs to be deleted from platform. This ratelimits the time
     * how often we try that. When the counter reaches zero, we forget about it. */
    guint8 os_zombie_count;

    /* whether we ever saw the object in platform. */
    bool os_was_in_platform : 1;

    /* Indicates whether NetworkManager actively tried to configure the object
     * in platform once. */
    bool os_nm_configured : 1;

    /* This flag is only used temporarily to do a bulk update and
     * clear all the ones that are no longer in used. */
    bool os_dirty : 1;
} ObjStateData;

G_STATIC_ASSERT(G_STRUCT_OFFSET(ObjStateData, obj) == 0);

struct _NML3CfgCommitTypeHandle {
    CList             commit_type_lst;
    NML3CfgCommitType commit_type;
};

typedef struct {
    const NML3ConfigData *l3cd;
    NML3CfgConfigFlags    config_flags;
    NML3ConfigMergeFlags  merge_flags;
    union {
        struct {
            guint32 default_route_table_6;
            guint32 default_route_table_4;
        };
        guint32 default_route_table_x[2];
    };
    union {
        struct {
            guint32 default_route_metric_6;
            guint32 default_route_metric_4;
        };
        guint32 default_route_metric_x[2];
    };
    union {
        struct {
            guint32 default_route_penalty_6;
            guint32 default_route_penalty_4;
        };
        guint32 default_route_penalty_x[2];
    };
    union {
        struct {
            int default_dns_priority_6;
            int default_dns_priority_4;
        };
        int default_dns_priority_x[2];
    };
    gconstpointer     tag_confdata;
    guint64           pseudo_timestamp_confdata;
    int               priority_confdata;
    guint32           acd_timeout_msec_confdata;
    NML3AcdDefendType acd_defend_type_confdata : 3;
    bool              dirty_confdata : 1;
} L3ConfigData;

struct _NML3CfgBlockHandle {
    NML3Cfg *self;
    CList    lst;
    gboolean is_ipv4;
};

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NML3Cfg, PROP_NETNS, PROP_IFINDEX, );

enum {
    SIGNAL_NOTIFY,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct _NML3CfgPrivate {
    GArray *l3_config_datas;

    NML3IPv4LL *ipv4ll;

    const NML3ConfigData *combined_l3cd_merged;

    const NML3ConfigData *combined_l3cd_commited;

    CList commit_type_lst_head;

    GHashTable *obj_state_hash;

    CList obj_state_lst_head;
    CList obj_state_zombie_lst_head;

    GHashTable *acd_ipv4_addresses_on_link;

    GHashTable *acd_lst_hash;
    CList       acd_lst_head;

    CList acd_event_notify_lst_head;

    NAcd    *nacd;
    GSource *nacd_source;

    GSource *nacd_event_down_source;
    gint64   nacd_event_down_ratelimited_until_msec;

    union {
        struct {
            CList blocked_lst_head_6;
            CList blocked_lst_head_4;
        };
        CList blocked_lst_head_x[2];
    };

    union {
        struct {
            NMIPConfig *ipconfig_6;
            NMIPConfig *ipconfig_4;
        };
        NMIPConfig *ipconfig_x[2];
    };

    /* Whether we earlier configured MPTCP endpoints for the interface. */
    union {
        struct {
            bool mptcp_set_6;
            bool mptcp_set_4;
        };
        bool mptcp_set_x[2];
    };

    /* This is for rate-limiting the creation of nacd instance. */
    GSource *nacd_instance_ensure_retry;

    GSource *commit_on_idle_source;

    guint64 pseudo_timestamp_counter;

    NMPrioq  failedobj_prioq;
    GSource *failedobj_timeout_source;
    gint64   failedobj_timeout_expiry_msec;

    NML3CfgCommitType commit_on_idle_type;

    gint8 commit_reentrant_count;

    union {
        struct {
            gint8 commit_reentrant_count_ip_address_sync_6;
            gint8 commit_reentrant_count_ip_address_sync_4;
        };
        gint8 commit_reentrant_count_ip_address_sync_x[2];
    };

    /* The value that was set before we touched the sysctl (this only is
     * meaningful if "ip6_privacy_set" is true. At the end, we want to restore
     * this value. */
    NMSettingIP6ConfigPrivacy ip6_privacy_initial : 4;

    /* The value that we set the last time. This is cached so that we don't
     * repeatedly try to commit the same value. */
    NMSettingIP6ConfigPrivacy ip6_privacy_set_before : 4;

    guint32 ndisc_retrans_timer_msec;
    guint32 ndisc_reachable_time_msec;
    int     ndisc_hop_limit;

    /* Whether "self" set the ip6_privacy sysctl (and whether it needs to be reset). */
    bool ip6_privacy_set : 1;
    bool ndisc_reachable_time_msec_set : 1;
    bool ndisc_retrans_timer_msec_set : 1;
    bool ndisc_hop_limit_set : 1;

    bool commit_type_update_sticky : 1;

    bool acd_is_pending : 1;

    bool nacd_acd_not_supported : 1;
    bool acd_ipv4_addresses_on_link_has : 1;

    bool changed_configs_configs : 1;
    bool changed_configs_acd_state : 1;

    bool rp_filter_handled : 1;
    bool rp_filter_set : 1;
} NML3CfgPrivate;

struct _NML3CfgClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NML3Cfg, nm_l3cfg, G_TYPE_OBJECT)

/*****************************************************************************/

#define _NODEV_ROUTES_TAG(self, IS_IPv4) \
    ((gconstpointer) (&(((const char *) (self))[0 + (!(IS_IPv4))])))

#define _MPTCP_TAG(self, IS_IPv4) ((gconstpointer) (&(((const char *) (self))[2 + (!(IS_IPv4))])))

#define _NETNS_WATCHER_IP_ADDR_TAG(self, addr_family) \
    ((gconstpointer) & (((char *) self)[1 + NM_IS_IPv4(addr_family)]))

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG_PREFIX_NAME "l3cfg"
#define _NMLOG(level, ...)                                                    \
    G_STMT_START                                                              \
    {                                                                         \
        nm_log((level),                                                       \
               (_NMLOG_DOMAIN),                                               \
               NULL,                                                          \
               NULL,                                                          \
               "l3cfg[" NM_HASH_OBFUSCATE_PTR_FMT                             \
               ",ifindex=%d]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),           \
               NM_HASH_OBFUSCATE_PTR(self),                                   \
               nm_l3cfg_get_ifindex(self) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                                         \
    G_STMT_END

#define _LOGT_acd(acd_data, ...)                                   \
    G_STMT_START                                                   \
    {                                                              \
        char _sbuf_acd[NM_INET_ADDRSTRLEN];                        \
                                                                   \
        _LOGT("acd[%s, %s]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),  \
              nm_inet4_ntop((acd_data)->info.addr, _sbuf_acd),     \
              _l3_acd_addr_state_to_string((acd_data)->info.state) \
                  _NM_UTILS_MACRO_REST(__VA_ARGS__));              \
    }                                                              \
    G_STMT_END

/*****************************************************************************/

static void _l3_commit(NML3Cfg *self, NML3CfgCommitType commit_type, gboolean is_idle);

static void _nm_l3cfg_emit_signal_notify_acd_event_all(NML3Cfg *self);

static gboolean _acd_has_valid_link(const NMPObject *obj,
                                    const guint8   **out_addr_bin,
                                    gboolean        *out_acd_not_supported);

static void
_l3_acd_nacd_instance_reset(NML3Cfg *self, NMTernary start_timer, gboolean acd_data_notify);

static void _l3_acd_data_state_change(NML3Cfg           *self,
                                      AcdData           *acd_data,
                                      AcdStateChangeMode mode,
                                      const NMEtherAddr *sender,
                                      gint64            *p_now_msec);

static AcdData *_l3_acd_data_find(NML3Cfg *self, in_addr_t addr);

/*****************************************************************************/

static NM_UTILS_ENUM2STR_DEFINE(_l3_cfg_commit_type_to_string,
                                NML3CfgCommitType,
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_AUTO, "auto"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_NONE, "none"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_UPDATE, "update"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_REAPPLY, "reapply"), );

static NM_UTILS_ENUM2STR_DEFINE(
    _l3_config_notify_type_to_string,
    NML3ConfigNotifyType,
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT, "acd-event"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT, "ipv4ll-event"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED, "l3cd-changed"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE, "platform-change"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE, "platform-change-on-idle"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_PRE_COMMIT, "pre-commit"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT, "post-commit"),
    NM_UTILS_ENUM2STR_IGNORE(_NM_L3_CONFIG_NOTIFY_TYPE_NUM), );

static NM_UTILS_ENUM2STR_DEFINE(_l3_acd_defend_type_to_string,
                                NML3AcdDefendType,
                                NM_UTILS_ENUM2STR(NM_L3_ACD_DEFEND_TYPE_ALWAYS, "always"),
                                NM_UTILS_ENUM2STR(NM_L3_ACD_DEFEND_TYPE_NEVER, "never"),
                                NM_UTILS_ENUM2STR(_NM_L3_ACD_DEFEND_TYPE_NONE, "none"),
                                NM_UTILS_ENUM2STR(NM_L3_ACD_DEFEND_TYPE_ONCE, "once"), );

static NM_UTILS_LOOKUP_DEFINE(_l3_acd_defend_type_to_nacd,
                              NML3AcdDefendType,
                              int,
                              NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT(0),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_DEFEND_TYPE_ALWAYS,
                                                   N_ACD_DEFEND_ALWAYS),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_DEFEND_TYPE_ONCE, N_ACD_DEFEND_ONCE),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_DEFEND_TYPE_NEVER, N_ACD_DEFEND_NEVER),
                              NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER(), );

static NM_UTILS_LOOKUP_DEFINE(_l3_acd_addr_state_to_string,
                              NML3AcdAddrState,
                              const char *,
                              NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT(NULL),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_CONFLICT, "conflict"),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_READY, "ready"),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_DEFENDING, "defending"),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_INIT, "init"),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_PROBING, "probing"),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED,
                                                   "external-removed"),
                              NM_UTILS_LOOKUP_ITEM(NM_L3_ACD_ADDR_STATE_USED, "used"), );

static gboolean
_obj_is_route_nodev(const NMPObject *obj)
{
    gboolean has_ifindex;

    nm_assert(obj);

    has_ifindex = (NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(obj)->ifindex > 0);

    nm_assert(has_ifindex
              == !(NM_IN_SET(NMP_OBJECT_GET_TYPE(obj),
                             NMP_OBJECT_TYPE_IP4_ROUTE,
                             NMP_OBJECT_TYPE_IP6_ROUTE)
                   && nm_platform_route_type_is_nodev(nm_platform_route_type_uncoerce(
                       NMP_OBJECT_CAST_IP_ROUTE(obj)->type_coerced))));

    return !has_ifindex;
}

/*****************************************************************************/

NMIPConfig *
nm_l3cfg_ipconfig_get(NML3Cfg *self, int addr_family)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), NULL);
    nm_assert_addr_family(addr_family);

    return self->priv.p->ipconfig_x[NM_IS_IPv4(addr_family)];
}

static void
_ipconfig_toggle_notify(gpointer data, GObject *object, gboolean is_last_ref)
{
    NML3Cfg    *self     = NM_L3CFG(data);
    NMIPConfig *ipconfig = NM_IP_CONFIG(object);

    if (!is_last_ref) {
        /* This happens while we take another ref below. Ignore the signal. */
        nm_assert(!NM_IN_SET(ipconfig, self->priv.p->ipconfig_4, self->priv.p->ipconfig_6));
        return;
    }

    if (ipconfig == self->priv.p->ipconfig_4)
        self->priv.p->ipconfig_4 = NULL;
    else {
        nm_assert(ipconfig == self->priv.p->ipconfig_6);
        self->priv.p->ipconfig_6 = NULL;
    }

    /* We take a second reference to keep the instance alive, while also removing the
     * toggle ref. This will notify the function again, but we will ignore that. */
    g_object_ref(ipconfig);

    g_object_remove_toggle_ref(G_OBJECT(ipconfig), _ipconfig_toggle_notify, self);

    /* pass on the reference, and unexport on idle. */
    nm_ip_config_take_and_unexport_on_idle(g_steal_pointer(&ipconfig));
}

NMIPConfig *
nm_l3cfg_ipconfig_acquire(NML3Cfg *self, int addr_family)
{
    NMIPConfig *ipconfig;

    g_return_val_if_fail(NM_IS_L3CFG(self), NULL);
    nm_assert_addr_family(addr_family);

    ipconfig = self->priv.p->ipconfig_x[NM_IS_IPv4(addr_family)];

    if (ipconfig)
        return g_object_ref(ipconfig);

    ipconfig = nm_ip_config_new(addr_family, self);

    self->priv.p->ipconfig_x[NM_IS_IPv4(addr_family)] = ipconfig;

    /* The ipconfig keeps self alive. We use a toggle reference
     * to avoid a cycle. But we anyway wouldn't want a strong reference,
     * because the user releases the instance by unrefing it, and we
     * notice that via the weak reference. */
    g_object_add_toggle_ref(G_OBJECT(ipconfig), _ipconfig_toggle_notify, self);

    /* We keep the toggle reference, and return the other reference to the caller. */
    return g_steal_pointer(&ipconfig);
}

/*****************************************************************************/

gboolean
nm_l3cfg_is_vrf(const NML3Cfg *self)
{
    const NMPlatformLink *pllink;

    pllink = nm_l3cfg_get_pllink(self, TRUE);
    return pllink && pllink->type == NM_LINK_TYPE_VRF;
}

/*****************************************************************************/

static const char *
_l3_config_notify_data_to_string(const NML3ConfigNotifyData *notify_data,
                                 char                       *sbuf,
                                 gsize                       sbuf_size)
{
    char      sbuf_addr[NM_INET_ADDRSTRLEN];
    char      sbuf100[100];
    char      sbufobf[NM_HASH_OBFUSCATE_PTR_STR_BUF_SIZE];
    char     *s = sbuf;
    gsize     l = sbuf_size;
    in_addr_t addr4;

    nm_assert(sbuf);
    nm_assert(sbuf_size > 0);

    _l3_config_notify_type_to_string(notify_data->notify_type, s, l);
    nm_strbuf_seek_end(&s, &l);

    switch (notify_data->notify_type) {
    case NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED:
        nm_strbuf_append(&s,
                         &l,
                         ", l3cd-old=%s",
                         NM_HASH_OBFUSCATE_PTR_STR(notify_data->l3cd_changed.l3cd_old, sbufobf));
        nm_strbuf_append(&s,
                         &l,
                         ", l3cd-new=%s",
                         NM_HASH_OBFUSCATE_PTR_STR(notify_data->l3cd_changed.l3cd_new, sbufobf));
        nm_strbuf_append(&s, &l, ", commited=%d", notify_data->l3cd_changed.commited);
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT:
        nm_strbuf_append(&s,
                         &l,
                         ", addr=%s, state=%s",
                         nm_inet4_ntop(notify_data->acd_event.info.addr, sbuf_addr),
                         _l3_acd_addr_state_to_string(notify_data->acd_event.info.state));
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE:
        nm_strbuf_append(
            &s,
            &l,
            ", obj-type=%s, change=%s, obj=",
            NMP_OBJECT_GET_CLASS(notify_data->platform_change.obj)->obj_type_name,
            nm_platform_signal_change_type_to_string(notify_data->platform_change.change_type));
        nmp_object_to_string(notify_data->platform_change.obj, NMP_OBJECT_TO_STRING_PUBLIC, s, l);
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE:
        nm_strbuf_append(&s,
                         &l,
                         ", obj-type-flags=0x%x",
                         notify_data->platform_change_on_idle.obj_type_flags);
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT:
        nm_assert(NM_IS_L3_IPV4LL(notify_data->ipv4ll_event.ipv4ll));
        addr4 = nm_l3_ipv4ll_get_addr(notify_data->ipv4ll_event.ipv4ll);
        nm_strbuf_append(
            &s,
            &l,
            ", ipv4ll=" NM_HASH_OBFUSCATE_PTR_FMT "%s%s, state=%s",
            NM_HASH_OBFUSCATE_PTR(notify_data->ipv4ll_event.ipv4ll),
            NM_PRINT_FMT_QUOTED2(addr4 != 0, ", addr=", nm_inet4_ntop(addr4, sbuf_addr), ""),
            nm_l3_ipv4ll_state_to_string(nm_l3_ipv4ll_get_state(notify_data->ipv4ll_event.ipv4ll),
                                         sbuf100,
                                         sizeof(sbuf100)));
        break;
    default:
        break;
    }

    return sbuf;
}

void
_nm_l3cfg_emit_signal_notify(NML3Cfg *self, const NML3ConfigNotifyData *notify_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    nm_assert(notify_data);
    nm_assert(_NM_INT_NOT_NEGATIVE(notify_data->notify_type));
    nm_assert(notify_data->notify_type < _NM_L3_CONFIG_NOTIFY_TYPE_NUM);

    _LOGT("emit signal (%s)", _l3_config_notify_data_to_string(notify_data, sbuf, sizeof(sbuf)));

    g_signal_emit(self, signals[SIGNAL_NOTIFY], 0, notify_data);
}

static void
_nm_l3cfg_emit_signal_notify_simple(NML3Cfg *self, NML3ConfigNotifyType notify_type)
{
    NML3ConfigNotifyData notify_data;

    notify_data.notify_type = notify_type;
    _nm_l3cfg_emit_signal_notify(self, &notify_data);
}

static void
_nm_l3cfg_emit_signal_notify_l3cd_changed(NML3Cfg              *self,
                                          const NML3ConfigData *l3cd_old,
                                          const NML3ConfigData *l3cd_new,
                                          gboolean              commited)
{
    NML3ConfigNotifyData notify_data;

    notify_data.notify_type  = NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED;
    notify_data.l3cd_changed = (typeof(notify_data.l3cd_changed)){
        .l3cd_old = l3cd_old,
        .l3cd_new = l3cd_new,
        .commited = commited,
    };
    _nm_l3cfg_emit_signal_notify(self, &notify_data);
}

/*****************************************************************************/

static void
_l3_changed_configs_set_dirty(NML3Cfg *self)
{
    _LOGT("IP configuration changed (mark dirty)");
    self->priv.p->changed_configs_configs   = TRUE;
    self->priv.p->changed_configs_acd_state = TRUE;
}

/*****************************************************************************/

static void
_l3_acd_ipv4_addresses_on_link_update(NML3Cfg  *self,
                                      in_addr_t addr,
                                      gboolean  add /* or else remove */)
{
    AcdData *acd_data;

    acd_data = _l3_acd_data_find(self, addr);

    if (add) {
        if (self->priv.p->acd_ipv4_addresses_on_link)
            g_hash_table_add(self->priv.p->acd_ipv4_addresses_on_link, GUINT_TO_POINTER(addr));
        else
            self->priv.p->acd_ipv4_addresses_on_link_has = FALSE;
        if (acd_data)
            _l3_acd_data_state_change(self,
                                      acd_data,
                                      ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED,
                                      NULL,
                                      NULL);
        return;
    }

    /* when we remove an IPv4 address from kernel, we cannot know whether the same address is still
     * present (with a different prefix length or peer). So we cannot be sure whether we removed
     * the only address, or whether more are still present. All we can do is forget about the
     * cached addresses, and fetch them new the next time we need the information. */
    nm_clear_pointer(&self->priv.p->acd_ipv4_addresses_on_link, g_hash_table_unref);
    self->priv.p->acd_ipv4_addresses_on_link_has = FALSE;
    if (acd_data) {
        _l3_acd_data_state_change(self,
                                  acd_data,
                                  ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED,
                                  NULL,
                                  NULL);
    }
}

static gboolean
_l3_acd_ipv4_addresses_on_link_contains(NML3Cfg *self, in_addr_t addr)
{
    if (!self->priv.p->acd_ipv4_addresses_on_link) {
        if (self->priv.p->acd_ipv4_addresses_on_link_has)
            return FALSE;
        self->priv.p->acd_ipv4_addresses_on_link_has = TRUE;
        self->priv.p->acd_ipv4_addresses_on_link =
            nm_platform_ip4_address_addr_to_hash(self->priv.platform, self->priv.ifindex);
        if (!self->priv.p->acd_ipv4_addresses_on_link)
            return FALSE;
    }
    return g_hash_table_contains(self->priv.p->acd_ipv4_addresses_on_link, GUINT_TO_POINTER(addr));
}

/*****************************************************************************/

static NAcdProbe *
_nm_n_acd_data_probe_new(NML3Cfg *self, in_addr_t addr, guint32 timeout_msec, gpointer user_data)
{
    nm_auto(n_acd_probe_config_freep) NAcdProbeConfig *probe_config = NULL;
    NAcdProbe                                         *probe;
    int                                                r;

    nm_assert(self);

    if (!self->priv.p->nacd)
        return NULL;

    if (addr == 0)
        return nm_assert_unreachable_val(NULL);

    r = n_acd_probe_config_new(&probe_config);
    if (r)
        return NULL;

    n_acd_probe_config_set_ip(probe_config, (struct in_addr){addr});
    n_acd_probe_config_set_timeout(probe_config, timeout_msec);

    r = n_acd_probe(self->priv.p->nacd, &probe, probe_config);
    if (r)
        return NULL;

    n_acd_probe_set_userdata(probe, user_data);
    return probe;
}

/*****************************************************************************/

#define nm_assert_obj_state(self, obj_state)                                                     \
    G_STMT_START                                                                                 \
    {                                                                                            \
        if (NM_MORE_ASSERTS > 0) {                                                               \
            const NML3Cfg      *_self      = (self);                                             \
            const ObjStateData *_obj_state = (obj_state);                                        \
                                                                                                 \
            nm_assert(_obj_state);                                                               \
            nm_assert(NM_IN_SET(NMP_OBJECT_GET_TYPE(_obj_state->obj),                            \
                                NMP_OBJECT_TYPE_IP4_ADDRESS,                                     \
                                NMP_OBJECT_TYPE_IP6_ADDRESS,                                     \
                                NMP_OBJECT_TYPE_IP4_ROUTE,                                       \
                                NMP_OBJECT_TYPE_IP6_ROUTE));                                     \
            nm_assert(!_obj_state->os_plobj || _obj_state->os_was_in_platform);                  \
            nm_assert(_obj_state->os_failedobj_expiry_msec != 0                                  \
                      || _obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);               \
            nm_assert(_obj_state->os_failedobj_expiry_msec == 0 || !_obj_state->os_plobj);       \
            nm_assert(_obj_state->os_failedobj_expiry_msec == 0                                  \
                      || c_list_is_empty(&_obj_state->os_zombie_lst));                           \
            nm_assert(_obj_state->os_failedobj_expiry_msec == 0 || _obj_state->obj);             \
            if (_self) {                                                                         \
                if (c_list_is_empty(&_obj_state->os_zombie_lst)) {                               \
                    nm_assert(_self->priv.p->combined_l3cd_commited);                            \
                                                                                                 \
                    if (NM_MORE_ASSERTS > 5) {                                                   \
                        nm_assert(c_list_contains(&_self->priv.p->obj_state_lst_head,            \
                                                  &_obj_state->os_lst));                         \
                        nm_assert(_obj_state->os_plobj                                           \
                                  == nm_platform_lookup_obj(_self->priv.platform,                \
                                                            NMP_CACHE_ID_TYPE_OBJECT_TYPE,       \
                                                            _obj_state->obj));                   \
                        nm_assert(                                                               \
                            c_list_is_empty(&obj_state->os_zombie_lst)                           \
                                ? (_obj_state->obj                                               \
                                   == nm_dedup_multi_entry_get_obj(nm_l3_config_data_lookup_obj( \
                                       _self->priv.p->combined_l3cd_commited,                    \
                                       _obj_state->obj)))                                        \
                                : (!nm_l3_config_data_lookup_obj(                                \
                                    _self->priv.p->combined_l3cd_commited,                       \
                                    _obj_state->obj)));                                          \
                    }                                                                            \
                }                                                                                \
            }                                                                                    \
        }                                                                                        \
    }                                                                                            \
    G_STMT_END

static ObjStateData *
_obj_state_data_new(const NMPObject *obj, const NMPObject *plobj)
{
    ObjStateData *obj_state;

    obj_state  = g_slice_new(ObjStateData);
    *obj_state = (ObjStateData){
        .obj                      = nmp_object_ref(obj),
        .os_plobj                 = nmp_object_ref(plobj),
        .os_was_in_platform       = !!plobj,
        .os_nm_configured         = FALSE,
        .os_dirty                 = FALSE,
        .os_failedobj_expiry_msec = 0,
        .os_failedobj_prioq_idx   = NM_PRIOQ_IDX_NULL,
        .os_zombie_lst            = C_LIST_INIT(obj_state->os_zombie_lst),
    };
    return obj_state;
}

static void
_obj_state_data_free(gpointer data)
{
    ObjStateData *obj_state = data;

    nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);

    c_list_unlink_stale(&obj_state->os_lst);
    c_list_unlink_stale(&obj_state->os_zombie_lst);
    nmp_object_unref(obj_state->obj);
    nmp_object_unref(obj_state->os_plobj);
    nm_g_slice_free(obj_state);
}

static const char *
_obj_state_data_to_string(const ObjStateData *obj_state, char *buf, gsize buf_size)
{
    const char *buf0     = buf;
    gint64      now_msec = 0;

    nm_assert(buf);
    nm_assert(buf_size > 0);
    nm_assert_obj_state(NULL, obj_state);

    nm_strbuf_append(&buf,
                     &buf_size,
                     "[" NM_HASH_OBFUSCATE_PTR_FMT ", %s, ",
                     NM_HASH_OBFUSCATE_PTR(obj_state),
                     NMP_OBJECT_GET_CLASS(obj_state->obj)->obj_type_name);

    nmp_object_to_string(obj_state->obj, NMP_OBJECT_TO_STRING_PUBLIC, buf, buf_size);
    nm_strbuf_seek_end(&buf, &buf_size);
    nm_strbuf_append_c(&buf, &buf_size, ']');

    if (!c_list_is_empty(&obj_state->os_zombie_lst))
        nm_strbuf_append(&buf, &buf_size, ", zombie[%u]", obj_state->os_zombie_count);

    if (obj_state->os_nm_configured)
        nm_strbuf_append_str(&buf, &buf_size, ", nm-configured");

    if (obj_state->os_plobj) {
        nm_assert(obj_state->os_was_in_platform);
        nm_strbuf_append_str(&buf, &buf_size, ", in-platform");
    } else if (obj_state->os_was_in_platform)
        nm_strbuf_append_str(&buf, &buf_size, ", was-in-platform");

    if (obj_state->os_failedobj_expiry_msec > 0) {
        nm_utils_get_monotonic_timestamp_msec_cached(&now_msec);
        nm_strbuf_append(&buf,
                         &buf_size,
                         ", %s-since=%" G_GINT64_FORMAT ".%03d",
                         (obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL) ? "failed"
                                                                                  : "failed-wait",
                         (obj_state->os_failedobj_expiry_msec - now_msec) / 1000,
                         (int) ((obj_state->os_failedobj_expiry_msec - now_msec) % 1000));
    } else
        nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);

    return buf0;
}

static gboolean
_obj_state_data_update(ObjStateData *obj_state, const NMPObject *obj)
{
    gboolean changed = FALSE;

    nm_assert_obj_state(NULL, obj_state);
    nm_assert(obj);
    nm_assert(nmp_object_id_equal(obj_state->obj, obj));

    obj_state->os_dirty = FALSE;

    if (obj_state->obj != obj) {
        nm_auto_nmpobj const NMPObject *obj_old = NULL;

        if (!nmp_object_equal(obj_state->obj, obj))
            changed = TRUE;
        obj_old        = g_steal_pointer(&obj_state->obj);
        obj_state->obj = nmp_object_ref(obj);
    }

    if (!c_list_is_empty(&obj_state->os_zombie_lst)) {
        c_list_unlink(&obj_state->os_zombie_lst);
        changed = TRUE;
    }

    return changed;
}

/*****************************************************************************/

static void
_obj_states_externally_removed_track(NML3Cfg *self, const NMPObject *obj, gboolean in_platform)
{
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    ObjStateData *obj_state;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert_is_bool(in_platform);

    nm_assert(
        in_platform
            ? (obj
               == nm_platform_lookup_obj(self->priv.platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj))
            : (!nm_platform_lookup_obj(self->priv.platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj)));

    obj_state = g_hash_table_lookup(self->priv.p->obj_state_hash, &obj);
    if (!obj_state)
        return;

    if (!in_platform)
        obj = NULL;

    if (obj_state->os_plobj == obj)
        goto out;

    if (!in_platform && !c_list_is_empty(&obj_state->os_zombie_lst)) {
        /* this is a zombie. We can forget about it.*/
        nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);
        nm_clear_nmp_object(&obj_state->os_plobj);
        c_list_unlink(&obj_state->os_zombie_lst);
        _LOGD("obj-state: zombie gone (untrack): %s",
              _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
        g_hash_table_remove(self->priv.p->obj_state_hash, obj_state);
        return;
    }

    /* Even if this is a zombie (os_zombie_lst), it is still in platform. We continue
     * tracking it, until it gets deleted from platform or until the os_zombie_count
     * drops to zero. We don't need to handle this specially here. */

    if (in_platform) {
        nmp_object_ref_set(&obj_state->os_plobj, obj);
        obj_state->os_was_in_platform = TRUE;
        if (obj_state->os_failedobj_expiry_msec != 0) {
            obj_state->os_failedobj_expiry_msec = 0;
            if (obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL) {
                _LOGT("obj-state: failed-obj: object now configured after failed earlier: %s",
                      _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
            } else {
                nm_prioq_remove(&self->priv.p->failedobj_prioq,
                                obj_state,
                                &obj_state->os_failedobj_prioq_idx);
                _LOGT("obj-state: failed-obj: object now configured after waiting: %s",
                      _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
            }
        } else {
            _LOGD("obj-state: appeared in platform: %s",
                  _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
        }
        nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);
        goto out;
    }

    nm_clear_nmp_object(&obj_state->os_plobj);
    _LOGD("obj-state: remove from platform: %s",
          _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));

out:
    nm_assert_obj_state(self, obj_state);
}

static void
_obj_states_update_all(NML3Cfg *self)
{
    static const NMPObjectType obj_types[] = {
        NMP_OBJECT_TYPE_IP4_ADDRESS,
        NMP_OBJECT_TYPE_IP6_ADDRESS,
        NMP_OBJECT_TYPE_IP4_ROUTE,
        NMP_OBJECT_TYPE_IP6_ROUTE,
    };
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    ObjStateData *obj_state;
    int           i;
    gboolean      any_dirty = FALSE;

    nm_assert(NM_IS_L3CFG(self));

    c_list_for_each_entry (obj_state, &self->priv.p->obj_state_lst_head, os_lst) {
        if (!c_list_is_empty(&obj_state->os_zombie_lst)) {
            /* we can ignore zombies. */
            continue;
        }
        any_dirty           = TRUE;
        obj_state->os_dirty = TRUE;
    }

    for (i = 0; i < (int) G_N_ELEMENTS(obj_types); i++) {
        const NMPObjectType obj_type = obj_types[i];
        NMDedupMultiIter    o_iter;
        const NMPObject    *obj;

        if (!self->priv.p->combined_l3cd_commited)
            continue;

        nm_l3_config_data_iter_obj_for_each (&o_iter,
                                             self->priv.p->combined_l3cd_commited,
                                             &obj,
                                             obj_type) {
            if (_obj_is_route_nodev(obj)) {
                /* this is a nodev route. We don't track an obj-state for this. */
                continue;
            }

            obj_state = g_hash_table_lookup(self->priv.p->obj_state_hash, &obj);
            if (!obj_state) {
                obj_state =
                    _obj_state_data_new(obj,
                                        nm_platform_lookup_obj(self->priv.platform,
                                                               NMP_CACHE_ID_TYPE_OBJECT_TYPE,
                                                               obj));
                c_list_link_tail(&self->priv.p->obj_state_lst_head, &obj_state->os_lst);
                g_hash_table_add(self->priv.p->obj_state_hash, obj_state);
                _LOGD("obj-state: track: %s",
                      _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
                nm_assert_obj_state(self, obj_state);
                continue;
            }

            if (_obj_state_data_update(obj_state, obj)) {
                _LOGD("obj-state: update: %s",
                      _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
            }

            nm_assert_obj_state(self, obj_state);
        }
    }

    if (any_dirty) {
        GHashTableIter h_iter;

        g_hash_table_iter_init(&h_iter, self->priv.p->obj_state_hash);
        while (g_hash_table_iter_next(&h_iter, (gpointer *) &obj_state, NULL)) {
            if (!c_list_is_empty(&obj_state->os_zombie_lst))
                continue;
            if (!obj_state->os_dirty)
                continue;

            if (obj_state->os_plobj && obj_state->os_nm_configured) {
                nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);
                c_list_link_tail(&self->priv.p->obj_state_zombie_lst_head,
                                 &obj_state->os_zombie_lst);
                obj_state->os_zombie_count = ZOMBIE_COUNT_START;
                _LOGD("obj-state: now zombie: %s",
                      _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
                continue;
            }

            _LOGD("obj-state: untrack: %s",
                  _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
            nm_prioq_remove(&self->priv.p->failedobj_prioq,
                            obj_state,
                            &obj_state->os_failedobj_prioq_idx);
            g_hash_table_iter_remove(&h_iter);
        }
    }
}

typedef struct {
    NML3Cfg          *self;
    NML3CfgCommitType commit_type;
} ObjStatesSyncFilterData;

static gboolean
_obj_states_sync_filter(NML3Cfg *self, const NMPObject *obj, NML3CfgCommitType commit_type)
{
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    NMPObjectType obj_type;
    ObjStateData *obj_state;

    obj_type = NMP_OBJECT_GET_TYPE(obj);

    if (obj_type == NMP_OBJECT_TYPE_IP4_ADDRESS
        && NMP_OBJECT_CAST_IP4_ADDRESS(obj)->a_acd_not_ready)
        return FALSE;

    obj_state = g_hash_table_lookup(self->priv.p->obj_state_hash, &obj);

    nm_assert_obj_state(self, obj_state);
    nm_assert(obj_state->obj == obj);
    nm_assert(c_list_is_empty(&obj_state->os_zombie_lst));

    if (!obj_state->os_nm_configured) {
        obj_state->os_nm_configured = TRUE;

        _LOGD("obj-state: configure-first-time: %s",
              _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
        return TRUE;
    }

    /* One goal would be that we don't forcefully re-add routes which were
     * externally removed (e.g. by the user via `ip route del`).
     *
     * However,
     *
     *  - some routes get automatically deleted by kernel (for example,
     *  when we have an IPv4 route with RTA_PREFSRC set and the referenced
     *  IPv4 address gets removed). The absence of such a route does not
     *  mean that the user doesn't want the route there. It means, kernel
     *  removed it because of some consistency check, but we want it back.
     *  - a route with a non-zero gateway requires that the gateway is
     *  directly reachable via an onlink route. The rules for this are
     *  complex, but kernel will reject adding a route which has such a
     *  gateway. If the user manually removed the needed onlink route, the
     *  gateway route cannot be added in kernel ("Nexthop has invalid
     *  gateway"). To handle that is a nightmare, so we always ensure that
     *  the onlink route is there.
     *  - a route with RTA_PREFSRC requires that such an address is
     *  configured otherwise kernel rejects adding the route with "Invalid
     *  prefsrc address"/"Invalid source address".  Removing an address can
     *  thus prevent adding the route, which is a problem for us.
     *
     * So the goal is not tenable and causes problems. NetworkManager will
     * try hard to re-add routes and address that it thinks should be
     * present. If you externally remove them, then you are starting a
     * fight where NetworkManager tries to re-add them on every commit. */
    return TRUE;
}

static gboolean
_obj_states_sync_filter_predicate(gconstpointer o, gpointer user_data)
{
    const NMPObject               *obj              = o;
    const ObjStatesSyncFilterData *sync_filter_data = user_data;

    return _obj_states_sync_filter(sync_filter_data->self, obj, sync_filter_data->commit_type);
}

static GPtrArray *
_commit_collect_addresses(NML3Cfg *self, int addr_family, NML3CfgCommitType commit_type)
{
    const int                     IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMDedupMultiHeadEntry  *head_entry;
    const ObjStatesSyncFilterData sync_filter_data = {
        .self        = self,
        .commit_type = commit_type,
    };

    head_entry = nm_l3_config_data_lookup_objs(self->priv.p->combined_l3cd_commited,
                                               NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4));
    return nm_dedup_multi_objs_to_ptr_array_head(head_entry,
                                                 _obj_states_sync_filter_predicate,
                                                 (gpointer) &sync_filter_data);
}

static void
_commit_collect_routes(NML3Cfg          *self,
                       int               addr_family,
                       NML3CfgCommitType commit_type,
                       gboolean          any_addrs,
                       GPtrArray       **routes,
                       GPtrArray       **routes_nodev)
{
    const int                    IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMDedupMultiHeadEntry *head_entry;
    const NMDedupMultiEntry     *entry;

    nm_assert(routes && !*routes);
    nm_assert(routes_nodev && !*routes_nodev);

    head_entry = nm_l3_config_data_lookup_objs(self->priv.p->combined_l3cd_commited,
                                               NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4));

    if (!head_entry)
        goto loop_done;

    c_list_for_each_entry (entry, &head_entry->lst_entries_head, lst_entries) {
        const NMPObject *obj = entry->obj;
        GPtrArray      **r;

        if (_obj_is_route_nodev(obj))
            r = routes_nodev;
        else {
            nm_assert(NMP_OBJECT_CAST_IP_ROUTE(obj)->ifindex == self->priv.ifindex);

            if (!any_addrs) {
                /* This is a unicast route (or a similar route, which has an
                 * ifindex).
                 *
                 * However, during this commit we don't plan to configure any
                 * IP addresses.  With `ipvx.method=manual` that should not be
                 * possible. More likely, this is because the profile has
                 * `ipvx.method=auto` and static routes.
                 *
                 * Don't configure any such routes before we also have at least
                 * one IP address.
                 *
                 * This code applies to IPv4 and IPv6, however for IPv6 we
                 * early on configure a link local address, so in practice the
                 * branch is not taken for IPv6. */
                continue;
            }

            if (IS_IPv4 && NMP_OBJECT_CAST_IP4_ROUTE(obj)->weight > 0) {
                /* This route needs to be registered as ECMP route. */
                nm_netns_ip_route_ecmp_register(self->priv.netns, self, obj);
                continue;
            }

            if (!_obj_states_sync_filter(self, obj, commit_type))
                continue;
            r = routes;
        }

        if (!*r)
            *r = g_ptr_array_new_full(head_entry->len, (GDestroyNotify) nm_dedup_multi_obj_unref);

        g_ptr_array_add(*r, (gpointer) nmp_object_ref(obj));
    }

loop_done:

    if (IS_IPv4) {
        gs_unref_ptrarray GPtrArray *singlehop_routes = NULL;
        guint                        i;

        /* NMNetns will merge the routes. The ones that found a merge partner are true multihop
         * routes, with potentially a next hop on different interfaces. The routes
         * that didn't find a merge partner are returned in "singlehop_routes". */
        nm_netns_ip_route_ecmp_commit(self->priv.netns,
                                      self,
                                      &singlehop_routes,
                                      NM_IN_SET(commit_type, NM_L3_CFG_COMMIT_TYPE_REAPPLY));

        if (singlehop_routes) {
            for (i = 0; i < singlehop_routes->len; i++) {
                const NMPObject *obj = singlehop_routes->pdata[i];

                if (!_obj_states_sync_filter(self, obj, commit_type))
                    continue;

                if (!*routes)
                    *routes =
                        g_ptr_array_new_with_free_func((GDestroyNotify) nm_dedup_multi_obj_unref);

                g_ptr_array_add(*routes, (gpointer) nmp_object_ref(obj));
            }
        }
    }
}

static void
_obj_state_zombie_lst_get_prune_lists(NML3Cfg    *self,
                                      int         addr_family,
                                      GPtrArray **out_addresses_prune,
                                      GPtrArray **out_routes_prune)
{
    const int           IS_IPv4          = NM_IS_IPv4(addr_family);
    const NMPObjectType obj_type_route   = NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4);
    const NMPObjectType obj_type_address = NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4);
    char                sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    ObjStateData       *obj_state;
    ObjStateData       *obj_state_safe;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(out_addresses_prune && !*out_addresses_prune);
    nm_assert(out_routes_prune && !*out_routes_prune);

    c_list_for_each_entry_safe (obj_state,
                                obj_state_safe,
                                &self->priv.p->obj_state_zombie_lst_head,
                                os_zombie_lst) {
        NMPObjectType obj_type;
        GPtrArray   **p_a;

        nm_assert_obj_state(self, obj_state);
        nm_assert(obj_state->os_zombie_count > 0);

        obj_type = NMP_OBJECT_GET_TYPE(obj_state->obj);

        if (obj_type == obj_type_route)
            p_a = out_routes_prune;
        else if (obj_type == obj_type_address)
            p_a = out_addresses_prune;
        else
            continue;

        if (!*p_a)
            *p_a = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);

        g_ptr_array_add(*p_a, (gpointer) nmp_object_ref(obj_state->obj));

        if (--obj_state->os_zombie_count == 0) {
            _LOGD("obj-state: prune zombie (untrack): %s",
                  _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
            nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);
            g_hash_table_remove(self->priv.p->obj_state_hash, obj_state);
            continue;
        }
        _LOGD("obj-state: prune zombie: %s",
              _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
    }
}

static void
_obj_state_zombie_lst_prune_all(NML3Cfg *self, int addr_family)
{
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    ObjStateData *obj_state;
    ObjStateData *obj_state_safe;

    /* we call this during reapply. Then we delete all the routes/addresses
     * that are configured, and not only the zombies.
     *
     * Still, we need to adjust the os_zombie_count and assume that we
     * are going to drop them. */

    c_list_for_each_entry_safe (obj_state,
                                obj_state_safe,
                                &self->priv.p->obj_state_zombie_lst_head,
                                os_zombie_lst) {
        nm_assert_obj_state(self, obj_state);
        nm_assert(obj_state->os_zombie_count > 0);

        if (NMP_OBJECT_GET_ADDR_FAMILY(obj_state->obj) != addr_family)
            continue;

        if (--obj_state->os_zombie_count == 0) {
            _LOGD("obj-state: zombie pruned during reapply (untrack): %s",
                  _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
            nm_assert(obj_state->os_failedobj_prioq_idx == NM_PRIOQ_IDX_NULL);
            g_hash_table_remove(self->priv.p->obj_state_hash, obj_state);
            continue;
        }
        _LOGD("obj-state: zombie pruned during reapply: %s",
              _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)));
    }
}

/*****************************************************************************/

static void
_load_link(NML3Cfg *self, gboolean initial)
{
    nm_auto_nmpobj const NMPObject *obj_old = NULL;
    const NMPObject                *obj;
    const char                     *ifname;
    const char                     *ifname_old;
    gboolean                        nacd_changed;
    gboolean                        nacd_new_valid;
    gboolean                        nacd_old_valid;
    const guint8                   *nacd_old_addr = NULL;
    const guint8                   *nacd_new_addr = NULL;
    gboolean                        nacd_link_now_up;
    AcdData                        *acd_data;

    if (initial) {
        obj = nm_platform_link_get_obj(self->priv.platform, self->priv.ifindex, TRUE);
        self->priv.plobj_next = nmp_object_ref(obj);
    } else {
        obj = self->priv.plobj_next;
        nm_assert(obj == nm_platform_link_get_obj(self->priv.platform, self->priv.ifindex, TRUE));
    }

    if (initial && obj == self->priv.plobj)
        return;

    obj_old          = g_steal_pointer(&self->priv.plobj);
    self->priv.plobj = nmp_object_ref(obj);

    if (obj && NM_FLAGS_HAS(NMP_OBJECT_CAST_LINK(obj)->n_ifi_flags, IFF_UP)
        && (!obj_old || !NM_FLAGS_HAS(NMP_OBJECT_CAST_LINK(obj_old)->n_ifi_flags, IFF_UP)))
        nacd_link_now_up = TRUE;
    else
        nacd_link_now_up = FALSE;

    nacd_changed   = FALSE;
    nacd_old_valid = _acd_has_valid_link(obj_old, &nacd_old_addr, NULL);
    nacd_new_valid = _acd_has_valid_link(obj, &nacd_new_addr, NULL);
    if (self->priv.p->nacd_instance_ensure_retry) {
        if (nacd_new_valid
            && (!nacd_old_valid
                || memcmp(nacd_new_addr, nacd_old_addr, ACD_SUPPORTED_ETH_ALEN) == 0))
            nacd_changed = TRUE;
    } else if (self->priv.p->nacd) {
        if (!nacd_new_valid)
            nacd_changed = TRUE;
        else if (!nacd_old_valid)
            nacd_changed = nm_assert_unreachable_val(TRUE);
        else if (memcmp(nacd_old_addr, nacd_new_addr, ACD_SUPPORTED_ETH_ALEN) != 0)
            nacd_changed = TRUE;
    } else if (nacd_new_valid)
        nacd_changed = TRUE;
    ifname_old = nmp_object_link_get_ifname(obj_old);
    ifname     = nmp_object_link_get_ifname(self->priv.plobj);

    if (initial) {
        _LOGT("link ifname changed: %s%s%s (initial)", NM_PRINT_FMT_QUOTE_STRING(ifname));
    } else if (!nm_streq0(ifname, ifname_old)) {
        _LOGT("link ifname changed: %s%s%s (was %s%s%s)",
              NM_PRINT_FMT_QUOTE_STRING(ifname),
              NM_PRINT_FMT_QUOTE_STRING(ifname_old));
    }

    if (nacd_changed) {
        if (!c_list_is_empty(&self->priv.p->acd_lst_head))
            _LOGT("acd: link change causes restart of ACD");
        _l3_acd_nacd_instance_reset(self, NM_TERNARY_FALSE, TRUE);
    } else if (nacd_link_now_up) {
        if (!c_list_is_empty(&self->priv.p->acd_lst_head)) {
            gint64 now_msec = 0;

            _LOGT("acd: link up requires are re-initialize of ACD probes");
            c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst) {
                _l3_acd_data_state_change(self,
                                          acd_data,
                                          ACD_STATE_CHANGE_MODE_LINK_NOW_UP,
                                          NULL,
                                          &now_msec);
            }
        }
    }
}

/*****************************************************************************/

void
_nm_l3cfg_notify_platform_change_on_idle(NML3Cfg *self, guint32 obj_type_flags)
{
    NML3ConfigNotifyData notify_data;

    if (self->priv.plobj_next != self->priv.plobj)
        _load_link(self, FALSE);

    notify_data.notify_type             = NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE;
    notify_data.platform_change_on_idle = (typeof(notify_data.platform_change_on_idle)){
        .obj_type_flags = obj_type_flags,
    };
    _nm_l3cfg_emit_signal_notify(self, &notify_data);

    _nm_l3cfg_emit_signal_notify_acd_event_all(self);
}

void
_nm_l3cfg_notify_platform_change(NML3Cfg                   *self,
                                 NMPlatformSignalChangeType change_type,
                                 const NMPObject           *obj)
{
    NML3ConfigNotifyData notify_data;
    NMPObjectType        obj_type;

    nm_assert(NMP_OBJECT_IS_VALID(obj));

    obj_type = NMP_OBJECT_GET_TYPE(obj);

    switch (obj_type) {
    case NMP_OBJECT_TYPE_LINK:
    {
        const NMPObject *plobj;

        plobj = (change_type != NM_PLATFORM_SIGNAL_REMOVED) ? obj : NULL;
        nm_assert(plobj == nm_platform_link_get_obj(self->priv.platform, self->priv.ifindex, TRUE));
        nmp_object_ref_set(&self->priv.plobj_next, plobj);
        break;
    }
    case NMP_OBJECT_TYPE_IP4_ADDRESS:
        _l3_acd_ipv4_addresses_on_link_update(self,
                                              NMP_OBJECT_CAST_IP4_ADDRESS(obj)->address,
                                              change_type != NM_PLATFORM_SIGNAL_REMOVED);
        /* fall-through */
    case NMP_OBJECT_TYPE_IP6_ADDRESS:
    case NMP_OBJECT_TYPE_IP4_ROUTE:
    case NMP_OBJECT_TYPE_IP6_ROUTE:
        _obj_states_externally_removed_track(self, obj, change_type != NM_PLATFORM_SIGNAL_REMOVED);
    default:
        break;
    }

    notify_data.notify_type     = NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE;
    notify_data.platform_change = (typeof(notify_data.platform_change)){
        .obj         = obj,
        .change_type = change_type,
    };
    _nm_l3cfg_emit_signal_notify(self, &notify_data);

    nm_assert(NMP_OBJECT_IS_VALID(obj));
}

/*****************************************************************************/

gboolean
nm_l3cfg_get_acd_is_pending(NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), FALSE);

    return self->priv.p->acd_is_pending;
}

static void
_acd_track_data_clear(NML3AcdAddrTrackInfo *acd_track)
{
    nm_l3_config_data_unref(acd_track->l3cd);
    nmp_object_unref(acd_track->obj);
}

static void
_acd_data_free(AcdData *acd_data)
{
    nm_assert(acd_data->info.n_track_infos == 0u);

    n_acd_probe_free(acd_data->nacd_probe);
    nm_clear_g_source_inst(&acd_data->acd_data_timeout_source);
    c_list_unlink_stale(&acd_data->acd_lst);
    c_list_unlink_stale(&acd_data->acd_event_notify_lst);
    g_free((NML3AcdAddrTrackInfo *) acd_data->info.track_infos);
    nm_g_slice_free(acd_data);
}

static guint
_acd_data_collect_tracks_data(NML3Cfg           *self,
                              const AcdData     *acd_data,
                              NMTernary          dirty_selector,
                              guint32           *out_best_acd_timeout_msec,
                              NML3AcdDefendType *out_best_acd_defend_type)
{
    NML3AcdDefendType best_acd_defend_type  = _NM_L3_ACD_DEFEND_TYPE_NONE;
    guint32           best_acd_timeout_msec = G_MAXUINT32;
    guint             n                     = 0;
    guint             i;

    /* We do a simple search over all track-infos for the best, which determines
     * our ACD state. That is, we prefer ACD disabled, and otherwise the
     * shortest configured timeout.
     *
     * This linear search is probably fast enough, because we expect that each
     * address/acd_data has few trackers.
     * The alternative would be caching the best result, but that is more complicated,
     * so not done. */

    for (i = 0; i < acd_data->info.n_track_infos; i++) {
        const NML3AcdAddrTrackInfo *acd_track = &acd_data->info.track_infos[i];

        if (dirty_selector != NM_TERNARY_DEFAULT) {
            if ((!!dirty_selector) != (!!acd_track->_priv.acd_dirty_track))
                continue;
        }
        n++;
        if (best_acd_timeout_msec > acd_track->_priv.acd_timeout_msec_track)
            best_acd_timeout_msec = acd_track->_priv.acd_timeout_msec_track;
        if (best_acd_defend_type < acd_track->_priv.acd_defend_type_track)
            best_acd_defend_type = acd_track->_priv.acd_defend_type_track;
    }

    nm_assert(n == 0 || best_acd_defend_type > _NM_L3_ACD_DEFEND_TYPE_NONE);
    nm_assert(best_acd_defend_type <= NM_L3_ACD_DEFEND_TYPE_ALWAYS);

    if (self->priv.ifindex == NM_LOOPBACK_IFINDEX) {
        /* On loopback interface, ACD makes no sense. We always force the
         * timeout to zero, which means no ACD. */
        best_acd_timeout_msec = 0;
    }

    NM_SET_OUT(out_best_acd_timeout_msec, n > 0 ? best_acd_timeout_msec : 0u);
    NM_SET_OUT(out_best_acd_defend_type, best_acd_defend_type);
    return n;
}

static NML3AcdAddrTrackInfo *
_acd_data_find_track(const AcdData        *acd_data,
                     const NML3ConfigData *l3cd,
                     const NMPObject      *obj,
                     gconstpointer         tag)
{
    guint i;

    for (i = 0; i < acd_data->info.n_track_infos; i++) {
        const NML3AcdAddrTrackInfo *acd_track = &acd_data->info.track_infos[i];

        if (acd_track->obj == obj && acd_track->l3cd == l3cd && acd_track->tag == tag)
            return (NML3AcdAddrTrackInfo *) acd_track;
    }

    return NULL;
}

/*****************************************************************************/

static gboolean
_acd_has_valid_link(const NMPObject *obj,
                    const guint8   **out_addr_bin,
                    gboolean        *out_acd_not_supported)
{
    const NMPlatformLink *link;
    const guint8         *addr_bin;
    gsize                 addr_len;

    if (!obj) {
        NM_SET_OUT(out_acd_not_supported, FALSE);
        return FALSE;
    }

    link = NMP_OBJECT_CAST_LINK(obj);

    addr_bin = nmp_link_address_get(&link->l_address, &addr_len);
    if (addr_len != ACD_SUPPORTED_ETH_ALEN) {
        NM_SET_OUT(out_acd_not_supported, TRUE);
        return FALSE;
    }

    NM_SET_OUT(out_acd_not_supported, FALSE);
    NM_SET_OUT(out_addr_bin, addr_bin);
    return TRUE;
}

static gboolean
_l3_acd_nacd_event_down_timeout_cb(gpointer user_data)
{
    NML3Cfg *self = user_data;
    AcdData *acd_data;
    gint64   now_msec = 0;

    _LOGT("acd: message possibly dropped due to device down (handle events)");
    nm_clear_g_source_inst(&self->priv.p->nacd_event_down_source);
    c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst)
        _l3_acd_data_state_change(self, acd_data, ACD_STATE_CHANGE_MODE_NACD_DOWN, NULL, &now_msec);
    _nm_l3cfg_emit_signal_notify_acd_event_all(self);
    return G_SOURCE_REMOVE;
}

static gboolean
_l3_acd_nacd_event(int fd, GIOCondition condition, gpointer user_data)
{
    gs_unref_object NML3Cfg *self    = g_object_ref(user_data);
    gboolean                 success = FALSE;
    int                      r;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(self->priv.p->nacd);

    r = n_acd_dispatch(self->priv.p->nacd);
    if (!NM_IN_SET(r, 0, N_ACD_E_PREEMPTED)) {
        _LOGT("acd: dispatch failed with error %d", r);
        goto out;
    }

    while (TRUE) {
        NMEtherAddr        sender_addr_data;
        const NMEtherAddr *sender_addr;
        AcdData           *acd_data;
        NAcdEvent         *event;

        if (!self->priv.p->nacd) {
            /* In the loop we emit signals, where *anything* might happen.
             * Check that we still have the nacd instance. */
            success = TRUE;
            goto out;
        }

        r = n_acd_pop_event(self->priv.p->nacd, &event);
        if (r) {
            _LOGT("acd: pop-event failed with error %d", r);
            goto out;
        }
        if (!event) {
            success = TRUE;
            goto out;
        }

        switch (event->event) {
        case N_ACD_EVENT_READY:
            n_acd_probe_get_userdata(event->ready.probe, (void **) &acd_data);
            _l3_acd_data_state_change(self, acd_data, ACD_STATE_CHANGE_MODE_NACD_READY, NULL, NULL);
            break;
        case N_ACD_EVENT_USED:
        case N_ACD_EVENT_DEFENDED:
        case N_ACD_EVENT_CONFLICT:
        {
#define _acd_event_payload_with_sender(event)          \
    ({                                                 \
        NAcdEvent *_event = (event);                   \
                                                       \
        nm_assert(event);                              \
        nm_assert(NM_IN_SET(event->event,              \
                            N_ACD_EVENT_USED,          \
                            N_ACD_EVENT_DEFENDED,      \
                            N_ACD_EVENT_CONFLICT));    \
        nm_assert(&_event->used == &_event->defended); \
        nm_assert(&_event->used == &_event->conflict); \
        &_event->used;                                 \
    })

            n_acd_probe_get_userdata(_acd_event_payload_with_sender(event)->probe,
                                     (void **) &acd_data);

            if (_acd_event_payload_with_sender(event)->n_sender == ETH_ALEN) {
                G_STATIC_ASSERT_EXPR(_nm_alignof(NMEtherAddr) == 1);
                nm_assert(_acd_event_payload_with_sender(event)->sender);
                memcpy(&sender_addr_data, _acd_event_payload_with_sender(event)->sender, ETH_ALEN);
                sender_addr = &sender_addr_data;
            } else {
                nm_assert_not_reached();
                sender_addr = &nm_ether_addr_zero;
            }

            _l3_acd_data_state_change(self,
                                      acd_data,
                                      (AcdStateChangeMode) event->event,
                                      sender_addr,
                                      NULL);
            break;
        }
        case N_ACD_EVENT_DOWN:
            if (!self->priv.p->nacd_event_down_source) {
                gint64  now_msec;
                guint32 timeout_msec;

                now_msec = nm_utils_get_monotonic_timestamp_msec();
                if (self->priv.p->nacd_event_down_ratelimited_until_msec > 0
                    && now_msec < self->priv.p->nacd_event_down_ratelimited_until_msec)
                    timeout_msec = self->priv.p->nacd_event_down_ratelimited_until_msec - now_msec;
                else {
                    timeout_msec                                         = 0;
                    self->priv.p->nacd_event_down_ratelimited_until_msec = now_msec + 2000;
                }
                _LOGT("acd: message possibly dropped due to device down (schedule handling event "
                      "in %u msec)",
                      timeout_msec);
                self->priv.p->nacd_event_down_source =
                    nm_g_timeout_add_source(timeout_msec, _l3_acd_nacd_event_down_timeout_cb, self);
            }
            break;
        default:
            _LOGE("acd: unexpected event %u. Ignore", event->event);
            nm_assert_not_reached();
            break;
        }

        /* We are on an idle handler, and the n-acd events are expected to be independent. So, after
         * each event emit all queued AcdEvent signals. */
        _nm_l3cfg_emit_signal_notify_acd_event_all(self);
    }

    nm_assert_not_reached();

out:
    if (!success) {
        /* Something is seriously wrong with our nacd instance. We handle that by resetting the
         * ACD instance. */
        _l3_acd_nacd_instance_reset(self, NM_TERNARY_TRUE, TRUE);
    }

    return G_SOURCE_CONTINUE;
}

static gboolean
_l3_acd_nacd_instance_ensure_retry_cb(gpointer user_data)
{
    NML3Cfg *self = user_data;

    nm_clear_g_source_inst(&self->priv.p->nacd_instance_ensure_retry);

    _l3_changed_configs_set_dirty(self);
    nm_l3cfg_commit(self, NM_L3_CFG_COMMIT_TYPE_AUTO);
    return G_SOURCE_REMOVE;
}

static void
_l3_acd_nacd_instance_reset(NML3Cfg *self, NMTernary start_timer, gboolean acd_data_notify)
{
    nm_assert(NM_IS_L3CFG(self));

    if (self->priv.p->nacd) {
        _LOGT("acd: clear nacd instance");
        self->priv.p->nacd = n_acd_unref(self->priv.p->nacd);
    }
    nm_clear_g_source_inst(&self->priv.p->nacd_source);
    nm_clear_g_source_inst(&self->priv.p->nacd_instance_ensure_retry);
    nm_clear_g_source_inst(&self->priv.p->nacd_event_down_source);

    if (c_list_is_empty(&self->priv.p->acd_lst_head))
        start_timer = NM_TERNARY_DEFAULT;

    switch (start_timer) {
    case NM_TERNARY_FALSE:
        _l3_changed_configs_set_dirty(self);
        nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);
        break;
    case NM_TERNARY_TRUE:
        self->priv.p->nacd_instance_ensure_retry =
            nm_g_timeout_add_seconds_source(ACD_ENSURE_RATELIMIT_MSEC / 1000u,
                                            _l3_acd_nacd_instance_ensure_retry_cb,
                                            self);
        break;
    case NM_TERNARY_DEFAULT:
        break;
    }

    if (acd_data_notify) {
        AcdData *acd_data;
        gint64   now_msec = 0;

        c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst) {
            _l3_acd_data_state_change(self,
                                      acd_data,
                                      ACD_STATE_CHANGE_MODE_INSTANCE_RESET,
                                      NULL,
                                      &now_msec);
        }
    }
}

static NAcd *
_l3_acd_nacd_instance_ensure(NML3Cfg *self, gboolean *out_acd_not_supported)
{
    nm_auto(n_acd_config_freep) NAcdConfig *config = NULL;
    nm_auto(n_acd_unrefp) NAcd             *nacd   = NULL;
    const guint8                           *addr_bin;
    gboolean                                acd_not_supported;
    gboolean                                valid;
    int                                     fd;
    int                                     r;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(self->priv.ifindex > 0);

again:
    if (G_LIKELY(self->priv.p->nacd)) {
        NM_SET_OUT(out_acd_not_supported, FALSE);
        return self->priv.p->nacd;
    }

    if (self->priv.p->nacd_instance_ensure_retry) {
        /* we just tried to create an instance and failed. We are rate-limited,
         * don't yet try again. */
        NM_SET_OUT(out_acd_not_supported, self->priv.p->nacd_acd_not_supported);
        return NULL;
    }

    valid = _acd_has_valid_link(self->priv.plobj, &addr_bin, &acd_not_supported);
    if (!valid)
        goto failed_create_acd;

    nm_assert(!acd_not_supported);

    r = n_acd_config_new(&config);
    if (r)
        goto failed_create_acd;

    n_acd_config_set_ifindex(config, self->priv.ifindex);
    n_acd_config_set_transport(config, N_ACD_TRANSPORT_ETHERNET);
    n_acd_config_set_mac(config, addr_bin, ACD_SUPPORTED_ETH_ALEN);

    r = n_acd_new(&nacd, config);
    if (r)
        goto failed_create_acd;

    self->priv.p->nacd = g_steal_pointer(&nacd);

    n_acd_get_fd(self->priv.p->nacd, &fd);

    self->priv.p->nacd_source = nm_g_unix_fd_add_source(fd, G_IO_IN, _l3_acd_nacd_event, self);

    NM_SET_OUT(out_acd_not_supported, FALSE);
    return self->priv.p->nacd;

failed_create_acd:
    /* is-internal-error means that we failed to create the NAcd instance. Most likely due
     * to being unable to create a file descriptor. Anyway, something is seriously wrong here.
     *
     * Otherwise, the MAC address might just not be suitable (ETH_ALEN) or we might have
     * not NMPlatformLink. In that case, it means the interface is currently not ready to
     * do acd. */
    self->priv.p->nacd_acd_not_supported = acd_not_supported;
    _l3_acd_nacd_instance_reset(self, NM_TERNARY_TRUE, FALSE);
    goto again;
}

static NAcdProbe *
_l3_acd_nacd_instance_create_probe(NML3Cfg     *self,
                                   in_addr_t    addr,
                                   guint32      timeout_msec,
                                   gpointer     user_data,
                                   gboolean    *out_acd_not_supported,
                                   const char **out_failure_reason)
{
    gboolean   acd_not_supported;
    NAcdProbe *probe;

    if (!_l3_acd_nacd_instance_ensure(self, &acd_not_supported)) {
        NM_SET_OUT(out_acd_not_supported, acd_not_supported);
        if (acd_not_supported)
            NM_SET_OUT(out_failure_reason, "interface not suitable for ACD");
        else
            NM_SET_OUT(out_failure_reason, "failure to create nacd instance");
        return NULL;
    }

    nm_assert(!acd_not_supported);
    NM_SET_OUT(out_acd_not_supported, FALSE);

    probe = _nm_n_acd_data_probe_new(self, addr, timeout_msec, user_data);
    if (!probe) {
        NM_SET_OUT(out_failure_reason, "failure to create nacd probe");
        return NULL;
    }

    NM_SET_OUT(out_failure_reason, NULL);
    return probe;
}

static void
_l3_acd_data_prune_one(NML3Cfg *self, AcdData *acd_data, gboolean all /* or only dirty */)
{
    NML3AcdAddrTrackInfo *acd_tracks;
    guint                 i;
    guint                 j;

    acd_tracks = (NML3AcdAddrTrackInfo *) acd_data->info.track_infos;
    j          = 0;
    for (i = 0; i < acd_data->info.n_track_infos; i++) {
        NML3AcdAddrTrackInfo *acd_track = &acd_tracks[i];

        /* If not "all" is requested, we only delete the dirty ones
         * (and mark the survivors as dirty right away). */
        if (!all && !acd_track->_priv.acd_dirty_track) {
            acd_track->_priv.acd_dirty_track = TRUE;
            if (j != i)
                acd_tracks[j] = *acd_track;
            j++;
            continue;
        }

        _LOGT_acd(acd_data, "untrack " ACD_TRACK_FMT "", ACD_TRACK_PTR(acd_track));

        _acd_track_data_clear(acd_track);
    }

    acd_data->info.n_track_infos = j;
    if (j > 0)
        return;

    _LOGT_acd(acd_data, "removed");
    if (!g_hash_table_remove(self->priv.p->acd_lst_hash, acd_data))
        nm_assert_not_reached();
    _acd_data_free(acd_data);
}

static void
_l3_acd_data_prune(NML3Cfg *self, gboolean all /* or only dirty */)
{
    AcdData *acd_data_safe;
    AcdData *acd_data;

    c_list_for_each_entry_safe (acd_data, acd_data_safe, &self->priv.p->acd_lst_head, acd_lst)
        _l3_acd_data_prune_one(self, acd_data, all);
}

static AcdData *
_l3_acd_data_find(NML3Cfg *self, in_addr_t addr)
{
    return nm_g_hash_table_lookup(self->priv.p->acd_lst_hash, &addr);
}

static gboolean
_l3_acd_data_defendconflict_warning_ratelimited(AcdData *acd_data, gint64 *p_now_msec)
{
    nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);

    if (acd_data->last_defendconflict_timestamp_msec == 0
        || acd_data->last_defendconflict_timestamp_msec
               > *p_now_msec - ACD_DEFENDCONFLICT_INFO_RATELIMIT_MSEC) {
        acd_data->last_defendconflict_timestamp_msec = *p_now_msec;
        return FALSE;
    }
    return TRUE;
}

static void
_l3_acd_data_add(NML3Cfg              *self,
                 const NML3ConfigData *l3cd,
                 const NMPObject      *obj,
                 gconstpointer         tag,
                 NML3AcdDefendType     acd_defend_type,
                 guint32               acd_timeout_msec)
{
    in_addr_t             addr = NMP_OBJECT_CAST_IP4_ADDRESS(obj)->address;
    NML3AcdAddrTrackInfo *acd_track;
    AcdData              *acd_data;
    const char           *track_mode;
    char                  sbuf100[100];

    if (ACD_ADDR_SKIP(addr))
        return;

    acd_data = _l3_acd_data_find(self, addr);

    if (acd_timeout_msec > NM_ACD_TIMEOUT_MAX_MSEC) {
        /* we limit the maximum timeout. Otherwise we have to handle integer overflow
         * when adding timeouts. */
        acd_timeout_msec = NM_ACD_TIMEOUT_MAX_MSEC;
    }

    if (!acd_data) {
        if (G_UNLIKELY(!self->priv.p->acd_lst_hash)) {
            G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(AcdData, info.addr) == 0);
            self->priv.p->acd_lst_hash = g_hash_table_new(nm_puint32_hash, nm_puint32_equal);
        }

        acd_data  = g_slice_new(AcdData);
        *acd_data = (AcdData){
            .info =
                {
                    .l3cfg         = self,
                    .addr          = addr,
                    .state         = NM_L3_ACD_ADDR_STATE_INIT,
                    .n_track_infos = 0,
                    .track_infos   = NULL,
                },
            .n_track_infos_alloc       = 0,
            .acd_event_notify_lst      = C_LIST_INIT(acd_data->acd_event_notify_lst),
            .probing_timestamp_msec    = 0,
            .acd_defend_type_desired   = _NM_L3_ACD_DEFEND_TYPE_NONE,
            .acd_defend_type_current   = _NM_L3_ACD_DEFEND_TYPE_NONE,
            .acd_defend_type_is_active = FALSE,
        };
        c_list_link_tail(&self->priv.p->acd_lst_head, &acd_data->acd_lst);
        if (!g_hash_table_add(self->priv.p->acd_lst_hash, acd_data))
            nm_assert_not_reached();
        acd_track = NULL;
    } else
        acd_track = _acd_data_find_track(acd_data, l3cd, obj, tag);

    if (!acd_track) {
        if (acd_data->info.n_track_infos >= acd_data->n_track_infos_alloc) {
            acd_data->n_track_infos_alloc = NM_MAX(2u, acd_data->n_track_infos_alloc * 2u);
            acd_data->info.track_infos =
                g_realloc((gpointer) acd_data->info.track_infos,
                          acd_data->n_track_infos_alloc * sizeof(acd_data->info.track_infos[0]));
        }
        acd_track =
            (NML3AcdAddrTrackInfo *) &acd_data->info.track_infos[acd_data->info.n_track_infos++];
        *acd_track = (NML3AcdAddrTrackInfo){
            .l3cd                         = nm_l3_config_data_ref(l3cd),
            .obj                          = nmp_object_ref(obj),
            .tag                          = tag,
            ._priv.acd_dirty_track        = FALSE,
            ._priv.acd_defend_type_track  = acd_defend_type,
            ._priv.acd_timeout_msec_track = acd_timeout_msec,
        };
        track_mode = "new";
    } else {
        nm_assert(acd_track->_priv.acd_dirty_track);
        acd_track->_priv.acd_dirty_track = FALSE;
        if (acd_track->_priv.acd_timeout_msec_track != acd_timeout_msec
            || acd_track->_priv.acd_defend_type_track != acd_defend_type) {
            acd_track->_priv.acd_defend_type_track  = acd_defend_type;
            acd_track->_priv.acd_timeout_msec_track = acd_timeout_msec;
            track_mode                              = "update";
        } else
            return;
    }

    acd_data->track_infos_changed = TRUE;
    _LOGT_acd(acd_data,
              "track " ACD_TRACK_FMT " with timeout %u msec, defend=%s (%s)",
              ACD_TRACK_PTR(acd_track),
              acd_timeout_msec,
              _l3_acd_defend_type_to_string(acd_track->_priv.acd_defend_type_track,
                                            sbuf100,
                                            sizeof(sbuf100)),
              track_mode);
}

static void
_l3_acd_data_add_all(NML3Cfg                   *self,
                     const L3ConfigData *const *infos,
                     guint                      infos_len,
                     gboolean                   reapply)
{
    AcdData *acd_data;
    guint    i_info;
    gint64   now_msec = 0;
    guint    i;

    if (NM_MORE_ASSERTS > 5) {
        c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst) {
            nm_assert(acd_data->info.n_track_infos > 0u);
            for (i = 0; i < acd_data->info.n_track_infos; i++)
                nm_assert(acd_data->info.track_infos[i]._priv.acd_dirty_track);
        }
    }

    /* First we add/track all the relevant addresses for ACD. */
    for (i_info = 0; i_info < infos_len; i_info++) {
        const L3ConfigData *info = infos[i_info];
        NMDedupMultiIter    iter;
        const NMPObject    *obj;

        nm_l3_config_data_iter_obj_for_each (&iter, info->l3cd, &obj, NMP_OBJECT_TYPE_IP4_ADDRESS) {
            _l3_acd_data_add(self,
                             info->l3cd,
                             obj,
                             info->tag_confdata,
                             info->acd_defend_type_confdata,
                             info->acd_timeout_msec_confdata);
        }
    }

    /* Then we do a pre-flight check, whether some of the acd_data entries can already
     * move forward to automatically pass ACD. That is the case if acd_timeout_msec
     * is zero (to disable ACD) or if the address is already configured on the
     * interface. */
    c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst) {
        _l3_acd_data_state_change(self,
                                  acd_data,
                                  reapply ? ACD_STATE_CHANGE_MODE_INIT_REAPPLY
                                          : ACD_STATE_CHANGE_MODE_INIT,
                                  NULL,
                                  &now_msec);
    }
}

static gboolean
_l3_acd_data_timeout_cb(gpointer user_data)
{
    AcdData *acd_data = user_data;
    NML3Cfg *self     = acd_data->info.l3cfg;

    nm_assert(NM_IS_L3CFG(self));

    nm_clear_g_source_inst(&acd_data->acd_data_timeout_source);
    _l3_acd_data_state_change(self, acd_data, ACD_STATE_CHANGE_MODE_TIMEOUT, NULL, NULL);
    return G_SOURCE_REMOVE;
}

static void
_l3_acd_data_timeout_schedule(AcdData *acd_data, gint64 timeout_msec)
{
    /* in _l3_acd_data_state_set_full() we clear the timer. At the same time,
     * in _l3_acd_data_state_change(ACD_STATE_CHANGE_MODE_TIMEOUT) we only
     * expect timeouts in certain states.
     *
     * That means, scheduling a timeout is only correct if we are in a certain
     * state, which allows to handle timeouts. This assert checks for that to
     * ensure we don't call a timeout in an unexpected state. */
    nm_assert(NM_IN_SET(acd_data->info.state,
                        NM_L3_ACD_ADDR_STATE_PROBING,
                        NM_L3_ACD_ADDR_STATE_USED,
                        NM_L3_ACD_ADDR_STATE_DEFENDING,
                        NM_L3_ACD_ADDR_STATE_CONFLICT));

    nm_clear_g_source_inst(&acd_data->acd_data_timeout_source);
    acd_data->acd_data_timeout_source =
        nm_g_timeout_add_source(NM_CLAMP((gint64) 0, timeout_msec, (gint64) G_MAXUINT),
                                _l3_acd_data_timeout_cb,
                                acd_data);
}

static void
_l3_acd_data_timeout_schedule_probing_restart(AcdData *acd_data, gint64 now_msec)
{
    gint64 expiry_msec;
    gint64 timeout_msec;

    nm_assert(acd_data);
    nm_assert(now_msec > 0);
    nm_assert(acd_data->info.state == NM_L3_ACD_ADDR_STATE_PROBING);
    nm_assert(!acd_data->nacd_probe);
    nm_assert(acd_data->probing_timeout_msec > 0);
    nm_assert(acd_data->probing_timestamp_msec > 0);

    expiry_msec = acd_data->probing_timestamp_msec + ACD_WAIT_PROBING_EXTRA_TIME_MSEC;

    timeout_msec = NM_MAX(0, expiry_msec - now_msec);

    if (timeout_msec > 1500) {
        /* we poll at least every 1.5 seconds to re-check the state. */
        timeout_msec = 1500;
    }

    _l3_acd_data_timeout_schedule(acd_data, timeout_msec);
}

static void
_nm_l3cfg_emit_signal_notify_acd_event(NML3Cfg *self, AcdData *acd_data)
{
    gs_free NML3AcdAddrTrackInfo *track_infos_clone = NULL;
    NML3ConfigNotifyData          notify_data;
    NML3AcdAddrInfo              *info;
    guint                         i;

    nm_assert(acd_data);
    nm_assert(acd_data->info.state > NM_L3_ACD_ADDR_STATE_INIT);
    nm_assert(acd_data->info.n_track_infos > 0);

    notify_data.notify_type = NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT;
    notify_data.acd_event   = (typeof(notify_data.acd_event)){
          .info = acd_data->info,
    };

    /* we need to clone the track-data, because the callee is allowed to add/remove
     * configs. This means, the event data is stale. If you need the current
     * value, look it up with nm_l3cfg_get_acd_addr_info().  */
    info              = &notify_data.acd_event.info;
    info->track_infos = nm_memdup_maybe_a(300,
                                          info->track_infos,
                                          info->n_track_infos * sizeof(info->track_infos[0]),
                                          &track_infos_clone);

    for (i = 0; i < info->n_track_infos; i++) {
        NML3AcdAddrTrackInfo *ti = (NML3AcdAddrTrackInfo *) &info->track_infos[i];

        nmp_object_ref(ti->obj);
        nm_l3_config_data_ref(ti->l3cd);
    }

    _nm_l3cfg_emit_signal_notify(self, &notify_data);

    for (i = 0; i < info->n_track_infos; i++) {
        NML3AcdAddrTrackInfo *ti = (NML3AcdAddrTrackInfo *) &info->track_infos[i];

        nmp_object_unref(ti->obj);
        nm_l3_config_data_unref(ti->l3cd);
    }
}

static void
_nm_l3cfg_emit_signal_notify_acd_event_queue(NML3Cfg *self, AcdData *acd_data)
{
    if (!c_list_is_empty(&acd_data->acd_event_notify_lst)) {
        nm_assert(c_list_contains(&self->priv.p->acd_event_notify_lst_head,
                                  &acd_data->acd_event_notify_lst));
        return;
    }
    c_list_link_tail(&self->priv.p->acd_event_notify_lst_head, &acd_data->acd_event_notify_lst);
}

static void
_nm_l3cfg_emit_signal_notify_acd_event_all(NML3Cfg *self)
{
    gs_unref_object NML3Cfg *self_keep_alive = NULL;
    AcdData                 *acd_data;

    while ((acd_data = c_list_first_entry(&self->priv.p->acd_event_notify_lst_head,
                                          AcdData,
                                          acd_event_notify_lst))) {
        if (!self_keep_alive)
            self_keep_alive = g_object_ref(self);
        c_list_unlink(&acd_data->acd_event_notify_lst);
        _nm_l3cfg_emit_signal_notify_acd_event(self, acd_data);
    }
}

_nm_printf(5, 6) static void _l3_acd_data_state_set_full(NML3Cfg         *self,
                                                         AcdData         *acd_data,
                                                         NML3AcdAddrState state,
                                                         gboolean         allow_commit,
                                                         const char      *format,
                                                         ...)
{
    NML3AcdAddrState old_state;
    gboolean         changed;

    if (acd_data->info.state == state)
        return;

    /* in every state we only have one timer possibly running. Resetting
     * the states makes the previous timeout obsolete. */
    nm_clear_g_source_inst(&acd_data->acd_data_timeout_source);

    old_state            = acd_data->info.state;
    acd_data->info.state = state;
    _nm_l3cfg_emit_signal_notify_acd_event_queue(self, acd_data);

    if (state == NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED)
        changed = FALSE;
    else if (NM_IN_SET(old_state, NM_L3_ACD_ADDR_STATE_READY, NM_L3_ACD_ADDR_STATE_DEFENDING)
             != NM_IN_SET(state, NM_L3_ACD_ADDR_STATE_READY, NM_L3_ACD_ADDR_STATE_DEFENDING))
        changed = TRUE;
    else
        changed = FALSE;

    if (_LOGT_ENABLED()) {
        if (format) {
            gs_free char *msg = NULL;
            va_list       args;

            va_start(args, format);
            msg = g_strdup_vprintf(format, args);
            va_end(args);

            _LOGT_acd(acd_data, "set state to %s (%s)", _l3_acd_addr_state_to_string(state), msg);
        } else
            _LOGT_acd(acd_data, "set state to %s", _l3_acd_addr_state_to_string(state));
    }

    if (changed && allow_commit) {
        /* The availability of an address just changed (and we are instructed to
         * trigger a new commit). Do it. */
        _l3_changed_configs_set_dirty(self);
        nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);
    }
}

static void
_l3_acd_data_state_set(NML3Cfg         *self,
                       AcdData         *acd_data,
                       NML3AcdAddrState state,
                       gboolean         allow_commit)
{
    _l3_acd_data_state_set_full(self, acd_data, state, allow_commit, NULL);
}

static void
_l3_acd_data_state_change(NML3Cfg           *self,
                          AcdData           *acd_data,
                          AcdStateChangeMode state_change_mode,
                          const NMEtherAddr *sender_addr,
                          gint64            *p_now_msec)

{
    guint32           acd_timeout_msec;
    NML3AcdDefendType acd_defend_type;
    gint64            now_msec;
    const char       *log_reason;
    char              sbuf256[256];
    char              sbuf_addr[NM_INET_ADDRSTRLEN];

    if (!p_now_msec) {
        now_msec   = 0;
        p_now_msec = &now_msec;
    }

    /* Keeping track of ACD inevitably requires keeping (and mutating) state. Then a multitude of
     * things can happen, and depending on the state, we need to do something.
     *
     * Here, all the state for one address that we probe/announce is tracked in AcdData/acd_data.
     *
     * The acd_data has a list of NML3AcdAddrTrackInfo/acd_track_lst_head, which are configuration items
     * that are interested in configuring this address. The "owners" of the ACD check for a certain
     * address.
     *
     * We try to do all the state changes in this _l3_acd_data_state_change() function, where --
     * depending on the @state_change_mode -- we progress the state.
     *
     * It is complicated, but I think this is not really avoidable if you want to handle all
     * the special things (state-changes) that can happen.
     */

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(acd_data);
    nm_assert(acd_data->info.n_track_infos);
    nm_assert(NM_IN_SET(acd_data->info.state,
                        NM_L3_ACD_ADDR_STATE_CONFLICT,
                        NM_L3_ACD_ADDR_STATE_READY,
                        NM_L3_ACD_ADDR_STATE_DEFENDING,
                        NM_L3_ACD_ADDR_STATE_INIT,
                        NM_L3_ACD_ADDR_STATE_PROBING,
                        NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED,
                        NM_L3_ACD_ADDR_STATE_USED));
    nm_assert(!acd_data->track_infos_changed
              || NM_IN_SET(state_change_mode,
                           ACD_STATE_CHANGE_MODE_INIT,
                           ACD_STATE_CHANGE_MODE_INIT_REAPPLY,
                           ACD_STATE_CHANGE_MODE_POST_COMMIT,
                           ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED,
                           ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED));
    nm_assert((!!sender_addr)
              == NM_IN_SET(state_change_mode,
                           ACD_STATE_CHANGE_MODE_NACD_USED,
                           ACD_STATE_CHANGE_MODE_NACD_CONFLICT,
                           ACD_STATE_CHANGE_MODE_NACD_DEFENDED));

    if (acd_data->info.state == NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED) {
        /* once remove, the state can only change by external added or during
         * the POST-COMMIT check. */
        if (!NM_IN_SET(state_change_mode,
                       ACD_STATE_CHANGE_MODE_POST_COMMIT,
                       ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED))
            return;
    }

    switch (state_change_mode) {
    case ACD_STATE_CHANGE_MODE_INIT:
    case ACD_STATE_CHANGE_MODE_INIT_REAPPLY:

        /* We are called right before commit. We check whether we have a acd_data
         * in INIT or PROBING state. In that case, maybe the new configuration
         * disables ACD, or we have the address already configured (which also let's
         * us skip/cancel the probing). The point is that if the address would be ready
         * already, we want to commit it right away. */

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_PROBING:
        case NM_L3_ACD_ADDR_STATE_INIT:
        case NM_L3_ACD_ADDR_STATE_USED:
            goto handle_init;
        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:
        case NM_L3_ACD_ADDR_STATE_READY:
        case NM_L3_ACD_ADDR_STATE_DEFENDING:
            if (state_change_mode != ACD_STATE_CHANGE_MODE_INIT_REAPPLY)
                return;
            goto handle_init;
        }
        nm_assert_not_reached();
        return;

handle_init:
        if (_acd_data_collect_tracks_data(self,
                                          acd_data,
                                          NM_TERNARY_FALSE,
                                          &acd_timeout_msec,
                                          &acd_defend_type)
            <= 0u) {
            /* the acd_data has no active trackers. It will soon be pruned. */
            return;
        }

        if (acd_timeout_msec == 0u)
            log_reason = "acd disabled by configuration";
        else if (_l3_acd_ipv4_addresses_on_link_contains(self, acd_data->info.addr))
            log_reason = "address already configured";
        else {
            if (state_change_mode == ACD_STATE_CHANGE_MODE_INIT_REAPPLY) {
                /* during a reapply, we forget all the state and start from scratch. */
                _LOGT_acd(acd_data, "reset state for reapply");
                acd_data->nacd_probe = n_acd_probe_free(acd_data->nacd_probe);
                _l3_acd_data_state_set(self, acd_data, NM_L3_ACD_ADDR_STATE_INIT, FALSE);
            }
            return;
        }

        _LOGT_acd(acd_data,
                  "%s probing (%s, during pre-check)",
                  acd_data->info.state == NM_L3_ACD_ADDR_STATE_INIT ? "skip" : "cancel",
                  log_reason);
        acd_data->nacd_probe              = n_acd_probe_free(acd_data->nacd_probe);
        acd_data->acd_defend_type_desired = acd_defend_type;
        _l3_acd_data_state_set(self, acd_data, NM_L3_ACD_ADDR_STATE_READY, FALSE);
        return;

    case ACD_STATE_CHANGE_MODE_POST_COMMIT:

        if (acd_data->track_infos_changed) {
            acd_data->track_infos_changed = FALSE;
            _nm_l3cfg_emit_signal_notify_acd_event_queue(self, acd_data);
        }

        if (_l3_acd_ipv4_addresses_on_link_contains(self, acd_data->info.addr)) {
            log_reason = "address already configured";
            goto handle_probing_done;
        }

        if (acd_data->info.state == NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED)
            return;

        /* we just did a commit of the IP configuration and now visit all ACD states
         * and kick off the necessary actions... */
        if (_acd_data_collect_tracks_data(self,
                                          acd_data,
                                          NM_TERNARY_TRUE,
                                          &acd_timeout_msec,
                                          &acd_defend_type)
            <= 0)
            nm_assert_not_reached();

        acd_data->acd_defend_type_desired = acd_defend_type;

        if (acd_timeout_msec <= 0) {
            log_reason = "acd disabled by configuration";
            goto handle_probing_done;
        }

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_INIT:
            nm_assert(!acd_data->nacd_probe);
            nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);
            acd_data->probing_timestamp_msec = (*p_now_msec);
            acd_data->probing_timeout_msec   = acd_timeout_msec;
            _nm_l3cfg_emit_signal_notify_acd_event_queue(self, acd_data);
            log_reason = "initial post-commit";
            goto handle_start_probing;

        case NM_L3_ACD_ADDR_STATE_PROBING:
        {
            gint64 old_expiry_msec;
            gint64 new_expiry_msec;

            nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);

            new_expiry_msec = (*p_now_msec) + acd_timeout_msec;
            old_expiry_msec = acd_data->probing_timestamp_msec + acd_data->probing_timeout_msec;

            if (!acd_data->nacd_probe) {
                /* we are currently waiting for restarting a probe. At this point, at most we have
                 * to adjust the timeout/timestamp and let the regular timeouts handle this. */

                if (new_expiry_msec >= old_expiry_msec) {
                    /* the running timeout expires before the new timeout. We don't update the timestamp/timeout,
                     * because we don't want to prolong the overall probing time. */
                    return;
                }
                /* update the timers after out timeout got reduced. Also, reschedule the timeout
                 * so that it expires immediately. */
                acd_data->probing_timestamp_msec = (*p_now_msec);
                acd_data->probing_timeout_msec   = acd_timeout_msec;
                _l3_acd_data_timeout_schedule(acd_data, 0);
                return;
            }

            if (new_expiry_msec >= old_expiry_msec) {
                /* we already have ACD running with a timeout that expires before the requested one. There
                 * is nothing to do at this time. */
                return;
            }

            /* the timeout got reduced. We try to restart the probe. */
            acd_data->probing_timestamp_msec = (*p_now_msec);
            acd_data->probing_timeout_msec   = acd_timeout_msec;
            log_reason                       = "post-commit timeout update";
            goto handle_start_probing;
        }

        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:
            /* we are done for now. We however scheduled a timeout to restart. This
             * will be handled with the ACD_STATE_CHANGE_MODE_TIMEOUT event. */
            return;

        case NM_L3_ACD_ADDR_STATE_READY:
        case NM_L3_ACD_ADDR_STATE_DEFENDING:
            goto handle_start_defending;

        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
            nm_assert_not_reached();
            return;
        }
        nm_assert_not_reached();
        return;

    case ACD_STATE_CHANGE_MODE_TIMEOUT:

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_INIT:
            nm_assert_not_reached();
            return;

        case NM_L3_ACD_ADDR_STATE_PROBING:
            if (acd_data->nacd_probe) {
                /* we are already probing. There is nothing to do for this timeout. */
                return;
            }
            /* fall-through */

        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:

            nm_assert(!acd_data->nacd_probe);

            /* after a timeout, re-probe the address. This only happens if the caller
             * does not deconfigure the address after USED/CONFLICT. But in that case,
             * we eventually want to retry. */
            if (_acd_data_collect_tracks_data(self,
                                              acd_data,
                                              NM_TERNARY_TRUE,
                                              &acd_timeout_msec,
                                              &acd_defend_type)
                <= 0)
                nm_assert_not_reached();

            acd_data->acd_defend_type_desired = acd_defend_type;

            if (acd_timeout_msec <= 0) {
                if (acd_data->info.state == NM_L3_ACD_ADDR_STATE_PROBING)
                    log_reason = "acd disabled by configuration (timeout during probing)";
                else
                    log_reason = "acd disabled by configuration (restart after previous conflict)";
                goto handle_probing_done;
            }

            if (_l3_acd_ipv4_addresses_on_link_contains(self, acd_data->info.addr)) {
                log_reason = "address already configured (restart after previous conflict)";
                goto handle_probing_done;
            }

            nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);

            if (acd_data->info.state == NM_L3_ACD_ADDR_STATE_PROBING) {
                if ((*p_now_msec) > acd_data->probing_timestamp_msec
                                        + ACD_WAIT_PROBING_EXTRA_TIME_MSEC
                                        + ACD_WAIT_PROBING_EXTRA_TIME2_MSEC) {
                    /* hm. We failed to create a new probe too long. Something is really wrong
                     * internally, but let's ignore the issue and assume the address is good. What
                     * else would we do? Assume the address is USED? */
                    _LOGT_acd(acd_data,
                              "probe-good (waiting for creating probe timed out. Assume good)");
                    goto handle_start_defending;
                }

                log_reason = "retry probing on timeout";
                goto handle_start_probing;
            }

            acd_data->probing_timestamp_msec = (*p_now_msec);
            acd_data->probing_timeout_msec   = acd_timeout_msec;
            if (acd_data->info.state == NM_L3_ACD_ADDR_STATE_USED)
                log_reason = "restart probing after previously used address";
            else
                log_reason = "restart probing after previous conflict";
            goto handle_start_probing;

        case NM_L3_ACD_ADDR_STATE_READY:
            nm_assert_not_reached();
            return;

        case NM_L3_ACD_ADDR_STATE_DEFENDING:

            nm_assert(!acd_data->nacd_probe);
            _LOGT_acd(acd_data, "retry announcing address");
            goto handle_start_defending;

        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
            nm_assert_not_reached();
            return;
        }

        nm_assert_not_reached();
        return;

    case ACD_STATE_CHANGE_MODE_NACD_USED:
        nm_assert(acd_data->info.state == NM_L3_ACD_ADDR_STATE_PROBING);
        nm_assert(acd_data->nacd_probe);

        acd_data->nacd_probe              = n_acd_probe_free(acd_data->nacd_probe);
        acd_data->info.last_conflict_addr = *sender_addr;
        _l3_acd_data_state_set_full(self,
                                    acd_data,
                                    NM_L3_ACD_ADDR_STATE_USED,
                                    TRUE,
                                    "acd completed with address already in use by %s",
                                    nm_ether_addr_to_string_a(sender_addr));

        if (!acd_data->acd_data_timeout_source)
            _l3_acd_data_timeout_schedule(acd_data, ACD_WAIT_TIME_PROBING_FULL_RESTART_MSEC);

        if (!_l3_acd_data_defendconflict_warning_ratelimited(acd_data, p_now_msec)) {
            _LOGD("IPv4 address %s is used on network connected to interface %d%s%s%s from "
                  "host %s",
                  nm_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  self->priv.ifindex,
                  NM_PRINT_FMT_QUOTED(self->priv.plobj_next,
                                      " (",
                                      NMP_OBJECT_CAST_LINK(self->priv.plobj_next)->name,
                                      ")",
                                      ""),
                  nm_ether_addr_to_string_a(sender_addr));
        }
        return;

    case ACD_STATE_CHANGE_MODE_NACD_DEFENDED:
        nm_assert(acd_data->info.state == NM_L3_ACD_ADDR_STATE_DEFENDING);
        _LOGT_acd(acd_data,
                  "address %s defended from %s",
                  nm_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  nm_ether_addr_to_string_a(sender_addr));
        /* we just log an info message. Nothing else to do. */
        return;

    case ACD_STATE_CHANGE_MODE_NACD_CONFLICT:
        nm_assert(acd_data->info.state == NM_L3_ACD_ADDR_STATE_DEFENDING);

        _LOGT_acd(acd_data,
                  "address conflict for %s detected with %s",
                  nm_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  nm_ether_addr_to_string_a(sender_addr));

        if (!_l3_acd_data_defendconflict_warning_ratelimited(acd_data, p_now_msec)) {
            _LOGD("IPv4 address collision detection sees conflict on interface %d%s%s%s for "
                  "address %s from host %s",
                  self->priv.ifindex,
                  NM_PRINT_FMT_QUOTED(self->priv.plobj_next,
                                      " (",
                                      NMP_OBJECT_CAST_LINK(self->priv.plobj_next)->name,
                                      ")",
                                      ""),
                  nm_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  nm_ether_addr_to_string_a(sender_addr));
        }

        acd_data->nacd_probe              = n_acd_probe_free(acd_data->nacd_probe);
        acd_data->info.last_conflict_addr = *sender_addr;
        _l3_acd_data_state_set(self, acd_data, NM_L3_ACD_ADDR_STATE_CONFLICT, TRUE);
        if (!acd_data->acd_data_timeout_source)
            _l3_acd_data_timeout_schedule(acd_data, ACD_WAIT_TIME_CONFLICT_RESTART_MSEC);
        return;

    case ACD_STATE_CHANGE_MODE_NACD_READY:

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_PROBING:
            nm_assert(acd_data->nacd_probe);
            /* we theoretically could re-use this probe for defending. But as we
             * may not start defending right away, it makes it more complicated. */
            acd_data->nacd_probe = n_acd_probe_free(acd_data->nacd_probe);
            log_reason           = "acd indicates ready";
            goto handle_probing_done;
        case NM_L3_ACD_ADDR_STATE_DEFENDING:
            nm_assert(!acd_data->acd_defend_type_is_active);
            acd_data->acd_defend_type_is_active = TRUE;
            _LOGT_acd(acd_data,
                      "start announcing (defend=%s) (after new probe ready)",
                      _l3_acd_defend_type_to_string(acd_data->acd_defend_type_current,
                                                    sbuf256,
                                                    sizeof(sbuf256)));
            if (n_acd_probe_announce(acd_data->nacd_probe,
                                     _l3_acd_defend_type_to_nacd(acd_data->acd_defend_type_current))
                != 0)
                nm_assert_not_reached();
            return;
        case NM_L3_ACD_ADDR_STATE_INIT:
        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_READY:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:
        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
            nm_assert_not_reached();
            return;
        }

        nm_assert_not_reached();
        return;

    case ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED:

        if (self->priv.p->commit_reentrant_count > 0)
            return;

        _LOGT_acd(acd_data, "address was externally added");

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_INIT:
            nm_assert_not_reached();
            return;
        case NM_L3_ACD_ADDR_STATE_READY:
        case NM_L3_ACD_ADDR_STATE_DEFENDING:
            goto handle_start_defending;
        case NM_L3_ACD_ADDR_STATE_PROBING:
        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:
        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
            log_reason = "address configured on link";
            goto handle_probing_done;
        }

        nm_assert_not_reached();
        return;

    case ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED:

        if (self->priv.p->commit_reentrant_count > 0)
            return;

        if (_l3_acd_ipv4_addresses_on_link_contains(self, acd_data->info.addr)) {
            /* this can happen, because there might still be the same address with different
             * plen or peer_address. */
            return;
        }

        _LOGT_acd(acd_data, "address was externally removed");

        acd_data->nacd_probe = n_acd_probe_free(acd_data->nacd_probe);
        _l3_acd_data_state_set(self, acd_data, NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED, FALSE);
        return;

    case ACD_STATE_CHANGE_MODE_NACD_DOWN:
    case ACD_STATE_CHANGE_MODE_LINK_NOW_UP:

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_INIT:
            nm_assert_not_reached();
            return;
        case NM_L3_ACD_ADDR_STATE_PROBING:

            if (!acd_data->nacd_probe) {
                /* we failed starting to probe before and have a timer running to
                 * restart. We don't do anything now, but let the timer handle it.
                 * This also implements some rate limiting for us. */
                _LOGT_acd(acd_data,
                          "ignore link %s event while we are waiting to start probing",
                          state_change_mode == ACD_STATE_CHANGE_MODE_NACD_DOWN ? "down" : "up");
                return;
            }

            nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);

            if (acd_data->probing_timestamp_msec + acd_data->probing_timeout_msec
                    + ACD_WAIT_PROBING_EXTRA_TIME_MSEC + ACD_WAIT_PROBING_EXTRA_TIME2_MSEC
                >= (*p_now_msec)) {
                /* The probing already started quite a while ago. We ignore the link event
                 * and let the probe come to it's natural end. */
                _LOGT_acd(acd_data, "ignore link up event for a probe started long ago");
                return;
            }

            acd_data->nacd_probe = n_acd_probe_free(acd_data->nacd_probe);
            if (state_change_mode == ACD_STATE_CHANGE_MODE_NACD_DOWN)
                log_reason = "restart probing after down event";
            else
                log_reason = "restart probing after link up";
            goto handle_start_probing;

        case NM_L3_ACD_ADDR_STATE_READY:
        case NM_L3_ACD_ADDR_STATE_DEFENDING:
        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:
        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
            /* if the link was down/came up, it's no clear what we should do about these
             * cases. Ignore the event. */
            return;
        }
        nm_assert_not_reached();
        return;

    case ACD_STATE_CHANGE_MODE_INSTANCE_RESET:
        nm_assert(NM_IN_SET(acd_data->info.state,
                            NM_L3_ACD_ADDR_STATE_PROBING,
                            NM_L3_ACD_ADDR_STATE_DEFENDING,
                            NM_L3_ACD_ADDR_STATE_READY,
                            NM_L3_ACD_ADDR_STATE_USED,
                            NM_L3_ACD_ADDR_STATE_CONFLICT,
                            NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED));

        /* an instance-reset is a dramatic event. We start over with probing. */
        _LOGT_acd(acd_data,
                  "n-acd instance reset. Reset to probing while in state %s",
                  _l3_acd_addr_state_to_string(acd_data->info.state));
        acd_data->nacd_probe                         = n_acd_probe_free(acd_data->nacd_probe);
        acd_data->last_defendconflict_timestamp_msec = 0;
        acd_data->probing_timestamp_msec = nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);
        _l3_acd_data_state_set(self, acd_data, NM_L3_ACD_ADDR_STATE_PROBING, FALSE);
        _l3_acd_data_timeout_schedule(acd_data, 0);
        return;
    }

    nm_assert_not_reached();
    return;

handle_start_probing:
    if (TRUE) {
        const NML3AcdAddrState                orig_state = acd_data->info.state;
        nm_auto(n_acd_probe_freep) NAcdProbe *probe      = NULL;
        const char                           *failure_reason;
        gboolean                              acd_not_supported;

        nm_assert(NM_IN_SET(acd_data->info.state,
                            NM_L3_ACD_ADDR_STATE_INIT,
                            NM_L3_ACD_ADDR_STATE_PROBING,
                            NM_L3_ACD_ADDR_STATE_USED,
                            NM_L3_ACD_ADDR_STATE_CONFLICT));

        /* note that we reach this line also during a ACD_STATE_CHANGE_MODE_TIMEOUT, when
         * or when we restart the probing (with a new timeout). In all cases, we still
         * give the original timeout (acd_data->probing_timeout_msec), and not the remaining
         * time. That means, the probing step might take longer then originally planned
         * (e.g. if we initially cannot start probing right away). */

        probe = _l3_acd_nacd_instance_create_probe(self,
                                                   acd_data->info.addr,
                                                   acd_data->probing_timeout_msec,
                                                   acd_data,
                                                   &acd_not_supported,
                                                   &failure_reason);
        NM_SWAP(&probe, &acd_data->nacd_probe);

        if (acd_not_supported) {
            nm_assert(!acd_data->nacd_probe);
            _LOGT_acd(acd_data,
                      "probe-good (interface does not support acd%s, %s)",
                      orig_state == NM_L3_ACD_ADDR_STATE_INIT ? ""
                      : (state_change_mode != ACD_STATE_CHANGE_MODE_TIMEOUT)
                          ? " anymore"
                          : " anymore after timeout",
                      log_reason);
            goto handle_start_defending;
        }

        _l3_acd_data_state_set(self,
                               acd_data,
                               NM_L3_ACD_ADDR_STATE_PROBING,
                               !NM_IN_SET(state_change_mode,
                                          ACD_STATE_CHANGE_MODE_INIT,
                                          ACD_STATE_CHANGE_MODE_INIT_REAPPLY,
                                          ACD_STATE_CHANGE_MODE_POST_COMMIT));

        if (!acd_data->nacd_probe) {
            _LOGT_acd(acd_data,
                      "probing currently %snot possible (timeout %u msec; %s, %s)",
                      orig_state == NM_L3_ACD_ADDR_STATE_INIT ? "" : " still",
                      acd_data->probing_timeout_msec,
                      failure_reason,
                      log_reason);
            _l3_acd_data_timeout_schedule_probing_restart(acd_data, (*p_now_msec));
            return;
        }

        _LOGT_acd(acd_data,
                  "%sstart probing (timeout %u msec, %s)",
                  orig_state == NM_L3_ACD_ADDR_STATE_INIT ? "" : "re",
                  acd_data->probing_timeout_msec,
                  log_reason);
        return;
    }

handle_probing_done:
    switch (acd_data->info.state) {
    case NM_L3_ACD_ADDR_STATE_INIT:
        _LOGT_acd(acd_data, "probe-done good (%s, initializing)", log_reason);
        goto handle_start_defending;
    case NM_L3_ACD_ADDR_STATE_PROBING:
        _LOGT_acd(acd_data, "probe-done good (%s, probing done)", log_reason);
        if (state_change_mode != ACD_STATE_CHANGE_MODE_NACD_READY)
            acd_data->nacd_probe = n_acd_probe_free(acd_data->nacd_probe);
        goto handle_start_defending;
    case NM_L3_ACD_ADDR_STATE_USED:
        _LOGT_acd(acd_data, "probe-done good (%s, after probe failed)", log_reason);
        goto handle_start_defending;
    case NM_L3_ACD_ADDR_STATE_READY:
    case NM_L3_ACD_ADDR_STATE_DEFENDING:
    case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
        goto handle_start_defending;
    case NM_L3_ACD_ADDR_STATE_CONFLICT:
        return;
        nm_assert_not_reached();
        return;
    }
    nm_assert_not_reached();
    return;

handle_start_defending:
    if (!_l3_acd_ipv4_addresses_on_link_contains(self, acd_data->info.addr)) {
        if (acd_data->info.state != NM_L3_ACD_ADDR_STATE_READY) {
            _l3_acd_data_state_set_full(self,
                                        acd_data,
                                        NM_L3_ACD_ADDR_STATE_READY,
                                        !NM_IN_SET(state_change_mode,
                                                   ACD_STATE_CHANGE_MODE_INIT,
                                                   ACD_STATE_CHANGE_MODE_INIT_REAPPLY,
                                                   ACD_STATE_CHANGE_MODE_POST_COMMIT),
                                        "probe is ready, waiting for address to be configured");
        }
        return;
    }

    _l3_acd_data_state_set(self,
                           acd_data,
                           NM_L3_ACD_ADDR_STATE_DEFENDING,
                           !NM_IN_SET(state_change_mode,
                                      ACD_STATE_CHANGE_MODE_INIT,
                                      ACD_STATE_CHANGE_MODE_INIT_REAPPLY,
                                      ACD_STATE_CHANGE_MODE_POST_COMMIT));

    nm_assert(acd_data->acd_defend_type_desired > _NM_L3_ACD_DEFEND_TYPE_NONE);
    nm_assert(acd_data->acd_defend_type_desired <= NM_L3_ACD_DEFEND_TYPE_ALWAYS);

    if (acd_data->acd_defend_type_desired != acd_data->acd_defend_type_current) {
        acd_data->acd_defend_type_current = acd_data->acd_defend_type_desired;
        acd_data->nacd_probe              = n_acd_probe_free(acd_data->nacd_probe);
    }

    if (!acd_data->nacd_probe) {
        const char *failure_reason;
        NAcdProbe  *probe;

        if (acd_data->acd_data_timeout_source) {
            /* we already failed to create a probe. We are ratelimited to retry, but
             * we have a timer pending... */
            return;
        }

        probe = _l3_acd_nacd_instance_create_probe(self,
                                                   acd_data->info.addr,
                                                   0,
                                                   acd_data,
                                                   NULL,
                                                   &failure_reason);
        if (!probe) {
            /* we failed to create a probe for announcing the address. We log a
             * warning and start a timer to retry. This way (of having a timer pending)
             * we also back off and are rate limited from retrying too frequently. */
            _LOGT_acd(acd_data, "start announcing failed to create probe (%s)", failure_reason);
            _l3_acd_data_timeout_schedule(acd_data, ACD_WAIT_TIME_ANNOUNCE_RESTART_MSEC);
            return;
        }

        _LOGT_acd(acd_data,
                  "start announcing (defend=%s) (probe created)",
                  _l3_acd_defend_type_to_string(acd_data->acd_defend_type_current,
                                                sbuf256,
                                                sizeof(sbuf256)));
        acd_data->acd_defend_type_is_active = FALSE;
        acd_data->nacd_probe                = probe;
        return;
    }

    if (!acd_data->acd_defend_type_is_active) {
        acd_data->acd_defend_type_is_active = TRUE;
        _LOGT_acd(acd_data,
                  "start announcing (defend=%s) (with existing probe)",
                  _l3_acd_defend_type_to_string(acd_data->acd_defend_type_current,
                                                sbuf256,
                                                sizeof(sbuf256)));
        if (n_acd_probe_announce(acd_data->nacd_probe,
                                 _l3_acd_defend_type_to_nacd(acd_data->acd_defend_type_current))
            != 0)
            nm_assert_not_reached();
        return;
    }
}

static void
_l3_acd_data_process_changes(NML3Cfg *self)
{
    gboolean acd_is_pending = FALSE;
    gboolean acd_busy       = FALSE;
    AcdData *acd_data;
    gint64   now_msec = 0;

    _l3_acd_data_prune(self, FALSE);

    c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst) {
        _l3_acd_data_state_change(self,
                                  acd_data,
                                  ACD_STATE_CHANGE_MODE_POST_COMMIT,
                                  NULL,
                                  &now_msec);
        if (acd_data->info.state <= NM_L3_ACD_ADDR_STATE_PROBING)
            acd_is_pending = TRUE;
        if (acd_data->nacd_probe)
            acd_busy = TRUE;
    }

    self->priv.p->acd_is_pending = acd_is_pending;

    if (!acd_busy)
        _l3_acd_nacd_instance_reset(self, NM_TERNARY_DEFAULT, FALSE);

    _nm_l3cfg_emit_signal_notify_acd_event_all(self);
}

/*****************************************************************************/

const NML3AcdAddrInfo *
nm_l3cfg_get_acd_addr_info(NML3Cfg *self, in_addr_t addr)
{
    AcdData *acd_data;

    nm_assert(NM_IS_L3CFG(self));

    acd_data = _l3_acd_data_find(self, addr);
    if (!acd_data)
        return NULL;

    return &acd_data->info;
}

/*****************************************************************************/

gboolean
nm_l3cfg_has_failedobj_pending(NML3Cfg *self, int addr_family)
{
    ObjStateData *obj_state;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert_addr_family(addr_family);

    nm_prioq_for_each (&self->priv.p->failedobj_prioq, obj_state) {
        if (NMP_OBJECT_GET_ADDR_FAMILY(obj_state->obj) == addr_family)
            return TRUE;
    }
    return FALSE;
}

gboolean
nm_l3cfg_check_ready(NML3Cfg               *self,
                     const NML3ConfigData  *l3cd,
                     int                    addr_family,
                     NML3CfgCheckReadyFlags flags,
                     GArray               **conflicts)
{
    NMDedupMultiIter iter;
    const NMPObject *obj;
    gboolean         ready = TRUE;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert_addr_family(addr_family);
    nm_assert(!conflicts || !*conflicts);

    if (!l3cd)
        return TRUE;

    if (addr_family == AF_INET) {
        if (NM_FLAGS_HAS(flags, NM_L3CFG_CHECK_READY_FLAGS_IP4_ACD_READY)) {
            nm_l3_config_data_iter_obj_for_each (&iter, l3cd, &obj, NMP_OBJECT_TYPE_IP4_ADDRESS) {
                const NML3AcdAddrInfo *addr_info;

                addr_info =
                    nm_l3cfg_get_acd_addr_info(self, NMP_OBJECT_CAST_IP4_ADDRESS(obj)->address);
                if (!addr_info) {
                    /* We don't track the this address? That's odd. Not ready. */
                    ready = FALSE;
                } else {
                    if (addr_info->state <= NM_L3_ACD_ADDR_STATE_PROBING) {
                        /* Still probing. Not ready. */
                        ready = FALSE;
                    } else if (addr_info->state == NM_L3_ACD_ADDR_STATE_USED) {
                        if (conflicts) {
                            if (!*conflicts)
                                *conflicts = g_array_new(FALSE,
                                                         FALSE,
                                                         nm_utils_addr_family_to_size(addr_family));
                            g_array_append_val(*conflicts, addr_info->addr);
                        }
                    }
                }
                /* we only care that we don't have ACD still pending. Otherwise we are ready,
                 * including if we have no addr_info about this address or the address is in use. */
            }
        }
        return ready;
    }

    /* AF_INET6 */
    if (NM_FLAGS_HAS(flags, NM_L3CFG_CHECK_READY_FLAGS_IP6_DAD_READY)) {
        nm_l3_config_data_iter_obj_for_each (&iter, l3cd, &obj, NMP_OBJECT_TYPE_IP6_ADDRESS) {
            ObjStateData *obj_state;
            gboolean      dadfailed = FALSE;

            obj_state = g_hash_table_lookup(self->priv.p->obj_state_hash, &obj);

            if (!obj_state) {
                /* Hm, we don't track this object? That is odd. Not ready. */
                ready = FALSE;
                continue;
            }

            if (!obj_state->os_nm_configured && !obj_state->os_plobj) {
                /* We didn't (yet) configure this address and it also is not in platform.
                 * Not ready. */
                ready = FALSE;
                continue;
            }

            if (obj_state->os_plobj
                && NM_FLAGS_HAS(NMP_OBJECT_CAST_IP6_ADDRESS(obj_state->os_plobj)->n_ifa_flags,
                                IFA_F_DADFAILED)) {
                /* The address is still present with DADFAILED flag. */
                dadfailed = TRUE;
            } else if (obj_state->os_nm_configured && !obj_state->os_plobj
                       && nm_platform_ip6_dadfailed_check(
                           self->priv.platform,
                           self->priv.ifindex,
                           &NMP_OBJECT_CAST_IP6_ADDRESS(obj_state->obj)->address)) {
                /* We configured the address and kernel removed it with DADFAILED flag. */
                dadfailed = TRUE;
            }

            if (dadfailed) {
                if (conflicts) {
                    if (!*conflicts) {
                        *conflicts =
                            g_array_new(FALSE, FALSE, nm_utils_addr_family_to_size(addr_family));
                    }
                    g_array_append_val(*conflicts,
                                       NMP_OBJECT_CAST_IP6_ADDRESS(obj_state->obj)->address);
                }
                continue;
            }

            if (obj_state->os_plobj
                && NM_FLAGS_HAS(NMP_OBJECT_CAST_IP6_ADDRESS(obj_state->os_plobj)->n_ifa_flags,
                                IFA_F_TENTATIVE)) {
                /* The address is configured in kernel, but still tentative. Not ready. */
                ready = FALSE;
                continue;
            }

            /* This address is ready. Even if it is not (not anymore) configured in kernel (as
             * indicated by obj_state->os_plobj). We apparently did configure it once, and
             * it's no longer tentative. This address are good. */
        }
    }

    return ready;
}

/*****************************************************************************/

static gboolean
_l3_commit_on_idle_cb(gpointer user_data)
{
    _nm_unused gs_unref_object NML3Cfg *self_keep_alive = NULL;
    NML3Cfg                            *self            = user_data;
    NML3CfgCommitType                   commit_type;

    commit_type = self->priv.p->commit_on_idle_type;

    if (nm_clear_g_source_inst(&self->priv.p->commit_on_idle_source))
        self_keep_alive = self;
    else
        nm_assert_not_reached();

    self->priv.p->commit_on_idle_type = NM_L3_CFG_COMMIT_TYPE_AUTO;

    _l3_commit(self, commit_type, TRUE);
    return G_SOURCE_REMOVE;
}

/* DOC(l3cfg:commit-type):
 *
 * Usually we don't want to call the synchronous nm_l3cfg_commit(), because
 * that has side effects and might not be safe to do (depending on the current
 * circumstances in which commit is called). The usually proper thing to do
 * is schedule a commit on an idle handler. Use this function.
 *
 * During commit, the actually used commit-type (that is, the level of "how much"
 * will be synced) is determined by users who register their desired commit
 * type via nm_l3cfg_commit_type_register(), where always the "maxium" is used.
 *
 * nm_l3cfg_commit() and nm_l3cfg_commit_on_idle_schedule() also accept an additional
 * commit_type argument. This acts like a one-shot registration.
 */
gboolean
nm_l3cfg_commit_on_idle_schedule(NML3Cfg *self, NML3CfgCommitType commit_type)
{
    char sbuf_commit_type[50];

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_AUTO,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE,
                        NM_L3_CFG_COMMIT_TYPE_REAPPLY));

    if (self->priv.p->commit_on_idle_source) {
        if (self->priv.p->commit_on_idle_type < commit_type) {
            /* For multiple calls, we collect the maximum "commit-type". */
            _LOGT("commit on idle (scheduled) (update to %s)",
                  _l3_cfg_commit_type_to_string(commit_type,
                                                sbuf_commit_type,
                                                sizeof(sbuf_commit_type)));
            self->priv.p->commit_on_idle_type = commit_type;
        }
        return FALSE;
    }

    _LOGT("commit on idle (scheduled) (%s)",
          _l3_cfg_commit_type_to_string(commit_type, sbuf_commit_type, sizeof(sbuf_commit_type)));
    self->priv.p->commit_on_idle_source = nm_g_idle_add_source(_l3_commit_on_idle_cb, self);
    self->priv.p->commit_on_idle_type   = commit_type;

    /* While we have an idle update scheduled, we need to keep the instance alive. */
    g_object_ref(self);

    return TRUE;
}

gboolean
nm_l3cfg_commit_on_idle_is_scheduled(NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    return !!(self->priv.p->commit_on_idle_source);
}

/*****************************************************************************/

#define _l3_config_datas_at(l3_config_datas, idx) \
    (&nm_g_array_index((l3_config_datas), L3ConfigData, (idx)))

static gssize
_l3_config_datas_find_next(GArray               *l3_config_datas,
                           guint                 start_idx,
                           gconstpointer         needle_tag,
                           const NML3ConfigData *needle_l3cd)
{
    guint i;

    nm_assert(l3_config_datas);
    nm_assert(start_idx <= l3_config_datas->len);

    for (i = start_idx; i < l3_config_datas->len; i++) {
        const L3ConfigData *l3_config_data = _l3_config_datas_at(l3_config_datas, i);

        if (NM_IN_SET(needle_tag, NULL, l3_config_data->tag_confdata)
            && NM_IN_SET(needle_l3cd, NULL, l3_config_data->l3cd))
            return i;
    }
    return -1;
}

static int
_l3_config_datas_get_sorted_cmp(gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
    const L3ConfigData *a = *((L3ConfigData **) p_a);
    const L3ConfigData *b = *((L3ConfigData **) p_b);

    nm_assert(a);
    nm_assert(b);
    nm_assert(nm_l3_config_data_get_ifindex(a->l3cd) == nm_l3_config_data_get_ifindex(b->l3cd));

    /* we sort the entries with higher priority (higher numerical value, more important)
     * first. */
    NM_CMP_FIELD(b, a, priority_confdata);

    /* if the priority is not unique, we sort them in the order they were added,
     * with the oldest first (lower numerical value). */
    NM_CMP_FIELD(a, b, pseudo_timestamp_confdata);

    return nm_assert_unreachable_val(0);
}

static void
_l3_config_datas_remove_index_fast(GArray *arr, guint idx)
{
    L3ConfigData *l3_config_data;

    nm_assert(arr);
    nm_assert(idx < arr->len);

    l3_config_data = _l3_config_datas_at(arr, idx);

    nm_l3_config_data_unref(l3_config_data->l3cd);

    g_array_remove_index_fast(arr, idx);
}

void
nm_l3cfg_mark_config_dirty(NML3Cfg *self, gconstpointer tag, gboolean dirty)
{
    gssize idx;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(tag);

    if (!self->priv.p->l3_config_datas)
        return;

    nm_assert(self->priv.p->l3_config_datas->len > 0);

    idx = 0;
    while (TRUE) {
        idx = _l3_config_datas_find_next(self->priv.p->l3_config_datas, idx, tag, NULL);
        if (idx < 0)
            return;

        _l3_config_datas_at(self->priv.p->l3_config_datas, idx)->dirty_confdata = dirty;
        idx++;
    }
}

/*
 * nm_l3cfg_add_config:
 * @priority: all l3cd get merged/combined. This merging requires that some
 *   l3cd are more important than others. For example, coming from static IP
 *   configuration needs to take precedence over DHCP. The @priority determines
 *   the order in which l3cds get merged (and thus the outcome). Higher numbers
 *   mean more important!!
 */
gboolean
nm_l3cfg_add_config(NML3Cfg              *self,
                    gconstpointer         tag,
                    gboolean              replace_same_tag,
                    const NML3ConfigData *l3cd,
                    int                   priority,
                    guint32               default_route_table_4,
                    guint32               default_route_table_6,
                    guint32               default_route_metric_4,
                    guint32               default_route_metric_6,
                    guint32               default_route_penalty_4,
                    guint32               default_route_penalty_6,
                    int                   default_dns_priority_4,
                    int                   default_dns_priority_6,
                    NML3AcdDefendType     acd_defend_type,
                    guint32               acd_timeout_msec,
                    NML3CfgConfigFlags    config_flags,
                    NML3ConfigMergeFlags  merge_flags)
{
    L3ConfigData *l3_config_data;
    gssize        idx;
    gboolean      changed = FALSE;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(tag);
    nm_assert(l3cd);
    nm_assert(nm_l3_config_data_get_ifindex(l3cd) == self->priv.ifindex);

    if (acd_timeout_msec > NM_ACD_TIMEOUT_MAX_MSEC)
        acd_timeout_msec = NM_ACD_TIMEOUT_MAX_MSEC;

    nm_assert(NM_IN_SET(acd_defend_type,
                        NM_L3_ACD_DEFEND_TYPE_NEVER,
                        NM_L3_ACD_DEFEND_TYPE_ONCE,
                        NM_L3_ACD_DEFEND_TYPE_ALWAYS));

    nm_assert(default_route_metric_6 != 0u); /* IPv6 default route metric cannot be zero. */

    if (default_route_table_4 == 0u)
        default_route_table_4 = RT_TABLE_MAIN;
    if (default_route_table_6 == 0u)
        default_route_table_6 = RT_TABLE_MAIN;

    if (!self->priv.p->l3_config_datas) {
        self->priv.p->l3_config_datas = g_array_new(FALSE, FALSE, sizeof(L3ConfigData));
        g_object_ref(self);
    } else
        nm_assert(self->priv.p->l3_config_datas->len > 0);

    idx = _l3_config_datas_find_next(self->priv.p->l3_config_datas,
                                     0,
                                     tag,
                                     replace_same_tag ? NULL : l3cd);

    if (replace_same_tag && idx >= 0) {
        gssize idx2;

        idx2 = idx;
        idx  = -1;
        while (TRUE) {
            l3_config_data = _l3_config_datas_at(self->priv.p->l3_config_datas, idx2);

            if (l3_config_data->l3cd == l3cd) {
                nm_assert(idx == -1);
                idx = idx2;
                idx2++;
            } else {
                changed = TRUE;
                _l3_config_datas_remove_index_fast(self->priv.p->l3_config_datas, idx2);
            }
            idx2 = _l3_config_datas_find_next(self->priv.p->l3_config_datas, idx2, tag, NULL);
            if (idx2 < 0)
                break;
        }
    }

    if (idx < 0) {
        l3_config_data  = nm_g_array_append_new(self->priv.p->l3_config_datas, L3ConfigData);
        *l3_config_data = (L3ConfigData){
            .tag_confdata              = tag,
            .l3cd                      = nm_l3_config_data_ref_and_seal(l3cd),
            .config_flags              = config_flags,
            .merge_flags               = merge_flags,
            .default_route_table_4     = default_route_table_4,
            .default_route_table_6     = default_route_table_6,
            .default_route_metric_4    = default_route_metric_4,
            .default_route_metric_6    = default_route_metric_6,
            .default_route_penalty_4   = default_route_penalty_4,
            .default_route_penalty_6   = default_route_penalty_6,
            .default_dns_priority_4    = default_dns_priority_4,
            .default_dns_priority_6    = default_dns_priority_6,
            .acd_defend_type_confdata  = acd_defend_type,
            .acd_timeout_msec_confdata = acd_timeout_msec,
            .priority_confdata         = priority,
            .pseudo_timestamp_confdata = ++self->priv.p->pseudo_timestamp_counter,
            .dirty_confdata            = FALSE,
        };
        changed = TRUE;
    } else {
        l3_config_data                 = _l3_config_datas_at(self->priv.p->l3_config_datas, idx);
        l3_config_data->dirty_confdata = FALSE;
        nm_assert(l3_config_data->tag_confdata == tag);
        nm_assert(l3_config_data->l3cd == l3cd);
        if (l3_config_data->priority_confdata != priority) {
            l3_config_data->priority_confdata = priority;
            changed                           = TRUE;
        }
        if (l3_config_data->config_flags != config_flags) {
            l3_config_data->config_flags = config_flags;
            changed                      = TRUE;
        }
        if (l3_config_data->merge_flags != merge_flags) {
            l3_config_data->merge_flags = merge_flags;
            changed                     = TRUE;
        }
        if (l3_config_data->default_route_table_4 != default_route_table_4) {
            l3_config_data->default_route_table_4 = default_route_table_4;
            changed                               = TRUE;
        }
        if (l3_config_data->default_route_table_6 != default_route_table_6) {
            l3_config_data->default_route_table_6 = default_route_table_6;
            changed                               = TRUE;
        }
        if (l3_config_data->default_route_metric_4 != default_route_metric_4) {
            l3_config_data->default_route_metric_4 = default_route_metric_4;
            changed                                = TRUE;
        }
        if (l3_config_data->default_route_metric_6 != default_route_metric_6) {
            l3_config_data->default_route_metric_6 = default_route_metric_6;
            changed                                = TRUE;
        }
        if (l3_config_data->default_route_penalty_4 != default_route_penalty_4) {
            l3_config_data->default_route_penalty_4 = default_route_penalty_4;
            changed                                 = TRUE;
        }
        if (l3_config_data->default_route_penalty_6 != default_route_penalty_6) {
            l3_config_data->default_route_penalty_6 = default_route_penalty_6;
            changed                                 = TRUE;
        }
        if (l3_config_data->default_dns_priority_4 != default_dns_priority_4) {
            l3_config_data->default_dns_priority_4 = default_dns_priority_4;
            changed                                = TRUE;
        }
        if (l3_config_data->default_dns_priority_6 != default_dns_priority_6) {
            l3_config_data->default_dns_priority_6 = default_dns_priority_6;
            changed                                = TRUE;
        }
        if (l3_config_data->acd_defend_type_confdata != acd_defend_type) {
            l3_config_data->acd_defend_type_confdata = acd_defend_type;
            changed                                  = TRUE;
        }
        if (l3_config_data->acd_timeout_msec_confdata != acd_timeout_msec) {
            l3_config_data->acd_timeout_msec_confdata = acd_timeout_msec;
            changed                                   = TRUE;
        }
    }

    nm_assert(l3_config_data->acd_defend_type_confdata == acd_defend_type);

    if (changed) {
        _l3_changed_configs_set_dirty(self);
        nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);
    }

    return changed;
}

static gboolean
_l3cfg_remove_config(NML3Cfg              *self,
                     gconstpointer         tag,
                     gboolean              only_dirty,
                     const NML3ConfigData *l3cd)
{
    gboolean changed;
    gssize   idx;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(tag);

    if (!self->priv.p->l3_config_datas)
        return FALSE;

    nm_assert(self->priv.p->l3_config_datas->len > 0);

    idx     = 0;
    changed = FALSE;
    while (TRUE) {
        idx = _l3_config_datas_find_next(self->priv.p->l3_config_datas, idx, tag, l3cd);
        if (idx < 0)
            break;

        if (only_dirty
            && !_l3_config_datas_at(self->priv.p->l3_config_datas, idx)->dirty_confdata) {
            idx++;
            continue;
        }

        _l3_changed_configs_set_dirty(self);
        _l3_config_datas_remove_index_fast(self->priv.p->l3_config_datas, idx);
        changed = TRUE;
        if (l3cd) {
            /* only one was requested to be removed. We are done. */
            break;
        }
    }

    if (changed)
        nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);

    if (self->priv.p->l3_config_datas->len == 0) {
        nm_assert(changed);
        nm_clear_pointer(&self->priv.p->l3_config_datas, g_array_unref);
        g_object_unref(self);
    }

    return changed;
}

gboolean
nm_l3cfg_remove_config(NML3Cfg *self, gconstpointer tag, const NML3ConfigData *l3cd)
{
    nm_assert(l3cd);

    return _l3cfg_remove_config(self, tag, FALSE, l3cd);
}

gboolean
nm_l3cfg_remove_config_all(NML3Cfg *self, gconstpointer tag)
{
    return _l3cfg_remove_config(self, tag, FALSE, NULL);
}

gboolean
nm_l3cfg_remove_config_all_dirty(NML3Cfg *self, gconstpointer tag)
{
    return _l3cfg_remove_config(self, tag, TRUE, NULL);
}

/*****************************************************************************/

static gboolean
_nodev_routes_untrack(NML3Cfg *self, int addr_family)
{
    return nmp_global_tracker_untrack_all(self->priv.global_tracker,
                                          _NODEV_ROUTES_TAG(self, NM_IS_IPv4(addr_family)),
                                          FALSE,
                                          TRUE);
}

static void
_nodev_routes_sync(NML3Cfg          *self,
                   int               addr_family,
                   NML3CfgCommitType commit_type,
                   GPtrArray        *routes_nodev)
{
    const int           IS_IPv4  = NM_IS_IPv4(addr_family);
    const NMPObjectType obj_type = NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4);
    guint               i;
    gboolean            changed = FALSE;

    if (!routes_nodev)
        goto out_clear;

    for (i = 0; i < routes_nodev->len; i++) {
        const NMPObject *obj = routes_nodev->pdata[i];

        if (nmp_global_tracker_track(self->priv.global_tracker,
                                     obj_type,
                                     NMP_OBJECT_CAST_IP_ROUTE(obj),
                                     1,
                                     _NODEV_ROUTES_TAG(self, IS_IPv4),
                                     NULL))
            changed = TRUE;
    }

out_clear:
    if (_nodev_routes_untrack(self, addr_family))
        changed = TRUE;

    if (changed || commit_type >= NM_L3_CFG_COMMIT_TYPE_REAPPLY) {
        nmp_global_tracker_sync(self->priv.global_tracker,
                                NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4),
                                FALSE);
    }
}

/*****************************************************************************/

typedef struct {
    NML3Cfg      *self;
    gconstpointer tag;
    bool          to_commit;
} L3ConfigMergeHookAddObjData;

static gboolean
_l3_hook_add_obj_cb(const NML3ConfigData      *l3cd,
                    const NMPObject           *obj,
                    NML3ConfigMergeHookResult *hook_result,
                    gpointer                   user_data)
{
    const L3ConfigMergeHookAddObjData *hook_data = user_data;
    NML3Cfg                           *self      = hook_data->self;
    AcdData                           *acd_data;
    in_addr_t                          addr;
    gboolean                           acd_bad = FALSE;

    nm_assert(obj);
    nm_assert(hook_result);
    nm_assert(hook_result->ip4acd_not_ready == NM_OPTION_BOOL_DEFAULT);

    switch (NMP_OBJECT_GET_TYPE(obj)) {
    case NMP_OBJECT_TYPE_IP4_ADDRESS:

        addr = NMP_OBJECT_CAST_IP4_ADDRESS(obj)->address;

        if (ACD_ADDR_SKIP(addr))
            goto out_ip4_address;

        acd_data = _l3_acd_data_find(self, addr);

        if (!hook_data->to_commit) {
            nm_assert(self->priv.p->changed_configs_acd_state);
            /* We don't do an actual commit in _l3cfg_update_combined_config(). That means our acd-data
             * is not up to date. Check whether we have no acd_data ready, and if not, consider the address
             * as not ready. It cannot be ready until the next commit starts ACD. */
            if (!acd_data) {
                acd_bad = TRUE;
                goto out_ip4_address;
            }
            nm_assert(({
                NML3AcdAddrTrackInfo *_ti =
                    _acd_data_find_track(acd_data, l3cd, obj, hook_data->tag);

                !_ti || _ti->_priv.acd_dirty_track;
            }));
        } else {
            /* If we commit, we called _l3_acd_data_add_all(), thus our acd_data must be present
             * and not dirty. */
            nm_assert(({
                NML3AcdAddrTrackInfo *_ti =
                    _acd_data_find_track(acd_data, l3cd, obj, hook_data->tag);

                _ti && !_ti->_priv.acd_dirty_track;
            }));
        }

        if (!NM_IN_SET(acd_data->info.state,
                       NM_L3_ACD_ADDR_STATE_READY,
                       NM_L3_ACD_ADDR_STATE_DEFENDING,
                       NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED)) {
            acd_bad = TRUE;
            goto out_ip4_address;
        }

out_ip4_address:
        hook_result->ip4acd_not_ready = acd_bad ? NM_OPTION_BOOL_TRUE : NM_OPTION_BOOL_FALSE;
        return TRUE;

    default:
        nm_assert_not_reached();
        /* fall-through */
    case NMP_OBJECT_TYPE_IP6_ADDRESS:
    case NMP_OBJECT_TYPE_IP4_ROUTE:
    case NMP_OBJECT_TYPE_IP6_ROUTE:
        return TRUE;
    }
}

static void
_l3cfg_update_combined_config(NML3Cfg               *self,
                              gboolean               to_commit,
                              gboolean               reapply,
                              const NML3ConfigData **out_old /* transfer reference */,
                              gboolean              *out_changed_combined_l3cd)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_commited_old    = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old             = NULL;
    nm_auto_unref_l3cd_init NML3ConfigData  *l3cd                 = NULL;
    gs_free const L3ConfigData             **l3_config_datas_free = NULL;
    const L3ConfigData                     **l3_config_datas_arr;
    guint                                    l3_config_datas_len;
    guint                                    i;
    gboolean                                 merged_changed   = FALSE;
    gboolean                                 commited_changed = FALSE;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(!out_old || !*out_old);

    NM_SET_OUT(out_changed_combined_l3cd, FALSE);

    if (!self->priv.p->changed_configs_configs) {
        if (!self->priv.p->changed_configs_acd_state)
            goto out;
        if (!to_commit) {
            /* since we are not going to commit, we don't care about the
             * ACD state. */
            goto out;
        }
    }

    self->priv.p->changed_configs_configs = FALSE;

    l3_config_datas_len = nm_g_array_len(self->priv.p->l3_config_datas);
    l3_config_datas_arr = nm_malloc_maybe_a(300,
                                            l3_config_datas_len * sizeof(l3_config_datas_arr[0]),
                                            &l3_config_datas_free);
    for (i = 0; i < l3_config_datas_len; i++)
        l3_config_datas_arr[i] = _l3_config_datas_at(self->priv.p->l3_config_datas, i);

    if (l3_config_datas_len > 1) {
        /* We are about to merge the l3cds. The order in which we do that matters.
         *
         * Below, we iterate over the l3cds and merge them into a new one. nm_l3_config_data_merge()
         * uses "NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE" flag, which means to keep the first entry.
         *
         * Consider for example addresses/routes, which have a set of ID attributes  (based on
         * which no duplicates can be accepted) and additional attributes. For example, trying
         * to add the same address twice ("same" according to their ID), only one can be added.
         * If they differ in their lifetimes, we need to make a choice.
         * We could merge the attributes in a sensible way. Instead, NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE
         * takes care to only take the first one.
         *
         * So we want to sort the more important entries *first*, and this is based on
         * the priority_confdata.  */
        g_qsort_with_data(l3_config_datas_arr,
                          l3_config_datas_len,
                          sizeof(l3_config_datas_arr[0]),
                          _l3_config_datas_get_sorted_cmp,
                          NULL);
    }

    if (!to_commit) {
        /* we are not going to commit these changes. Hence, we don't update the
         * ACD states, but we need to remember that we have to on the next commit. */
        self->priv.p->changed_configs_acd_state = TRUE;
    } else {
        _l3_acd_data_add_all(self, l3_config_datas_arr, l3_config_datas_len, reapply);
        self->priv.p->changed_configs_acd_state = FALSE;
    }

    if (l3_config_datas_len > 0) {
        L3ConfigMergeHookAddObjData hook_data = {
            .self      = self,
            .to_commit = to_commit,
        };

        l3cd = nm_l3_config_data_new(nm_platform_get_multi_idx(self->priv.platform),
                                     self->priv.ifindex,
                                     NM_IP_CONFIG_SOURCE_UNKNOWN);

        for (i = 0; i < l3_config_datas_len; i++) {
            const L3ConfigData *l3cd_data = l3_config_datas_arr[i];

            /* more important entries must be sorted *first*. */
            nm_assert(
                i == 0
                || (l3_config_datas_arr[i - 1]->priority_confdata > l3cd_data->priority_confdata)
                || (l3_config_datas_arr[i - 1]->priority_confdata == l3cd_data->priority_confdata
                    && l3_config_datas_arr[i - 1]->pseudo_timestamp_confdata
                           < l3cd_data->pseudo_timestamp_confdata));

            if (NM_FLAGS_HAS(l3cd_data->config_flags, NM_L3CFG_CONFIG_FLAGS_ONLY_FOR_ACD))
                continue;

            hook_data.tag = l3cd_data->tag_confdata;

            nm_l3_config_data_merge(l3cd,
                                    l3cd_data->l3cd,
                                    l3cd_data->merge_flags,
                                    l3cd_data->default_route_table_x,
                                    l3cd_data->default_route_metric_x,
                                    l3cd_data->default_route_penalty_x,
                                    l3cd_data->default_dns_priority_x,
                                    _l3_hook_add_obj_cb,
                                    &hook_data);
        }

        if (self->priv.ifindex == NM_LOOPBACK_IFINDEX) {
            NMPlatformIPXAddress ax;
            NMPlatformIPXRoute   rx;

            if (!nm_l3_config_data_lookup_address_4(l3cd,
                                                    NM_IPV4LO_ADDR1,
                                                    NM_IPV4LO_PREFIXLEN,
                                                    NM_IPV4LO_ADDR1)) {
                nm_l3_config_data_add_address_4(
                    l3cd,
                    nm_platform_ip4_address_init_loopback_addr1(&ax.a4));
            }
            if (!nm_l3_config_data_lookup_address_6(l3cd, &in6addr_loopback)) {
                nm_l3_config_data_add_address_6(l3cd,
                                                nm_platform_ip6_address_init_loopback(&ax.a6));
            }

            rx.r4 = (NMPlatformIP4Route){
                .ifindex       = NM_LOOPBACK_IFINDEX,
                .rt_source     = NM_IP_CONFIG_SOURCE_KERNEL,
                .network       = NM_IPV4LO_ADDR1,
                .plen          = NM_IPV4LO_PREFIXLEN,
                .table_coerced = nm_platform_route_table_coerce(RT_TABLE_LOCAL),
                .scope_inv     = nm_platform_route_scope_inv(RT_SCOPE_HOST),
                .type_coerced  = nm_platform_route_type_coerce(RTN_LOCAL),
                .pref_src      = NM_IPV4LO_ADDR1,
            };
            nm_platform_ip_route_normalize(AF_INET, &rx.rx);
            if (!nm_l3_config_data_lookup_route(l3cd, AF_INET, &rx.rx)) {
                nm_l3_config_data_add_route_4(l3cd, &rx.r4);
            }
        }
        for (i = 0; i < l3_config_datas_len; i++) {
            const L3ConfigData *l3cd_data = l3_config_datas_arr[i];
            int                 IS_IPv4;

            if (NM_FLAGS_HAS(l3cd_data->config_flags, NM_L3CFG_CONFIG_FLAGS_ONLY_FOR_ACD))
                continue;

            for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
                nm_l3_config_data_add_dependent_device_routes(
                    l3cd,
                    IS_IPv4 ? AF_INET : AF_INET6,
                    l3cd_data->default_route_table_x[IS_IPv4],
                    l3cd_data->default_route_metric_x[IS_IPv4],
                    l3cd_data->l3cd);
            }
        }

        nm_l3_config_data_add_dependent_onlink_routes(l3cd, AF_UNSPEC);

        nm_assert(l3cd);
        nm_assert(nm_l3_config_data_get_ifindex(l3cd) == self->priv.ifindex);

        nm_l3_config_data_seal(l3cd);
    }

    if (nm_l3_config_data_equal(l3cd, self->priv.p->combined_l3cd_merged))
        goto out;

    l3cd_old                           = g_steal_pointer(&self->priv.p->combined_l3cd_merged);
    self->priv.p->combined_l3cd_merged = nm_l3_config_data_seal(g_steal_pointer(&l3cd));
    merged_changed                     = TRUE;

    _nm_l3cfg_emit_signal_notify_l3cd_changed(self,
                                              l3cd_old,
                                              self->priv.p->combined_l3cd_merged,
                                              FALSE);

    if (!to_commit) {
        NM_SET_OUT(out_old, g_steal_pointer(&l3cd_old));
        NM_SET_OUT(out_changed_combined_l3cd, TRUE);
    }

out:
    if (to_commit && self->priv.p->combined_l3cd_commited != self->priv.p->combined_l3cd_merged) {
        l3cd_commited_old = g_steal_pointer(&self->priv.p->combined_l3cd_commited);
        self->priv.p->combined_l3cd_commited =
            nm_l3_config_data_ref(self->priv.p->combined_l3cd_merged);
        commited_changed = TRUE;

        _obj_states_update_all(self);

        _nm_l3cfg_emit_signal_notify_l3cd_changed(self,
                                                  l3cd_commited_old,
                                                  self->priv.p->combined_l3cd_commited,
                                                  TRUE);

        NM_SET_OUT(out_old, g_steal_pointer(&l3cd_commited_old));
        NM_SET_OUT(out_changed_combined_l3cd, TRUE);
    }

    if ((merged_changed || commited_changed) && _LOGT_ENABLED()) {
        char sbuf256[256];
        char sbuf30[30];

        _LOGT("IP configuration changed (merged=%c%s, commited=%c%s)",
              merged_changed ? '>' : '=',
              NM_HASH_OBFUSCATE_PTR_STR(self->priv.p->combined_l3cd_merged, sbuf256),
              commited_changed ? '>' : '=',
              NM_HASH_OBFUSCATE_PTR_STR(self->priv.p->combined_l3cd_commited, sbuf30));

        if (merged_changed) {
            nm_l3_config_data_log(self->priv.p->combined_l3cd_merged,
                                  NULL,
                                  nm_sprintf_buf(sbuf256,
                                                 "l3cfg[" NM_HASH_OBFUSCATE_PTR_FMT
                                                 ",ifindex=%d]:    ",
                                                 NM_HASH_OBFUSCATE_PTR(self),
                                                 nm_l3cfg_get_ifindex(self)),
                                  LOGL_TRACE,
                                  _NMLOG_DOMAIN);
        }
    }
}

/*****************************************************************************/

static gboolean
_failedobj_timeout_cb(gpointer user_data)
{
    NML3Cfg *self = NM_L3CFG(user_data);

    _LOGT("obj-state: failed-obj: handle timeout");

    nm_clear_g_source_inst(&self->priv.p->failedobj_timeout_source);

    nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);

    return G_SOURCE_CONTINUE;
}

static void
_failedobj_reschedule(NML3Cfg *self, gint64 now_msec)
{
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    ObjStateData *obj_state;

    nm_utils_get_monotonic_timestamp_msec_cached(&now_msec);

again:
    obj_state = nm_prioq_peek(&self->priv.p->failedobj_prioq);

    if (obj_state && obj_state->os_failedobj_expiry_msec <= now_msec) {
        /* The object is already expired... */

        /* we shouldn't have a "os_plobj", because if we had, we should have
         * removed "obj_state" from the queue. */
        nm_assert(!obj_state->os_plobj);

        /* we need to have an "obj", otherwise the "obj_state" instance
         * shouldn't exist (as it also has not "os_plobj"). */
        nm_assert(obj_state->obj);

        /* It seems that nm_platform_ip_route_sync() signaled success and did
         * not report the route as missing. Regardless, it is still not
         * configured and the timeout expired. */
        nm_prioq_remove(&self->priv.p->failedobj_prioq,
                        obj_state,
                        &obj_state->os_failedobj_prioq_idx);
        _LOGW(
            "missing IPv%c route: %s",
            nm_utils_addr_family_to_char(NMP_OBJECT_GET_ADDR_FAMILY(obj_state->obj)),
            nmp_object_to_string(obj_state->obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
        goto again;
    }

    if (!obj_state) {
        if (nm_clear_g_source_inst(&self->priv.p->failedobj_timeout_source))
            _LOGT("obj-state: failed-obj: cancel timeout");
        return;
    }

    if (nm_g_timeout_reschedule(&self->priv.p->failedobj_timeout_source,
                                &self->priv.p->failedobj_timeout_expiry_msec,
                                obj_state->os_failedobj_expiry_msec,
                                _failedobj_timeout_cb,
                                self)) {
        _LOGT(
            "obj-state: failed-obj: schedule timeout in %" G_GINT64_FORMAT " msec",
            NM_MAX((gint64) 0,
                   obj_state->os_failedobj_expiry_msec - nm_utils_get_monotonic_timestamp_msec()));
    }
}

static void
_failedobj_handle_routes(NML3Cfg *self, int addr_family, GPtrArray *routes_failed)
{
    const gint64  now_msec = nm_utils_get_monotonic_timestamp_msec();
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    ObjStateData *obj_state;
    guint         i;

    if (!routes_failed)
        return;

    for (i = 0; i < routes_failed->len; i++) {
        const NMPObject          *o                    = routes_failed->pdata[i];
        const NMPlatformIPXRoute *rt                   = NMP_OBJECT_CAST_IPX_ROUTE(o);
        gboolean                  just_started_to_fail = FALSE;
        gboolean                  just_failed          = FALSE;
        gboolean                  arm_timer            = FALSE;
        int                       grace_timeout_msec;
        gint64                    grace_expiry_msec;

        nm_assert(NMP_OBJECT_GET_TYPE(o) == NMP_OBJECT_TYPE_IP_ROUTE(NM_IS_IPv4(addr_family)));

        obj_state = g_hash_table_lookup(self->priv.p->obj_state_hash, &o);

        if (!obj_state) {
            /* Hm? We don't track this object? Very odd, a bug? */
            nm_assert_not_reached();
            continue;
        }

        if (obj_state->os_plobj) {
            /* This object is apparently present in platform. Not sure what this failure report
             * is about. Probably some harmless glitch. Ignore. */
            continue;
        }

        /* This route failed, but why? That determines the grace time that we
         * give before considering it bad. */
        if (!nm_ip_addr_is_null(addr_family,
                                nm_platform_ip_route_get_pref_src(addr_family, &rt->rx))) {
            /* This route has a pref_src. A common cause for being unable to
             * configure such routes, is that the referenced IP address is not
             * configured/ready (yet). Give a longer timeout to this case. */
            grace_timeout_msec = 10000;
        } else {
            /* Other route don't have any grace time. There is no retry/wait,
             * they are a failure right away. */
            grace_timeout_msec = 0;
        }

        grace_expiry_msec = now_msec + grace_timeout_msec;

        if (obj_state->os_failedobj_expiry_msec == 0) {
            /* This is a new failure that we didn't see before... */
            obj_state->os_failedobj_expiry_msec = grace_expiry_msec;
            if (grace_timeout_msec == 0)
                just_failed = TRUE;
            else {
                arm_timer            = TRUE;
                just_started_to_fail = TRUE;
            }
        } else {
            if (obj_state->os_failedobj_expiry_msec > grace_expiry_msec) {
                /* Shorten the grace timeout. We anyway rearm below... */
                obj_state->os_failedobj_expiry_msec = grace_expiry_msec;
            }
            if (obj_state->os_failedobj_expiry_msec <= now_msec) {
                /* The grace period is (already) expired. */
                if (obj_state->os_failedobj_prioq_idx != NM_PRIOQ_IDX_NULL) {
                    /* We are still tracking the element. It just is about to become failed. */
                    just_failed = TRUE;
                }
            } else
                arm_timer = TRUE;
        }

        nm_prioq_update(&self->priv.p->failedobj_prioq,
                        obj_state,
                        &obj_state->os_failedobj_prioq_idx,
                        arm_timer);

        if (just_failed) {
            _LOGW("unable to configure IPv%c route: %s",
                  nm_utils_addr_family_to_char(addr_family),
                  nmp_object_to_string(o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
        } else if (just_started_to_fail) {
            _LOGT("obj-state: failed-obj: unable to configure %s. Wait for %d msec",
                  _obj_state_data_to_string(obj_state, sbuf, sizeof(sbuf)),
                  grace_timeout_msec);
        }
    }
}

static int
_failedobj_prioq_cmp(gconstpointer a, gconstpointer b)
{
    const ObjStateData *object_state_a = a;
    const ObjStateData *object_state_b = b;

    nm_assert(object_state_a);
    nm_assert(object_state_a->os_failedobj_expiry_msec > 0);
    nm_assert(object_state_b);
    nm_assert(object_state_b->os_failedobj_expiry_msec > 0);

    NM_CMP_SELF(object_state_a, object_state_b);
    NM_CMP_FIELD(object_state_a, object_state_b, os_failedobj_expiry_msec);
    return 0;
}

/*****************************************************************************/

static const char *
ip6_privacy_to_str(NMSettingIP6ConfigPrivacy ip6_privacy)
{
    switch (ip6_privacy) {
    case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
        return "0";
    case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
        return "1";
    case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
        return "2";
    case NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN:
        break;
    }
    return nm_assert_unreachable_val("0");
}

static void
_l3_commit_ndisc_params(NML3Cfg *self, NML3CfgCommitType commit_type)
{
    const NML3ConfigData *l3cd;
    gboolean              retrans_set   = FALSE;
    gboolean              reachable_set = FALSE;
    gboolean              hop_limit_set = FALSE;
    guint32               reachable     = 0;
    guint32               retrans       = 0;
    int                   hop_limit     = 0;
    const char           *ifname;

    if (commit_type < NM_L3_CFG_COMMIT_TYPE_UPDATE) {
        self->priv.p->ndisc_reachable_time_msec_set = FALSE;
        self->priv.p->ndisc_retrans_timer_msec_set  = FALSE;
        self->priv.p->ndisc_hop_limit_set           = FALSE;
        return;
    }

    l3cd = self->priv.p->combined_l3cd_commited;
    if (l3cd) {
        reachable_set = nm_l3_config_data_get_ndisc_reachable_time_msec(l3cd, &reachable);
        retrans_set   = nm_l3_config_data_get_ndisc_retrans_timer_msec(l3cd, &retrans);
        hop_limit     = nm_l3_config_data_get_ndisc_hop_limit(l3cd, &hop_limit);
    }
    ifname = nm_l3cfg_get_ifname(self, TRUE);

    if (reachable_set
        && (!self->priv.p->ndisc_reachable_time_msec_set
            || self->priv.p->ndisc_reachable_time_msec != reachable)) {
        self->priv.p->ndisc_reachable_time_msec     = reachable;
        self->priv.p->ndisc_reachable_time_msec_set = TRUE;
        if (ifname) {
            nm_platform_sysctl_ip_neigh_set_ipv6_reachable_time(self->priv.platform,
                                                                ifname,
                                                                reachable);
        }
    }

    if (retrans_set
        && (!self->priv.p->ndisc_retrans_timer_msec_set
            || self->priv.p->ndisc_retrans_timer_msec != retrans)) {
        self->priv.p->ndisc_retrans_timer_msec     = retrans;
        self->priv.p->ndisc_retrans_timer_msec_set = TRUE;
        if (ifname) {
            nm_platform_sysctl_ip_neigh_set_ipv6_retrans_time(self->priv.platform, ifname, retrans);
        }
    }

    if (hop_limit_set
        && (!self->priv.p->ndisc_hop_limit_set || self->priv.p->ndisc_hop_limit != hop_limit)) {
        self->priv.p->ndisc_hop_limit     = hop_limit;
        self->priv.p->ndisc_hop_limit_set = TRUE;
        if (ifname) {
            nm_platform_sysctl_ip_conf_set_ipv6_hop_limit_safe(self->priv.platform,
                                                               ifname,
                                                               hop_limit);
        }
    }

    // FIXME: restore values if necessary
}

static void
_l3_commit_ip6_privacy(NML3Cfg *self, NML3CfgCommitType commit_type)
{
    NMSettingIP6ConfigPrivacy ip6_privacy;
    NMSettingIP6ConfigPrivacy ip6_privacy_set_before;
    const char               *ifname;

    if (commit_type < NM_L3_CFG_COMMIT_TYPE_UPDATE)
        ip6_privacy = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
    else
        ip6_privacy = nm_l3_config_data_get_ip6_privacy(self->priv.p->combined_l3cd_commited);

    if (ip6_privacy == NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN) {
        if (!self->priv.p->ip6_privacy_set) {
            /* Nothing to set. But do we need to reset a previous value? */
            return;
        }
        self->priv.p->ip6_privacy_set = FALSE;
        ip6_privacy                   = self->priv.p->ip6_privacy_initial;
        ifname                        = nm_l3cfg_get_ifname(self, TRUE);
        _LOGT("commit-ip6-privacy: reset initial value %d (was %d)%s%s",
              (int) ip6_privacy,
              (int) self->priv.p->ip6_privacy_set_before,
              NM_PRINT_FMT_QUOTED2(ifname, ", ifname ", ifname, " (skip, no interface)"));
        if (ip6_privacy == NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
            return;
        if (!ifname)
            return;
        goto set;
    }

    nm_assert(NM_IN_SET(ip6_privacy,
                        NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED,
                        NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR,
                        NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR));

    if (self->priv.p->ip6_privacy_set && self->priv.p->ip6_privacy_set_before == ip6_privacy
        && commit_type < NM_L3_CFG_COMMIT_TYPE_REAPPLY) {
        /* Already set. We leave this alone except during reapply. */
        return;
    }

    ip6_privacy_set_before               = self->priv.p->ip6_privacy_set_before;
    self->priv.p->ip6_privacy_set_before = ip6_privacy;

    if (!self->priv.p->ip6_privacy_set) {
        gint64 s = G_MININT64;

        self->priv.p->ip6_privacy_set = TRUE;
        ifname                        = nm_l3cfg_get_ifname(self, TRUE);
        if (ifname) {
            s = nm_platform_sysctl_ip_conf_get_int_checked(self->priv.platform,
                                                           AF_INET6,
                                                           ifname,
                                                           "use_tempaddr",
                                                           10,
                                                           G_MININT32,
                                                           G_MAXINT32,
                                                           G_MININT64);
            if (s != G_MININT64)
                s = NM_CLAMP(s, 0, 2);
        }
        switch (s) {
        case 0:
            self->priv.p->ip6_privacy_initial = NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED;
            break;
        case 1:
            self->priv.p->ip6_privacy_initial = NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR;
            break;
        case 2:
            self->priv.p->ip6_privacy_initial = NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR;
            break;
        default:
            nm_assert_not_reached();
            /* fall-through */
        case G_MININT64:
            self->priv.p->ip6_privacy_initial = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
            break;
        }
        _LOGT("commit-ip6-privacy: set value %d (initial value was %d)%s%s",
              (int) ip6_privacy,
              (int) self->priv.p->ip6_privacy_initial,
              NM_PRINT_FMT_QUOTED2(ifname, ", ifname ", ifname, " (skip, no interface)"));
        if (!ifname)
            return;
        /* The first time, we always set the value, and don't skip it based on what we
         * read. */
        goto set;
    }

    ifname = nm_l3cfg_get_ifname(self, TRUE);
    _LOGT("commit-ip6-privacy: set value %d (after %d, initial value was %d)%s%s",
          (int) ip6_privacy,
          (int) ip6_privacy_set_before,
          (int) self->priv.p->ip6_privacy_initial,
          NM_PRINT_FMT_QUOTED2(ifname, ", ifname ", ifname, " (skip, no interface)"));
    if (!ifname)
        return;

set:
    nm_assert(ifname);
    self->priv.p->ip6_privacy_set_before = ip6_privacy;
    nm_platform_sysctl_ip_conf_set(self->priv.platform,
                                   AF_INET6,
                                   ifname,
                                   "use_tempaddr",
                                   ip6_privacy_to_str(ip6_privacy));
}

static void
_l3_commit_ip6_token(NML3Cfg *self, NML3CfgCommitType commit_type)
{
    NMUtilsIPv6IfaceId    token;
    const NMPlatformLink *pllink;
    int                   val;

    if (commit_type < NM_L3_CFG_COMMIT_TYPE_UPDATE || !self->priv.p->combined_l3cd_commited)
        token.id = 0;
    else
        token = nm_l3_config_data_get_ip6_token(self->priv.p->combined_l3cd_commited);

    pllink = nm_l3cfg_get_pllink(self, TRUE);
    if (!pllink || pllink->inet6_token.id == token.id)
        return;

    if (_LOGT_ENABLED()) {
        struct in6_addr addr     = {};
        struct in6_addr addr_old = {};
        char            addr_str[INET6_ADDRSTRLEN];
        char            addr_str_old[INET6_ADDRSTRLEN];

        nm_utils_ipv6_addr_set_interface_identifier(&addr, &token);
        nm_utils_ipv6_addr_set_interface_identifier(&addr_old, &pllink->inet6_token);

        _LOGT("commit-ip6-token: set value %s (was %s)",
              inet_ntop(AF_INET6, &addr, addr_str, INET6_ADDRSTRLEN),
              inet_ntop(AF_INET6, &addr_old, addr_str_old, INET6_ADDRSTRLEN));
    }

    /* The kernel allows setting a token only when 'accept_ra'
     * is 1: temporarily flip it if necessary; unfortunately
     * this will also generate an additional Router Solicitation
     * from kernel. */
    val = nm_platform_sysctl_ip_conf_get_int_checked(self->priv.platform,
                                                     AF_INET6,
                                                     pllink->name,
                                                     "accept_ra",
                                                     10,
                                                     G_MININT32,
                                                     G_MAXINT32,
                                                     1);

    if (val != 1) {
        nm_platform_sysctl_ip_conf_set(self->priv.platform,
                                       AF_INET6,
                                       pllink->name,
                                       "accept_ra",
                                       "1");
    }

    nm_platform_link_set_ipv6_token(self->priv.platform, self->priv.ifindex, &token);

    if (val != 1) {
        nm_platform_sysctl_ip_conf_set_int64(self->priv.platform,
                                             AF_INET6,
                                             pllink->name,
                                             "accept_ra",
                                             val);
    }
}

/*****************************************************************************/

static void
_rp_filter_update(NML3Cfg *self, gboolean reapply)
{
    gboolean    rp_filter_relax = FALSE;
    const char *ifname;
    int         rf_val;

    /* The rp_filter sysctl is only an IPv4 thing. We only enable the rp-filter
     * handling, if we did anything to MPTCP about IPv4 addresses.
     *
     * While we only have one "connection.mptcp-flags=enabled" property, whether
     * we handle MPTCP is still tracked per AF. In particular, with "enabled-on-global-iface"
     * flag, which honors the AF-specific default route. */
    if (self->priv.p->mptcp_set_4)
        rp_filter_relax = TRUE;

    if (!rp_filter_relax) {
        if (self->priv.p->rp_filter_handled) {
            self->priv.p->rp_filter_handled = FALSE;
            if (self->priv.p->rp_filter_set) {
                self->priv.p->rp_filter_set = FALSE;

                ifname = nm_l3cfg_get_ifname(self, TRUE);
                rf_val = nm_platform_sysctl_ip_conf_get_rp_filter_ipv4(self->priv.platform,
                                                                       ifname,
                                                                       FALSE,
                                                                       NULL);
                if (rf_val == 2) {
                    /* We only relaxed from 1 to 2. Only if that is still the case, reset. */
                    nm_platform_sysctl_ip_conf_set(self->priv.platform,
                                                   AF_INET,
                                                   ifname,
                                                   "rp_filter",
                                                   "1");
                }
            }
        }
        return;
    }

    if (self->priv.p->rp_filter_handled && !reapply) {
        /* We only set rp_filter once (except reapply). */
        return;
    }

    /* No matter whether we actually reset the value below, we set the "handled" flag
     * so that we only do this once (except during reapply). */
    self->priv.p->rp_filter_handled = TRUE;

    ifname = nm_l3cfg_get_ifname(self, TRUE);

    rf_val =
        nm_platform_sysctl_ip_conf_get_rp_filter_ipv4(self->priv.platform, ifname, FALSE, NULL);

    if (rf_val != 1) {
        /* We only relax from strict (1) to loose (2). No other transition. Nothing to do. */
        return;
    }

    /* We actually loosen the flag. We need to remember to reset it. */
    self->priv.p->rp_filter_set = TRUE;
    nm_platform_sysctl_ip_conf_set(self->priv.platform, AF_INET, ifname, "rp_filter", "2");
}

/*****************************************************************************/

static void
_routes_watch_ip_addrs_cb(NMNetns                       *netns,
                          NMNetnsWatcherType             watcher_type,
                          const NMNetnsWatcherData      *watcher_data,
                          gconstpointer                  tag,
                          const NMNetnsWatcherEventData *event_data,
                          gpointer                       user_data)
{
    const int IS_IPv4 = NM_IS_IPv4(watcher_data->ip_addr.addr.addr_family);
    NML3Cfg  *self    = user_data;
    char      sbuf[NM_INET_ADDRSTRLEN];

    if (NMP_OBJECT_CAST_IP_ADDRESS(event_data->ip_addr.obj)->ifindex == self->priv.ifindex) {
        if (self->priv.p->commit_reentrant_count_ip_address_sync_x[IS_IPv4] > 0) {
            /* We are currently commiting IP addresses on this very interface.
             * We can ignore the event. Also, because we will sync the routes
             * immediately after already.  So even if somebody externally added
             * the address just this very moment, we would still do the commit
             * at the right time to ensure our routes are there. */
            return;
        }
    }

    if (event_data->ip_addr.change_type == NM_PLATFORM_SIGNAL_REMOVED)
        return;

    _LOGT("watched ip-address %s changed. Schedule an idle commit",
          nm_inet_ntop(watcher_data->ip_addr.addr.addr_family,
                       &watcher_data->ip_addr.addr.addr,
                       sbuf));
    nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);
}

static void
_routes_watch_ip_addrs(NML3Cfg *self, int addr_family, GPtrArray *addresses, GPtrArray *routes)
{
    gconstpointer const TAG          = _NETNS_WATCHER_IP_ADDR_TAG(self, addr_family);
    NMNetnsWatcherData  watcher_data = {
         .ip_addr =
            {
                 .addr =
                    {
                         .addr_family = addr_family,
                    },
            },
    };
    guint i;
    guint j;

    /* IP routes that have a pref_src, can only be configured in kernel if that
     * address exists (and is non-tentative, in case of IPv6).  That address
     * might be on another interface. So we actually watch all other
     * interfaces.
     *
     * Note that while we track failure to configure routes via "failedobj"
     * mechanism, we eagerly register watchers, even if the route is already
     * successfully configured or if the route is to be configure the first
     * time.  Maybe that could be improved, but
     * - watchers should be cheap unless they notify the event.
     * - upon change we do an async commit, which is maybe not entirely cheap
     *   but cheap enough. More importantly, committing is something that
     *   *always* should be permissible -- because NML3Cfg has multiple,
     *   independent users, that don't know about each other and which
     *   independently are allowed to issue a commit when they think something
     *   relevant changed. If there are really too many, unnecessary commits,
     *   then the cause needs to be understood and addressed explicitly. */

    if (!routes)
        goto out;

    for (i = 0; i < routes->len; i++) {
        const NMPlatformIPRoute *rt = NMP_OBJECT_CAST_IP_ROUTE(routes->pdata[i]);
        gconstpointer            pref_src;

        nm_assert(NMP_OBJECT_GET_ADDR_FAMILY(routes->pdata[i]) == addr_family);

        pref_src = nm_platform_ip_route_get_pref_src(addr_family, rt);

        if (nm_ip_addr_is_null(addr_family, pref_src))
            continue;

        if (NM_IS_IPv4(addr_family)) {
            if (addresses) {
                /* This nested loop makes the whole operation O(n*m). We still
                 * do it that way, because it's probably faster to just iterate
                 * over the few addresses instead of building a lookup index to
                 * get it in O(n+m). */
                for (j = 0; j < addresses->len; j++) {
                    const NMPlatformIPAddress *a = NMP_OBJECT_CAST_IP_ADDRESS(addresses->pdata[j]);

                    nm_assert(NMP_OBJECT_GET_ADDR_FAMILY(addresses->pdata[j]) == addr_family);

                    if (nm_ip_addr_equal(addr_family, pref_src, a->address_ptr)) {
                        /* We optimize for the case where the required address
                         * is about be configured in the same commit. That is a
                         * common case, because our DHCP routes have prefsrc
                         * set, and we commonly have the respective IP address
                         * ready.  Otherwise, the very common DHCP case would
                         * also require the overhead of registering a watcher
                         * (every time).
                         */
                        goto next;
                    }
                }
            }
        } else {
            /* For IPv6, the prefsrc address must also be non-tentative (or
             * IFA_F_OPTIMISTIC).  So by only looking at the addresses we are
             * about to configure, it's not clear whether we will be able to
             * configure the route too.
             *
             * Maybe we could check current platform, whether the address
             * exists there as non-tentative, but that seems fragile.
             *
             * Maybe we should only register watchers, after we encountered a
             * failure to configure a route, but that seems complicated (and
             * has the potential to be wrong).
             *
             * The overhead for always watching the IPv6 address should be
             * acceptably small. So just do that.
             */
        }

        nm_assert(watcher_data.ip_addr.addr.addr_family == addr_family);
        nm_ip_addr_set(addr_family, &watcher_data.ip_addr.addr.addr, pref_src);

        nm_netns_watcher_add(self->priv.netns,
                             NM_NETNS_WATCHER_TYPE_IP_ADDR,
                             &watcher_data,
                             TAG,
                             _routes_watch_ip_addrs_cb,
                             self);
next:
        (void) 0;
    }

out:
    nm_netns_watcher_remove_all(self->priv.netns, TAG, FALSE);
}
/*****************************************************************************/

static gboolean
_global_tracker_mptcp_untrack(NML3Cfg *self, int addr_family)
{
    return nmp_global_tracker_untrack_all(self->priv.global_tracker,
                                          _MPTCP_TAG(self, NM_IS_IPv4(addr_family)),
                                          FALSE,
                                          TRUE);
}

static gboolean
_l3_commit_mptcp_af(NML3Cfg          *self,
                    NML3CfgCommitType commit_type,
                    int               addr_family,
                    gboolean         *out_reapply)
{
    const int    IS_IPv4 = NM_IS_IPv4(addr_family);
    NMMptcpFlags mptcp_flags;
    gboolean     reapply = FALSE;
    gboolean     changed = FALSE;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_NONE,
                        NM_L3_CFG_COMMIT_TYPE_REAPPLY,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE));

    if (commit_type >= NM_L3_CFG_COMMIT_TYPE_REAPPLY)
        reapply = TRUE;

    if (commit_type != NM_L3_CFG_COMMIT_TYPE_NONE && self->priv.p->combined_l3cd_commited)
        mptcp_flags = nm_l3_config_data_get_mptcp_flags(self->priv.p->combined_l3cd_commited);
    else
        mptcp_flags = NM_MPTCP_FLAGS_DISABLED;

    if (mptcp_flags == NM_MPTCP_FLAGS_NONE || NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_DISABLED))
        mptcp_flags = NM_MPTCP_FLAGS_DISABLED;
    else if (!NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_ALSO_WITHOUT_DEFAULT_ROUTE)) {
        /* Whether MPTCP is enabled/disabled (per address family), depends on whether we have a unicast
         * default route (in the main routing table). */
        if (self->priv.p->combined_l3cd_commited
            && nm_l3_config_data_get_best_default_route(self->priv.p->combined_l3cd_commited,
                                                        addr_family))
            mptcp_flags = NM_FLAGS_UNSET(mptcp_flags, NM_MPTCP_FLAGS_ALSO_WITHOUT_DEFAULT_ROUTE)
                          | NM_MPTCP_FLAGS_ENABLED;
        else
            mptcp_flags = NM_MPTCP_FLAGS_DISABLED;
    } else
        mptcp_flags |= NM_MPTCP_FLAGS_ENABLED;

    if (NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_DISABLED)) {
        if (!self->priv.p->mptcp_set_x[IS_IPv4] && !reapply) {
            /* Nothing to configure, and we did not earlier configure MPTCP. Nothing to do. */
            NM_SET_OUT(out_reapply, FALSE);
            return FALSE;
        }

        self->priv.p->mptcp_set_x[IS_IPv4] = FALSE;
        reapply                            = TRUE;
    } else {
        const NMPlatformIPXAddress *addr;
        NMDedupMultiIter            iter;
        const guint32               FLAGS =
            (NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_SIGNAL) ? MPTCP_PM_ADDR_FLAG_SIGNAL : 0)
            | (NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_SUBFLOW) ? MPTCP_PM_ADDR_FLAG_SUBFLOW : 0)
            | (NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_BACKUP) ? MPTCP_PM_ADDR_FLAG_BACKUP : 0)
            | (NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_FULLMESH) ? MPTCP_PM_ADDR_FLAG_FULLMESH
                                                                  : 0);
        NMPlatformMptcpAddr a = {
            .ifindex     = self->priv.ifindex,
            .id          = 0,
            .flags       = FLAGS,
            .addr_family = addr_family,
            .port        = 0,
        };
        gboolean any_tracked = FALSE;

        self->priv.p->mptcp_set_x[IS_IPv4] = TRUE;

        if (self->priv.p->combined_l3cd_commited) {
            gint32 addr_prio;

            addr_prio = 100;

            nm_l3_config_data_iter_ip_address_for_each (&iter,
                                                        self->priv.p->combined_l3cd_commited,
                                                        addr_family,
                                                        (const NMPlatformIPAddress **) &addr) {
                /* We want to evaluate the  with-{loopback,link_local}-{4,6} flags based on the actual
                 * ifa_scope that the address will have once we configure it.
                 * "addr" is an address we want to configure, we expect that it will
                 * later have the scope nm_platform_ip_address_get_scope() based on
                 * the address. */
                switch (nm_platform_ip_address_get_scope(addr_family, addr->ax.address_ptr)) {
                case RT_SCOPE_HOST:
                    goto skip_addr;
                case RT_SCOPE_LINK:
                    goto skip_addr;
                default:
                    if (IS_IPv4) {
                        /* We take all addresses, including rfc1918 private addresses
                         * (nm_ip_addr_is_site_local()). */
                    } else {
                        if (nm_ip6_addr_is_ula(&addr->a6.address)) {
                            /* Exclude unique local IPv6 addresses fc00::/7. */
                            goto skip_addr;
                        } else {
                            /* We take all other addresses, including deprecated IN6_IS_ADDR_SITELOCAL()
                             * (fec0::/10). */
                        }
                    }
                    break;
                }

                a.addr = nm_ip_addr_init(addr_family, addr->ax.address_ptr);

                /* We track the address with different priorities, that depends
                 * on the order in which they are listed here. NMPGlobalTracker
                 * will sort all tracked addresses by priority. That means, if we
                 * have multiple interfaces then we will prefer the first address
                 * of those interfaces, then the second, etc.
                 *
                 * That is relevant, because the overall number of addresses we
                 * can configure in kernel is strongly limited (MPTCP_PM_ADDR_MAX). */
                if (addr_prio > 10)
                    addr_prio--;

                if (nmp_global_tracker_track(self->priv.global_tracker,
                                             NMP_OBJECT_TYPE_MPTCP_ADDR,
                                             &a,
                                             addr_prio,
                                             _MPTCP_TAG(self, IS_IPv4),
                                             NULL))
                    changed = TRUE;

                any_tracked = TRUE;

skip_addr:
                (void) 0;
            }
        }

        if (!any_tracked) {
            /* We need to make it known that this ifindex is used. Track a dummy object. */
            if (nmp_global_tracker_track(
                    self->priv.global_tracker,
                    NMP_OBJECT_TYPE_MPTCP_ADDR,
                    nmp_global_tracker_mptcp_addr_init_for_ifindex(&a, self->priv.ifindex),
                    1,
                    _MPTCP_TAG(self, IS_IPv4),
                    NULL))
                changed = TRUE;
        }
    }

    if (_global_tracker_mptcp_untrack(self, addr_family))
        changed = TRUE;

    NM_SET_OUT(out_reapply, reapply);
    return changed || reapply;
}

static void
_l3_commit_mptcp(NML3Cfg *self, NML3CfgCommitType commit_type)
{
    gboolean changed   = FALSE;
    gboolean reapply   = FALSE;
    gboolean i_reapply = FALSE;

    if (_l3_commit_mptcp_af(self, commit_type, AF_INET, &i_reapply))
        changed = TRUE;
    reapply |= i_reapply;
    if (_l3_commit_mptcp_af(self, commit_type, AF_INET6, &i_reapply))
        changed = TRUE;
    reapply |= i_reapply;

    nm_assert(commit_type < NM_L3_CFG_COMMIT_TYPE_REAPPLY || reapply);

    if (changed)
        nmp_global_tracker_sync_mptcp_addrs(self->priv.global_tracker, reapply);
    else
        nm_assert(!reapply);

    _rp_filter_update(self, reapply);
}

static void
_l3_commit_one(NML3Cfg              *self,
               int                   addr_family,
               NML3CfgCommitType     commit_type,
               gboolean              changed_combined_l3cd,
               const NML3ConfigData *l3cd_old)
{
    const int                    IS_IPv4         = NM_IS_IPv4(addr_family);
    gs_unref_ptrarray GPtrArray *addresses       = NULL;
    gs_unref_ptrarray GPtrArray *routes          = NULL;
    gs_unref_ptrarray GPtrArray *routes_nodev    = NULL;
    gs_unref_ptrarray GPtrArray *addresses_prune = NULL;
    gs_unref_ptrarray GPtrArray *routes_prune    = NULL;
    gs_unref_ptrarray GPtrArray *routes_failed   = NULL;
    NMIPRouteTableSyncMode       route_table_sync;
    char                         sbuf_commit_type[50];
    guint                        i;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_NONE,
                        NM_L3_CFG_COMMIT_TYPE_REAPPLY,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE));
    nm_assert_addr_family(addr_family);

    _LOGT("committing IPv%c configuration (%s)",
          nm_utils_addr_family_to_char(addr_family),
          _l3_cfg_commit_type_to_string(commit_type, sbuf_commit_type, sizeof(sbuf_commit_type)));

    addresses = _commit_collect_addresses(self, addr_family, commit_type);

    _commit_collect_routes(self,
                           addr_family,
                           commit_type,
                           nm_g_ptr_array_len(addresses) > 0,
                           &routes,
                           &routes_nodev);

    route_table_sync =
        self->priv.p->combined_l3cd_commited
            ? nm_l3_config_data_get_route_table_sync(self->priv.p->combined_l3cd_commited,
                                                     addr_family)
            : NM_IP_ROUTE_TABLE_SYNC_MODE_NONE;

    if (!IS_IPv4) {
        _l3_commit_ip6_privacy(self, commit_type);
        _l3_commit_ndisc_params(self, commit_type);
        _l3_commit_ip6_token(self, commit_type);
    }

    if (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_NONE)
        route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN;

    if (commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY) {
        gs_unref_array GArray *ipv6_temp_addrs_keep = NULL;

        nm_platform_process_events(self->priv.platform);

        if (!IS_IPv4 && addresses) {
            for (i = 0; i < addresses->len; i++) {
                const NMPlatformIP6Address *addr = NMP_OBJECT_CAST_IP6_ADDRESS(addresses->pdata[i]);

                if (!NM_FLAGS_HAS(addr->n_ifa_flags, IFA_F_MANAGETEMPADDR))
                    continue;

                nm_assert(addr->plen == 64);

                /* Construct a list of all IPv6 prefixes for which we (still) set
                 * IFA_F_MANAGETEMPADDR (that is, for which we will have temporary addresses).
                 * Those should not be pruned during reapply. */
                if (!ipv6_temp_addrs_keep)
                    ipv6_temp_addrs_keep = g_array_new(FALSE, FALSE, sizeof(struct in6_addr));
                g_array_append_val(ipv6_temp_addrs_keep, addr->address);
            }
        }

        if (c_list_is_empty(&self->priv.p->blocked_lst_head_x[IS_IPv4])) {
            addresses_prune =
                nm_platform_ip_address_get_prune_list(self->priv.platform,
                                                      addr_family,
                                                      self->priv.ifindex,
                                                      nm_g_array_data(ipv6_temp_addrs_keep),
                                                      nm_g_array_len(ipv6_temp_addrs_keep));

            routes_prune = nm_platform_ip_route_get_prune_list(self->priv.platform,
                                                               addr_family,
                                                               self->priv.ifindex,
                                                               route_table_sync);
            _obj_state_zombie_lst_prune_all(self, addr_family);
        }
    } else {
        if (c_list_is_empty(&self->priv.p->blocked_lst_head_x[IS_IPv4])) {
            _obj_state_zombie_lst_get_prune_lists(self,
                                                  addr_family,
                                                  &addresses_prune,
                                                  &routes_prune);
        }
    }

    if (self->priv.ifindex == NM_LOOPBACK_IFINDEX) {
        if (!addresses) {
            NMPlatformIPXAddress ax;

            addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
            if (IS_IPv4) {
                g_ptr_array_add(
                    addresses,
                    nmp_object_new(NMP_OBJECT_TYPE_IP4_ADDRESS,
                                   nm_platform_ip4_address_init_loopback_addr1(&ax.a4)));
            } else {
                g_ptr_array_add(addresses,
                                nmp_object_new(NMP_OBJECT_TYPE_IP6_ADDRESS,
                                               nm_platform_ip6_address_init_loopback(&ax.a6)));
            }
        }
    }

    _routes_watch_ip_addrs(self, addr_family, addresses, routes);

    /* FIXME(l3cfg): need to honor and set nm_l3_config_data_get_ndisc_*(). */
    /* FIXME(l3cfg): need to honor and set nm_l3_config_data_get_mtu(). */

    self->priv.p->commit_reentrant_count_ip_address_sync_x[IS_IPv4]++;

    nm_platform_ip_address_sync(self->priv.platform,
                                addr_family,
                                self->priv.ifindex,
                                addresses,
                                addresses_prune,
                                self->priv.ifindex == NM_LOOPBACK_IFINDEX
                                    ? NMP_IP_ADDRESS_SYNC_FLAGS_NONE
                                    : NMP_IP_ADDRESS_SYNC_FLAGS_WITH_NOPREFIXROUTE);

    self->priv.p->commit_reentrant_count_ip_address_sync_x[IS_IPv4]--;

    _nodev_routes_sync(self, addr_family, commit_type, routes_nodev);

    nm_platform_ip_route_sync(self->priv.platform,
                              addr_family,
                              self->priv.ifindex,
                              routes,
                              routes_prune,
                              &routes_failed);

    _failedobj_handle_routes(self, addr_family, routes_failed);
}

static void
_l3_commit(NML3Cfg *self, NML3CfgCommitType commit_type, gboolean is_idle)
{
    _nm_unused gs_unref_object NML3Cfg      *self_keep_alive = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old        = NULL;
    NML3CfgCommitType                        commit_type_auto;
    gboolean                                 commit_type_from_auto = FALSE;
    gboolean                                 is_sticky_update      = FALSE;
    char                                     sbuf_ct[30];
    gboolean                                 changed_combined_l3cd;

    g_return_if_fail(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_NONE,
                        NM_L3_CFG_COMMIT_TYPE_AUTO,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE,
                        NM_L3_CFG_COMMIT_TYPE_REAPPLY));
    nm_assert(self->priv.p->commit_reentrant_count == 0);

    /* The actual commit type is always the maximum of what is requested
     * and what is registered via nm_l3cfg_commit_type_register(), combined
     * with the ad-hoc requested @commit_type argument. */
    commit_type_auto = nm_l3cfg_commit_type_get(self);
    if (commit_type == NM_L3_CFG_COMMIT_TYPE_AUTO || commit_type_auto > commit_type) {
        commit_type_from_auto = TRUE;
        commit_type           = commit_type_auto;
    }

    /* Levels UPDATE and higher are sticky. That means, when do perform such a commit
     * type, then the next one will at least be of level "UPDATE". The idea is
     * that if the current commit adds an address, then the following needs
     * to do at least "UPDATE" level to remove it again. Even if in the meantime
     * the "UPDATE" is unregistered (nm_l3cfg_commit_type_unregister()). */
    if (commit_type < NM_L3_CFG_COMMIT_TYPE_UPDATE) {
        if (self->priv.p->commit_type_update_sticky) {
            self->priv.p->commit_type_update_sticky = FALSE;
            commit_type                             = NM_L3_CFG_COMMIT_TYPE_UPDATE;
            is_sticky_update                        = TRUE;
        }
    } else
        self->priv.p->commit_type_update_sticky = TRUE;

    _LOGT("commit %s%s%s%s",
          _l3_cfg_commit_type_to_string(commit_type, sbuf_ct, sizeof(sbuf_ct)),
          commit_type_from_auto ? " (auto)" : "",
          is_sticky_update ? " (sticky-update)" : "",
          is_idle ? " (idle handler)" : "");

    nm_assert(commit_type > NM_L3_CFG_COMMIT_TYPE_AUTO);

    if (nm_clear_g_source_inst(&self->priv.p->commit_on_idle_source))
        self_keep_alive = self;
    self->priv.p->commit_on_idle_type = NM_L3_CFG_COMMIT_TYPE_AUTO;

    if (commit_type <= NM_L3_CFG_COMMIT_TYPE_NONE)
        return;

    self->priv.p->commit_reentrant_count++;

    _l3cfg_update_combined_config(self,
                                  TRUE,
                                  commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY,
                                  &l3cd_old,
                                  &changed_combined_l3cd);

    _nm_l3cfg_emit_signal_notify_simple(self, NM_L3_CONFIG_NOTIFY_TYPE_PRE_COMMIT);

    _l3_commit_one(self, AF_INET, commit_type, changed_combined_l3cd, l3cd_old);
    _l3_commit_one(self, AF_INET6, commit_type, changed_combined_l3cd, l3cd_old);

    _failedobj_reschedule(self, 0);

    _l3_commit_mptcp(self, commit_type);

    _l3_acd_data_process_changes(self);

    nm_assert(self->priv.p->commit_reentrant_count == 1);
    self->priv.p->commit_reentrant_count--;

    _nm_l3cfg_emit_signal_notify_simple(self, NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT);
}

NML3CfgBlockHandle *
nm_l3cfg_block_obj_pruning(NML3Cfg *self, int addr_family)
{
    const int           IS_IPv4 = NM_IS_IPv4(addr_family);
    NML3CfgBlockHandle *handle;

    if (!self)
        return NULL;

    nm_assert(NM_IS_L3CFG(self));

    handle          = g_slice_new(NML3CfgBlockHandle);
    handle->self    = g_object_ref(self);
    handle->is_ipv4 = IS_IPv4;
    c_list_link_tail(&self->priv.p->blocked_lst_head_x[IS_IPv4], &handle->lst);

    _LOGT("obj-pruning for IPv%c: blocked (%zu)",
          nm_utils_addr_family_to_char(addr_family),
          c_list_length(&self->priv.p->blocked_lst_head_x[IS_IPv4]));

    return handle;
}

void
nm_l3cfg_unblock_obj_pruning(NML3CfgBlockHandle *handle)
{
    gs_unref_object NML3Cfg *self    = handle->self;
    const int                IS_IPv4 = handle->is_ipv4;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(c_list_is_linked(&handle->lst));
    nm_assert(c_list_contains(&self->priv.p->blocked_lst_head_x[IS_IPv4], &handle->lst));

    c_list_unlink_stale(&handle->lst);

    _LOGT("obj-pruning for IPv%c: unblocked (%zu)",
          IS_IPv4 ? '4' : '6',
          c_list_length(&self->priv.p->blocked_lst_head_x[IS_IPv4]));

    nm_g_slice_free(handle);
}

/* See DOC(l3cfg:commit-type) */
void
nm_l3cfg_commit(NML3Cfg *self, NML3CfgCommitType commit_type)
{
    _l3_commit(self, commit_type, FALSE);
}

/*****************************************************************************/

NML3CfgCommitType
nm_l3cfg_commit_type_get(NML3Cfg *self)
{
    NML3CfgCommitTypeHandle *handle;

    nm_assert(NM_IS_L3CFG(self));

    handle = c_list_first_entry(&self->priv.p->commit_type_lst_head,
                                NML3CfgCommitTypeHandle,
                                commit_type_lst);
    return handle ? handle->commit_type : NM_L3_CFG_COMMIT_TYPE_NONE;
}

/**
 * nm_l3cfg_commit_type_register:
 * @self: the #NML3Cfg
 * @commit_type: the commit type to register
 * @existing_handle: instead of being a new registration, update an existing handle.
 *   This may be %NULL, which is like having no previous registration.
 * @source: the source of the commit type, for logging.
 *
 * NML3Cfg needs to know whether it is in charge of an interface (and how "much").
 * By default, it is not in charge, but various users can register themself with
 * a certain @commit_type. The "higher" commit type is the used one when calling
 * nm_l3cfg_commit() with %NM_L3_CFG_COMMIT_TYPE_AUTO.
 *
 * Returns: a handle tracking the registration, or %NULL if @commit_type
 *   is %NM_L3_CFG_COMMIT_TYPE_NONE.
 */
NML3CfgCommitTypeHandle *
nm_l3cfg_commit_type_register(NML3Cfg                 *self,
                              NML3CfgCommitType        commit_type,
                              NML3CfgCommitTypeHandle *existing_handle,
                              const char              *source)
{
    NML3CfgCommitTypeHandle *handle;
    NML3CfgCommitTypeHandle *h;
    gboolean                 linked;
    NML3CfgCommitTypeHandle *ret = NULL;
    char                     buf[64];

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type, NM_L3_CFG_COMMIT_TYPE_NONE, NM_L3_CFG_COMMIT_TYPE_UPDATE));

    /* It would be easy (and maybe convenient) to allow that @existing_handle
     * can currently be registered on another NML3Cfg instance. But then we couldn't
     * do this assertion, and it seems error prone to allow arbitrary handles where
     * we cannot check whether it is valid. So if @existing_handle is given, it
     * must be tracked by @self (and only by @self). */
    nm_assert(
        !existing_handle
        || c_list_contains(&self->priv.p->commit_type_lst_head, &existing_handle->commit_type_lst));

    if (existing_handle) {
        if (commit_type == NM_L3_CFG_COMMIT_TYPE_NONE) {
            nm_l3cfg_commit_type_unregister(self, existing_handle);
            goto out;
        }
        if (existing_handle->commit_type == commit_type) {
            ret = existing_handle;
            goto out;
        }
        c_list_unlink_stale(&existing_handle->commit_type_lst);
        handle = existing_handle;
    } else {
        if (commit_type == NM_L3_CFG_COMMIT_TYPE_NONE)
            goto out;
        handle = g_slice_new(NML3CfgCommitTypeHandle);
        if (c_list_is_empty(&self->priv.p->commit_type_lst_head))
            g_object_ref(self);
    }

    handle->commit_type = commit_type;

    linked = FALSE;
    c_list_for_each_entry (h, &self->priv.p->commit_type_lst_head, commit_type_lst) {
        if (handle->commit_type >= h->commit_type) {
            c_list_link_before(&h->commit_type_lst, &handle->commit_type_lst);
            linked = TRUE;
            break;
        }
    }
    if (!linked)
        c_list_link_tail(&self->priv.p->commit_type_lst_head, &handle->commit_type_lst);

    ret = handle;

    nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);

out:
    _LOGT("commit type register (type \"%s\", source \"%s\", existing " NM_HASH_OBFUSCATE_PTR_FMT
          ") -> " NM_HASH_OBFUSCATE_PTR_FMT "",
          _l3_cfg_commit_type_to_string(commit_type, buf, sizeof(buf)),
          source,
          NM_HASH_OBFUSCATE_PTR(existing_handle),
          NM_HASH_OBFUSCATE_PTR(ret));
    return ret;
}

void
nm_l3cfg_commit_type_unregister(NML3Cfg *self, NML3CfgCommitTypeHandle *handle)
{
    nm_assert(NM_IS_L3CFG(self));

    if (!handle)
        return;

    nm_assert(c_list_contains(&self->priv.p->commit_type_lst_head, &handle->commit_type_lst));

    _LOGT("commit type unregister " NM_HASH_OBFUSCATE_PTR_FMT "", NM_HASH_OBFUSCATE_PTR(handle));

    nm_l3cfg_commit_on_idle_schedule(self, NM_L3_CFG_COMMIT_TYPE_AUTO);

    c_list_unlink_stale(&handle->commit_type_lst);
    if (c_list_is_empty(&self->priv.p->commit_type_lst_head))
        g_object_unref(self);
    nm_g_slice_free(handle);
}

void
nm_l3cfg_commit_type_reset_update(NML3Cfg *self)
{
    NML3CfgCommitTypeHandle *h;

    c_list_for_each_entry (h, &self->priv.p->commit_type_lst_head, commit_type_lst) {
        if (h->commit_type >= NM_L3_CFG_COMMIT_TYPE_UPDATE) {
            return;
        }
    }

    self->priv.p->commit_type_update_sticky = FALSE;
}

/*****************************************************************************/

const NML3ConfigData *
nm_l3cfg_get_combined_l3cd(NML3Cfg *self, gboolean get_commited)
{
    nm_assert(NM_IS_L3CFG(self));

    if (get_commited)
        return self->priv.p->combined_l3cd_commited;

    _l3cfg_update_combined_config(self, FALSE, FALSE, NULL, NULL);
    return self->priv.p->combined_l3cd_merged;
}

const NMPObject *
nm_l3cfg_get_best_default_route(NML3Cfg *self, int addr_family, gboolean get_commited)
{
    const NML3ConfigData *l3cd;

    l3cd = nm_l3cfg_get_combined_l3cd(self, get_commited);
    if (!l3cd)
        return NULL;

    return nm_l3_config_data_get_best_default_route(l3cd, addr_family);
}

/*****************************************************************************/

gboolean
nm_l3cfg_has_commited_ip6_addresses_pending_dad(NML3Cfg *self)
{
    const NML3ConfigData *l3cd;
    const NMPObject      *plat_obj;
    NMPLookup             plat_lookup;
    NMDedupMultiIter      iter;

    nm_assert(NM_IS_L3CFG(self));

    l3cd = nm_l3cfg_get_combined_l3cd(self, TRUE);
    if (!l3cd)
        return FALSE;

    /* we iterate over all addresses in platform, and check whether the tentative
     * addresses are tracked by our l3cd. Not the other way around, because we assume
     * that there are few addresses in platform that are still tentative, so
     * we only need to lookup few platform addresses in l3cd.
     *
     * Of course, all lookups are O(1) anyway, so in any case the operation is
     * O(n) (once "n" being the addresses in platform, and once in l3cd). */

    nmp_lookup_init_object_by_ifindex(&plat_lookup,
                                      NMP_OBJECT_TYPE_IP6_ADDRESS,
                                      self->priv.ifindex);

    nm_platform_iter_obj_for_each (&iter, self->priv.platform, &plat_lookup, &plat_obj) {
        const NMPlatformIP6Address *plat_addr = NMP_OBJECT_CAST_IP6_ADDRESS(plat_obj);
        const NMDedupMultiEntry    *l3cd_entry;

        if (!NM_FLAGS_HAS(plat_addr->n_ifa_flags, IFA_F_TENTATIVE)
            || NM_FLAGS_ANY(plat_addr->n_ifa_flags, IFA_F_DADFAILED | IFA_F_OPTIMISTIC))
            continue;

        l3cd_entry = nm_l3_config_data_lookup_obj(l3cd, plat_obj);

        nm_assert(NMP_OBJECT_CAST_IP6_ADDRESS(nm_dedup_multi_entry_get_obj(l3cd_entry))
                  == nm_l3_config_data_lookup_address_6(l3cd, &plat_addr->address));

        if (l3cd_entry)
            return TRUE;
    }

    return FALSE;
}

/*****************************************************************************/

NML3IPv4LL *
nm_l3cfg_get_ipv4ll(NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), NULL);

    return self->priv.p->ipv4ll;
}

NML3IPv4LL *
nm_l3cfg_access_ipv4ll(NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), NULL);

    if (self->priv.p->ipv4ll)
        return nm_l3_ipv4ll_ref(self->priv.p->ipv4ll);

    /* We return the reference. But the NML3IPv4LL instance
     * will call _nm_l3cfg_unregister_ipv4ll() when it gets
     * destroyed.
     *
     * We don't have weak references, but NML3Cfg and NML3IPv4LL
     * cooperate to handle this reference. */
    self->priv.p->ipv4ll = nm_l3_ipv4ll_new(self);
    return self->priv.p->ipv4ll;
}

void
_nm_l3cfg_unregister_ipv4ll(NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    /* we don't own the reference to "self->priv.p->ipv4ll", but
     * when that instance gets destroyed, we get called back to
     * forget about it. Basically, it's like a weak pointer. */

    nm_assert(self->priv.p->ipv4ll);
    self->priv.p->ipv4ll = NULL;
}

/*****************************************************************************/

gboolean
nm_l3cfg_is_ready(NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), FALSE);

    if (self->priv.p->changed_configs_configs)
        return FALSE;
    if (self->priv.p->changed_configs_acd_state)
        return FALSE;
    if (self->priv.p->commit_on_idle_source)
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NML3Cfg *self = NM_L3CFG(object);

    switch (prop_id) {
    case PROP_NETNS:
        /* construct-only */
        self->priv.netns = g_object_ref(g_value_get_pointer(value));
        nm_assert(NM_IS_NETNS(self->priv.netns));
        break;
    case PROP_IFINDEX:
        /* construct-only */
        self->priv.ifindex = g_value_get_int(value);
        nm_assert(self->priv.ifindex > 0);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_l3cfg_init(NML3Cfg *self)
{
    self->priv.p = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_L3CFG, NML3CfgPrivate);

    c_list_init(&self->priv.p->acd_lst_head);
    c_list_init(&self->priv.p->acd_event_notify_lst_head);
    c_list_init(&self->priv.p->commit_type_lst_head);
    c_list_init(&self->priv.p->obj_state_lst_head);
    c_list_init(&self->priv.p->obj_state_zombie_lst_head);
    c_list_init(&self->priv.p->blocked_lst_head_4);
    c_list_init(&self->priv.p->blocked_lst_head_6);

    c_list_init(&self->internal_netns.signal_pending_lst);
    c_list_init(&self->internal_netns.ecmp_track_ifindex_lst_head);

    self->priv.p->obj_state_hash = g_hash_table_new_full(nmp_object_indirect_id_hash,
                                                         nmp_object_indirect_id_equal,
                                                         _obj_state_data_free,
                                                         NULL);

    nm_prioq_init(&self->priv.p->failedobj_prioq, _failedobj_prioq_cmp);
}

static void
constructed(GObject *object)
{
    NML3Cfg *self = NM_L3CFG(object);

    nm_assert(NM_IS_NETNS(self->priv.netns));
    nm_assert(self->priv.ifindex > 0);

    self->priv.platform = g_object_ref(nm_netns_get_platform(self->priv.netns));
    nm_assert(NM_IS_PLATFORM(self->priv.platform));

    self->priv.global_tracker =
        nmp_global_tracker_ref(nm_netns_get_global_tracker(self->priv.netns));

    _LOGT("created (netns=" NM_HASH_OBFUSCATE_PTR_FMT ")", NM_HASH_OBFUSCATE_PTR(self->priv.netns));

    G_OBJECT_CLASS(nm_l3cfg_parent_class)->constructed(object);

    _load_link(self, TRUE);
}

NML3Cfg *
nm_l3cfg_new(NMNetns *netns, int ifindex)
{
    nm_assert(NM_IS_NETNS(netns));
    nm_assert(ifindex > 0);

    return g_object_new(NM_TYPE_L3CFG, NM_L3CFG_NETNS, netns, NM_L3CFG_IFINDEX, ifindex, NULL);
}

static void
finalize(GObject *object)
{
    NML3Cfg *self = NM_L3CFG(object);
    gboolean changed;

    if (self->priv.netns) {
        nm_netns_watcher_remove_all(self->priv.netns,
                                    _NETNS_WATCHER_IP_ADDR_TAG(self, AF_INET),
                                    TRUE);
        nm_netns_watcher_remove_all(self->priv.netns,
                                    _NETNS_WATCHER_IP_ADDR_TAG(self, AF_INET6),
                                    TRUE);
    }

    nm_prioq_destroy(&self->priv.p->failedobj_prioq);
    nm_clear_g_source_inst(&self->priv.p->failedobj_timeout_source);

    nm_assert(c_list_is_empty(&self->internal_netns.signal_pending_lst));
    nm_assert(c_list_is_empty(&self->internal_netns.ecmp_track_ifindex_lst_head));

    nm_assert(!self->priv.p->ipconfig_4);
    nm_assert(!self->priv.p->ipconfig_6);

    nm_assert(!self->priv.p->l3_config_datas);
    nm_assert(!self->priv.p->ipv4ll);

    nm_assert(c_list_is_empty(&self->priv.p->commit_type_lst_head));
    nm_assert(c_list_is_empty(&self->priv.p->blocked_lst_head_4));
    nm_assert(c_list_is_empty(&self->priv.p->blocked_lst_head_6));

    nm_assert(!self->priv.p->commit_on_idle_source);

    _l3_acd_data_prune(self, TRUE);

    nm_assert(c_list_is_empty(&self->priv.p->acd_lst_head));
    nm_assert(c_list_is_empty(&self->priv.p->acd_event_notify_lst_head));
    nm_assert(nm_g_hash_table_size(self->priv.p->acd_lst_hash) == 0);

    nm_clear_pointer(&self->priv.p->acd_lst_hash, g_hash_table_unref);
    nm_clear_pointer(&self->priv.p->nacd, n_acd_unref);
    nm_clear_g_source_inst(&self->priv.p->nacd_source);
    nm_clear_g_source_inst(&self->priv.p->nacd_instance_ensure_retry);
    nm_clear_g_source_inst(&self->priv.p->nacd_event_down_source);

    nm_clear_pointer(&self->priv.p->obj_state_hash, g_hash_table_destroy);
    nm_assert(c_list_is_empty(&self->priv.p->obj_state_lst_head));
    nm_assert(c_list_is_empty(&self->priv.p->obj_state_zombie_lst_head));

    if (_nodev_routes_untrack(self, AF_INET))
        nmp_global_tracker_sync(self->priv.global_tracker, NMP_OBJECT_TYPE_IP4_ROUTE, FALSE);
    if (_nodev_routes_untrack(self, AF_INET6))
        nmp_global_tracker_sync(self->priv.global_tracker, NMP_OBJECT_TYPE_IP6_ROUTE, FALSE);

    changed = FALSE;
    if (_global_tracker_mptcp_untrack(self, AF_INET))
        changed = TRUE;
    if (_global_tracker_mptcp_untrack(self, AF_INET6))
        changed = TRUE;
    if (changed)
        nmp_global_tracker_sync_mptcp_addrs(self->priv.global_tracker, FALSE);

    g_clear_object(&self->priv.netns);
    g_clear_object(&self->priv.platform);
    nm_clear_pointer(&self->priv.global_tracker, nmp_global_tracker_unref);

    nm_clear_l3cd(&self->priv.p->combined_l3cd_merged);
    nm_clear_l3cd(&self->priv.p->combined_l3cd_commited);

    nm_clear_pointer(&self->priv.plobj, nmp_object_unref);
    nm_clear_pointer(&self->priv.plobj_next, nmp_object_unref);

    nm_clear_pointer(&self->priv.p->acd_ipv4_addresses_on_link, g_hash_table_unref);

    _LOGT("finalized");

    G_OBJECT_CLASS(nm_l3cfg_parent_class)->finalize(object);
}

static void
nm_l3cfg_class_init(NML3CfgClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    g_type_class_add_private(klass, sizeof(NML3CfgPrivate));

    object_class->set_property = set_property;
    object_class->constructed  = constructed;
    object_class->finalize     = finalize;

    obj_properties[PROP_NETNS] =
        g_param_spec_pointer(NM_L3CFG_NETNS,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_IFINDEX] =
        g_param_spec_int(NM_L3CFG_IFINDEX,
                         "",
                         "",
                         0,
                         G_MAXINT,
                         0,
                         G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[SIGNAL_NOTIFY] = g_signal_new(NM_L3CFG_SIGNAL_NOTIFY,
                                          G_OBJECT_CLASS_TYPE(object_class),
                                          G_SIGNAL_RUN_FIRST,
                                          0,
                                          NULL,
                                          NULL,
                                          g_cclosure_marshal_VOID__POINTER,
                                          G_TYPE_NONE,
                                          1,
                                          G_TYPE_POINTER /* (const NML3ConfigNotifyData *) */);
}
