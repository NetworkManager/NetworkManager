/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-l3cfg.h"

#include <net/if.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "nm-netns.h"
#include "n-acd/src/n-acd.h"
#include "nm-l3-ipv4ll.h"

/*****************************************************************************/

G_STATIC_ASSERT(NM_ACD_TIMEOUT_RFC5227_MSEC == N_ACD_TIMEOUT_RFC5227);

#define ACD_SUPPORTED_ETH_ALEN                  ETH_ALEN
#define ACD_ENSURE_RATELIMIT_MSEC               ((guint32) 4000u)
#define ACD_WAIT_PROBING_EXTRA_TIME_MSEC        ((guint32)(1000u + ACD_ENSURE_RATELIMIT_MSEC))
#define ACD_WAIT_PROBING_EXTRA_TIME2_MSEC       ((guint32) 1000u)
#define ACD_MAX_TIMEOUT_MSEC                    ((guint32) 30000u)
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

    NMEtherAddr last_conflict_addr;

    NML3AcdDefendType acd_defend_type_desired : 3;
    NML3AcdDefendType acd_defend_type_current : 3;
    bool              acd_defend_type_is_active : 1;

    bool track_infos_changed : 1;
} AcdData;

G_STATIC_ASSERT(G_STRUCT_OFFSET(AcdData, info.addr) == 0);

struct _NML3CfgCommitTypeHandle {
    CList             commit_type_lst;
    NML3CfgCommitType commit_type;
};

typedef struct {
    const NML3ConfigData *l3cd;
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
    gconstpointer     tag_confdata;
    guint64           pseudo_timestamp_confdata;
    int               priority_confdata;
    guint32           acd_timeout_msec_confdata;
    NML3AcdDefendType acd_defend_type_confdata : 3;
    bool              dirty_confdata : 1;
} L3ConfigData;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NML3Cfg, PROP_NETNS, PROP_IFINDEX, );

enum {
    SIGNAL_NOTIFY,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct _NML3CfgPrivate {
    GArray *property_emit_list;
    GArray *l3_config_datas;

    NML3IPv4LL *ipv4ll;

    const NML3ConfigData *combined_l3cd_merged;

    const NML3ConfigData *combined_l3cd_commited;

    CList commit_type_lst_head;

    GHashTable *routes_temporary_not_available_hash;

    GHashTable *externally_removed_objs_hash;

    GHashTable *acd_ipv4_addresses_on_link;

    GHashTable *acd_lst_hash;
    CList       acd_lst_head;

    CList acd_event_notify_lst_head;

    NAcd *   nacd;
    GSource *nacd_source;

    GSource *nacd_event_down_source;
    gint64   nacd_event_down_ratelimited_until_msec;

    /* This is for rate-limiting the creation of nacd instance. */
    GSource *nacd_instance_ensure_retry;

    GSource *commit_on_idle_source;

    guint64 pseudo_timestamp_counter;

    union {
        struct {
            guint externally_removed_objs_cnt_addresses_6;
            guint externally_removed_objs_cnt_addresses_4;
        };
        guint externally_removed_objs_cnt_addresses_x[2];
    };

    union {
        struct {
            guint externally_removed_objs_cnt_routes_6;
            guint externally_removed_objs_cnt_routes_4;
        };
        guint externally_removed_objs_cnt_routes_x[2];
    };

    union {
        struct {
            GPtrArray *last_addresses_6;
            GPtrArray *last_addresses_4;
        };
        GPtrArray *last_addresses_x[2];
    };

    union {
        struct {
            GPtrArray *last_routes_6;
            GPtrArray *last_routes_4;
        };
        GPtrArray *last_routes_x[2];
    };

    guint routes_temporary_not_available_id;

    gint8 commit_reentrant_count;

    bool commit_type_update_sticky : 1;

    bool acd_is_pending : 1;

    bool nacd_acd_not_supported : 1;
    bool acd_ipv4_addresses_on_link_has : 1;

    bool changed_configs_configs : 1;
    bool changed_configs_acd_state : 1;
} NML3CfgPrivate;

struct _NML3CfgClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NML3Cfg, nm_l3cfg, G_TYPE_OBJECT)

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

#define _LOGT_acd(acd_data, ...)                                      \
    G_STMT_START                                                      \
    {                                                                 \
        char _sbuf_acd[NM_UTILS_INET_ADDRSTRLEN];                     \
                                                                      \
        _LOGT("acd[%s, %s]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),     \
              _nm_utils_inet4_ntop((acd_data)->info.addr, _sbuf_acd), \
              _l3_acd_addr_state_to_string((acd_data)->info.state)    \
                  _NM_UTILS_MACRO_REST(__VA_ARGS__));                 \
    }                                                                 \
    G_STMT_END

/*****************************************************************************/

static void _l3_commit(NML3Cfg *self, NML3CfgCommitType commit_type, gboolean is_idle);

static void _property_emit_notify(NML3Cfg *self, NML3CfgPropertyEmitType emit_type);

static void _nm_l3cfg_emit_signal_notify_acd_event_all(NML3Cfg *self);

static gboolean _acd_has_valid_link(const NMPObject *obj,
                                    const guint8 **  out_addr_bin,
                                    gboolean *       out_acd_not_supported);

static void
_l3_acd_nacd_instance_reset(NML3Cfg *self, NMTernary start_timer, gboolean acd_data_notify);

static void _l3_acd_data_state_change(NML3Cfg *          self,
                                      AcdData *          acd_data,
                                      AcdStateChangeMode mode,
                                      const NMEtherAddr *sender,
                                      gint64 *           p_now_msec);

static AcdData *_l3_acd_data_find(NML3Cfg *self, in_addr_t addr);

/*****************************************************************************/

static NM_UTILS_ENUM2STR_DEFINE(_l3_cfg_commit_type_to_string,
                                NML3CfgCommitType,
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_AUTO, "auto"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_NONE, "none"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_ASSUME, "assume"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_UPDATE, "update"),
                                NM_UTILS_ENUM2STR(NM_L3_CFG_COMMIT_TYPE_REAPPLY, "reapply"), );

static NM_UTILS_ENUM2STR_DEFINE(
    _l3_config_notify_type_to_string,
    NML3ConfigNotifyType,
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT, "acd-event"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT, "ipv4ll-event"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE, "platform-change"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE, "platform-change-on-idle"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT, "post-commit"),
    NM_UTILS_ENUM2STR(NM_L3_CONFIG_NOTIFY_TYPE_ROUTES_TEMPORARY_NOT_AVAILABLE_EXPIRED,
                      "routes-temporary-not-available-expired"),
    NM_UTILS_ENUM2STR_IGNORE(_NM_L3_CONFIG_NOTIFY_TYPE_NUM), );

static NM_UTILS_ENUM2STR_DEFINE(_l3_acd_defend_type_to_string,
                                NML3AcdDefendType,
                                NM_UTILS_ENUM2STR(NM_L3_ACD_DEFEND_TYPE_ALWAYS, "always"),
                                NM_UTILS_ENUM2STR(NM_L3_ACD_DEFEND_TYPE_NEVER, "never"),
                                NM_UTILS_ENUM2STR(NM_L3_ACD_DEFEND_TYPE_NONE, "none"),
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

/*****************************************************************************/

static const char *
_l3_config_notify_data_to_string(const NML3ConfigNotifyData *notify_data,
                                 char *                      sbuf,
                                 gsize                       sbuf_size)
{
    char      sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];
    char      sbuf100[100];
    char *    s = sbuf;
    gsize     l = sbuf_size;
    in_addr_t addr4;

    nm_assert(sbuf);
    nm_assert(sbuf_size > 0);

    _l3_config_notify_type_to_string(notify_data->notify_type, s, l);
    nm_utils_strbuf_seek_end(&s, &l);

    switch (notify_data->notify_type) {
    case NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT:
        nm_utils_strbuf_append(&s,
                               &l,
                               ", addr=%s, state=%s",
                               _nm_utils_inet4_ntop(notify_data->acd_event.info.addr, sbuf_addr),
                               _l3_acd_addr_state_to_string(notify_data->acd_event.info.state));
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE:
        nm_utils_strbuf_append(
            &s,
            &l,
            ", obj-type=%s, change=%s, obj=",
            NMP_OBJECT_GET_CLASS(notify_data->platform_change.obj)->obj_type_name,
            nm_platform_signal_change_type_to_string(notify_data->platform_change.change_type));
        nmp_object_to_string(notify_data->platform_change.obj, NMP_OBJECT_TO_STRING_PUBLIC, s, l);
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE:
        nm_utils_strbuf_append(&s,
                               &l,
                               ", obj-type-flags=0x%x",
                               notify_data->platform_change_on_idle.obj_type_flags);
        break;
    case NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT:
        nm_assert(NM_IS_L3_IPV4LL(notify_data->ipv4ll_event.ipv4ll));
        addr4 = nm_l3_ipv4ll_get_addr(notify_data->ipv4ll_event.ipv4ll);
        nm_utils_strbuf_append(
            &s,
            &l,
            ", ipv4ll=" NM_HASH_OBFUSCATE_PTR_FMT "%s%s, state=%s",
            NM_HASH_OBFUSCATE_PTR(notify_data->ipv4ll_event.ipv4ll),
            NM_PRINT_FMT_QUOTED2(addr4 != 0, ", addr=", _nm_utils_inet4_ntop(addr4, sbuf_addr), ""),
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
    char sbuf[sizeof(_nm_utils_to_string_buffer)];

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
_l3_acd_ipv4_addresses_on_link_update(NML3Cfg * self,
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
    NAcdProbe *                                        probe;
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

static guint *
_l3cfg_externally_removed_objs_counter(NML3Cfg *self, NMPObjectType obj_type)
{
    switch (obj_type) {
    case NMP_OBJECT_TYPE_IP4_ADDRESS:
        return &self->priv.p->externally_removed_objs_cnt_addresses_4;
    case NMP_OBJECT_TYPE_IP6_ADDRESS:
        return &self->priv.p->externally_removed_objs_cnt_addresses_6;
    case NMP_OBJECT_TYPE_IP4_ROUTE:
        return &self->priv.p->externally_removed_objs_cnt_routes_4;
    case NMP_OBJECT_TYPE_IP6_ROUTE:
        return &self->priv.p->externally_removed_objs_cnt_routes_6;
    default:
        return nm_assert_unreachable_val(NULL);
    }
}

static void
_l3cfg_externally_removed_objs_drop(NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    self->priv.p->externally_removed_objs_cnt_addresses_4 = 0;
    self->priv.p->externally_removed_objs_cnt_addresses_6 = 0;
    self->priv.p->externally_removed_objs_cnt_routes_4    = 0;
    self->priv.p->externally_removed_objs_cnt_routes_6    = 0;
    if (nm_g_hash_table_size(self->priv.p->externally_removed_objs_hash) > 0)
        _LOGD("externally-removed: untrack all");
    nm_clear_pointer(&self->priv.p->externally_removed_objs_hash, g_hash_table_unref);
}

static void
_l3cfg_externally_removed_objs_drop_unused(NML3Cfg *self)
{
    GHashTableIter   h_iter;
    const NMPObject *obj;
    char             sbuf[sizeof(_nm_utils_to_string_buffer)];

    nm_assert(NM_IS_L3CFG(self));

    if (!self->priv.p->externally_removed_objs_hash)
        return;

    if (!self->priv.p->combined_l3cd_commited) {
        _l3cfg_externally_removed_objs_drop(self);
        return;
    }

    g_hash_table_iter_init(&h_iter, self->priv.p->externally_removed_objs_hash);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &obj, NULL)) {
        if (!nm_l3_config_data_lookup_obj(self->priv.p->combined_l3cd_commited, obj)) {
            /* The object is no longer tracked in the configuration.
             * The externally_removed_objs_hash is to prevent adding entires that were
             * removed externally, so if we don't plan to add the entry, we no longer need to track
             * it. */
            _LOGD("externally-removed: untrack %s",
                  nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            (*(_l3cfg_externally_removed_objs_counter(self, NMP_OBJECT_GET_TYPE(obj))))--;
            g_hash_table_iter_remove(&h_iter);
        }
    }
}

static void
_l3cfg_externally_removed_objs_track(NML3Cfg *self, const NMPObject *obj, gboolean is_removed)
{
    char sbuf[1000];

    nm_assert(NM_IS_L3CFG(self));

    if (!self->priv.p->combined_l3cd_commited)
        return;

    if (!is_removed) {
        /* the object is still (or again) present. It no longer gets hidden. */
        if (self->priv.p->externally_removed_objs_hash) {
            const NMPObject *obj2;
            gpointer         x_val;

            if (g_hash_table_steal_extended(self->priv.p->externally_removed_objs_hash,
                                            obj,
                                            (gpointer *) &obj2,
                                            &x_val)) {
                (*(_l3cfg_externally_removed_objs_counter(self, NMP_OBJECT_GET_TYPE(obj2))))--;
                _LOGD("externally-removed: untrack %s",
                      nmp_object_to_string(obj2, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
                nmp_object_unref(obj2);
            }
        }
        return;
    }

    if (!nm_l3_config_data_lookup_obj(self->priv.p->combined_l3cd_commited, obj)) {
        /* we don't care about this object, so there is nothing to hide hide */
        return;
    }

    if (G_UNLIKELY(!self->priv.p->externally_removed_objs_hash)) {
        self->priv.p->externally_removed_objs_hash =
            g_hash_table_new_full((GHashFunc) nmp_object_id_hash,
                                  (GEqualFunc) nmp_object_id_equal,
                                  (GDestroyNotify) nmp_object_unref,
                                  NULL);
    }

    if (g_hash_table_add(self->priv.p->externally_removed_objs_hash,
                         (gpointer) nmp_object_ref(obj))) {
        (*(_l3cfg_externally_removed_objs_counter(self, NMP_OBJECT_GET_TYPE(obj))))++;
        _LOGD("externally-removed: track %s",
              nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
    }
}

static void
_l3cfg_externally_removed_objs_pickup(NML3Cfg *self, int addr_family)
{
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);
    NMDedupMultiIter iter;
    const NMPObject *obj;

    if (!self->priv.p->combined_l3cd_commited)
        return;

    nm_l3_config_data_iter_obj_for_each (&iter,
                                         self->priv.p->combined_l3cd_commited,
                                         &obj,
                                         NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)) {
        if (!nm_platform_lookup_entry(self->priv.platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj))
            _l3cfg_externally_removed_objs_track(self, obj, TRUE);
    }
    nm_l3_config_data_iter_obj_for_each (&iter,
                                         self->priv.p->combined_l3cd_commited,
                                         &obj,
                                         NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
        if (!nm_platform_lookup_entry(self->priv.platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj))
            _l3cfg_externally_removed_objs_track(self, obj, TRUE);
    }
}

static gboolean
_l3cfg_externally_removed_objs_filter(/* const NMDedupMultiObj * */ gconstpointer o,
                                      gpointer                                    user_data)
{
    const NMPObject *obj                          = o;
    GHashTable *     externally_removed_objs_hash = user_data;

    if (NMP_OBJECT_GET_TYPE(obj) == NMP_OBJECT_TYPE_IP4_ADDRESS
        && NMP_OBJECT_CAST_IP4_ADDRESS(obj)->ip4acd_not_ready)
        return FALSE;

    return !nm_g_hash_table_contains(externally_removed_objs_hash, obj);
}

/*****************************************************************************/

static void
_load_link(NML3Cfg *self, gboolean initial)
{
    nm_auto_nmpobj const NMPObject *obj_old = NULL;
    const NMPObject *               obj;
    const char *                    ifname;
    const char *                    ifname_old;
    gboolean                        nacd_changed;
    gboolean                        nacd_new_valid;
    gboolean                        nacd_old_valid;
    const guint8 *                  nacd_old_addr = NULL;
    const guint8 *                  nacd_new_addr = NULL;
    gboolean                        nacd_link_now_up;
    AcdData *                       acd_data;

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

    if (NM_FLAGS_ANY(obj_type_flags, nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP4_ROUTE)))
        _property_emit_notify(self, NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE);
    if (NM_FLAGS_ANY(obj_type_flags, nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP6_ROUTE)))
        _property_emit_notify(self, NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE);
}

void
_nm_l3cfg_notify_platform_change(NML3Cfg *                  self,
                                 NMPlatformSignalChangeType change_type,
                                 const NMPObject *          obj)
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
        _l3cfg_externally_removed_objs_track(self, obj, change_type == NM_PLATFORM_SIGNAL_REMOVED);
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

typedef struct {
    GObject *               target_obj;
    const GParamSpec *      target_property;
    NML3CfgPropertyEmitType emit_type;
} PropertyEmitData;

static void
_property_emit_notify(NML3Cfg *self, NML3CfgPropertyEmitType emit_type)
{
    gs_free PropertyEmitData *collected_heap = NULL;
    PropertyEmitData *        collected      = NULL;
    PropertyEmitData *        emit_data;
    guint                     num;
    guint                     i;
    guint                     j;

    if (!self->priv.p->property_emit_list)
        return;

    num       = 0;
    emit_data = &g_array_index(self->priv.p->property_emit_list, PropertyEmitData, 0);
    for (i = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
        if (emit_data->emit_type == emit_type) {
            collected = emit_data;
            num++;
        }
    }

    if (num == 0)
        return;

    if (num == 1) {
        g_object_notify_by_pspec(collected->target_obj, (GParamSpec *) collected->target_property);
        return;
    }

    if (num < 300u / sizeof(*collected))
        collected = g_alloca(sizeof(PropertyEmitData) * num);
    else {
        collected_heap = g_new(PropertyEmitData, num);
        collected      = collected_heap;
    }

    emit_data = &g_array_index(self->priv.p->property_emit_list, PropertyEmitData, 0);
    for (i = 0, j = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
        if (emit_data->emit_type == emit_type) {
            collected[j++] = *emit_data;
            g_object_ref(collected->target_obj);
        }
    }

    nm_assert(j == num);

    for (i = 0; i < num; i++) {
        g_object_notify_by_pspec(collected[i].target_obj,
                                 (GParamSpec *) collected[i].target_property);
        if (i > 0)
            g_object_unref(collected[i].target_obj);
    }
}

void
nm_l3cfg_property_emit_register(NML3Cfg *               self,
                                GObject *               target_obj,
                                const GParamSpec *      target_property,
                                NML3CfgPropertyEmitType emit_type)
{
    PropertyEmitData *emit_data;
    guint             i;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(G_IS_OBJECT(target_obj));
    nm_assert(target_property);
    nm_assert(NM_IN_SET(emit_type,
                        NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE,
                        NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE));
    nm_assert(target_property
              == nm_g_object_class_find_property_from_gtype(G_OBJECT_TYPE(target_obj),
                                                            target_property->name));

    if (!self->priv.p->property_emit_list)
        self->priv.p->property_emit_list = g_array_new(FALSE, FALSE, sizeof(PropertyEmitData));
    else {
        emit_data = &g_array_index(self->priv.p->property_emit_list, PropertyEmitData, 0);
        for (i = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
            if (emit_data->target_obj != target_obj
                || emit_data->target_property != target_property)
                continue;
            nm_assert(emit_data->emit_type == emit_type);
            emit_data->emit_type = emit_type;
            return;
        }
    }

    emit_data  = nm_g_array_append_new(self->priv.p->property_emit_list, PropertyEmitData);
    *emit_data = (PropertyEmitData){
        .target_obj      = target_obj,
        .target_property = target_property,
        .emit_type       = emit_type,
    };
}

void
nm_l3cfg_property_emit_unregister(NML3Cfg *         self,
                                  GObject *         target_obj,
                                  const GParamSpec *target_property)
{
    PropertyEmitData *emit_data;
    guint             i;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(G_IS_OBJECT(target_obj));
    nm_assert(!target_property
              || target_property
                     == nm_g_object_class_find_property_from_gtype(G_OBJECT_TYPE(target_obj),
                                                                   target_property->name));

    if (!self->priv.p->property_emit_list)
        return;

    for (i = self->priv.p->property_emit_list->len; i > 0; i--) {
        emit_data = &g_array_index(self->priv.p->property_emit_list, PropertyEmitData, i);

        if (emit_data->target_obj != target_obj)
            continue;
        if (target_property && emit_data->target_property != target_property)
            continue;

        g_array_remove_index_fast(self->priv.p->property_emit_list, i);

        if (target_property) {
            /* if a target-property is given, we don't have another entry in
             * the list. */
            return;
        }
    }
}

/*****************************************************************************/

gboolean
nm_l3cfg_get_acd_is_pending(NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), FALSE);

    return self->priv.p->acd_is_pending;
}

static gboolean
_acd_track_data_is_not_dirty(const NML3AcdAddrTrackInfo *acd_track)
{
    return acd_track && !acd_track->_priv.acd_dirty_track;
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
_acd_data_collect_tracks_data(const AcdData *    acd_data,
                              NMTernary          dirty_selector,
                              guint32 *          out_best_acd_timeout_msec,
                              NML3AcdDefendType *out_best_acd_defend_type)
{
    NML3AcdDefendType best_acd_defend_type  = NM_L3_ACD_DEFEND_TYPE_NONE;
    guint32           best_acd_timeout_msec = G_MAXUINT32;
    guint             n                     = 0;
    guint             i;

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

    nm_assert(n == 0 || best_acd_defend_type > NM_L3_ACD_DEFEND_TYPE_NONE);
    nm_assert(best_acd_defend_type <= NM_L3_ACD_DEFEND_TYPE_ALWAYS);

    NM_SET_OUT(out_best_acd_timeout_msec, n > 0 ? best_acd_timeout_msec : 0u);
    NM_SET_OUT(out_best_acd_defend_type, best_acd_defend_type);
    return n;
}

static NML3AcdAddrTrackInfo *
_acd_data_find_track(const AcdData *       acd_data,
                     const NML3ConfigData *l3cd,
                     const NMPObject *     obj,
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
                    const guint8 **  out_addr_bin,
                    gboolean *       out_acd_not_supported)
{
    const NMPlatformLink *link;
    const guint8 *        addr_bin;
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
    NML3Cfg *self    = user_data;
    gboolean success = FALSE;
    int      r;

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
        AcdData *          acd_data;
        NAcdEvent *        event;

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
                    nm_g_timeout_source_new(timeout_msec,
                                            G_PRIORITY_DEFAULT,
                                            _l3_acd_nacd_event_down_timeout_cb,
                                            self,
                                            NULL);
                g_source_attach(self->priv.p->nacd_event_down_source, NULL);
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

    if (c_list_is_empty(&self->priv.p->acd_lst_head))
        start_timer = NM_TERNARY_DEFAULT;

    switch (start_timer) {
    case NM_TERNARY_FALSE:
        _l3_changed_configs_set_dirty(self);
        nm_l3cfg_commit_on_idle_schedule(self);
        break;
    case NM_TERNARY_TRUE:
        self->priv.p->nacd_instance_ensure_retry =
            nm_g_timeout_source_new_seconds(ACD_ENSURE_RATELIMIT_MSEC / 1000u,
                                            G_PRIORITY_DEFAULT,
                                            _l3_acd_nacd_instance_ensure_retry_cb,
                                            self,
                                            NULL);
        g_source_attach(self->priv.p->nacd_instance_ensure_retry, NULL);
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
    nm_auto(n_acd_unrefp) NAcd *            nacd   = NULL;
    const guint8 *                          addr_bin;
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

    self->priv.p->nacd_source =
        nm_g_unix_fd_source_new(fd, G_IO_IN, G_PRIORITY_DEFAULT, _l3_acd_nacd_event, self, NULL);
    nm_g_source_attach(self->priv.p->nacd_source, NULL);

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
_l3_acd_nacd_instance_create_probe(NML3Cfg *    self,
                                   in_addr_t    addr,
                                   guint32      timeout_msec,
                                   gpointer     user_data,
                                   gboolean *   out_acd_not_supported,
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
_l3_acd_data_add(NML3Cfg *             self,
                 const NML3ConfigData *l3cd,
                 const NMPObject *     obj,
                 gconstpointer         tag,
                 NML3AcdDefendType     acd_defend_type,
                 guint32               acd_timeout_msec)
{
    in_addr_t             addr = NMP_OBJECT_CAST_IP4_ADDRESS(obj)->address;
    NML3AcdAddrTrackInfo *acd_track;
    AcdData *             acd_data;
    const char *          track_mode;
    char                  sbuf100[100];

    if (ACD_ADDR_SKIP(addr))
        return;

    acd_data = _l3_acd_data_find(self, addr);

    if (acd_timeout_msec > ACD_MAX_TIMEOUT_MSEC) {
        /* we limit the maximum timeout. Otherwise we have to handle integer overflow
         * when adding timeouts. */
        acd_timeout_msec = ACD_MAX_TIMEOUT_MSEC;
    }

    if (!acd_data) {
        if (G_UNLIKELY(!self->priv.p->acd_lst_hash)) {
            G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(AcdData, info.addr) == 0);
            self->priv.p->acd_lst_hash = g_hash_table_new(nm_puint32_hash, nm_puint32_equals);
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
            .acd_defend_type_desired   = NM_L3_ACD_DEFEND_TYPE_NONE,
            .acd_defend_type_current   = NM_L3_ACD_DEFEND_TYPE_NONE,
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
_l3_acd_data_add_all(NML3Cfg *                  self,
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
        const NMPObject *   obj;

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
    nm_clear_g_source_inst(&acd_data->acd_data_timeout_source);
    acd_data->acd_data_timeout_source =
        nm_g_timeout_source_new(NM_CLAMP((gint64) 0, timeout_msec, (gint64) G_MAXUINT),
                                G_PRIORITY_DEFAULT,
                                _l3_acd_data_timeout_cb,
                                acd_data,
                                NULL);
    g_source_attach(acd_data->acd_data_timeout_source, NULL);
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
    NML3AcdAddrInfo *             info;
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
    AcdData *                acd_data;

    while ((acd_data = c_list_first_entry(&self->priv.p->acd_event_notify_lst_head,
                                          AcdData,
                                          acd_event_notify_lst))) {
        if (!self_keep_alive)
            self_keep_alive = g_object_ref(self);
        c_list_unlink(&acd_data->acd_event_notify_lst);
        _nm_l3cfg_emit_signal_notify_acd_event(self, acd_data);
    }
}

_nm_printf(5, 6) static void _l3_acd_data_state_set_full(NML3Cfg *        self,
                                                         AcdData *        acd_data,
                                                         NML3AcdAddrState state,
                                                         gboolean         allow_commit,
                                                         const char *     format,
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

    if (format) {
        gs_free char *msg = NULL;
        va_list       args;

        va_start(args, format);
        msg = g_strdup_vprintf(format, args);
        va_end(args);

        _LOGT_acd(acd_data, "set state to %s (%s)", _l3_acd_addr_state_to_string(state), msg);
    } else
        _LOGT_acd(acd_data, "set state to %s", _l3_acd_addr_state_to_string(state));

    if (changed && allow_commit) {
        /* The availability of an address just changed (and we are instructed to
         * trigger a new commit). Do it. */
        _l3_changed_configs_set_dirty(self);
        nm_l3cfg_commit_on_idle_schedule(self);
    }
}

static void
_l3_acd_data_state_set(NML3Cfg *        self,
                       AcdData *        acd_data,
                       NML3AcdAddrState state,
                       gboolean         allow_commit)
{
    _l3_acd_data_state_set_full(self, acd_data, state, allow_commit, NULL);
}

static void
_l3_acd_data_state_change(NML3Cfg *          self,
                          AcdData *          acd_data,
                          AcdStateChangeMode state_change_mode,
                          const NMEtherAddr *sender_addr,
                          gint64 *           p_now_msec)

{
    guint32           acd_timeout_msec;
    NML3AcdDefendType acd_defend_type;
    gint64            now_msec;
    const char *      log_reason;
    char              sbuf256[256];
    char              sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];

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
        if (_acd_data_collect_tracks_data(acd_data,
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
        if (_acd_data_collect_tracks_data(acd_data,
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

            nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);

            if (acd_data->probing_timestamp_msec + ACD_WAIT_PROBING_EXTRA_TIME_MSEC
                    + ACD_WAIT_PROBING_EXTRA_TIME2_MSEC
                >= (*p_now_msec)) {
                /* hm. We failed to create a new probe too long. Something is really wrong
                 * internally, but let's ignore the issue and assume the address is good. What
                 * else would we do? Assume the address is USED? */
                _LOGT_acd(acd_data,
                          "probe-good (waiting for creating probe timed out. Assume good)");
                goto handle_start_defending;
            }

            log_reason = "retry probing on timeout";
            goto handle_start_probing;

        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:

            nm_assert(!acd_data->nacd_probe);

            /* after a timeout, re-probe the address. This only happens if the caller
             * does not deconfigure the address after USED/CONFLICT. But in that case,
             * we eventually want to retry. */
            if (_acd_data_collect_tracks_data(acd_data,
                                              NM_TERNARY_TRUE,
                                              &acd_timeout_msec,
                                              &acd_defend_type)
                <= 0)
                nm_assert_not_reached();

            acd_data->acd_defend_type_desired = acd_defend_type;

            if (acd_timeout_msec <= 0) {
                log_reason = "acd disabled by configuration (restart after previous conflict)";
                goto handle_probing_done;
            }

            if (_l3_acd_ipv4_addresses_on_link_contains(self, acd_data->info.addr)) {
                log_reason = "address already configured (restart after previous conflict)";
                goto handle_probing_done;
            }

            nm_utils_get_monotonic_timestamp_msec_cached(p_now_msec);
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

        acd_data->nacd_probe         = n_acd_probe_free(acd_data->nacd_probe);
        acd_data->last_conflict_addr = *sender_addr;
        _l3_acd_data_state_set_full(self,
                                    acd_data,
                                    NM_L3_ACD_ADDR_STATE_USED,
                                    TRUE,
                                    "acd completed with address already in use by %s",
                                    nm_ether_addr_to_string_a(sender_addr));

        if (!acd_data->acd_data_timeout_source)
            _l3_acd_data_timeout_schedule(acd_data, ACD_WAIT_TIME_PROBING_FULL_RESTART_MSEC);

        if (!_l3_acd_data_defendconflict_warning_ratelimited(acd_data, p_now_msec)) {
            _LOGI("IPv4 address %s is used on network connected to interface %d%s%s%s from "
                  "host %s",
                  _nm_utils_inet4_ntop(acd_data->info.addr, sbuf_addr),
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
                  _nm_utils_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  nm_ether_addr_to_string_a(sender_addr));
        /* we just log an info message. Nothing else to do. */
        return;

    case ACD_STATE_CHANGE_MODE_NACD_CONFLICT:
        nm_assert(acd_data->info.state == NM_L3_ACD_ADDR_STATE_DEFENDING);

        _LOGT_acd(acd_data,
                  "address conflict for %s detected with %s",
                  _nm_utils_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  nm_ether_addr_to_string_a(sender_addr));

        if (!_l3_acd_data_defendconflict_warning_ratelimited(acd_data, p_now_msec)) {
            _LOGW("IPv4 address collision detection sees conflict on interface %d%s%s%s for "
                  "address %s from host %s",
                  self->priv.ifindex,
                  NM_PRINT_FMT_QUOTED(self->priv.plobj_next,
                                      " (",
                                      NMP_OBJECT_CAST_LINK(self->priv.plobj_next)->name,
                                      ")",
                                      ""),
                  _nm_utils_inet4_ntop(acd_data->info.addr, sbuf_addr),
                  nm_ether_addr_to_string_a(sender_addr));
        }

        acd_data->nacd_probe         = n_acd_probe_free(acd_data->nacd_probe);
        acd_data->last_conflict_addr = *sender_addr;
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

        switch (acd_data->info.state) {
        case NM_L3_ACD_ADDR_STATE_INIT:
            nm_assert_not_reached();
            return;
        case NM_L3_ACD_ADDR_STATE_PROBING:
        case NM_L3_ACD_ADDR_STATE_DEFENDING:

            if (!acd_data->nacd_probe) {
                /* we failed starting to probe before and have a timer running to
                 * restart. We don't do anything now, but let the timer handle it.
                 * This also implements some rate limiting for us. */
                _LOGT_acd(acd_data,
                          "n-acd instance reset. Ignore event while restarting %s",
                          (acd_data->info.state == NM_L3_ACD_ADDR_STATE_PROBING) ? "probing"
                                                                                 : "defending");
                return;
            }

            _LOGT_acd(acd_data,
                      "n-acd instance reset. Trigger a restart of the %s",
                      (acd_data->info.state == NM_L3_ACD_ADDR_STATE_PROBING) ? "probing"
                                                                             : "defending");
            acd_data->nacd_probe = n_acd_probe_free(acd_data->nacd_probe);
            _l3_acd_data_timeout_schedule(acd_data, 0);
            return;
        case NM_L3_ACD_ADDR_STATE_READY:
        case NM_L3_ACD_ADDR_STATE_USED:
        case NM_L3_ACD_ADDR_STATE_CONFLICT:
        case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
            nm_assert(!acd_data->nacd_probe);
            return;
        }
        nm_assert_not_reached();
        return;
    }

    nm_assert_not_reached();
    return;

handle_start_probing:
    if (TRUE) {
        const NML3AcdAddrState                orig_state = acd_data->info.state;
        nm_auto(n_acd_probe_freep) NAcdProbe *probe      = NULL;
        const char *                          failure_reason;
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
        goto handle_start_defending;
    case NM_L3_ACD_ADDR_STATE_CONFLICT:
        return;
    case NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED:
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

    nm_assert(acd_data->acd_defend_type_desired > NM_L3_ACD_DEFEND_TYPE_NONE);
    nm_assert(acd_data->acd_defend_type_desired <= NM_L3_ACD_DEFEND_TYPE_ALWAYS);

    if (acd_data->acd_defend_type_desired != acd_data->acd_defend_type_current) {
        acd_data->acd_defend_type_current = acd_data->acd_defend_type_desired;
        acd_data->nacd_probe              = n_acd_probe_free(acd_data->nacd_probe);
    }

    if (!acd_data->nacd_probe) {
        const char *failure_reason;
        NAcdProbe * probe;

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

static gboolean
_l3_commit_on_idle_cb(gpointer user_data)
{
    NML3Cfg *self = user_data;

    nm_clear_g_source_inst(&self->priv.p->commit_on_idle_source);

    _LOGT("commit on idle");
    _l3_commit(self, NM_L3_CFG_COMMIT_TYPE_AUTO, TRUE);
    return G_SOURCE_REMOVE;
}

void
nm_l3cfg_commit_on_idle_schedule(NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    if (self->priv.p->commit_on_idle_source)
        return;

    _LOGT("commit on idle (scheduled)");
    self->priv.p->commit_on_idle_source =
        nm_g_idle_source_new(G_PRIORITY_DEFAULT, _l3_commit_on_idle_cb, self, NULL);
    g_source_attach(self->priv.p->commit_on_idle_source, NULL);
}

/*****************************************************************************/

#define _l3_config_datas_at(l3_config_datas, idx) \
    (&g_array_index((l3_config_datas), L3ConfigData, (idx)))

static gssize
_l3_config_datas_find_next(GArray *              l3_config_datas,
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

    /* we sort the entries with higher priority (more important, lower numerical value)
     * first. */
    NM_CMP_FIELD(a, b, priority_confdata);

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

gboolean
nm_l3cfg_add_config(NML3Cfg *             self,
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
                    NML3AcdDefendType     acd_defend_type,
                    guint32               acd_timeout_msec,
                    NML3ConfigMergeFlags  merge_flags)
{
    L3ConfigData *l3_config_data;
    gssize        idx;
    gboolean      changed = FALSE;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(tag);
    nm_assert(l3cd);
    nm_assert(nm_l3_config_data_get_ifindex(l3cd) == self->priv.ifindex);

    if (acd_timeout_msec > ACD_MAX_TIMEOUT_MSEC)
        acd_timeout_msec = ACD_MAX_TIMEOUT_MSEC;

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
            .merge_flags               = merge_flags,
            .default_route_table_4     = default_route_table_4,
            .default_route_table_6     = default_route_table_6,
            .default_route_metric_4    = default_route_metric_4,
            .default_route_metric_6    = default_route_metric_6,
            .default_route_penalty_4   = default_route_penalty_4,
            .default_route_penalty_6   = default_route_penalty_6,
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

    if (changed)
        _l3_changed_configs_set_dirty(self);

    return changed;
}

static gboolean
_l3cfg_remove_config(NML3Cfg *             self,
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

    if (self->priv.p->l3_config_datas->len == 0) {
        nm_assert(changed);
        nm_clear_pointer(&self->priv.p->l3_config_datas, g_array_unref);
        g_object_unref(self);
    }

    return changed;
}

gboolean
nm_l3cfg_remove_config(NML3Cfg *self, gconstpointer tag, const NML3ConfigData *ifcfg)
{
    nm_assert(ifcfg);

    return _l3cfg_remove_config(self, tag, FALSE, ifcfg);
}

gboolean
nm_l3cfg_remove_config_all(NML3Cfg *self, gconstpointer tag, gboolean only_dirty)
{
    return _l3cfg_remove_config(self, tag, only_dirty, NULL);
}

/*****************************************************************************/

typedef struct {
    NML3Cfg *     self;
    gconstpointer tag;
} L3ConfigMergeHookAddObjData;

static gboolean
_l3_hook_add_addr_cb(const NML3ConfigData *l3cd,
                     const NMPObject *     obj,
                     NMTernary *           out_ip4acd_not_ready,
                     gpointer              user_data)
{
    const L3ConfigMergeHookAddObjData *hook_data = user_data;
    NML3Cfg *                          self      = hook_data->self;
    AcdData *                          acd_data;
    in_addr_t                          addr;
    gboolean                           acd_bad = FALSE;

    nm_assert(out_ip4acd_not_ready && *out_ip4acd_not_ready == NM_TERNARY_DEFAULT);

    if (NMP_OBJECT_GET_TYPE(obj) != NMP_OBJECT_TYPE_IP4_ADDRESS)
        return TRUE;

    addr = NMP_OBJECT_CAST_IP4_ADDRESS(obj)->address;

    if (ACD_ADDR_SKIP(addr))
        goto out;

    acd_data = _l3_acd_data_find(self, addr);

    if (!acd_data) {
        /* we don't yet track an ACD state for this address. That can only
         * happend during _l3cfg_update_combined_config() with !to_commit,
         * where we didn't update the ACD state.
         *
         * This means, unless you actually commit, nm_l3cfg_get_combined_l3cd(self, get_commited = FALSE)
         * won't consider IPv4 addresses ready, that have no known ACD state yet. */
        nm_assert(self->priv.p->changed_configs_acd_state);
        acd_bad = TRUE;
        goto out;
    }

    nm_assert(
        _acd_track_data_is_not_dirty(_acd_data_find_track(acd_data, l3cd, obj, hook_data->tag)));
    if (!NM_IN_SET(acd_data->info.state,
                   NM_L3_ACD_ADDR_STATE_READY,
                   NM_L3_ACD_ADDR_STATE_DEFENDING))
        acd_bad = TRUE;

out:
    *out_ip4acd_not_ready = acd_bad ? NM_TERNARY_TRUE : NM_TERNARY_FALSE;
    return TRUE;
}

static void
_l3cfg_update_combined_config(NML3Cfg *              self,
                              gboolean               to_commit,
                              gboolean               reapply,
                              const NML3ConfigData **out_old /* transfer reference */,
                              gboolean *             out_changed_combined_l3cd)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_commited_old = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old          = NULL;
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd               = NULL;
    gs_free const L3ConfigData **l3_config_datas_free          = NULL;
    const L3ConfigData **        l3_config_datas_arr;
    guint                        l3_config_datas_len;
    guint                        i;
    gboolean                     merged_changed   = FALSE;
    gboolean                     commited_changed = FALSE;

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
            .self = self,
        };

        l3cd = nm_l3_config_data_new(nm_platform_get_multi_idx(self->priv.platform),
                                     self->priv.ifindex);

        for (i = 0; i < l3_config_datas_len; i++) {
            const L3ConfigData *l3cd_data = l3_config_datas_arr[i];

            if (NM_FLAGS_HAS(l3cd_data->merge_flags, NM_L3_CONFIG_MERGE_FLAGS_ONLY_FOR_ACD))
                continue;

            hook_data.tag = l3cd_data->tag_confdata;
            nm_l3_config_data_merge(l3cd,
                                    l3cd_data->l3cd,
                                    l3cd_data->merge_flags,
                                    l3cd_data->default_route_table_x,
                                    l3cd_data->default_route_metric_x,
                                    l3cd_data->default_route_penalty_x,
                                    _l3_hook_add_addr_cb,
                                    &hook_data);
        }

        nm_assert(l3cd);
        nm_assert(nm_l3_config_data_get_ifindex(l3cd) == self->priv.ifindex);

        nm_l3_config_data_seal(l3cd);
    }

    if (nm_l3_config_data_equal(l3cd, self->priv.p->combined_l3cd_merged))
        goto out;

    l3cd_old                           = g_steal_pointer(&self->priv.p->combined_l3cd_merged);
    self->priv.p->combined_l3cd_merged = nm_l3_config_data_seal(g_steal_pointer(&l3cd));
    merged_changed                     = TRUE;
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

typedef struct {
    const NMPObject *obj;
    gint64           timestamp_msec;
    bool             dirty;
} RoutesTemporaryNotAvailableData;

static void
_routes_temporary_not_available_data_free(gpointer user_data)
{
    RoutesTemporaryNotAvailableData *data = user_data;

    nmp_object_unref(data->obj);
    nm_g_slice_free(data);
}

#define ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC ((gint64) 20000)

static gboolean
_routes_temporary_not_available_timeout(gpointer user_data)
{
    RoutesTemporaryNotAvailableData *data;
    NML3Cfg *                        self = NM_L3CFG(user_data);
    GHashTableIter                   iter;
    gint64                           expiry_threshold_msec;
    gboolean                         any_expired = FALSE;
    gint64                           now_msec;
    gint64                           oldest_msec;

    self->priv.p->routes_temporary_not_available_id = 0;

    if (!self->priv.p->routes_temporary_not_available_hash)
        return G_SOURCE_REMOVE;

    /* we check the timeouts again. That is, because we allow to remove
     * entries from routes_temporary_not_available_hash, without rescheduling
     * out timeouts. */

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    expiry_threshold_msec = now_msec - ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC;
    oldest_msec           = G_MAXINT64;

    g_hash_table_iter_init(&iter, self->priv.p->routes_temporary_not_available_hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &data, NULL)) {
        if (data->timestamp_msec >= expiry_threshold_msec) {
            any_expired = TRUE;
            break;
        }
        if (data->timestamp_msec < oldest_msec)
            oldest_msec = data->timestamp_msec;
    }

    if (any_expired) {
        /* a route expired. We emit a signal, but we don't schedule it again. That will
         * only happen if the user calls nm_l3cfg_commit() again. */
        _nm_l3cfg_emit_signal_notify_simple(
            self,
            NM_L3_CONFIG_NOTIFY_TYPE_ROUTES_TEMPORARY_NOT_AVAILABLE_EXPIRED);
        return G_SOURCE_REMOVE;
    }

    if (oldest_msec != G_MAXINT64) {
        /* we have a timeout still. Reschedule. */
        self->priv.p->routes_temporary_not_available_id =
            g_timeout_add(oldest_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC - now_msec,
                          _routes_temporary_not_available_timeout,
                          self);
    }
    return G_SOURCE_REMOVE;
}

static gboolean
_routes_temporary_not_available_update(NML3Cfg *  self,
                                       int        addr_family,
                                       GPtrArray *routes_temporary_not_available_arr)
{
    RoutesTemporaryNotAvailableData *data;
    GHashTableIter                   iter;
    gint64                           oldest_msec;
    gint64                           now_msec;
    gboolean                         prune_all = FALSE;
    gboolean                         success   = TRUE;
    guint                            i;

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    if (nm_g_ptr_array_len(routes_temporary_not_available_arr) <= 0) {
        prune_all = TRUE;
        goto out_prune;
    }

    if (self->priv.p->routes_temporary_not_available_hash) {
        g_hash_table_iter_init(&iter, self->priv.p->routes_temporary_not_available_hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) &data, NULL)) {
            if (NMP_OBJECT_GET_ADDR_FAMILY(data->obj) == addr_family)
                data->dirty = TRUE;
        }
    } else {
        self->priv.p->routes_temporary_not_available_hash =
            g_hash_table_new_full(nmp_object_indirect_id_hash,
                                  nmp_object_indirect_id_equal,
                                  _routes_temporary_not_available_data_free,
                                  NULL);
    }

    for (i = 0; i < routes_temporary_not_available_arr->len; i++) {
        const NMPObject *o = routes_temporary_not_available_arr->pdata[i];
        char             sbuf[1024];

        nm_assert(NMP_OBJECT_GET_TYPE(o) == NMP_OBJECT_TYPE_IP_ROUTE(NM_IS_IPv4(addr_family)));

        data = g_hash_table_lookup(self->priv.p->routes_temporary_not_available_hash, &o);

        if (data) {
            if (!data->dirty)
                continue;

            nm_assert(data->timestamp_msec > 0 && data->timestamp_msec <= now_msec);

            if (now_msec > data->timestamp_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC) {
                /* timeout. Could not add this address. */
                _LOGW("failure to add IPv%c route: %s",
                      nm_utils_addr_family_to_char(addr_family),
                      nmp_object_to_string(o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
                success = FALSE;
                continue;
            }

            data->dirty = FALSE;
            continue;
        }

        _LOGT("(temporarily) unable to add IPv%c route: %s",
              nm_utils_addr_family_to_char(addr_family),
              nmp_object_to_string(o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));

        data  = g_slice_new(RoutesTemporaryNotAvailableData);
        *data = (RoutesTemporaryNotAvailableData){
            .obj            = nmp_object_ref(o),
            .timestamp_msec = now_msec,
            .dirty          = FALSE,
        };
        g_hash_table_add(self->priv.p->routes_temporary_not_available_hash, data);
    }

out_prune:
    oldest_msec = G_MAXINT64;

    if (self->priv.p->routes_temporary_not_available_hash) {
        g_hash_table_iter_init(&iter, self->priv.p->routes_temporary_not_available_hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) &data, NULL)) {
            nm_assert(NMP_OBJECT_GET_ADDR_FAMILY(data->obj) == addr_family || !data->dirty);
            if (!prune_all && !data->dirty) {
                if (data->timestamp_msec < oldest_msec)
                    oldest_msec = data->timestamp_msec;
                continue;
            }
            g_hash_table_iter_remove(&iter);
        }
        if (oldest_msec != G_MAXINT64)
            nm_clear_pointer(&self->priv.p->routes_temporary_not_available_hash,
                             g_hash_table_unref);
    }

    nm_clear_g_source(&self->priv.p->routes_temporary_not_available_id);
    if (oldest_msec != G_MAXINT64) {
        nm_assert(oldest_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC < now_msec);
        self->priv.p->routes_temporary_not_available_id =
            g_timeout_add(oldest_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC - now_msec,
                          _routes_temporary_not_available_timeout,
                          self);
    }

    return success;
}

/*****************************************************************************/

static gboolean
_l3_commit_one(NML3Cfg *             self,
               int                   addr_family,
               NML3CfgCommitType     commit_type,
               gboolean              changed_combined_l3cd,
               const NML3ConfigData *l3cd_old)
{
    const int         IS_IPv4                                       = NM_IS_IPv4(addr_family);
    gs_unref_ptrarray GPtrArray *addresses                          = NULL;
    gs_unref_ptrarray GPtrArray *routes                             = NULL;
    gs_unref_ptrarray GPtrArray *addresses_prune                    = NULL;
    gs_unref_ptrarray GPtrArray *routes_prune                       = NULL;
    gs_unref_ptrarray GPtrArray *routes_temporary_not_available_arr = NULL;
    NMIPRouteTableSyncMode       route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_NONE;
    gboolean                     final_failure_for_temporary_not_available = FALSE;
    char                         sbuf_commit_type[50];
    gboolean                     success = TRUE;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_NONE,
                        NM_L3_CFG_COMMIT_TYPE_REAPPLY,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE,
                        NM_L3_CFG_COMMIT_TYPE_ASSUME));
    nm_assert_addr_family(addr_family);

    _LOGT("committing IPv%c configuration (%s)",
          nm_utils_addr_family_to_char(addr_family),
          _l3_cfg_commit_type_to_string(commit_type, sbuf_commit_type, sizeof(sbuf_commit_type)));

    if (changed_combined_l3cd) {
        /* our combined configuration changed. We may track entries in externally_removed_objs_hash,
         * which are not longer to be considered by our configuration. We need to forget about them. */
        _l3cfg_externally_removed_objs_drop_unused(self);
    }

    if (commit_type == NM_L3_CFG_COMMIT_TYPE_ASSUME) {
        /* we need to artificially pre-populate the externally remove hash. */
        _l3cfg_externally_removed_objs_pickup(self, addr_family);
    }

    if (self->priv.p->combined_l3cd_commited) {
        GHashTable *                   externally_removed_objs_hash;
        NMDedupMultiFcnSelectPredicate predicate;
        const NMDedupMultiHeadEntry *  head_entry;

        if (commit_type != NM_L3_CFG_COMMIT_TYPE_REAPPLY
            && self->priv.p->externally_removed_objs_cnt_addresses_x[IS_IPv4] > 0) {
            predicate                    = _l3cfg_externally_removed_objs_filter;
            externally_removed_objs_hash = self->priv.p->externally_removed_objs_hash;
        } else {
            if (IS_IPv4)
                predicate = _l3cfg_externally_removed_objs_filter;
            else
                predicate = NULL;
            externally_removed_objs_hash = NULL;
        }
        head_entry = nm_l3_config_data_lookup_objs(self->priv.p->combined_l3cd_commited,
                                                   NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4));
        addresses  = nm_dedup_multi_objs_to_ptr_array_head(head_entry,
                                                          predicate,
                                                          externally_removed_objs_hash);

        if (commit_type != NM_L3_CFG_COMMIT_TYPE_REAPPLY
            && self->priv.p->externally_removed_objs_cnt_routes_x[IS_IPv4] > 0) {
            predicate                    = _l3cfg_externally_removed_objs_filter;
            externally_removed_objs_hash = self->priv.p->externally_removed_objs_hash;
        } else {
            predicate                    = NULL;
            externally_removed_objs_hash = NULL;
        }
        head_entry = nm_l3_config_data_lookup_objs(self->priv.p->combined_l3cd_commited,
                                                   NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4));
        routes     = nm_dedup_multi_objs_to_ptr_array_head(head_entry,
                                                       predicate,
                                                       externally_removed_objs_hash);

        route_table_sync =
            nm_l3_config_data_get_route_table_sync(self->priv.p->combined_l3cd_commited,
                                                   addr_family);
    }

    if (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_NONE)
        route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_ALL;

    if (commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY) {
        addresses_prune = nm_platform_ip_address_get_prune_list(self->priv.platform,
                                                                addr_family,
                                                                self->priv.ifindex,
                                                                TRUE);
        routes_prune    = nm_platform_ip_route_get_prune_list(self->priv.platform,
                                                           addr_family,
                                                           self->priv.ifindex,
                                                           route_table_sync);
    } else if (commit_type == NM_L3_CFG_COMMIT_TYPE_UPDATE) {
        addresses_prune = nm_g_ptr_array_ref(self->priv.p->last_addresses_x[IS_IPv4]);
        routes_prune    = nm_g_ptr_array_ref(self->priv.p->last_routes_x[IS_IPv4]);
    }

    nm_g_ptr_array_set(&self->priv.p->last_addresses_x[IS_IPv4], addresses);
    nm_g_ptr_array_set(&self->priv.p->last_routes_x[IS_IPv4], routes);

    /* FIXME(l3cfg): need to honor and set nm_l3_config_data_get_ip6_privacy(). */
    /* FIXME(l3cfg): need to honor and set nm_l3_config_data_get_ndisc_*(). */
    /* FIXME(l3cfg): need to honor and set nm_l3_config_data_get_ip6_mtu(). */
    /* FIXME(l3cfg): need to honor and set nm_l3_config_data_get_mtu(). */

    nm_platform_ip_address_sync(self->priv.platform,
                                addr_family,
                                self->priv.ifindex,
                                addresses,
                                addresses_prune);

    if (!nm_platform_ip_route_sync(self->priv.platform,
                                   addr_family,
                                   self->priv.ifindex,
                                   routes,
                                   routes_prune,
                                   &routes_temporary_not_available_arr))
        success = FALSE;

    final_failure_for_temporary_not_available = FALSE;
    if (!_routes_temporary_not_available_update(self,
                                                addr_family,
                                                routes_temporary_not_available_arr))
        final_failure_for_temporary_not_available = TRUE;

    /* FIXME(l3cfg) */
    (void) final_failure_for_temporary_not_available;

    return success;
}

static void
_l3_commit(NML3Cfg *self, NML3CfgCommitType commit_type, gboolean is_idle)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old             = NULL;
    gboolean                                 commit_type_detected = FALSE;
    char                                     sbuf_ct[30];
    gboolean                                 changed_combined_l3cd;

    g_return_if_fail(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_NONE,
                        NM_L3_CFG_COMMIT_TYPE_AUTO,
                        NM_L3_CFG_COMMIT_TYPE_ASSUME,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE,
                        NM_L3_CFG_COMMIT_TYPE_REAPPLY));
    nm_assert(self->priv.p->commit_reentrant_count == 0);

    switch (commit_type) {
    case NM_L3_CFG_COMMIT_TYPE_AUTO:
        /* if in "AUTO" mode we currently have commit-type "UPDATE", that
         * causes also the following update to still be "UPDATE". Either
         * the same commit */
        commit_type_detected = TRUE;
        commit_type          = nm_l3cfg_commit_type_get(self);
        if (commit_type == NM_L3_CFG_COMMIT_TYPE_UPDATE)
            self->priv.p->commit_type_update_sticky = TRUE;
        else if (self->priv.p->commit_type_update_sticky) {
            self->priv.p->commit_type_update_sticky = FALSE;
            commit_type                             = NM_L3_CFG_COMMIT_TYPE_UPDATE;
        }
        break;
    case NM_L3_CFG_COMMIT_TYPE_ASSUME:
        break;
    case NM_L3_CFG_COMMIT_TYPE_REAPPLY:
    case NM_L3_CFG_COMMIT_TYPE_UPDATE:
        self->priv.p->commit_type_update_sticky = FALSE;
        break;
    case NM_L3_CFG_COMMIT_TYPE_NONE:
        break;
    }

    _LOGT("commit %s%s%s",
          _l3_cfg_commit_type_to_string(commit_type, sbuf_ct, sizeof(sbuf_ct)),
          commit_type_detected ? " (auto)" : "",
          is_idle ? " (idle handler)" : "");

    if (commit_type == NM_L3_CFG_COMMIT_TYPE_NONE)
        return;

    self->priv.p->commit_reentrant_count++;

    nm_clear_g_source_inst(&self->priv.p->commit_on_idle_source);

    if (commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY)
        _l3cfg_externally_removed_objs_drop(self);

    _l3cfg_update_combined_config(self,
                                  TRUE,
                                  commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY,
                                  &l3cd_old,
                                  &changed_combined_l3cd);

    /* FIXME(l3cfg): handle items currently not configurable in kernel. */

    _l3_commit_one(self, AF_INET, commit_type, changed_combined_l3cd, l3cd_old);
    _l3_commit_one(self, AF_INET6, commit_type, changed_combined_l3cd, l3cd_old);

    _l3_acd_data_process_changes(self);

    nm_assert(self->priv.p->commit_reentrant_count == 1);
    self->priv.p->commit_reentrant_count--;

    _nm_l3cfg_emit_signal_notify_simple(self, NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT);
}

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
 *
 * NML3Cfg needs to know whether it is in charge of an interface (and how "much").
 * By default, it is not in charge, but various users can register themself with
 * a certain @commit_type. The "higher" commit type is the used one when calling
 * nm_l3cfg_commit() with %NM_L3_CFG_COMMIT_TYPE_AUTO.
 *
 * Returns: a handle tracking the registration, or %NULL of @commit_type
 *   is %NM_L3_CFG_COMMIT_TYPE_NONE.
 */
NML3CfgCommitTypeHandle *
nm_l3cfg_commit_type_register(NML3Cfg *                self,
                              NML3CfgCommitType        commit_type,
                              NML3CfgCommitTypeHandle *existing_handle)
{
    NML3CfgCommitTypeHandle *handle;
    NML3CfgCommitTypeHandle *h;
    gboolean                 linked;

    nm_assert(NM_IS_L3CFG(self));
    nm_assert(NM_IN_SET(commit_type,
                        NM_L3_CFG_COMMIT_TYPE_NONE,
                        NM_L3_CFG_COMMIT_TYPE_ASSUME,
                        NM_L3_CFG_COMMIT_TYPE_UPDATE));
    nm_assert(
        !existing_handle
        || c_list_contains(&self->priv.p->commit_type_lst_head, &existing_handle->commit_type_lst));

    if (existing_handle) {
        if (commit_type == NM_L3_CFG_COMMIT_TYPE_NONE) {
            nm_l3cfg_commit_type_unregister(self, existing_handle);
            return NULL;
        }
        if (existing_handle->commit_type == commit_type)
            return existing_handle;
        c_list_unlink_stale(&existing_handle->commit_type_lst);
        handle = existing_handle;
    } else {
        if (commit_type == NM_L3_CFG_COMMIT_TYPE_NONE)
            return NULL;
        handle              = g_slice_new(NML3CfgCommitTypeHandle);
        handle->commit_type = commit_type;
        if (c_list_is_empty(&self->priv.p->commit_type_lst_head))
            g_object_ref(self);
    }

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

    return handle;
}

void
nm_l3cfg_commit_type_unregister(NML3Cfg *self, NML3CfgCommitTypeHandle *handle)
{
    nm_assert(NM_IS_L3CFG(self));

    if (!handle)
        return;

    nm_assert(c_list_contains(&self->priv.p->commit_type_lst_head, &handle->commit_type_lst));

    c_list_unlink_stale(&handle->commit_type_lst);
    if (c_list_is_empty(&self->priv.p->commit_type_lst_head))
        g_object_unref(self);
    nm_g_slice_free(handle);
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
    const NMPObject *     plat_obj;
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

    nmp_lookup_init_object(&plat_lookup, NMP_OBJECT_TYPE_IP6_ADDRESS, self->priv.ifindex);

    nm_platform_iter_obj_for_each (&iter, self->priv.platform, &plat_lookup, &plat_obj) {
        const NMPlatformIP6Address *plat_addr = NMP_OBJECT_CAST_IP6_ADDRESS(plat_obj);
        const NMDedupMultiEntry *   l3cd_entry;

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

    /* we don't own the refernce to "self->priv.p->ipv4ll", but
     * when that instance gets destroyed, we get called back to
     * forget about it. Basically, it's like a weak pointer. */

    nm_assert(self->priv.p->ipv4ll);
    self->priv.p->ipv4ll = NULL;
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
}

static void
constructed(GObject *object)
{
    NML3Cfg *self = NM_L3CFG(object);

    nm_assert(NM_IS_NETNS(self->priv.netns));
    nm_assert(self->priv.ifindex > 0);

    self->priv.platform = g_object_ref(nm_netns_get_platform(self->priv.netns));
    nm_assert(NM_IS_PLATFORM(self->priv.platform));

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

    nm_assert(!self->priv.p->l3_config_datas);
    nm_assert(!self->priv.p->ipv4ll);

    nm_assert(c_list_is_empty(&self->priv.p->commit_type_lst_head));

    nm_clear_g_source_inst(&self->priv.p->commit_on_idle_source);

    nm_assert(nm_g_array_len(self->priv.p->property_emit_list) == 0u);

    _l3_acd_data_prune(self, TRUE);

    nm_assert(c_list_is_empty(&self->priv.p->acd_lst_head));
    nm_assert(c_list_is_empty(&self->priv.p->acd_event_notify_lst_head));
    nm_assert(nm_g_hash_table_size(self->priv.p->acd_lst_hash) == 0);

    nm_clear_pointer(&self->priv.p->acd_lst_hash, g_hash_table_unref);
    nm_clear_pointer(&self->priv.p->nacd, n_acd_unref);
    nm_clear_g_source_inst(&self->priv.p->nacd_source);
    nm_clear_g_source_inst(&self->priv.p->nacd_instance_ensure_retry);

    nm_clear_pointer(&self->priv.p->last_addresses_4, g_ptr_array_unref);
    nm_clear_pointer(&self->priv.p->last_addresses_6, g_ptr_array_unref);
    nm_clear_pointer(&self->priv.p->last_routes_4, g_ptr_array_unref);
    nm_clear_pointer(&self->priv.p->last_routes_6, g_ptr_array_unref);

    nm_clear_g_source(&self->priv.p->routes_temporary_not_available_id);
    nm_clear_pointer(&self->priv.p->routes_temporary_not_available_hash, g_hash_table_unref);

    nm_clear_pointer(&self->priv.p->externally_removed_objs_hash, g_hash_table_unref);

    g_clear_object(&self->priv.netns);
    g_clear_object(&self->priv.platform);

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
