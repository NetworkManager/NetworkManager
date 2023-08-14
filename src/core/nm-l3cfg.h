/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_L3CFG_H__
#define __NM_L3CFG_H__

#include "libnm-platform/nmp-object.h"
#include "nm-l3-config-data.h"

#define NM_L3CFG_CONFIG_PRIORITY_IPV4LL 0
#define NM_L3CFG_CONFIG_PRIORITY_IPV6LL 1
#define NM_L3CFG_CONFIG_PRIORITY_VPN    9
#define NM_ACD_TIMEOUT_RFC5227_MSEC     9000u
#define NM_ACD_TIMEOUT_MAX_MSEC         30000u

#define NM_TYPE_L3CFG            (nm_l3cfg_get_type())
#define NM_L3CFG(obj)            (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_L3CFG, NML3Cfg))
#define NM_L3CFG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_L3CFG, NML3CfgClass))
#define NM_IS_L3CFG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_L3CFG))
#define NM_IS_L3CFG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_L3CFG))
#define NM_L3CFG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_L3CFG, NML3CfgClass))

#define NM_L3CFG_NETNS   "netns"
#define NM_L3CFG_IFINDEX "ifindex"

#define NM_L3CFG_SIGNAL_NOTIFY "l3cfg-notify"

typedef enum _nm_packed {
    _NM_L3_ACD_DEFEND_TYPE_NONE,
    NM_L3_ACD_DEFEND_TYPE_NEVER,
    NM_L3_ACD_DEFEND_TYPE_ONCE,
    NM_L3_ACD_DEFEND_TYPE_ALWAYS,
} NML3AcdDefendType;

/**
 * NML3CfgConfigFlags:
 * @NM_L3CFG_CONFIG_FLAGS_NONE: no flags, the default.
 * @NM_L3_CONFIG_MERGE_FLAGS_ONLY_FOR_ACD: if this merge flag is set,
 *   the the NML3ConfigData doesn't get merged and it's information won't be
 *   synced. The only purpose is to run ACD on its IPv4 addresses, but
 *   regardless whether ACD succeeds/fails, the IP addresses won't be configured.
 *   The point is to run ACD first (without configuring it), and only
 *   commit the settings if requested. That can either happen by
 *   nm_l3cfg_add_config() the same NML3Cfg again (with a different
 *   tag), or by calling nm_l3cfg_add_config() again with this flag
 *   cleared (and the same tag).
 * @NM_L3CFG_CONFIG_FLAGS_ASSUME_CONFIG_ONCE: a commit with
 *   %NM_L3_CFG_COMMIT_TYPE_ASSUME, means to not remove/add
 *   addresses that are missing/already exist. The assume mode
 *   is for taking over a device gracefully after restart, so
 *   it aims to preserve whatever was configured (or not configured).
 *   With this flag enabled, the first commit in assume mode will still
 *   add the addresses/routes. This is necessary for example with IPv6LL.
 *   Also while assuming a device, we want to configure things
 *   (like an IPv6 address), so we need to bypass the common
 *   "don't change" behavior. At least once. If the address/route
 *   is still not (no longer) configured on the subsequent
 *   commit, it's not getting added again.
 */
typedef enum _nm_packed {
    NM_L3CFG_CONFIG_FLAGS_NONE               = 0,
    NM_L3CFG_CONFIG_FLAGS_ONLY_FOR_ACD       = (1LL << 0),
    NM_L3CFG_CONFIG_FLAGS_ASSUME_CONFIG_ONCE = (1LL << 1),
} NML3CfgConfigFlags;

typedef enum _nm_packed {
    NM_L3_ACD_ADDR_STATE_INIT,
    NM_L3_ACD_ADDR_STATE_PROBING,
    NM_L3_ACD_ADDR_STATE_USED,
    NM_L3_ACD_ADDR_STATE_READY,
    NM_L3_ACD_ADDR_STATE_DEFENDING,
    NM_L3_ACD_ADDR_STATE_CONFLICT,
    NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED,
} NML3AcdAddrState;

typedef struct {
    const NMPObject      *obj;
    const NML3ConfigData *l3cd;
    gconstpointer         tag;

    struct {
        guint32           acd_timeout_msec_track;
        NML3AcdDefendType acd_defend_type_track;
        bool              acd_dirty_track : 1;
        bool              acd_failed_notified_track : 1;
    } _priv;

} NML3AcdAddrTrackInfo;

typedef struct {
    in_addr_t                   addr;
    guint                       n_track_infos;
    NML3AcdAddrState            state;
    NML3Cfg                    *l3cfg;
    const NML3AcdAddrTrackInfo *track_infos;
    NMEtherAddr                 last_conflict_addr;
} NML3AcdAddrInfo;

static inline const NML3AcdAddrTrackInfo *
nm_l3_acd_addr_info_find_track_info(const NML3AcdAddrInfo *addr_info,
                                    gconstpointer          tag,
                                    const NML3ConfigData  *l3cd,
                                    const NMPObject       *obj)
{
    guint                       i;
    const NML3AcdAddrTrackInfo *ti;

    nm_assert(addr_info);

    /* we always expect that the number n_track_infos is reasonably small. Hence,
     * a naive linear search is simplest and fastest (e.g. we don't have a hash table). */

    for (i = 0, ti = addr_info->track_infos; i < addr_info->n_track_infos; i++, ti++) {
        if (l3cd && ti->l3cd != l3cd)
            continue;
        if (tag && ti->tag != tag)
            continue;
        if (obj && ti->obj != obj)
            continue;
        return ti;
    }

    return NULL;
}

typedef enum {
    /* emitted when the merged/commited NML3ConfigData instance changes.
     * Note that this gets emitted "under unsafe circumstances". That means,
     * you should not perform complex operations inside this callback,
     * and neither should you call into NML3Cfg again (reentrancy). */
    NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED,

    NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT,

    /* emitted before the merged l3cd is committed to platform.
     *
     * This event also gets emitted "under unsafe circumstances".
     * See NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED. */
    NM_L3_CONFIG_NOTIFY_TYPE_PRE_COMMIT,

    /* emitted at the end of nm_l3cfg_platform_commit(). This signals also that
     * nm_l3cfg_is_ready() might have switched to TRUE. */
    NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT,

    /* NML3Cfg hooks to the NMPlatform signals for link, addresses and routes.
     * It re-emits the platform signal.
     * Contrary to NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE, this even
     * is re-emitted synchronously. You probably want to hook to the on-idle signal,
     * unless you need to catch all intermediate changes too. Note that this
     * event is not re-entrant safe (so beware what you are doing). */
    NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE,

    /* NML3Cfg hooks to the NMPlatform signals for link, addresses and routes.
     * It re-emits the signal on an idle handler. The purpose is for something
     * like NMDevice which is already subscribed to these signals, it can get the
     * notifications without also subscribing directly to the platform. */
    NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE,

    NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT,

    _NM_L3_CONFIG_NOTIFY_TYPE_NUM,
} NML3ConfigNotifyType;

struct _NML3IPv4LL;

typedef struct {
    NML3ConfigNotifyType notify_type;
    union {
        struct {
            const NML3ConfigData *l3cd_old;
            const NML3ConfigData *l3cd_new;
            bool                  commited;
        } l3cd_changed;

        struct {
            NML3AcdAddrInfo info;
        } acd_event;

        struct {
            const NMPObject           *obj;
            NMPlatformSignalChangeType change_type;
        } platform_change;

        struct {
            guint32 obj_type_flags;
        } platform_change_on_idle;

        struct {
            struct _NML3IPv4LL *ipv4ll;
        } ipv4ll_event;
    };
} NML3ConfigNotifyData;

struct _NML3CfgPrivate;
struct _NMPGlobalTracker;

struct _NML3Cfg {
    GObject parent;
    struct {
        struct _NML3CfgPrivate   *p;
        NMNetns                  *netns;
        NMPlatform               *platform;
        struct _NMPGlobalTracker *global_tracker;
        const NMPObject          *plobj;
        const NMPObject          *plobj_next;
        int                       ifindex;
    } priv;

    /* NML3Cfg strongly cooperates with NMNetns. The latter is
     * the one that creates and manages (also) the lifetime of the
     * NML3Cfg instance. We track some per-l3cfg-data that is only
     * relevant to NMNetns here. */
    struct {
        guint32 signal_pending_obj_type_flags;
        CList   signal_pending_lst;
        CList   ecmp_track_ifindex_lst_head;
    } internal_netns;
};

typedef struct _NML3CfgClass NML3CfgClass;

GType nm_l3cfg_get_type(void);

NML3Cfg *nm_l3cfg_new(NMNetns *netns, int ifindex);

/*****************************************************************************/

gboolean nm_l3cfg_is_ready(NML3Cfg *self);

void _nm_l3cfg_notify_platform_change_on_idle(NML3Cfg *self, guint32 obj_type_flags);

void _nm_l3cfg_notify_platform_change(NML3Cfg                   *self,
                                      NMPlatformSignalChangeType change_type,
                                      const NMPObject           *obj);

/*****************************************************************************/

struct _NMDedupMultiIndex;

struct _NMDedupMultiIndex *nm_netns_get_multi_idx(NMNetns *self);

static inline struct _NMDedupMultiIndex *
nm_l3cfg_get_multi_idx(const NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), NULL);

    return nm_netns_get_multi_idx(self->priv.netns);
}

/*****************************************************************************/

static inline int
nm_l3cfg_get_ifindex(const NML3Cfg *self)
{
    g_return_val_if_fail(NM_IS_L3CFG(self), 0);

    return self->priv.ifindex;
}

static inline const NMPObject *
nm_l3cfg_get_plobj(const NML3Cfg *self, gboolean get_next)
{
    if (!self)
        return NULL;

    nm_assert(NM_IS_L3CFG(self));

    if (get_next) {
        /* This is the instance that we just got reported in the last signal from
         * the platform cache. It's probably exactly the same as if you would look
         * into the platform cache.
         *
         * On the other hand, we pick up changes only on an idle handler. So the last
         * decisions were not made based on this, but instead of "plobj". */
        return self->priv.plobj_next;
    }
    return self->priv.plobj;
}

static inline const NMPlatformLink *
nm_l3cfg_get_pllink(const NML3Cfg *self, gboolean get_next)
{
    return NMP_OBJECT_CAST_LINK(nm_l3cfg_get_plobj(self, get_next));
}

static inline const char *
nm_l3cfg_get_ifname(const NML3Cfg *self, gboolean get_next)
{
    return nmp_object_link_get_ifname(nm_l3cfg_get_plobj(self, get_next));
}

gboolean nm_l3cfg_is_vrf(const NML3Cfg *self);

static inline NMNetns *
nm_l3cfg_get_netns(const NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    return self->priv.netns;
}

static inline NMPlatform *
nm_l3cfg_get_platform(const NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    return self->priv.platform;
}

/*****************************************************************************/

void _nm_l3cfg_emit_signal_notify(NML3Cfg *self, const NML3ConfigNotifyData *notify_data);

/*****************************************************************************/

void nm_l3cfg_mark_config_dirty(NML3Cfg *self, gconstpointer tag, gboolean dirty);

gboolean nm_l3cfg_add_config(NML3Cfg              *self,
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
                             NML3ConfigMergeFlags  merge_flags);

gboolean nm_l3cfg_remove_config(NML3Cfg *self, gconstpointer tag, const NML3ConfigData *l3cd);

gboolean nm_l3cfg_remove_config_all(NML3Cfg *self, gconstpointer tag);
gboolean nm_l3cfg_remove_config_all_dirty(NML3Cfg *self, gconstpointer tag);

/*****************************************************************************/

/* DOC(l3cfg:commit-type):
 *
 * The major idea of NML3Cfg is that independent parties can register configuration
 * (NML3ConfigData via nm_l3cfg_add_config()), and then nm_l3cfg_commit() will
 * actually configure it. Usually we would not call the synchronous nm_l3cfg_commit(),
 * but instead nm_l3cfg_commit_on_idle_schedule().
 *
 * We have different levels of "how much" we should sync during commit. That is
 * NML3CfgCommitType. Since independent parties should be able to work together,
 * they can only ask for their minimal required commit-type level. That means,
 * during commit we will commit with the highest level of how much one of the
 * users request the commit. To request a commit level, users can call
 * nm_l3cfg_commit_type_register(). nm_l3cfg_commit_on_idle_schedule() also
 * accepts a one-time commit-type argument.
 *
 * This is related to NMDevice's sys_iface_state, which we use to control whether
 * to touch/assume/manage the interface.
 *
 * The numeric values of the enum matters: higher number mean more "important".
 * E.g. "assume" tries to preserve the most settings, while "reapply" forces
 * all configuration to match. */
typedef enum _nm_packed {

    /* the NML3Cfg instance tracks with nm_l3cfg_commit_setup_register() the requested commit type.
     * Use _NM_L3_CFG_COMMIT_TYPE_AUTO to automatically choose the level as requested. */
    NM_L3_CFG_COMMIT_TYPE_AUTO,

    /* Don't touch the interface. */
    NM_L3_CFG_COMMIT_TYPE_NONE,

    /* UPDATE means to add new addresses/routes, while also removing addresses/routes
     * that are no longer present (but were previously configured by NetworkManager).
     * Routes/addresses that were removed externally won't be re-added, and routes/addresses
     * that are added externally won't be removed. */
    NM_L3_CFG_COMMIT_TYPE_UPDATE,

    /* This is a full sync. It configures the IP addresses/routes that are indicated,
     * while removing the existing ones from the interface. */
    NM_L3_CFG_COMMIT_TYPE_REAPPLY,

} NML3CfgCommitType;

void nm_l3cfg_commit(NML3Cfg *self, NML3CfgCommitType commit_type);

gboolean nm_l3cfg_commit_on_idle_schedule(NML3Cfg *self, NML3CfgCommitType commit_type);

gboolean nm_l3cfg_commit_on_idle_is_scheduled(NML3Cfg *self);

/*****************************************************************************/

gboolean nm_l3cfg_get_acd_is_pending(NML3Cfg *self);

const NML3AcdAddrInfo *nm_l3cfg_get_acd_addr_info(NML3Cfg *self, in_addr_t addr);

/*****************************************************************************/

typedef enum {
    NM_L3CFG_CHECK_READY_FLAGS_NONE          = 0,
    NM_L3CFG_CHECK_READY_FLAGS_IP4_ACD_READY = (1ull << 0),
    NM_L3CFG_CHECK_READY_FLAGS_IP6_DAD_READY = (1ull << 1),
} NML3CfgCheckReadyFlags;

gboolean nm_l3cfg_check_ready(NML3Cfg               *self,
                              const NML3ConfigData  *l3cd,
                              int                    addr_family,
                              NML3CfgCheckReadyFlags flags,
                              GArray               **conflicts);

gboolean nm_l3cfg_has_failedobj_pending(NML3Cfg *self, int addr_family);

/*****************************************************************************/

NML3CfgCommitType nm_l3cfg_commit_type_get(NML3Cfg *self);

typedef struct _NML3CfgCommitTypeHandle NML3CfgCommitTypeHandle;

NML3CfgCommitTypeHandle *nm_l3cfg_commit_type_register(NML3Cfg                 *self,
                                                       NML3CfgCommitType        commit_type,
                                                       NML3CfgCommitTypeHandle *existing_handle,
                                                       const char              *source);

void nm_l3cfg_commit_type_unregister(NML3Cfg *self, NML3CfgCommitTypeHandle *handle);

static inline gboolean
nm_l3cfg_commit_type_clear(NML3Cfg *self, NML3CfgCommitTypeHandle **handle)
{
    if (!handle || !*handle)
        return FALSE;

    nm_l3cfg_commit_type_unregister(self, g_steal_pointer(handle));
    return TRUE;
}

void nm_l3cfg_commit_type_reset_update(NML3Cfg *self);

/*****************************************************************************/

const NML3ConfigData *nm_l3cfg_get_combined_l3cd(NML3Cfg *self, gboolean get_commited);

const NMPObject *
nm_l3cfg_get_best_default_route(NML3Cfg *self, int addr_family, gboolean get_commited);

/*****************************************************************************/

gboolean nm_l3cfg_has_commited_ip6_addresses_pending_dad(NML3Cfg *self);

/*****************************************************************************/

struct _NML3IPv4LL *nm_l3cfg_get_ipv4ll(NML3Cfg *self);

struct _NML3IPv4LL *nm_l3cfg_access_ipv4ll(NML3Cfg *self);

void _nm_l3cfg_unregister_ipv4ll(NML3Cfg *self);

/*****************************************************************************/

struct _NMIPConfig;
struct _NMIPConfig *nm_l3cfg_ipconfig_get(NML3Cfg *self, int addr_family);
struct _NMIPConfig *nm_l3cfg_ipconfig_acquire(NML3Cfg *self, int addr_family);

/*****************************************************************************/

typedef struct _NML3CfgBlockHandle NML3CfgBlockHandle;

NML3CfgBlockHandle *nm_l3cfg_block_obj_pruning(NML3Cfg *self, int addr_family);
void                nm_l3cfg_unblock_obj_pruning(NML3CfgBlockHandle *handle);

#endif /* __NM_L3CFG_H__ */
