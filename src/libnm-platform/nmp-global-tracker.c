/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-global-tracker.h"

#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

#include "libnm-log-core/nm-logging.h"
#include "libnm-std-aux/c-list-util.h"
#include "nmp-object.h"

/* This limit comes from kernel, and it limits the number of MPTCP addresses
 * we can configure. */
#define MPTCP_PM_ADDR_MAX 8

/*****************************************************************************/

/* NMPGlobalTracker tracks certain objects for the entire network namespace and can
 * commit them.
 *
 * We tend to configure things per-interface and per-profile. In many cases,
 * we thereby only need to care about the things for that interface. For example,
 * we can configure IP addresses and (unicast) routes without having a system wide
 * view. That is mainly, because such objects are themselves tied to an ifindex.
 *
 * However, for certain objects that's not the case. For example, policy routing
 * rules, certain route types (blackhole, unreachable, prohibit, throw) and MPTCP
 * endpoints require a holistic view of the system. That is, because rules and
 * these route types have no ifindex. For MPTCP endpoints, they have an ifindex,
 * however we can only configure a small number of them at a time, so we need a
 * central (global) instance that can track which endpoints to configure.
 *
 * In general, the NMPGlobalTracker tracks objects for the entire namespace, and
 * it's sync() method will figure out how to configure them.
 *
 * Since the users of NMPGloablTracker (NML3Cfg, NMDevice) themselves don't
 * have this holistic view, the API of NMPGlobalTracker allows them to track
 * individual objects independently (they register their objects for a private
 * user-tag). If multiple such independent users track the same object, the tracking
 * priority (track_priority_val) determines which one wins.
 *
 * NMPGlobalTracker can not only track whether an object should be present,
 * it also can track whether it should be absent. See track_priority_present.
 */

/*****************************************************************************/

struct _NMPGlobalTracker {
    NMPlatform *platform;
    GHashTable *by_obj;
    GHashTable *by_user_tag;
    GHashTable *by_data;
    CList       by_obj_lst_heads[4];
    guint       ref_count;
};

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME "global-tracker"

#define _NMLOG(level, ...) __NMLOG_DEFAULT(level, LOGD_PLATFORM, _NMLOG_PREFIX_NAME, __VA_ARGS__)

/*****************************************************************************/

static gboolean
NMP_IS_GLOBAL_TRACKER(gpointer self)
{
    return self && ((NMPGlobalTracker *) self)->ref_count > 0
           && NM_IS_PLATFORM(((NMPGlobalTracker *) self)->platform);
}

/*****************************************************************************/

typedef struct {
    const NMPObject *obj;
    gconstpointer    user_tag;
    CList            obj_lst;
    CList            user_tag_lst;

    /* @track_priority_val zero is special: those are weakly tracked objects.
     * That means: NetworkManager will restore them only if it removed them earlier.
     * But it will not remove or add them otherwise.
     *
     * Otherwise, @track_priority_val goes together with @track_priority_present.
     * In case of one object being tracked multiple times (with different priorities),
     * the one with higher priority wins. See _track_obj_data_get_best_data().
     * Then, the winning present state either enforces that the rule is present
     * or absent.
     *
     * If an object is not tracked at all, it is ignored by NetworkManager (except
     * for MPTCP endpoints for the tracked interface). Assuming that it was added
     * externally by the user. But unlike weakly tracked rules, NM will *not* restore
     * such rules if NetworkManager themself removed them. */
    guint32 track_priority_val;
    bool    track_priority_present : 1;

    /* Calling nmp_global_tracker_track() will ensure that the tracked entry is
     * non-dirty. Together with nmp_global_tracker_set_dirty() and nmp_global_tracker_untrack_all()'s
     * @all parameter, this can be used to remove stale entries. */
    bool dirty : 1;
} TrackData;

typedef enum {
    CONFIG_STATE_NONE          = 0,
    CONFIG_STATE_ADDED_BY_US   = 1,
    CONFIG_STATE_REMOVED_BY_US = 2,

    /* ConfigState encodes whether the object was touched by us at all (CONFIG_STATE_NONE).
     *
     * Maybe we would only need to track whether we touched the object at all. But we
     * track it more in detail what we did: did we add it (CONFIG_STATE_ADDED_BY_US)
     * or did we remove it (CONFIG_STATE_REMOVED_BY_US)?
     * Finally, we need CONFIG_STATE_OWNED_BY_US, which means that we didn't actively
     * add/remove it, but whenever we are about to undo the add/remove, we need to do it.
     * In that sense, CONFIG_STATE_OWNED_BY_US is really just a flag that we unconditionally
     * force the state next time when necessary. */
    CONFIG_STATE_OWNED_BY_US = 3,
} ConfigState;

typedef struct {
    const NMPObject *obj;
    CList            obj_lst_head;

    CList by_obj_lst;

    /* indicates whether we configured/removed the object (during sync()). We need that, so
     * if the object gets untracked, that we know to remove/restore it.
     *
     * This makes NMPGlobalTracker stateful (beyond the configuration that indicates
     * which objects are tracked).
     * After a restart, NetworkManager would no longer remember which objects were added
     * by us.
     *
     * That is partially fixed by NetworkManager taking over the objects that it
     * actively configures (see %NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG). */
    ConfigState config_state;
} TrackObjData;

typedef struct {
    gconstpointer user_tag;
    CList         user_tag_lst_head;
} TrackUserTagData;

/*****************************************************************************/

static void _track_data_untrack(NMPGlobalTracker *self,
                                TrackData        *track_data,
                                gboolean          remove_user_tag_data,
                                gboolean          make_owned_by_us);

/*****************************************************************************/

static CList *
_by_obj_lst_head(NMPGlobalTracker *self, NMPObjectType obj_type)
{
    G_STATIC_ASSERT(G_N_ELEMENTS(self->by_obj_lst_heads) == 4);

    switch (obj_type) {
    case NMP_OBJECT_TYPE_IP4_ROUTE:
        return &self->by_obj_lst_heads[0];
    case NMP_OBJECT_TYPE_IP6_ROUTE:
        return &self->by_obj_lst_heads[1];
    case NMP_OBJECT_TYPE_ROUTING_RULE:
        return &self->by_obj_lst_heads[2];
    case NMP_OBJECT_TYPE_MPTCP_ADDR:
        return &self->by_obj_lst_heads[3];
    default:
        return nm_assert_unreachable_val(NULL);
    }
}

/*****************************************************************************/

static void
_track_data_assert(const TrackData *track_data, gboolean linked)
{
    nm_assert(track_data);
    nm_assert(NM_IN_SET(NMP_OBJECT_GET_TYPE(track_data->obj),
                        NMP_OBJECT_TYPE_IP4_ROUTE,
                        NMP_OBJECT_TYPE_IP6_ROUTE,
                        NMP_OBJECT_TYPE_ROUTING_RULE,
                        NMP_OBJECT_TYPE_MPTCP_ADDR));
    nm_assert(nmp_object_is_visible(track_data->obj));
    nm_assert(track_data->user_tag);
    nm_assert(!linked || !c_list_is_empty(&track_data->obj_lst));
    nm_assert(!linked || !c_list_is_empty(&track_data->user_tag_lst));
}

static guint
_track_data_hash(gconstpointer data)
{
    const TrackData *track_data = data;
    NMHashState      h;

    _track_data_assert(track_data, FALSE);

    nm_hash_init(&h, 269297543u);
    nmp_object_hash_update(track_data->obj, &h);
    nm_hash_update_val(&h, track_data->user_tag);
    return nm_hash_complete(&h);
}

static gboolean
_track_data_equal(gconstpointer data_a, gconstpointer data_b)
{
    const TrackData *track_data_a = data_a;
    const TrackData *track_data_b = data_b;

    _track_data_assert(track_data_a, FALSE);
    _track_data_assert(track_data_b, FALSE);

    return track_data_a->user_tag == track_data_b->user_tag
           && nmp_object_equal(track_data_a->obj, track_data_b->obj);
}

static void
_track_data_destroy(gpointer data)
{
    TrackData *track_data = data;

    _track_data_assert(track_data, FALSE);

    c_list_unlink_stale(&track_data->obj_lst);
    c_list_unlink_stale(&track_data->user_tag_lst);
    nmp_object_unref(track_data->obj);
    nm_g_slice_free(track_data);
}

static const TrackData *
_track_obj_data_get_best_data(TrackObjData *obj_data)
{
    TrackData       *track_data;
    const TrackData *td_best = NULL;

    c_list_for_each_entry (track_data, &obj_data->obj_lst_head, obj_lst) {
        _track_data_assert(track_data, TRUE);

        if (td_best) {
            if (td_best->track_priority_val > track_data->track_priority_val)
                continue;
            if (td_best->track_priority_val == track_data->track_priority_val) {
                if (td_best->track_priority_present || !track_data->track_priority_present) {
                    /* if the priorities are identical, then "present" wins over
                     * "!present" (absent). */
                    continue;
                }
            }
        }

        td_best = track_data;
    }

    if (!td_best)
        return NULL;

    /* Always copy the object from the best TrackData to the TrackObjData. It is
     * a bit odd that this getter modifies TrackObjData. However, it gives the
     * nice property that after calling _track_obj_data_get_best_data() you can
     * use obj_data->obj (and get the same as td_best->obj).
     *
     * This is actually important, because the previous obj_data->obj will have
     * the same ID, but it might have minor differences to td_best->obj.
     *
     * Note that at this point obj_data->obj also might be an object that is no longer
     * tracked. Updating the reference will ensure that we don't have such old references
     * around and update to use the most appropriate one. */
    nmp_object_ref_set(&obj_data->obj, td_best->obj);

    return td_best;
}

static guint
_track_obj_data_hash(gconstpointer data)
{
    const TrackObjData *obj_data = data;

    return nmp_object_id_hash(obj_data->obj);
}

static gboolean
_track_obj_data_equal(gconstpointer data_a, gconstpointer data_b)
{
    const TrackObjData *obj_data_a = data_a;
    const TrackObjData *obj_data_b = data_b;

    return nmp_object_id_equal(obj_data_a->obj, obj_data_b->obj);
}

static void
_track_obj_data_destroy(gpointer data)
{
    TrackObjData *obj_data = data;

    c_list_unlink_stale(&obj_data->obj_lst_head);
    c_list_unlink_stale(&obj_data->by_obj_lst);
    nmp_object_unref(obj_data->obj);
    nm_g_slice_free(obj_data);
}

static void
_track_user_tag_data_destroy(gpointer data)
{
    TrackUserTagData *user_tag_data = data;

    c_list_unlink_stale(&user_tag_data->user_tag_lst_head);
    nm_g_slice_free(user_tag_data);
}

static TrackData *
_track_data_lookup(GHashTable *by_data, const NMPObject *obj, gconstpointer user_tag)
{
    TrackData track_data_needle = {
        .obj      = obj,
        .user_tag = user_tag,
    };

    return g_hash_table_lookup(by_data, &track_data_needle);
}

/*****************************************************************************/

static const NMPObject *
_obj_stackinit(NMPObject *obj_stack, NMPObjectType obj_type, gconstpointer obj)
{
    nmp_object_stackinit(obj_stack, obj_type, obj);

    if (NM_MORE_ASSERTS > 10) {
        if (obj_type == NMP_OBJECT_TYPE_MPTCP_ADDR) {
            NMPlatformMptcpAddr *m = NMP_OBJECT_CAST_MPTCP_ADDR(obj_stack);
            NMPlatformMptcpAddr  m_dummy;

            /* Only certain MPTCP addresses can be added. */
            nm_assert(m->ifindex > 0);
            if (nm_platform_mptcp_addr_cmp(
                    nmp_global_tracker_mptcp_addr_init_for_ifindex(&m_dummy, m->ifindex),
                    m)
                == 0) {
                /* This is a dummy instance. We are good. */
            } else {
                nm_assert_addr_family(m->addr_family);
                nm_assert(m->port == 0);
                nm_assert(m->id == 0);
            }
        }
    }

    nm_assert(nmp_object_is_visible(obj_stack));
    return obj_stack;
}

/**
 * nmp_global_tracker_track:
 * @self: the #NMPGlobalTracker instance
 * @obj_type: the NMPObjectType of @obj that we are tracking.
 * @obj: the NMPlatformObject (of type NMPObjectType) to track. Usually
 *   a #NMPlatformRoutingRule, #NMPlatformIP4Route, #NMPlatformIP6Route
 *   or #NMPlatformMptcpAddr pointer.
 * @track_priority: the priority for tracking the rule. Note that
 *   negative values indicate a forced absence of the rule. Priorities
 *   are compared with their absolute values (with higher absolute
 *   value being more important). For example, if you track the same
 *   rule twice, once with priority -5 and +10, then the rule is
 *   present (because the positive number is more important).
 *   The special value 0 indicates weakly-tracked rules.
 * @user_tag: the tag associated with tracking this rule. The same tag
 *   must be used to untrack the rule later.
 * @user_tag_untrack: if not %NULL, at the same time untrack this user-tag
 *   for the same rule. Note that this is different from a plain nmp_global_tracker_untrack_rule(),
 *   because it enforces ownership of the now tracked rule. On the other hand,
 *   a plain nmp_global_tracker_untrack_rule() merely forgets about the tracking.
 *   The purpose here is to set this to %NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG.
 *
 * Returns: %TRUE, if something changed.
 */
gboolean
nmp_global_tracker_track(NMPGlobalTracker *self,
                         NMPObjectType     obj_type,
                         gconstpointer     obj,
                         gint32            track_priority,
                         gconstpointer     user_tag,
                         gconstpointer     user_tag_untrack)
{
    NMPObject         obj_stack;
    const NMPObject  *p_obj_stack;
    TrackData        *track_data;
    TrackObjData     *obj_data;
    TrackUserTagData *user_tag_data;
    gboolean          changed         = FALSE;
    gboolean          changed_untrack = FALSE;
    guint32           track_priority_val;
    gboolean          track_priority_present;

    g_return_val_if_fail(NMP_IS_GLOBAL_TRACKER(self), FALSE);
    g_return_val_if_fail(obj, FALSE);
    g_return_val_if_fail(user_tag, FALSE);

    /* The route must not be tied to an interface. We can only handle here
     * blackhole/unreachable/prohibit route types. */
    g_return_val_if_fail(
        NM_IN_SET(obj_type, NMP_OBJECT_TYPE_ROUTING_RULE, NMP_OBJECT_TYPE_MPTCP_ADDR)
            || (NM_IN_SET(obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)
                && ((const NMPlatformIPRoute *) obj)->ifindex == 0),
        FALSE);

    /* only positive track priorities are implemented for MPTCP addrs. */
    nm_assert(obj_type != NMP_OBJECT_TYPE_MPTCP_ADDR || track_priority > 0);

    p_obj_stack = _obj_stackinit(&obj_stack, obj_type, obj);

    if (track_priority >= 0) {
        track_priority_val     = track_priority;
        track_priority_present = TRUE;
    } else {
        track_priority_val     = -track_priority;
        track_priority_present = FALSE;
    }

    track_data = _track_data_lookup(self->by_data, p_obj_stack, user_tag);

    if (!track_data) {
        track_data  = g_slice_new(TrackData);
        *track_data = (TrackData){
            .obj      = nm_dedup_multi_index_obj_intern(nm_platform_get_multi_idx(self->platform),
                                                   p_obj_stack),
            .user_tag = user_tag,
            .track_priority_val     = track_priority_val,
            .track_priority_present = track_priority_present,
            .dirty                  = FALSE,
        };
        g_hash_table_add(self->by_data, track_data);

        obj_data = g_hash_table_lookup(self->by_obj, &track_data->obj);
        if (!obj_data) {
            obj_data  = g_slice_new(TrackObjData);
            *obj_data = (TrackObjData){
                .obj          = nmp_object_ref(track_data->obj),
                .obj_lst_head = C_LIST_INIT(obj_data->obj_lst_head),
                .config_state = CONFIG_STATE_NONE,
            };
            g_hash_table_add(self->by_obj, obj_data);
            c_list_link_tail(_by_obj_lst_head(self, obj_type), &obj_data->by_obj_lst);
        }
        c_list_link_tail(&obj_data->obj_lst_head, &track_data->obj_lst);

        user_tag_data = g_hash_table_lookup(self->by_user_tag, &track_data->user_tag);
        if (!user_tag_data) {
            user_tag_data  = g_slice_new(TrackUserTagData);
            *user_tag_data = (TrackUserTagData){
                .user_tag          = user_tag,
                .user_tag_lst_head = C_LIST_INIT(user_tag_data->user_tag_lst_head),
            };
            g_hash_table_add(self->by_user_tag, user_tag_data);
        }
        c_list_link_tail(&user_tag_data->user_tag_lst_head, &track_data->user_tag_lst);
        changed = TRUE;
    } else {
        track_data->dirty = FALSE;
        if (track_data->track_priority_val != track_priority_val
            || track_data->track_priority_present != track_priority_present) {
            track_data->track_priority_val     = track_priority_val;
            track_data->track_priority_present = track_priority_present;
            changed                            = TRUE;
        }
    }

    if (user_tag_untrack) {
        if (user_tag != user_tag_untrack) {
            TrackData *track_data_untrack;

            track_data_untrack = _track_data_lookup(self->by_data, p_obj_stack, user_tag_untrack);
            if (track_data_untrack) {
                _track_data_untrack(self, track_data_untrack, FALSE, TRUE);
                changed_untrack = TRUE;
            }
        } else
            nm_assert_not_reached();
    }

    _track_data_assert(track_data, TRUE);

    if (changed) {
        char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

        _LOGD(
            "track [" NM_HASH_OBFUSCATE_PTR_FMT ",%s%u] %s \"%s\"",
            NM_HASH_OBFUSCATE_PTR(track_data->user_tag),
            (track_data->track_priority_val == 0
                 ? ""
                 : (track_data->track_priority_present ? "+" : "-")),
            (guint) track_data->track_priority_val,
            NMP_OBJECT_GET_CLASS(track_data->obj)->obj_type_name,
            nmp_object_to_string(track_data->obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
    }

    return changed || changed_untrack;
}

static void
_track_data_untrack(NMPGlobalTracker *self,
                    TrackData        *track_data,
                    gboolean          remove_user_tag_data,
                    gboolean          make_owned_by_us)
{
    char          sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    TrackObjData *obj_data;

    nm_assert(NMP_IS_GLOBAL_TRACKER(self));
    _track_data_assert(track_data, TRUE);
    nm_assert(self->by_data);
    nm_assert(g_hash_table_lookup(self->by_data, track_data) == track_data);

    _LOGD("untrack [" NM_HASH_OBFUSCATE_PTR_FMT "] %s \"%s\"",
          NM_HASH_OBFUSCATE_PTR(track_data->user_tag),
          NMP_OBJECT_GET_CLASS(track_data->obj)->obj_type_name,
          nmp_object_to_string(track_data->obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));

#if NM_MORE_ASSERTS
    {
        TrackUserTagData *user_tag_data;

        user_tag_data = g_hash_table_lookup(self->by_user_tag, &track_data->user_tag);
        nm_assert(user_tag_data);
        nm_assert(c_list_contains(&user_tag_data->user_tag_lst_head, &track_data->user_tag_lst));
    }
#endif

    nm_assert(!c_list_is_empty(&track_data->user_tag_lst));

    obj_data = g_hash_table_lookup(self->by_obj, &track_data->obj);
    nm_assert(obj_data);
    nm_assert(c_list_contains(&obj_data->obj_lst_head, &track_data->obj_lst));
    nm_assert(obj_data == g_hash_table_lookup(self->by_obj, &track_data->obj));

    if (make_owned_by_us) {
        if (obj_data->config_state == CONFIG_STATE_NONE) {
            /* we need to mark this entry that it requires a touch on the next
             * sync. */
            obj_data->config_state = CONFIG_STATE_OWNED_BY_US;
        }
    } else if (remove_user_tag_data && c_list_length_is(&track_data->user_tag_lst, 1))
        g_hash_table_remove(self->by_user_tag, &track_data->user_tag);

    /* if obj_data is marked to be "added_by_us" or "removed_by_us", we need to keep this entry
     * around for the next sync -- so that we can undo what we did earlier. */
    if (obj_data->config_state == CONFIG_STATE_NONE && c_list_length_is(&track_data->obj_lst, 1))
        g_hash_table_remove(self->by_obj, &track_data->obj);

    g_hash_table_remove(self->by_data, track_data);
}

gboolean
nmp_global_tracker_untrack(NMPGlobalTracker *self,
                           NMPObjectType     obj_type,
                           gconstpointer     obj,
                           gconstpointer     user_tag)
{
    NMPObject        obj_stack;
    const NMPObject *p_obj_stack;
    TrackData       *track_data;
    gboolean         changed = FALSE;

    g_return_val_if_fail(NMP_IS_GLOBAL_TRACKER(self), FALSE);
    nm_assert(NM_IN_SET(obj_type,
                        NMP_OBJECT_TYPE_IP4_ROUTE,
                        NMP_OBJECT_TYPE_IP6_ROUTE,
                        NMP_OBJECT_TYPE_ROUTING_RULE,
                        NMP_OBJECT_TYPE_MPTCP_ADDR));
    g_return_val_if_fail(obj, FALSE);
    g_return_val_if_fail(user_tag, FALSE);

    p_obj_stack = _obj_stackinit(&obj_stack, obj_type, obj);

    track_data = _track_data_lookup(self->by_data, p_obj_stack, user_tag);
    if (track_data) {
        _track_data_untrack(self, track_data, TRUE, FALSE);
        changed = TRUE;
    }

    return changed;
}

void
nmp_global_tracker_set_dirty(NMPGlobalTracker *self, gconstpointer user_tag)
{
    TrackData        *track_data;
    TrackUserTagData *user_tag_data;

    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));
    g_return_if_fail(user_tag);

    user_tag_data = g_hash_table_lookup(self->by_user_tag, &user_tag);
    if (!user_tag_data)
        return;

    c_list_for_each_entry (track_data, &user_tag_data->user_tag_lst_head, user_tag_lst)
        track_data->dirty = TRUE;
}

gboolean
nmp_global_tracker_untrack_all(NMPGlobalTracker *self,
                               gconstpointer     user_tag,
                               gboolean          all /* or only dirty */,
                               gboolean          make_survivors_dirty)
{
    TrackData        *track_data;
    TrackData        *track_data_safe;
    TrackUserTagData *user_tag_data;
    gboolean          changed = FALSE;

    g_return_val_if_fail(NMP_IS_GLOBAL_TRACKER(self), FALSE);
    g_return_val_if_fail(user_tag, FALSE);

    user_tag_data = g_hash_table_lookup(self->by_user_tag, &user_tag);
    if (!user_tag_data)
        return FALSE;

    c_list_for_each_entry_safe (track_data,
                                track_data_safe,
                                &user_tag_data->user_tag_lst_head,
                                user_tag_lst) {
        if (all || track_data->dirty) {
            _track_data_untrack(self, track_data, FALSE, FALSE);
            changed = TRUE;
            continue;
        }
        if (make_survivors_dirty)
            track_data->dirty = TRUE;
    }
    if (c_list_is_empty(&user_tag_data->user_tag_lst_head))
        g_hash_table_remove(self->by_user_tag, user_tag_data);

    return changed;
}

/*****************************************************************************/

/* Usually, we track NMPlatformMptcpAddr instances with an ifindex set.
 * If we have *any* such instance, we know that the ifindex is fully
 * synched (meaning, we will delete all unknown endpoints for that interface).
 * However, if we don't have an endpoint on the interface, we may still
 * want to track that a certain ifindex is fully managed.
 *
 * This initializes a dummy instance for exactly that purpose. */
const NMPlatformMptcpAddr *
nmp_global_tracker_mptcp_addr_init_for_ifindex(NMPlatformMptcpAddr *addr, int ifindex)
{
    nm_assert(addr);
    nm_assert(ifindex > 0);

    *addr = (NMPlatformMptcpAddr){
        .ifindex     = ifindex,
        .addr_family = AF_UNSPEC,
    };

    return addr;
}

/*****************************************************************************/

typedef struct {
    TrackObjData    *obj_data;
    const TrackData *td_best;
} MptcpSyncData;

static int
_mptcp_entries_cmp(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const MptcpSyncData *d_a = a;
    const MptcpSyncData *d_b = b;

    /* 1) prefer addresses based on the priority (highest priority
     * sorted first). */
    NM_CMP_FIELD(d_b->td_best, d_a->td_best, track_priority_val);

    /* Finally, we only care about the order in which they were tracked.
     * Rely on the stable sort to get that right. */
    return 0;
}

void
nmp_global_tracker_sync_mptcp_addrs(NMPGlobalTracker *self, gboolean reapply)
{
    char                           sbuf[64 + NM_UTILS_TO_STRING_BUFFER_SIZE];
    gs_unref_ptrarray GPtrArray   *kaddrs_arr = NULL;
    gs_unref_hashtable GHashTable *kaddrs_idx = NULL;
    TrackObjData                  *obj_data;
    TrackObjData                  *obj_data_safe;
    CList                         *by_obj_lst_head;
    const TrackData               *td_best;
    gs_unref_hashtable GHashTable *handled_ifindexes    = NULL;
    gs_unref_array GArray         *entries              = NULL;
    gs_unref_hashtable GHashTable *entries_hash_by_addr = NULL;
    gs_unref_hashtable GHashTable *entries_to_delete    = NULL;
    guint                          i;
    guint                          j;

    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));

    _LOGD("sync mptcp-addr%s", reapply ? " (reapply)" : "");

    /* Iterate over the tracked objects and construct @handled_ifindexes, @entries
     * and @entries_to_delete.
     * - @handled_ifindexes is a hash with all managed interfaces (their ifindex).
     * - @entries are the MptcpSyncData instances for the tracked objects.
     * - @entries_to_delete are the NMPObject which we added earlier, but now not
     *     anymore (and which we shall delete). */
    by_obj_lst_head = _by_obj_lst_head(self, NMP_OBJECT_TYPE_MPTCP_ADDR);
    c_list_for_each_entry_safe (obj_data, obj_data_safe, by_obj_lst_head, by_obj_lst) {
        const NMPlatformMptcpAddr *mptcp_addr = NMP_OBJECT_CAST_MPTCP_ADDR(obj_data->obj);
        NMPlatformMptcpAddr        xtst;

        nm_assert(mptcp_addr->port == 0);
        nm_assert(mptcp_addr->ifindex > 0);
        nm_assert(mptcp_addr->id == 0);
        nm_assert_addr_family_or_unspec(mptcp_addr->addr_family);

        /* AF_UNSPEC means this is the dummy object. We only care about it to make the
         * ifindex as managed via @handled_ifindexes. */
        nm_assert(
            (mptcp_addr->addr_family == AF_UNSPEC)
            == (nm_platform_mptcp_addr_cmp(
                    mptcp_addr,
                    nmp_global_tracker_mptcp_addr_init_for_ifindex(&xtst, mptcp_addr->ifindex))
                == 0));

        /* We need to know which ifindexes are managed/handled by us. Build an index
         * for that. */
        if (!handled_ifindexes)
            handled_ifindexes = g_hash_table_new(nm_direct_hash, NULL);
        g_hash_table_add(handled_ifindexes, GINT_TO_POINTER(mptcp_addr->ifindex));

        td_best = _track_obj_data_get_best_data(obj_data);

        if (!td_best) {
            nm_assert(obj_data->config_state == CONFIG_STATE_ADDED_BY_US);

            /* This entry is a tombstone, that tells us that added the object earlier.
             * We can delete the MPTCP address (if it's still configured).
             *
             * Then we can drop the tombstone. */

            if (mptcp_addr->addr_family != AF_UNSPEC) {
                if (!reapply) {
                    if (!entries_to_delete) {
                        entries_to_delete = g_hash_table_new_full((GHashFunc) nmp_object_id_hash,
                                                                  (GEqualFunc) nmp_object_id_equal,
                                                                  (GDestroyNotify) nmp_object_unref,
                                                                  NULL);
                    }
                    g_hash_table_add(entries_to_delete, (gpointer) nmp_object_ref(obj_data->obj));
                }
            }

            /* We can forget about this entry now. */
            g_hash_table_remove(self->by_obj, obj_data);
            continue;
        }

        /* negative and zero track priorities are not implemented (and make no sense?). */
        nm_assert(td_best->track_priority_val > 0);
        nm_assert(td_best->track_priority_present);

        if (mptcp_addr->addr_family == AF_UNSPEC) {
            /* This is a nmp_global_tracker_mptcp_addr_init_for_ifindex() dummy entry.
             * It only exists so we can add the @handled_ifindexes entry above
             * and handle addresses on this interface. */
            obj_data->config_state = CONFIG_STATE_ADDED_BY_US;
            continue;
        }

        if (!entries)
            entries = g_array_new(FALSE, FALSE, sizeof(MptcpSyncData));

        g_array_append_val(entries,
                           ((const MptcpSyncData){
                               .obj_data = obj_data,
                               .td_best  = td_best,
                           }));
    }
    /* We collected all the entires we want to configure. Now, sort them by
     * priority, and drop all the duplicates (preferring the entries that
     * appear first, where first means "older"). In kernel, we can only configure an IP
     * address (without port) as endpoint once. If two interfaces provide the same IP
     * address, we can only configure one. We need to select one and filter out duplicates.
     * While there is no solution, the idea is to select the preferred address
     * somewhat consistently.
     *
     * Also, create a lookup index @entries_hash_by_addr to lookup by address. */
    if (entries) {
        /* First we sort the entries by priority, to prefer the ones with higher
         * priority. In case of equal priority, we rely on the stable sort to
         * preserve the order in which things got tracked. */
        g_array_sort_with_data(entries, _mptcp_entries_cmp, NULL);

        entries_hash_by_addr = g_hash_table_new(nm_platform_mptcp_addr_index_addr_cmp,
                                                nm_platform_mptcp_addr_index_addr_equal);

        /* Now, drop all duplicates addresses. Only keep the first one. */
        for (i = 0, j = 0; i < entries->len; i++) {
            const MptcpSyncData       *d          = &nm_g_array_index(entries, MptcpSyncData, i);
            const NMPlatformMptcpAddr *mptcp_addr = NMP_OBJECT_CAST_MPTCP_ADDR(d->obj_data->obj);

            obj_data = g_hash_table_lookup(entries_hash_by_addr, (gpointer) mptcp_addr);
            if (obj_data) {
                /* This object is shadowed. We ignore it.
                 *
                 * However, we first propagate the config_state. For MPTCP addrs, it can only be
                 * NONE or ADDED_BY_US. */
                nm_assert(NM_IN_SET(d->obj_data->config_state,
                                    CONFIG_STATE_NONE,
                                    CONFIG_STATE_ADDED_BY_US));
                nm_assert(
                    NM_IN_SET(obj_data->config_state, CONFIG_STATE_NONE, CONFIG_STATE_ADDED_BY_US));

                if (d->obj_data->config_state == CONFIG_STATE_ADDED_BY_US) {
                    obj_data->config_state    = CONFIG_STATE_ADDED_BY_US;
                    d->obj_data->config_state = CONFIG_STATE_NONE;
                }
                continue;
            }

            if (!g_hash_table_insert(entries_hash_by_addr, (gpointer) mptcp_addr, d->obj_data))
                nm_assert_not_reached();

            if (i != j)
                (nm_g_array_index(entries, MptcpSyncData, j)) = *d;
            j++;

            if (j >= MPTCP_PM_ADDR_MAX) {
                /* Kernel limits the number of addresses we can configure.
                 * It's hard-coded here, taken from current kernel. Hopefully
                 * it matches the running kernel.
                 *
                 * It's worse. There might be other addresses already configured
                 * on other interfaces (or with a port). Our sync method will leave
                 * them alone, as they were not added by us. So the actual limit
                 * is possibly smaller, and kernel fails with EINVAL.
                 *
                 * Still, we definitely need to truncate the list here. Imagine
                 * during an earlier sync we added MAX addresses on one interface.
                 * Now, another interface activates, and wants to configure one
                 * address. That address will get a higher priority (chosen by NML3Cfg),
                 * so that part is good. However, it means we must drop the last from
                 * the other MAX addresses. We achieve that by truncating the list
                 * to MPTCP_PM_ADDR_MAX.
                 */
                break;
            }
        }
        g_array_set_size(entries, j);
    }

    /* Get the list of currently (in kernel) configured MPTCP endpoints. */
    kaddrs_arr = nm_platform_mptcp_addrs_dump(self->platform);

    /* First, delete all kaddrs which we no longer want... */
    if (kaddrs_arr) {
        for (i = 0; i < kaddrs_arr->len; i++) {
            const NMPObject           *obj              = kaddrs_arr->pdata[i];
            const NMPlatformMptcpAddr *mptcp_addr       = NMP_OBJECT_CAST_MPTCP_ADDR(obj);
            gboolean                   add_to_kaddr_idx = FALSE;

            if (mptcp_addr->port != 0 || mptcp_addr->ifindex <= 0) {
                /* We ignore all endpoints that have a port or no ifindex.
                 * Those were never created by us, let the user who created
                 * them handle them. */
                goto keep_and_next;
            }

            if (!nm_g_hash_table_contains(handled_ifindexes,
                                          GINT_TO_POINTER(mptcp_addr->ifindex))) {
                /* This endpoint is on an interface we don't manage. Ignore (and keep) it. */
                goto keep_and_next;
            }

            /* We have the object in the delete-list. However, we might still also want
             * to add it back. Check for that too. */
            obj_data = nm_g_hash_table_lookup(entries_hash_by_addr, mptcp_addr);
            if (obj_data) {
                const NMPlatformMptcpAddr *mptcp_addr2 = NMP_OBJECT_CAST_MPTCP_ADDR(obj_data->obj);

                if (mptcp_addr->flags == mptcp_addr2->flags
                    && mptcp_addr->ifindex == mptcp_addr2->ifindex) {
                    /* We want to add this address and it's already configured. Keep it
                     * and remember that we already have it. */
                    add_to_kaddr_idx = TRUE;
                    goto keep_and_next;
                }

                /* We want to configure a similar address mptcp_addr2) as the one that is already configured
                 * (mptcp_addr). However, the ifindex or flag differs. Delete this one to add the
                 * right one blow. */
            } else {
                /* We don't want to configure this address (anymore). */
                if (reapply) {
                    /* in reapply mode, we delete the extra address. */
                } else {
                    /* Otherwise, we only delete it, if we remember that we added this one
                     * before. */
                    if (!nm_g_hash_table_contains(entries_to_delete, obj)) {
                        /* This address was not added by us. Keep it. */
                        goto keep_and_next;
                    }
                }
            }

            if (!nm_platform_object_delete(self->platform, obj)) {
                /* We failed to delete it. It's unclear what is the matter with this
                 * object. Ignore the failure. */
            }

            continue;

keep_and_next:
            _LOGt("keep: %s \"%s\"%s",
                  NMP_OBJECT_GET_CLASS(obj)->obj_type_name,
                  nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)),
                  add_to_kaddr_idx ? " (index)" : "");
            if (add_to_kaddr_idx) {
                if (!kaddrs_idx) {
                    kaddrs_idx = g_hash_table_new((GHashFunc) nmp_object_id_hash,
                                                  (GEqualFunc) nmp_object_id_equal);
                }
                g_hash_table_add(kaddrs_idx, (gpointer) obj);
            }
        }
    }

    if (entries) {
        for (i = 0; i < entries->len; i++) {
            const MptcpSyncData       *d          = &nm_g_array_index(entries, MptcpSyncData, i);
            const NMPlatformMptcpAddr *mptcp_addr = NMP_OBJECT_CAST_MPTCP_ADDR(d->obj_data->obj);
            const NMPObject           *kobj;

            nm_assert(mptcp_addr->port == 0);
            nm_assert(mptcp_addr->ifindex > 0);

            d->obj_data->config_state = CONFIG_STATE_ADDED_BY_US;

            kobj = nm_g_hash_table_lookup(kaddrs_idx, d->obj_data->obj);
            if (kobj && kobj->mptcp_addr.flags == mptcp_addr->flags) {
                /* This address is already added with the right flags. We can
                 * skip it. */
                continue;
            }

            /* Kernel actually only allows us to add a small number of addresses.
             * Also, if we have a conflicting address on another interface, the
             * request will be rejected.
             *
             * Don't try to handle that. Just attempt to add the address, and if
             * we fail, there is nothing we can do about it. */
            nm_platform_mptcp_addr_update(self->platform, TRUE, mptcp_addr);
        }
    }
}

void
nmp_global_tracker_sync(NMPGlobalTracker *self, NMPObjectType obj_type, gboolean keep_deleted)
{
    char                         sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    const NMDedupMultiHeadEntry *pl_head_entry;
    const NMPObject             *plobj;
    gs_unref_ptrarray GPtrArray *objs_to_delete = NULL;
    TrackObjData                *obj_data;
    TrackObjData                *obj_data_safe;
    CList                       *by_obj_lst_head;
    guint                        i;
    const TrackData             *td_best;

    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));
    g_return_if_fail(NM_IN_SET(obj_type,
                               NMP_OBJECT_TYPE_IP4_ROUTE,
                               NMP_OBJECT_TYPE_IP6_ROUTE,
                               NMP_OBJECT_TYPE_ROUTING_RULE));

    _LOGD("sync %s%s",
          nmp_class_from_type(obj_type)->obj_type_name,
          keep_deleted ? " (don't remove any)" : "");

    if (obj_type == NMP_OBJECT_TYPE_ROUTING_RULE)
        pl_head_entry = nm_platform_lookup_obj_type(self->platform, obj_type);
    else
        pl_head_entry = nm_platform_lookup_object(self->platform, obj_type, 0);

    if (pl_head_entry) {
        NMDedupMultiIter pl_iter;

        nmp_cache_iter_for_each (&pl_iter, pl_head_entry, &plobj) {
            obj_data = g_hash_table_lookup(self->by_obj, &plobj);

            if (!obj_data) {
                /* this obj is not tracked. It was externally added, hence we
                 * ignore it. */
                continue;
            }

            td_best = _track_obj_data_get_best_data(obj_data);
            if (td_best) {
                if (td_best->track_priority_present) {
                    if (obj_data->config_state == CONFIG_STATE_OWNED_BY_US)
                        obj_data->config_state = CONFIG_STATE_ADDED_BY_US;
                    continue;
                }
                if (td_best->track_priority_val == 0) {
                    if (!NM_IN_SET(obj_data->config_state,
                                   CONFIG_STATE_ADDED_BY_US,
                                   CONFIG_STATE_OWNED_BY_US)) {
                        obj_data->config_state = CONFIG_STATE_NONE;
                        continue;
                    }
                    obj_data->config_state = CONFIG_STATE_NONE;
                }
            }

            if (keep_deleted) {
                _LOGD("forget/leak object added by us: %s \"%s\"",
                      NMP_OBJECT_GET_CLASS(plobj)->obj_type_name,
                      nmp_object_to_string(plobj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
                continue;
            }

            if (!objs_to_delete)
                objs_to_delete = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);

            g_ptr_array_add(objs_to_delete, (gpointer) nmp_object_ref(plobj));

            obj_data->config_state = CONFIG_STATE_REMOVED_BY_US;
        }
    }

    if (objs_to_delete) {
        for (i = 0; i < objs_to_delete->len; i++)
            nm_platform_object_delete(self->platform, objs_to_delete->pdata[i]);
    }

    by_obj_lst_head = _by_obj_lst_head(self, obj_type);

    c_list_for_each_entry_safe (obj_data, obj_data_safe, by_obj_lst_head, by_obj_lst) {
        nm_assert(NMP_OBJECT_GET_TYPE(obj_data->obj) == obj_type);

        td_best = _track_obj_data_get_best_data(obj_data);

        if (!td_best) {
            g_hash_table_remove(self->by_obj, obj_data);
            continue;
        }

        if (!td_best->track_priority_present) {
            if (obj_data->config_state == CONFIG_STATE_OWNED_BY_US)
                obj_data->config_state = CONFIG_STATE_REMOVED_BY_US;
            continue;
        }
        if (td_best->track_priority_val == 0) {
            if (!NM_IN_SET(obj_data->config_state,
                           CONFIG_STATE_REMOVED_BY_US,
                           CONFIG_STATE_OWNED_BY_US)) {
                obj_data->config_state = CONFIG_STATE_NONE;
                continue;
            }
            obj_data->config_state = CONFIG_STATE_NONE;
        }

        plobj =
            nm_platform_lookup_obj(self->platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj_data->obj);
        if (plobj) {
            int c;

            switch (obj_type) {
            case NMP_OBJECT_TYPE_ROUTING_RULE:
                c = nm_platform_routing_rule_cmp(NMP_OBJECT_CAST_ROUTING_RULE(obj_data->obj),
                                                 NMP_OBJECT_CAST_ROUTING_RULE(plobj),
                                                 NM_PLATFORM_ROUTING_RULE_CMP_TYPE_SEMANTICALLY);
                break;
            case NMP_OBJECT_TYPE_IP4_ROUTE:
                c = nm_platform_ip4_route_cmp(NMP_OBJECT_CAST_IP4_ROUTE(obj_data->obj),
                                              NMP_OBJECT_CAST_IP4_ROUTE(plobj),
                                              NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY);
                break;
            case NMP_OBJECT_TYPE_IP6_ROUTE:
                c = nm_platform_ip6_route_cmp(NMP_OBJECT_CAST_IP6_ROUTE(obj_data->obj),
                                              NMP_OBJECT_CAST_IP6_ROUTE(plobj),
                                              NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY);
                break;
            default:
                c = nm_assert_unreachable_val(0);
                break;
            }
            if (c == 0)
                continue;
            nm_platform_object_delete(self->platform, plobj);
        }

        obj_data->config_state = CONFIG_STATE_ADDED_BY_US;

        if (obj_type == NMP_OBJECT_TYPE_ROUTING_RULE) {
            nm_platform_routing_rule_add(self->platform,
                                         NMP_NLM_FLAG_ADD,
                                         NMP_OBJECT_CAST_ROUTING_RULE(obj_data->obj));
        } else
            nm_platform_ip_route_add(self->platform, NMP_NLM_FLAG_APPEND, obj_data->obj);
    }
}

/*****************************************************************************/

void
nmp_global_tracker_track_rule_from_platform(NMPGlobalTracker *self,
                                            NMPlatform       *platform,
                                            int               addr_family,
                                            gint32            tracking_priority,
                                            gconstpointer     user_tag)
{
    NMPLookup                    lookup;
    const NMDedupMultiHeadEntry *head_entry;
    NMDedupMultiIter             iter;
    const NMPObject             *o;

    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));

    if (!platform)
        platform = self->platform;
    else
        g_return_if_fail(NM_IS_PLATFORM(platform));

    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
    head_entry = nm_platform_lookup(platform, &lookup);
    nmp_cache_iter_for_each (&iter, head_entry, &o) {
        const NMPlatformRoutingRule *rr = NMP_OBJECT_CAST_ROUTING_RULE(o);

        if (addr_family != AF_UNSPEC && rr->addr_family != addr_family)
            continue;

        nmp_global_tracker_track_rule(self, rr, tracking_priority, user_tag, NULL);
    }
}

/*****************************************************************************/

void
nmp_global_tracker_track_rule_default(NMPGlobalTracker *self,
                                      int               addr_family,
                                      gint32            track_priority,
                                      gconstpointer     user_tag)
{
    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));

    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    /* track the default rules. See also `man ip-rule`. */

    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET)) {
        nmp_global_tracker_track_local_rule(self, addr_family, track_priority, user_tag, NULL);
        nmp_global_tracker_track_rule(self,
                                      &((NMPlatformRoutingRule){
                                          .addr_family = AF_INET,
                                          .priority    = 32766,
                                          .table       = RT_TABLE_MAIN,
                                          .action      = FR_ACT_TO_TBL,
                                          .protocol    = RTPROT_KERNEL,
                                      }),
                                      track_priority,
                                      user_tag,
                                      NULL);
        nmp_global_tracker_track_rule(self,
                                      &((NMPlatformRoutingRule){
                                          .addr_family = AF_INET,
                                          .priority    = 32767,
                                          .table       = RT_TABLE_DEFAULT,
                                          .action      = FR_ACT_TO_TBL,
                                          .protocol    = RTPROT_KERNEL,
                                      }),
                                      track_priority,
                                      user_tag,
                                      NULL);
    }
    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET6)) {
        nmp_global_tracker_track_local_rule(self, addr_family, track_priority, user_tag, NULL);
        nmp_global_tracker_track_rule(self,
                                      &((NMPlatformRoutingRule){
                                          .addr_family = AF_INET6,
                                          .priority    = 32766,
                                          .table       = RT_TABLE_MAIN,
                                          .action      = FR_ACT_TO_TBL,
                                          .protocol    = RTPROT_KERNEL,
                                      }),
                                      track_priority,
                                      user_tag,
                                      NULL);
    }
}

void
nmp_global_tracker_track_local_rule(NMPGlobalTracker *self,
                                    int               addr_family,
                                    gint32            track_priority,
                                    gconstpointer     user_tag,
                                    gconstpointer     user_tag_untrack)
{
    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));

    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET)) {
        nmp_global_tracker_track_rule(self,
                                      &((NMPlatformRoutingRule){
                                          .addr_family = AF_INET,
                                          .priority    = 0,
                                          .table       = RT_TABLE_LOCAL,
                                          .action      = FR_ACT_TO_TBL,
                                          .protocol    = RTPROT_KERNEL,
                                      }),
                                      track_priority,
                                      user_tag,
                                      user_tag_untrack);
    }
    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET6)) {
        nmp_global_tracker_track_rule(self,
                                      &((NMPlatformRoutingRule){
                                          .addr_family = AF_INET6,
                                          .priority    = 0,
                                          .table       = RT_TABLE_LOCAL,
                                          .action      = FR_ACT_TO_TBL,
                                          .protocol    = RTPROT_KERNEL,
                                      }),
                                      track_priority,
                                      user_tag,
                                      user_tag_untrack);
    }
}

/*****************************************************************************/

NMPGlobalTracker *
nmp_global_tracker_new(NMPlatform *platform)
{
    NMPGlobalTracker *self;

    g_return_val_if_fail(NM_IS_PLATFORM(platform), NULL);

    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(TrackUserTagData, user_tag) == 0);

    self  = g_slice_new(NMPGlobalTracker);
    *self = (NMPGlobalTracker){
        .ref_count = 1,
        .platform  = g_object_ref(platform),
        .by_data =
            g_hash_table_new_full(_track_data_hash, _track_data_equal, NULL, _track_data_destroy),
        .by_obj              = g_hash_table_new_full(_track_obj_data_hash,
                                        _track_obj_data_equal,
                                        NULL,
                                        _track_obj_data_destroy),
        .by_user_tag         = g_hash_table_new_full(nm_pdirect_hash,
                                             nm_pdirect_equal,
                                             NULL,
                                             _track_user_tag_data_destroy),
        .by_obj_lst_heads[0] = C_LIST_INIT(self->by_obj_lst_heads[0]),
        .by_obj_lst_heads[1] = C_LIST_INIT(self->by_obj_lst_heads[1]),
        .by_obj_lst_heads[2] = C_LIST_INIT(self->by_obj_lst_heads[2]),
        .by_obj_lst_heads[3] = C_LIST_INIT(self->by_obj_lst_heads[3]),
    };
    return self;
}

NMPGlobalTracker *
nmp_global_tracker_ref(NMPGlobalTracker *self)
{
    g_return_val_if_fail(NMP_IS_GLOBAL_TRACKER(self), NULL);

    self->ref_count++;
    return self;
}

void
nmp_global_tracker_unref(NMPGlobalTracker *self)
{
    g_return_if_fail(NMP_IS_GLOBAL_TRACKER(self));

    if (--self->ref_count > 0)
        return;

    g_hash_table_destroy(self->by_user_tag);
    g_hash_table_destroy(self->by_obj);
    g_hash_table_destroy(self->by_data);
    nm_assert(c_list_is_empty(&self->by_obj_lst_heads[0]));
    nm_assert(c_list_is_empty(&self->by_obj_lst_heads[1]));
    nm_assert(c_list_is_empty(&self->by_obj_lst_heads[2]));
    nm_assert(c_list_is_empty(&self->by_obj_lst_heads[3]));
    g_object_unref(self->platform);
    nm_g_slice_free(self);
}
