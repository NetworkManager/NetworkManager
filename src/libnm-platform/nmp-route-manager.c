/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-route-manager.h"

#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

#include "libnm-log-core/nm-logging.h"
#include "libnm-std-aux/c-list-util.h"
#include "nmp-object.h"

/*****************************************************************************/

struct _NMPRouteManager {
    NMPlatform *platform;
    GHashTable *by_obj;
    GHashTable *by_user_tag;
    GHashTable *by_data;
    guint       ref_count;
};

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME "route-manager"

#define _NMLOG(level, ...)                                                 \
    G_STMT_START                                                           \
    {                                                                      \
        const NMLogLevel __level = (level);                                \
                                                                           \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) {                  \
            _nm_log(__level,                                               \
                    _NMLOG_DOMAIN,                                         \
                    0,                                                     \
                    NULL,                                                  \
                    NULL,                                                  \
                    "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),             \
                    _NMLOG_PREFIX_NAME _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        }                                                                  \
    }                                                                      \
    G_STMT_END

/*****************************************************************************/

static gboolean
NMP_IS_ROUTE_MANAGER(gpointer self)
{
    return self && ((NMPRouteManager *) self)->ref_count > 0
           && NM_IS_PLATFORM(((NMPRouteManager *) self)->platform);
}

#define _USER_TAG_LOG(user_tag) nm_hash_obfuscate_ptr(1240261787u, (user_tag))

/*****************************************************************************/

typedef struct {
    const NMPObject *obj;
    gconstpointer    user_tag;
    CList            obj_lst;
    CList            user_tag_lst;

    /* track_priority_val zero is special: those are weakly tracked rules.
     * That means: NetworkManager will restore them only if it removed them earlier.
     * But it will not remove or add them otherwise.
     *
     * Otherwise, the track_priority_val goes together with track_priority_present.
     * In case of one rule being tracked multiple times (with different priorities),
     * the one with higher priority wins. See _track_obj_data_get_best_data().
     * Then, the winning present state either enforces that the rule is present
     * or absent.
     *
     * If a rules is not tracked at all, it is ignored by NetworkManager. Assuming
     * that it was added externally by the user. But unlike weakly tracked rules,
     * NM will *not* restore such rules if NetworkManager themself removed them. */
    guint32 track_priority_val;
    bool    track_priority_present : 1;

    bool dirty : 1;
} TrackData;

typedef enum {
    CONFIG_STATE_NONE          = 0,
    CONFIG_STATE_ADDED_BY_US   = 1,
    CONFIG_STATE_REMOVED_BY_US = 2,

    /* ConfigState encodes whether the rule was touched by us at all (CONFIG_STATE_NONE).
     *
     * Maybe we would only need to track whether we touched the rule at all. But we
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

    /* indicates whether we configured/removed the rule (during sync()). We need that, so
     * if the rule gets untracked, that we know to remove/restore it.
     *
     * This makes NMPRouteManager stateful (beyond the configuration that indicates
     * which rules are tracked).
     * After a restart, NetworkManager would no longer remember which rules were added
     * by us.
     *
     * That is partially fixed by NetworkManager taking over the rules that it
     * actively configures (see %NMP_ROUTE_MANAGER_EXTERN_WEAKLY_TRACKED_USER_TAG). */
    ConfigState config_state;
} TrackObjData;

typedef struct {
    gconstpointer user_tag;
    CList         user_tag_lst_head;
} TrackUserTagData;

/*****************************************************************************/

static void _track_data_untrack(NMPRouteManager *self,
                                TrackData       *track_data,
                                gboolean         remove_user_tag_data,
                                gboolean         make_owned_by_us);

/*****************************************************************************/

static void
_track_data_assert(const TrackData *track_data, gboolean linked)
{
    nm_assert(track_data);
    nm_assert(NMP_OBJECT_GET_TYPE(track_data->obj) == NMP_OBJECT_TYPE_ROUTING_RULE);
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
    nm_platform_routing_rule_hash_update(NMP_OBJECT_CAST_ROUTING_RULE(track_data->obj),
                                         NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID,
                                         &h);
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
           && (nm_platform_routing_rule_cmp(NMP_OBJECT_CAST_ROUTING_RULE(track_data_a->obj),
                                            NMP_OBJECT_CAST_ROUTING_RULE(track_data_b->obj),
                                            NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID)
               == 0);
}

static void
_track_data_destroy(gpointer data)
{
    TrackData *track_data = data;

    _track_data_assert(track_data, FALSE);

    c_list_unlink_stale(&track_data->obj_lst);
    c_list_unlink_stale(&track_data->user_tag_lst);
    nmp_object_unref(track_data->obj);
    g_slice_free(TrackData, track_data);
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

    return td_best;
}

static guint
_track_obj_data_hash(gconstpointer data)
{
    const TrackObjData *obj_data = data;
    NMHashState         h;

    nm_hash_init(&h, 432817559u);
    nm_platform_routing_rule_hash_update(NMP_OBJECT_CAST_ROUTING_RULE(obj_data->obj),
                                         NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID,
                                         &h);
    return nm_hash_complete(&h);
}

static gboolean
_track_obj_data_equal(gconstpointer data_a, gconstpointer data_b)
{
    const TrackObjData *obj_data_a = data_a;
    const TrackObjData *obj_data_b = data_b;

    return (nm_platform_routing_rule_cmp(NMP_OBJECT_CAST_ROUTING_RULE(obj_data_a->obj),
                                         NMP_OBJECT_CAST_ROUTING_RULE(obj_data_b->obj),
                                         NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID)
            == 0);
}

static void
_track_obj_data_destroy(gpointer data)
{
    TrackObjData *obj_data = data;

    c_list_unlink_stale(&obj_data->obj_lst_head);
    nmp_object_unref(obj_data->obj);
    g_slice_free(TrackObjData, obj_data);
}

static guint
_track_user_tag_data_hash(gconstpointer data)
{
    const TrackUserTagData *user_tag_data = data;

    return nm_hash_val(644693447u, user_tag_data->user_tag);
}

static gboolean
_track_user_tag_data_equal(gconstpointer data_a, gconstpointer data_b)
{
    const TrackUserTagData *user_tag_data_a = data_a;
    const TrackUserTagData *user_tag_data_b = data_b;

    return user_tag_data_a->user_tag == user_tag_data_b->user_tag;
}

static void
_track_user_tag_data_destroy(gpointer data)
{
    TrackUserTagData *user_tag_data = data;

    c_list_unlink_stale(&user_tag_data->user_tag_lst_head);
    g_slice_free(TrackUserTagData, user_tag_data);
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

/**
 * nmp_route_manager_track_rule:
 * @self: the #NMPRouteManager instance
 * @routing_rule: the #NMPlatformRoutingRule to track or untrack
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
 *   for the same rule. Note that this is different from a plain nmp_route_manager_untrack_rule(),
 *   because it enforces ownership of the now tracked rule. On the other hand,
 *   a plain nmp_route_manager_untrack_rule() merely forgets about the tracking.
 *   The purpose here is to set this to %NMP_ROUTE_MANAGER_EXTERN_WEAKLY_TRACKED_USER_TAG.
 */
void
nmp_route_manager_track_rule(NMPRouteManager             *self,
                             const NMPlatformRoutingRule *routing_rule,
                             gint32                       track_priority,
                             gconstpointer                user_tag,
                             gconstpointer                user_tag_untrack)
{
    NMPObject         obj_stack;
    const NMPObject  *p_obj_stack;
    TrackData        *track_data;
    TrackObjData     *obj_data;
    TrackUserTagData *user_tag_data;
    gboolean          changed = FALSE;
    guint32           track_priority_val;
    gboolean          track_priority_present;

    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));
    g_return_if_fail(routing_rule);
    g_return_if_fail(user_tag);
    nm_assert(track_priority != G_MININT32);

    p_obj_stack = nmp_object_stackinit(&obj_stack, NMP_OBJECT_TYPE_ROUTING_RULE, routing_rule);

    nm_assert(nmp_object_is_visible(p_obj_stack));

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
            if (track_data_untrack)
                _track_data_untrack(self, track_data_untrack, FALSE, TRUE);
        } else
            nm_assert_not_reached();
    }

    _track_data_assert(track_data, TRUE);

    if (changed) {
        _LOGD("routing-rule: track [" NM_HASH_OBFUSCATE_PTR_FMT ",%s%u] \"%s\")",
              _USER_TAG_LOG(track_data->user_tag),
              (track_data->track_priority_val == 0
                   ? ""
                   : (track_data->track_priority_present ? "+" : "-")),
              (guint) track_data->track_priority_val,
              nmp_object_to_string(track_data->obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
    }
}

static void
_track_data_untrack(NMPRouteManager *self,
                    TrackData       *track_data,
                    gboolean         remove_user_tag_data,
                    gboolean         make_owned_by_us)
{
    TrackObjData *obj_data;

    nm_assert(NMP_IS_ROUTE_MANAGER(self));
    _track_data_assert(track_data, TRUE);
    nm_assert(self->by_data);
    nm_assert(g_hash_table_lookup(self->by_data, track_data) == track_data);

    _LOGD("routing-rule: untrack [" NM_HASH_OBFUSCATE_PTR_FMT "] \"%s\"",
          _USER_TAG_LOG(track_data->user_tag),
          nmp_object_to_string(track_data->obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));

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

void
nmp_route_manager_untrack_rule(NMPRouteManager             *self,
                               const NMPlatformRoutingRule *routing_rule,
                               gconstpointer                user_tag)
{
    NMPObject        obj_stack;
    const NMPObject *p_obj_stack;
    TrackData       *track_data;

    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));
    g_return_if_fail(routing_rule);
    g_return_if_fail(user_tag);

    p_obj_stack = nmp_object_stackinit(&obj_stack, NMP_OBJECT_TYPE_ROUTING_RULE, routing_rule);

    nm_assert(nmp_object_is_visible(p_obj_stack));

    track_data = _track_data_lookup(self->by_data, p_obj_stack, user_tag);
    if (track_data)
        _track_data_untrack(self, track_data, TRUE, FALSE);
}

void
nmp_route_manager_set_dirty(NMPRouteManager *self, gconstpointer user_tag)
{
    TrackData        *track_data;
    TrackUserTagData *user_tag_data;

    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));
    g_return_if_fail(user_tag);

    user_tag_data = g_hash_table_lookup(self->by_user_tag, &user_tag);
    if (!user_tag_data)
        return;

    c_list_for_each_entry (track_data, &user_tag_data->user_tag_lst_head, user_tag_lst)
        track_data->dirty = TRUE;
}

void
nmp_route_manager_untrack_all(NMPRouteManager *self,
                              gconstpointer    user_tag,
                              gboolean         all /* or only dirty */)
{
    TrackData        *track_data;
    TrackData        *track_data_safe;
    TrackUserTagData *user_tag_data;

    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));
    g_return_if_fail(user_tag);

    user_tag_data = g_hash_table_lookup(self->by_user_tag, &user_tag);
    if (!user_tag_data)
        return;

    c_list_for_each_entry_safe (track_data,
                                track_data_safe,
                                &user_tag_data->user_tag_lst_head,
                                user_tag_lst) {
        if (all || track_data->dirty)
            _track_data_untrack(self, track_data, FALSE, FALSE);
    }
    if (c_list_is_empty(&user_tag_data->user_tag_lst_head))
        g_hash_table_remove(self->by_user_tag, user_tag_data);
}

void
nmp_route_manager_sync_rules(NMPRouteManager *self, gboolean keep_deleted_rules)
{
    const NMDedupMultiHeadEntry *pl_head_entry;
    NMDedupMultiIter             pl_iter;
    const NMPObject             *plobj;
    gs_unref_ptrarray GPtrArray *rules_to_delete = NULL;
    TrackObjData                *obj_data;
    GHashTableIter               h_iter;
    guint                        i;
    const TrackData             *td_best;

    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));

    _LOGD("sync%s", keep_deleted_rules ? " (don't remove any rules)" : "");

    pl_head_entry = nm_platform_lookup_obj_type(self->platform, NMP_OBJECT_TYPE_ROUTING_RULE);
    if (pl_head_entry) {
        nmp_cache_iter_for_each (&pl_iter, pl_head_entry, &plobj) {
            obj_data = g_hash_table_lookup(self->by_obj, &plobj);

            if (!obj_data) {
                /* this rule is not tracked. It was externally added, hence we
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

            if (keep_deleted_rules) {
                _LOGD("forget/leak rule added by us: %s",
                      nmp_object_to_string(plobj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
                continue;
            }

            if (!rules_to_delete)
                rules_to_delete = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);

            g_ptr_array_add(rules_to_delete, (gpointer) nmp_object_ref(plobj));

            obj_data->config_state = CONFIG_STATE_REMOVED_BY_US;
        }
    }

    if (rules_to_delete) {
        for (i = 0; i < rules_to_delete->len; i++)
            nm_platform_object_delete(self->platform, rules_to_delete->pdata[i]);
    }

    g_hash_table_iter_init(&h_iter, self->by_obj);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &obj_data, NULL)) {
        td_best = _track_obj_data_get_best_data(obj_data);

        if (!td_best) {
            g_hash_table_iter_remove(&h_iter);
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
        if (plobj)
            continue;

        obj_data->config_state = CONFIG_STATE_ADDED_BY_US;
        nm_platform_routing_rule_add(self->platform,
                                     NMP_NLM_FLAG_ADD,
                                     NMP_OBJECT_CAST_ROUTING_RULE(obj_data->obj));
    }
}

void
nmp_route_manager_track_rule_from_platform(NMPRouteManager *self,
                                           NMPlatform      *platform,
                                           int              addr_family,
                                           gint32           tracking_priority,
                                           gconstpointer    user_tag)
{
    NMPLookup                    lookup;
    const NMDedupMultiHeadEntry *head_entry;
    NMDedupMultiIter             iter;
    const NMPObject             *o;

    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));

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

        nmp_route_manager_track_rule(self, rr, tracking_priority, user_tag, NULL);
    }
}

/*****************************************************************************/

void
nmp_route_manager_track_rule_default(NMPRouteManager *self,
                                     int              addr_family,
                                     gint32           track_priority,
                                     gconstpointer    user_tag)
{
    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));

    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    /* track the default rules. See also `man ip-rule`. */

    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET)) {
        nmp_route_manager_track_rule(self,
                                     &((NMPlatformRoutingRule){
                                         .addr_family = AF_INET,
                                         .priority    = 0,
                                         .table       = RT_TABLE_LOCAL,
                                         .action      = FR_ACT_TO_TBL,
                                         .protocol    = RTPROT_KERNEL,
                                     }),
                                     track_priority,
                                     user_tag,
                                     NULL);
        nmp_route_manager_track_rule(self,
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
        nmp_route_manager_track_rule(self,
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
        nmp_route_manager_track_rule(self,
                                     &((NMPlatformRoutingRule){
                                         .addr_family = AF_INET6,
                                         .priority    = 0,
                                         .table       = RT_TABLE_LOCAL,
                                         .action      = FR_ACT_TO_TBL,
                                         .protocol    = RTPROT_KERNEL,
                                     }),
                                     track_priority,
                                     user_tag,
                                     NULL);
        nmp_route_manager_track_rule(self,
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

/*****************************************************************************/

NMPRouteManager *
nmp_route_manager_new(NMPlatform *platform)
{
    NMPRouteManager *self;

    g_return_val_if_fail(NM_IS_PLATFORM(platform), NULL);

    self  = g_slice_new(NMPRouteManager);
    *self = (NMPRouteManager){
        .ref_count = 1,
        .platform  = g_object_ref(platform),
        .by_data =
            g_hash_table_new_full(_track_data_hash, _track_data_equal, NULL, _track_data_destroy),
        .by_obj      = g_hash_table_new_full(_track_obj_data_hash,
                                        _track_obj_data_equal,
                                        NULL,
                                        _track_obj_data_destroy),
        .by_user_tag = g_hash_table_new_full(_track_user_tag_data_hash,
                                             _track_user_tag_data_equal,
                                             NULL,
                                             _track_user_tag_data_destroy),
    };
    return self;
}

void
nmp_route_manager_ref(NMPRouteManager *self)
{
    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));

    self->ref_count++;
}

void
nmp_route_manager_unref(NMPRouteManager *self)
{
    g_return_if_fail(NMP_IS_ROUTE_MANAGER(self));

    if (--self->ref_count > 0)
        return;

    g_hash_table_destroy(self->by_user_tag);
    g_hash_table_destroy(self->by_obj);
    g_hash_table_destroy(self->by_data);
    g_object_unref(self->platform);
    g_slice_free(NMPRouteManager, self);
}
