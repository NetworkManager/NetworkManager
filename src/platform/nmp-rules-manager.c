/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 */

#include "nm-default.h"

#include "nmp-rules-manager.h"

#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

#include "nm-std-aux/c-list-util.h"
#include "nmp-object.h"

/*****************************************************************************/

struct _NMPRulesManager {
	NMPlatform *platform;
	GHashTable *by_obj;
	GHashTable *by_user_tag;
	GHashTable *by_data;
	guint ref_count;
};

/*****************************************************************************/

static void _rules_init (NMPRulesManager *self);

/*****************************************************************************/

#define _NMLOG_DOMAIN           LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME      "rules-manager"

#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            _nm_log (__level, _NMLOG_DOMAIN, 0, NULL, NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static gboolean
NMP_IS_RULES_MANAGER (gpointer self)
{
	return    self
	       && ((NMPRulesManager *) self)->ref_count > 0
	       && NM_IS_PLATFORM (((NMPRulesManager *) self)->platform);
}

#define _USER_TAG_LOG(user_tag) nm_hash_obfuscate_ptr (1240261787u, (user_tag))

/*****************************************************************************/

typedef struct {
	const NMPObject *obj;
	gconstpointer user_tag;
	CList obj_lst;
	CList user_tag_lst;

	/* track_priority_val zero is special: those are weakly tracked rules.
	 * That means: NetworkManager will restore them only if it removed them earlier.
	 * But it will not remove or add them otherwise.
	 *
	 * Otherwise, the track_priority_val goes together with track_priority_present.
	 * In case of one rule being tracked multile times (with different priorities),
	 * the one with higher priority wins. See _rules_obj_get_best_data().
	 * Then, the winning present state either enforces that the rule is present
	 * or absent.
	 *
	 * If a rules is not tracked at all, it is ignored by NetworkManager. Assuming
	 * that it was added externally by the user. But unlike weakly tracked rules,
	 * NM will *not* restore such rules if NetworkManager themself removed them. */
	guint32 track_priority_val;
	bool track_priority_present:1;

	bool dirty:1;
} RulesData;

typedef enum {
	CONFIG_STATE_NONE          = 0,
	CONFIG_STATE_ADDED_BY_US   = 1,
	CONFIG_STATE_REMOVED_BY_US = 2,
} ConfigState;

typedef struct {
	const NMPObject *obj;
	CList obj_lst_head;

	/* indicates whether we configured/removed the rule (during sync()). We need that, so
	 * if the rule gets untracked, that we know to remove/restore it.
	 *
	 * This makes NMPRulesManager stateful (beyond the configuration that indicates
	 * which rules are tracked).
	 * After a restart, NetworkManager would no longer remember which rules were added
	 * by us. That would need to be fixed by persisting the state and reloading it after
	 * restart. */
	ConfigState config_state;
} RulesObjData;

typedef struct {
	gconstpointer user_tag;
	CList user_tag_lst_head;
} RulesUserTagData;

static void
_rules_data_assert (const RulesData *rules_data, gboolean linked)
{
	nm_assert (rules_data);
	nm_assert (NMP_OBJECT_GET_TYPE (rules_data->obj) == NMP_OBJECT_TYPE_ROUTING_RULE);
	nm_assert (nmp_object_is_visible (rules_data->obj));
	nm_assert (rules_data->user_tag);
	nm_assert (!linked || !c_list_is_empty (&rules_data->obj_lst));
	nm_assert (!linked || !c_list_is_empty (&rules_data->user_tag_lst));
}

static guint
_rules_data_hash (gconstpointer data)
{
	const RulesData *rules_data = data;
	NMHashState h;

	_rules_data_assert (rules_data, FALSE);

	nm_hash_init (&h, 269297543u);
	nm_platform_routing_rule_hash_update (NMP_OBJECT_CAST_ROUTING_RULE (rules_data->obj),
	                                      NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID,
	                                      &h);
	nm_hash_update_val (&h, rules_data->user_tag);
	return nm_hash_complete (&h);
}

static gboolean
_rules_data_equal (gconstpointer data_a, gconstpointer data_b)
{
	const RulesData *rules_data_a = data_a;
	const RulesData *rules_data_b = data_b;

	_rules_data_assert (rules_data_a, FALSE);
	_rules_data_assert (rules_data_b, FALSE);

	return    rules_data_a->user_tag == rules_data_b->user_tag
	       && (nm_platform_routing_rule_cmp (NMP_OBJECT_CAST_ROUTING_RULE (rules_data_a->obj),
	                                         NMP_OBJECT_CAST_ROUTING_RULE (rules_data_b->obj),
	                                         NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID) == 0);
}

static void
_rules_data_destroy (gpointer data)
{
	RulesData *rules_data = data;

	_rules_data_assert (rules_data, FALSE);

	c_list_unlink_stale (&rules_data->obj_lst);
	c_list_unlink_stale (&rules_data->user_tag_lst);
	nmp_object_unref (rules_data->obj);
	g_slice_free (RulesData, rules_data);
}

static const RulesData *
_rules_obj_get_best_data (RulesObjData *obj_data)
{
	RulesData *rules_data;
	const RulesData *rd_best = NULL;

	c_list_for_each_entry (rules_data, &obj_data->obj_lst_head, obj_lst) {

		_rules_data_assert (rules_data, TRUE);

		if (rd_best) {
			if (rd_best->track_priority_val > rules_data->track_priority_val)
				continue;
			if (rd_best->track_priority_val == rules_data->track_priority_val) {
				if (   rd_best->track_priority_present
				    || !rules_data->track_priority_present) {
					/* if the priorities are identical, then "present" wins over
					 * "!present" (absent). */
					continue;
				}
			}
		}

		rd_best = rules_data;
	}

	return rd_best;
}

static guint
_rules_obj_hash (gconstpointer data)
{
	const RulesObjData *obj_data = data;
	NMHashState h;

	nm_hash_init (&h, 432817559u);
	nm_platform_routing_rule_hash_update (NMP_OBJECT_CAST_ROUTING_RULE (obj_data->obj),
	                                      NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID,
	                                      &h);
	return nm_hash_complete (&h);
}

static gboolean
_rules_obj_equal (gconstpointer data_a, gconstpointer data_b)
{
	const RulesObjData *obj_data_a = data_a;
	const RulesObjData *obj_data_b = data_b;

	return (nm_platform_routing_rule_cmp (NMP_OBJECT_CAST_ROUTING_RULE (obj_data_a->obj),
	                                      NMP_OBJECT_CAST_ROUTING_RULE (obj_data_b->obj),
	                                      NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID) == 0);
}

static void
_rules_obj_destroy (gpointer data)
{
	RulesObjData *obj_data = data;

	c_list_unlink_stale (&obj_data->obj_lst_head);
	nmp_object_unref (obj_data->obj);
	g_slice_free (RulesObjData, obj_data);
}

static guint
_rules_user_tag_hash (gconstpointer data)
{
	const RulesUserTagData *user_tag_data = data;

	return nm_hash_val (644693447u, user_tag_data->user_tag);
}

static gboolean
_rules_user_tag_equal (gconstpointer data_a, gconstpointer data_b)
{
	const RulesUserTagData *user_tag_data_a = data_a;
	const RulesUserTagData *user_tag_data_b = data_b;

	return user_tag_data_a->user_tag == user_tag_data_b->user_tag;
}

static void
_rules_user_tag_destroy (gpointer data)
{
	RulesUserTagData *user_tag_data = data;

	c_list_unlink_stale (&user_tag_data->user_tag_lst_head);
	g_slice_free (RulesUserTagData, user_tag_data);
}

static RulesData *
_rules_data_lookup (GHashTable *by_data,
                    const NMPObject *obj,
                    gconstpointer user_tag)
{
	RulesData rules_data_needle = {
		.obj      = obj,
		.user_tag = user_tag,
	};

	return g_hash_table_lookup (by_data, &rules_data_needle);
}

void
nmp_rules_manager_track (NMPRulesManager *self,
                         const NMPlatformRoutingRule *routing_rule,
                         gint32 track_priority,
                         gconstpointer user_tag)
{
	NMPObject obj_stack;
	const NMPObject *p_obj_stack;
	RulesData *rules_data;
	RulesObjData *obj_data;
	RulesUserTagData *user_tag_data;
	gboolean changed = FALSE;
	guint32 track_priority_val;
	gboolean track_priority_present;

	g_return_if_fail (NMP_IS_RULES_MANAGER (self));
	g_return_if_fail (routing_rule);
	g_return_if_fail (user_tag);
	nm_assert (track_priority != G_MININT32);

	_rules_init (self);

	p_obj_stack = nmp_object_stackinit (&obj_stack, NMP_OBJECT_TYPE_ROUTING_RULE, routing_rule);

	nm_assert (nmp_object_is_visible (p_obj_stack));

	if (track_priority >= 0) {
		track_priority_val = track_priority;
		track_priority_present = TRUE;
	} else {
		track_priority_val = -track_priority;
		track_priority_present = FALSE;
	}

	rules_data = _rules_data_lookup (self->by_data, p_obj_stack, user_tag);

	if (!rules_data) {
		rules_data = g_slice_new (RulesData);
		*rules_data = (RulesData) {
			.obj                    = nm_dedup_multi_index_obj_intern (nm_platform_get_multi_idx (self->platform),
			                                                           p_obj_stack),
			.user_tag               = user_tag,
			.track_priority_val     = track_priority_val,
			.track_priority_present = track_priority_present,
			.dirty                  = FALSE,
		};
		g_hash_table_add (self->by_data, rules_data);

		obj_data = g_hash_table_lookup (self->by_obj, &rules_data->obj);
		if (!obj_data) {
			obj_data = g_slice_new (RulesObjData);
			*obj_data = (RulesObjData) {
				.obj          = nmp_object_ref (rules_data->obj),
				.obj_lst_head = C_LIST_INIT (obj_data->obj_lst_head),
				.config_state = CONFIG_STATE_NONE,
			};
			g_hash_table_add (self->by_obj, obj_data);
		}
		c_list_link_tail (&obj_data->obj_lst_head, &rules_data->obj_lst);

		user_tag_data = g_hash_table_lookup (self->by_user_tag, &rules_data->user_tag);
		if (!user_tag_data) {
			user_tag_data = g_slice_new (RulesUserTagData);
			*user_tag_data = (RulesUserTagData) {
				.user_tag          = user_tag,
				.user_tag_lst_head = C_LIST_INIT (user_tag_data->user_tag_lst_head),
			};
			g_hash_table_add (self->by_user_tag, user_tag_data);
		}
		c_list_link_tail (&user_tag_data->user_tag_lst_head, &rules_data->user_tag_lst);
		changed = TRUE;
	} else {
		rules_data->dirty = FALSE;
		if (   rules_data->track_priority_val != track_priority_val
		    || rules_data->track_priority_present != track_priority_present) {
			rules_data->track_priority_val = track_priority_val;
			rules_data->track_priority_present = track_priority_present;
			changed = TRUE;
		}
	}

	_rules_data_assert (rules_data, TRUE);

	if (changed) {
		_LOGD ("routing-rule: track ["NM_HASH_OBFUSCATE_PTR_FMT",%s%u] \"%s\")",
		       _USER_TAG_LOG (rules_data->user_tag),
		       ( rules_data->track_priority_val == 0
		        ? ""
		        : (  rules_data->track_priority_present
		           ? "+"
		           : "-")),
		       (guint) rules_data->track_priority_val,
		       nmp_object_to_string (rules_data->obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
	}
}

static void
_rules_data_untrack (NMPRulesManager *self,
                     RulesData *rules_data,
                     gboolean remove_user_tag_data)
{
	RulesObjData *obj_data;

	nm_assert (NMP_IS_RULES_MANAGER (self));
	_rules_data_assert (rules_data, TRUE);
	nm_assert (self->by_data);
	nm_assert (g_hash_table_lookup (self->by_data, rules_data) == rules_data);

	_LOGD ("routing-rule: untrack ["NM_HASH_OBFUSCATE_PTR_FMT"] \"%s\"",
	       _USER_TAG_LOG (rules_data->user_tag),
	       nmp_object_to_string (rules_data->obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));

#if NM_MORE_ASSERTS
	{
		RulesUserTagData *user_tag_data;

		user_tag_data = g_hash_table_lookup (self->by_user_tag, &rules_data->user_tag);
		nm_assert (user_tag_data);
		nm_assert (c_list_contains (&user_tag_data->user_tag_lst_head, &rules_data->user_tag_lst));
	}
#endif

	nm_assert (!c_list_is_empty (&rules_data->user_tag_lst));
	if (   remove_user_tag_data
	    && c_list_length_is (&rules_data->user_tag_lst, 1))
		g_hash_table_remove (self->by_user_tag, &rules_data->user_tag);

	obj_data = g_hash_table_lookup (self->by_obj, &rules_data->obj);
	nm_assert (obj_data);
	nm_assert (c_list_contains (&obj_data->obj_lst_head, &rules_data->obj_lst));
	nm_assert (obj_data == g_hash_table_lookup (self->by_obj, &rules_data->obj));

	/* if obj_data is marked to be "added_by_us" or "removed_by_us", we need to keep this entry
	 * around for the next sync -- so that we can undo what we did earlier. */
	if (   obj_data->config_state == CONFIG_STATE_NONE
	    && c_list_length_is (&rules_data->obj_lst, 1))
		g_hash_table_remove (self->by_obj, &rules_data->obj);

	g_hash_table_remove (self->by_data, rules_data);
}

void
nmp_rules_manager_untrack (NMPRulesManager *self,
                           const NMPlatformRoutingRule *routing_rule,
                           gconstpointer user_tag)
{
	NMPObject obj_stack;
	const NMPObject *p_obj_stack;
	RulesData *rules_data;

	g_return_if_fail (NMP_IS_RULES_MANAGER (self));
	g_return_if_fail (routing_rule);
	g_return_if_fail (user_tag);

	_rules_init (self);

	p_obj_stack = nmp_object_stackinit (&obj_stack, NMP_OBJECT_TYPE_ROUTING_RULE, routing_rule);

	nm_assert (nmp_object_is_visible (p_obj_stack));

	rules_data = _rules_data_lookup (self->by_data, p_obj_stack, user_tag);
	if (rules_data)
		_rules_data_untrack (self, rules_data, TRUE);
}

void
nmp_rules_manager_set_dirty (NMPRulesManager *self,
                             gconstpointer user_tag)
{
	RulesData *rules_data;
	RulesUserTagData *user_tag_data;

	g_return_if_fail (NMP_IS_RULES_MANAGER (self));
	g_return_if_fail (user_tag);

	if (!self->by_data)
		return;

	user_tag_data = g_hash_table_lookup (self->by_user_tag, &user_tag);
	if (!user_tag_data)
		return;

	c_list_for_each_entry (rules_data, &user_tag_data->user_tag_lst_head, user_tag_lst)
		rules_data->dirty = TRUE;
}

void
nmp_rules_manager_untrack_all (NMPRulesManager *self,
                               gconstpointer user_tag,
                               gboolean all /* or only dirty */)
{
	RulesData *rules_data;
	RulesData *rules_data_safe;
	RulesUserTagData *user_tag_data;

	g_return_if_fail (NMP_IS_RULES_MANAGER (self));
	g_return_if_fail (user_tag);

	if (!self->by_data)
		return;

	user_tag_data = g_hash_table_lookup (self->by_user_tag, &user_tag);
	if (!user_tag_data)
		return;

	c_list_for_each_entry_safe (rules_data, rules_data_safe, &user_tag_data->user_tag_lst_head, user_tag_lst) {
		if (   all
		    || rules_data->dirty)
			_rules_data_untrack (self, rules_data, FALSE);
	}
	if (c_list_is_empty (&user_tag_data->user_tag_lst_head))
		g_hash_table_remove (self->by_user_tag, user_tag_data);
}

void
nmp_rules_manager_sync (NMPRulesManager *self,
                        gboolean keep_deleted_rules)
{
	const NMDedupMultiHeadEntry *pl_head_entry;
	NMDedupMultiIter pl_iter;
	const NMPObject *plobj;
	gs_unref_ptrarray GPtrArray *rules_to_delete = NULL;
	RulesObjData *obj_data;
	GHashTableIter h_iter;
	guint i;
	const RulesData *rd_best;

	g_return_if_fail (NMP_IS_RULES_MANAGER (self));

	if (!self->by_data)
		return;

	_LOGD ("sync%s", keep_deleted_rules ? " (don't remove any rules)" : "");

	pl_head_entry = nm_platform_lookup_obj_type (self->platform, NMP_OBJECT_TYPE_ROUTING_RULE);
	if (pl_head_entry) {
		nmp_cache_iter_for_each (&pl_iter, pl_head_entry, &plobj) {
			obj_data = g_hash_table_lookup (self->by_obj, &plobj);

			if (!obj_data) {
				/* this rule is not tracked. It was externally added, hence we
				 * ignore it. */
				continue;
			}

			rd_best = _rules_obj_get_best_data (obj_data);
			if (rd_best) {
				if (rd_best->track_priority_present)
					continue;
				if (rd_best->track_priority_val == 0) {
					if (obj_data->config_state != CONFIG_STATE_ADDED_BY_US)
						continue;
					obj_data->config_state = CONFIG_STATE_NONE;
				}
			}

			if (keep_deleted_rules) {
				_LOGD ("forget/leak rule added by us: %s", nmp_object_to_string (plobj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
				continue;
			}

			if (!rules_to_delete)
				rules_to_delete = g_ptr_array_new_with_free_func ((GDestroyNotify) nmp_object_unref);

			g_ptr_array_add (rules_to_delete, (gpointer) nmp_object_ref (plobj));

			obj_data->config_state = CONFIG_STATE_REMOVED_BY_US;
		}
	}

	if (rules_to_delete) {
		for (i = 0; i < rules_to_delete->len; i++)
			nm_platform_object_delete (self->platform, rules_to_delete->pdata[i]);
	}

	g_hash_table_iter_init (&h_iter, self->by_obj);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &obj_data, NULL)) {

		rd_best = _rules_obj_get_best_data (obj_data);

		if (!rd_best) {
			g_hash_table_iter_remove (&h_iter);
			continue;
		}

		if (!rd_best->track_priority_present)
			continue;
		if (rd_best->track_priority_val == 0) {
			if (obj_data->config_state != CONFIG_STATE_REMOVED_BY_US)
				continue;
			obj_data->config_state = CONFIG_STATE_NONE;
		}

		plobj = nm_platform_lookup_obj (self->platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj_data->obj);
		if (plobj)
			continue;

		obj_data->config_state = CONFIG_STATE_ADDED_BY_US;
		nm_platform_routing_rule_add (self->platform, NMP_NLM_FLAG_ADD, NMP_OBJECT_CAST_ROUTING_RULE (obj_data->obj));
	}
}

void
nmp_rules_manager_track_from_platform (NMPRulesManager *self,
                                       NMPlatform *platform,
                                       int addr_family,
                                       gint32 tracking_priority,
                                       gconstpointer user_tag)
{
	NMPLookup lookup;
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter iter;
	const NMPObject *o;

	g_return_if_fail (NMP_IS_RULES_MANAGER (self));

	if (!platform)
		platform = self->platform;
	else
		g_return_if_fail (NM_IS_PLATFORM (platform));

	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
	head_entry = nm_platform_lookup (platform, &lookup);
	nmp_cache_iter_for_each (&iter, head_entry, &o) {
		const NMPlatformRoutingRule *rr = NMP_OBJECT_CAST_ROUTING_RULE (o);

		if (   addr_family != AF_UNSPEC
		    && rr->addr_family != addr_family)
			continue;

		nmp_rules_manager_track (self, rr, tracking_priority, user_tag);
	}
}

/*****************************************************************************/

void
nmp_rules_manager_track_default (NMPRulesManager *self,
                                 int addr_family,
                                 gint32 track_priority,
                                 gconstpointer user_tag)
{
	g_return_if_fail (NMP_IS_RULES_MANAGER (self));

	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	/* track the default rules. See also `man ip-rule`. */

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET)) {
		nmp_rules_manager_track (self,
		                         &((NMPlatformRoutingRule) {
		                             .addr_family = AF_INET,
		                             .priority    = 0,
		                             .table       = RT_TABLE_LOCAL,
		                             .action      = FR_ACT_TO_TBL,
		                             .protocol    = RTPROT_KERNEL,
		                         }),
		                         track_priority,
		                         user_tag);
		nmp_rules_manager_track (self,
		                         &((NMPlatformRoutingRule) {
		                             .addr_family = AF_INET,
		                             .priority    = 32766,
		                             .table       = RT_TABLE_MAIN,
		                             .action      = FR_ACT_TO_TBL,
		                             .protocol    = RTPROT_KERNEL,
		                         }),
		                         track_priority,
		                         user_tag);
		nmp_rules_manager_track (self,
		                         &((NMPlatformRoutingRule) {
		                             .addr_family = AF_INET,
		                             .priority    = 32767,
		                             .table       = RT_TABLE_DEFAULT,
		                             .action      = FR_ACT_TO_TBL,
		                             .protocol    = RTPROT_KERNEL,
		                         }),
		                         track_priority,
		                         user_tag);
	}
	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6)) {
		nmp_rules_manager_track (self,
		                         &((NMPlatformRoutingRule) {
		                             .addr_family = AF_INET6,
		                             .priority    = 0,
		                             .table       = RT_TABLE_LOCAL,
		                             .action      = FR_ACT_TO_TBL,
		                             .protocol    = RTPROT_KERNEL,
		                         }),
		                         track_priority,
		                         user_tag);
		nmp_rules_manager_track (self,
		                         &((NMPlatformRoutingRule) {
		                             .addr_family = AF_INET6,
		                             .priority    = 32766,
		                             .table       = RT_TABLE_MAIN,
		                             .action      = FR_ACT_TO_TBL,
		                             .protocol    = RTPROT_KERNEL,
		                         }),
		                         track_priority,
		                         user_tag);
	}
}

static void
_rules_init (NMPRulesManager *self)
{
	if (self->by_data)
		return;

	self->by_data      = g_hash_table_new_full (_rules_data_hash,      _rules_data_equal,      NULL, _rules_data_destroy);
	self->by_obj       = g_hash_table_new_full (_rules_obj_hash,       _rules_obj_equal,       NULL, _rules_obj_destroy);
	self->by_user_tag  = g_hash_table_new_full (_rules_user_tag_hash,  _rules_user_tag_equal,  NULL, _rules_user_tag_destroy);
}

/*****************************************************************************/

NMPRulesManager *
nmp_rules_manager_new (NMPlatform *platform)
{
	NMPRulesManager *self;

	g_return_val_if_fail (NM_IS_PLATFORM (platform), NULL);

	self = g_slice_new (NMPRulesManager);
	*self = (NMPRulesManager) {
		.ref_count     = 1,
		.platform      = g_object_ref (platform),
	};
	return self;
}

void
nmp_rules_manager_ref (NMPRulesManager *self)
{
	g_return_if_fail (NMP_IS_RULES_MANAGER (self));

	self->ref_count++;
}

void nmp_rules_manager_unref (NMPRulesManager *self)
{
	g_return_if_fail (NMP_IS_RULES_MANAGER (self));

	if (--self->ref_count > 0)
		return;

	if (self->by_data) {
		g_hash_table_destroy (self->by_user_tag);
		g_hash_table_destroy (self->by_obj);
		g_hash_table_destroy (self->by_data);
	}
	g_object_unref (self->platform);
	g_slice_free (NMPRulesManager, self);
}
