/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
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
 *
 * (C) Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dedup-multi.h"

#include "nm-hash-utils.h"
#include "nm-c-list.h"

/*****************************************************************************/

typedef struct {
	/* the stack-allocated lookup entry. It has a compatible
	 * memory layout with NMDedupMultiEntry and NMDedupMultiHeadEntry.
	 *
	 * It is recognizable by having lst_entries_sentinel.next set to NULL.
	 * Contrary to the other entries, which have lst_entries.next
	 * always non-NULL.
	 * */
	CList lst_entries_sentinel;
	const NMDedupMultiObj *obj;
	const NMDedupMultiIdxType *idx_type;
	bool lookup_head;
} LookupEntry;

struct _NMDedupMultiIndex {
	int ref_count;
	GHashTable *idx_entries;
	GHashTable *idx_objs;
};

/*****************************************************************************/

static void
ASSERT_idx_type (const NMDedupMultiIdxType *idx_type)
{
	nm_assert (idx_type);
#if NM_MORE_ASSERTS > 10
	nm_assert (idx_type->klass);
	nm_assert (idx_type->klass->idx_obj_id_hash_update);
	nm_assert (idx_type->klass->idx_obj_id_equal);
	nm_assert (!!idx_type->klass->idx_obj_partition_hash_update == !!idx_type->klass->idx_obj_partition_equal);
	nm_assert (idx_type->lst_idx_head.next);
#endif
}

void
nm_dedup_multi_idx_type_init (NMDedupMultiIdxType *idx_type,
                              const NMDedupMultiIdxTypeClass *klass)
{
	nm_assert (idx_type);
	nm_assert (klass);

	memset (idx_type, 0, sizeof (*idx_type));
	idx_type->klass = klass;
	c_list_init (&idx_type->lst_idx_head);

	ASSERT_idx_type (idx_type);
}

/*****************************************************************************/

static NMDedupMultiEntry *
_entry_lookup_obj (const NMDedupMultiIndex *self,
                   const NMDedupMultiIdxType *idx_type,
                   const NMDedupMultiObj *obj)
{
	const LookupEntry stack_entry = {
		.obj = obj,
		.idx_type = idx_type,
		.lookup_head = FALSE,
	};

	ASSERT_idx_type (idx_type);
	return g_hash_table_lookup (self->idx_entries, &stack_entry);
}

static NMDedupMultiHeadEntry *
_entry_lookup_head (const NMDedupMultiIndex *self,
                    const NMDedupMultiIdxType *idx_type,
                    const NMDedupMultiObj *obj)
{
	NMDedupMultiHeadEntry *head_entry;
	const LookupEntry stack_entry = {
		.obj = obj,
		.idx_type = idx_type,
		.lookup_head = TRUE,
	};

	ASSERT_idx_type (idx_type);

	if (!idx_type->klass->idx_obj_partition_equal) {
		if (c_list_is_empty (&idx_type->lst_idx_head))
			head_entry = NULL;
		else {
			nm_assert (c_list_length (&idx_type->lst_idx_head) == 1);
			head_entry = c_list_entry (idx_type->lst_idx_head.next, NMDedupMultiHeadEntry, lst_idx);
		}
		nm_assert (head_entry == g_hash_table_lookup (self->idx_entries, &stack_entry));
		return head_entry;
	}

	return g_hash_table_lookup (self->idx_entries, &stack_entry);
}

static void
_entry_unpack (const NMDedupMultiEntry *entry,
               const NMDedupMultiIdxType **out_idx_type,
               const NMDedupMultiObj **out_obj,
               gboolean *out_lookup_head)
{
	const NMDedupMultiHeadEntry *head_entry;
	const LookupEntry *lookup_entry;

	nm_assert (entry);

	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (LookupEntry, lst_entries_sentinel) == G_STRUCT_OFFSET (NMDedupMultiEntry, lst_entries));
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMDedupMultiEntry, lst_entries) == G_STRUCT_OFFSET (NMDedupMultiHeadEntry, lst_entries_head));
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMDedupMultiEntry, obj) == G_STRUCT_OFFSET (NMDedupMultiHeadEntry, idx_type));
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMDedupMultiEntry, is_head) == G_STRUCT_OFFSET (NMDedupMultiHeadEntry, is_head));

	if (!entry->lst_entries.next) {
		/* the entry is stack-allocated by _entry_lookup(). */
		lookup_entry = (LookupEntry *) entry;
		*out_obj = lookup_entry->obj;
		*out_idx_type = lookup_entry->idx_type;
		*out_lookup_head = lookup_entry->lookup_head;
	} else if (entry->is_head) {
		head_entry = (NMDedupMultiHeadEntry *) entry;
		nm_assert (!c_list_is_empty (&head_entry->lst_entries_head));
		*out_obj = c_list_entry (head_entry->lst_entries_head.next, NMDedupMultiEntry, lst_entries)->obj;
		*out_idx_type = head_entry->idx_type;
		*out_lookup_head = TRUE;
	} else {
		*out_obj = entry->obj;
		*out_idx_type = entry->head->idx_type;
		*out_lookup_head = FALSE;
	}

	nm_assert (NM_IN_SET (*out_lookup_head, FALSE, TRUE));
	ASSERT_idx_type (*out_idx_type);

	/* for lookup of the head, we allow to omit object, but only
	 * if the idx_type does not partition the objects. Otherwise, we
	 * require a obj to compare. */
	nm_assert (   !*out_lookup_head
	           || (   *out_obj
	               || !(*out_idx_type)->klass->idx_obj_partition_equal));

	/* lookup of the object requires always an object. */
	nm_assert (   *out_lookup_head
	           || *out_obj);
}

static guint
_dict_idx_entries_hash (const NMDedupMultiEntry *entry)
{
	const NMDedupMultiIdxType *idx_type;
	const NMDedupMultiObj *obj;
	gboolean lookup_head;
	NMHashState h;

	_entry_unpack (entry, &idx_type, &obj, &lookup_head);

	nm_hash_init (&h, 1914869417u);
	if (idx_type->klass->idx_obj_partition_hash_update) {
		nm_assert (obj);
		idx_type->klass->idx_obj_partition_hash_update (idx_type, obj, &h);
	}

	if (!lookup_head)
		idx_type->klass->idx_obj_id_hash_update (idx_type, obj, &h);

	nm_hash_update_val (&h, idx_type);
	return nm_hash_complete (&h);
}

static gboolean
_dict_idx_entries_equal (const NMDedupMultiEntry *entry_a,
                         const NMDedupMultiEntry *entry_b)
{
	const NMDedupMultiIdxType *idx_type_a, *idx_type_b;
	const NMDedupMultiObj *obj_a, *obj_b;
	gboolean lookup_head_a, lookup_head_b;

	_entry_unpack (entry_a, &idx_type_a, &obj_a, &lookup_head_a);
	_entry_unpack (entry_b, &idx_type_b, &obj_b, &lookup_head_b);

	if (   idx_type_a != idx_type_b
	    || lookup_head_a != lookup_head_b)
		return FALSE;
	if (!nm_dedup_multi_idx_type_partition_equal (idx_type_a, obj_a, obj_b))
		return FALSE;
	if (   !lookup_head_a
	    && !nm_dedup_multi_idx_type_id_equal (idx_type_a, obj_a, obj_b))
		return FALSE;
	return TRUE;
}

/*****************************************************************************/

static gboolean
_add (NMDedupMultiIndex *self,
      NMDedupMultiIdxType *idx_type,
      const NMDedupMultiObj *obj,
      NMDedupMultiEntry *entry,
      NMDedupMultiIdxMode mode,
      const NMDedupMultiEntry *entry_order,
      NMDedupMultiHeadEntry *head_existing,
      const NMDedupMultiEntry **out_entry,
      const NMDedupMultiObj **out_obj_old)
{
	NMDedupMultiHeadEntry *head_entry;
	const NMDedupMultiObj *obj_new, *obj_old;
	gboolean add_head_entry = FALSE;

	nm_assert (self);
	ASSERT_idx_type (idx_type);
	nm_assert (obj);
	nm_assert (NM_IN_SET (mode,
	                      NM_DEDUP_MULTI_IDX_MODE_PREPEND,
	                      NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE,
	                      NM_DEDUP_MULTI_IDX_MODE_APPEND,
	                      NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE));
	nm_assert (!head_existing || head_existing->idx_type == idx_type);
	nm_assert (({
	                const NMDedupMultiHeadEntry *_h;
	                gboolean _ok = TRUE;
	                if (head_existing) {
	                    _h = nm_dedup_multi_index_lookup_head (self, idx_type, obj);
	                    if (head_existing == NM_DEDUP_MULTI_HEAD_ENTRY_MISSING)
	                        _ok = (_h == NULL);
	                    else
	                        _ok = (_h == head_existing);
	                }
	                _ok;
	            }));

	if (entry) {
		gboolean changed = FALSE;

		nm_dedup_multi_entry_set_dirty (entry, FALSE);

		nm_assert (!head_existing || entry->head == head_existing);
		nm_assert (!entry_order || entry_order->head == entry->head);
		nm_assert (!entry_order || c_list_contains (&entry->lst_entries, &entry_order->lst_entries));
		nm_assert (!entry_order || c_list_contains (&entry_order->lst_entries, &entry->lst_entries));

		switch (mode) {
		case NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE:
			if (entry_order) {
				if (nm_c_list_move_before ((CList *) &entry_order->lst_entries, &entry->lst_entries))
					changed = TRUE;
			} else {
				if (nm_c_list_move_front ((CList *) &entry->head->lst_entries_head, &entry->lst_entries))
					changed = TRUE;
			}
			break;
		case NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE:
			if (entry_order) {
				if (nm_c_list_move_after ((CList *) &entry_order->lst_entries, &entry->lst_entries))
					changed = TRUE;
			} else {
				if (nm_c_list_move_tail ((CList *) &entry->head->lst_entries_head, &entry->lst_entries))
					changed = TRUE;
			}
			break;
		case NM_DEDUP_MULTI_IDX_MODE_PREPEND:
		case NM_DEDUP_MULTI_IDX_MODE_APPEND:
			break;
		};

		nm_assert (obj->klass == ((const NMDedupMultiObj *) entry->obj)->klass);
		if (   obj == entry->obj
		    || obj->klass->obj_full_equal (obj,
		                                   entry->obj)) {
			NM_SET_OUT (out_entry, entry);
			NM_SET_OUT (out_obj_old, nm_dedup_multi_obj_ref (entry->obj));
			return changed;
		}

		obj_new = nm_dedup_multi_index_obj_intern (self, obj);

		obj_old = entry->obj;
		entry->obj = obj_new;

		NM_SET_OUT (out_entry, entry);
		if (out_obj_old)
			*out_obj_old = obj_old;
		else
			nm_dedup_multi_obj_unref (obj_old);
		return TRUE;
	}

	if (    idx_type->klass->idx_obj_partitionable
	    && !idx_type->klass->idx_obj_partitionable (idx_type, obj)) {
		/* this object cannot be partitioned by this idx_type. */
		nm_assert (!head_existing || head_existing == NM_DEDUP_MULTI_HEAD_ENTRY_MISSING);
		NM_SET_OUT (out_entry, NULL);
		NM_SET_OUT (out_obj_old, NULL);
		return FALSE;
	}

	obj_new = nm_dedup_multi_index_obj_intern (self, obj);

	if (!head_existing)
		head_entry = _entry_lookup_head (self, idx_type, obj_new);
	else if (head_existing == NM_DEDUP_MULTI_HEAD_ENTRY_MISSING)
		head_entry = NULL;
	else
		head_entry = head_existing;

	if (!head_entry) {
		head_entry = g_slice_new0 (NMDedupMultiHeadEntry);
		head_entry->is_head = TRUE;
		head_entry->idx_type = idx_type;
		c_list_init (&head_entry->lst_entries_head);
		c_list_link_tail (&idx_type->lst_idx_head, &head_entry->lst_idx);
		add_head_entry = TRUE;
	} else
		nm_assert (c_list_contains (&idx_type->lst_idx_head, &head_entry->lst_idx));

	if (entry_order) {
		nm_assert (!add_head_entry);
		nm_assert (entry_order->head == head_entry);
		nm_assert (c_list_contains (&head_entry->lst_entries_head, &entry_order->lst_entries));
		nm_assert (c_list_contains (&entry_order->lst_entries, &head_entry->lst_entries_head));
	}

	entry = g_slice_new0 (NMDedupMultiEntry);
	entry->obj = obj_new;
	entry->head = head_entry;

	switch (mode) {
	case NM_DEDUP_MULTI_IDX_MODE_PREPEND:
	case NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE:
		if (entry_order)
			c_list_link_before ((CList *) &entry_order->lst_entries, &entry->lst_entries);
		else
			c_list_link_front (&head_entry->lst_entries_head, &entry->lst_entries);
		break;
	default:
		if (entry_order)
			c_list_link_after ((CList *) &entry_order->lst_entries, &entry->lst_entries);
		else
			c_list_link_tail (&head_entry->lst_entries_head, &entry->lst_entries);
		break;
	};

	idx_type->len++;
	head_entry->len++;

	if (   add_head_entry
	    && !g_hash_table_add (self->idx_entries, head_entry))
		nm_assert_not_reached ();

	if (!g_hash_table_add (self->idx_entries, entry))
		nm_assert_not_reached ();

	NM_SET_OUT (out_entry, entry);
	NM_SET_OUT (out_obj_old, NULL);
	return TRUE;
}

gboolean
nm_dedup_multi_index_add (NMDedupMultiIndex *self,
                          NMDedupMultiIdxType *idx_type,
                          /*const NMDedupMultiObj * */ gconstpointer obj,
                          NMDedupMultiIdxMode mode,
                          const NMDedupMultiEntry **out_entry,
                          /* const NMDedupMultiObj ** */ gpointer out_obj_old)
{
	NMDedupMultiEntry *entry;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (idx_type, FALSE);
	g_return_val_if_fail (obj, FALSE);
	g_return_val_if_fail (NM_IN_SET (mode,
	                                 NM_DEDUP_MULTI_IDX_MODE_PREPEND,
	                                 NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE,
	                                 NM_DEDUP_MULTI_IDX_MODE_APPEND,
	                                 NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE),
	                      FALSE);

	entry = _entry_lookup_obj (self, idx_type, obj);
	return _add (self, idx_type, obj,
	             entry, mode,
	             NULL, NULL,
	             out_entry, out_obj_old);
}

/* nm_dedup_multi_index_add_full:
 * @self: the index instance.
 * @idx_type: the index handle for storing @obj.
 * @obj: the NMDedupMultiObj instance to add.
 * @mode: whether to append or prepend the new item. If @entry_order is given,
 *   the entry will be sorted after/before, instead of appending/prepending to
 *   the entire list. If a comparable object is already tracked, then it may
 *   still be resorted by specifying one of the "FORCE" modes.
 * @entry_order: if not NULL, the new entry will be sorted before or after @entry_order.
 *   If given, @entry_order MUST be tracked by @self, and the object it points to MUST
 *   be in the same partition tracked by @idx_type. That is, they must have the same
 *   head_entry and it means, you must ensure that @entry_order and the created/modified
 *   entry will share the same head.
 * @entry_existing: if not NULL, it safes a hash lookup of the entry where the
 *   object will be placed in. You can omit this, and it will be automatically
 *   detected (at the expense of an additional hash lookup).
 *   Basically, this is the result of nm_dedup_multi_index_lookup_obj(),
 *   with the peculiarity that if you know that @obj is not yet tracked,
 *   you may specify %NM_DEDUP_MULTI_ENTRY_MISSING.
 * @head_existing: an optional argument to safe a lookup for the head. If specified,
 *   it must be identical to nm_dedup_multi_index_lookup_head(), with the peculiarity
 *   that if the head is not yet tracked, you may specify %NM_DEDUP_MULTI_HEAD_ENTRY_MISSING
 * @out_entry: if give, return the added entry. This entry may have already exists (update)
 *   or be newly created. If @obj is not partitionable according to @idx_type, @obj
 *   is not to be added and it returns %NULL.
 * @out_obj_old: if given, return the previously contained object. It only
 *   returns a  object, if a matching entry was tracked previously, not if a
 *   new entry was created. Note that when passing @out_obj_old you obtain a reference
 *   to the boxed object and MUST return it with nm_dedup_multi_obj_unref().
 *
 * Adds and object to the index.
 *
 * Return: %TRUE if anything changed, %FALSE if nothing changed.
 */
gboolean
nm_dedup_multi_index_add_full (NMDedupMultiIndex *self,
                               NMDedupMultiIdxType *idx_type,
                               /*const NMDedupMultiObj * */ gconstpointer obj,
                               NMDedupMultiIdxMode mode,
                               const NMDedupMultiEntry *entry_order,
                               const NMDedupMultiEntry *entry_existing,
                               const NMDedupMultiHeadEntry *head_existing,
                               const NMDedupMultiEntry **out_entry,
                               /* const NMDedupMultiObj ** */ gpointer out_obj_old)
{
	NMDedupMultiEntry *entry;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (idx_type, FALSE);
	g_return_val_if_fail (obj, FALSE);
	g_return_val_if_fail (NM_IN_SET (mode,
	                                 NM_DEDUP_MULTI_IDX_MODE_PREPEND,
	                                 NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE,
	                                 NM_DEDUP_MULTI_IDX_MODE_APPEND,
	                                 NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE),
	                      FALSE);

	if (entry_existing == NULL)
		entry = _entry_lookup_obj (self, idx_type, obj);
	else if (entry_existing == NM_DEDUP_MULTI_ENTRY_MISSING) {
		nm_assert (!_entry_lookup_obj (self, idx_type, obj));
		entry = NULL;
	} else {
		nm_assert (entry_existing == _entry_lookup_obj (self, idx_type, obj));
		entry = (NMDedupMultiEntry *) entry_existing;
	}
	return _add (self, idx_type, obj,
	             entry,
	             mode, entry_order,
	             (NMDedupMultiHeadEntry *) head_existing,
	             out_entry, out_obj_old);
}

/*****************************************************************************/

static void
_remove_entry (NMDedupMultiIndex *self,
               NMDedupMultiEntry *entry,
               gboolean *out_head_entry_removed)
{
	const NMDedupMultiObj *obj;
	NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIdxType *idx_type;

	nm_assert (self);
	nm_assert (entry);
	nm_assert (entry->obj);
	nm_assert (entry->head);
	nm_assert (!c_list_is_empty (&entry->lst_entries));
	nm_assert (g_hash_table_lookup (self->idx_entries, entry) == entry);

	head_entry = (NMDedupMultiHeadEntry *) entry->head;
	obj = entry->obj;

	nm_assert (head_entry);
	nm_assert (head_entry->len > 0);
	nm_assert (g_hash_table_lookup (self->idx_entries, head_entry) == head_entry);

	idx_type = (NMDedupMultiIdxType *) head_entry->idx_type;
	ASSERT_idx_type (idx_type);

	nm_assert (idx_type->len >= head_entry->len);
	if (--head_entry->len > 0) {
		nm_assert (idx_type->len > 1);
		idx_type->len--;
		head_entry = NULL;
	}

	NM_SET_OUT (out_head_entry_removed, head_entry != NULL);

	if (!g_hash_table_remove (self->idx_entries, entry))
		nm_assert_not_reached ();

	if (   head_entry
	    && !g_hash_table_remove (self->idx_entries, head_entry))
		nm_assert_not_reached ();

	c_list_unlink_stale (&entry->lst_entries);
	g_slice_free (NMDedupMultiEntry, entry);

	if (head_entry) {
		nm_assert (c_list_is_empty (&head_entry->lst_entries_head));
		c_list_unlink_stale (&head_entry->lst_idx);
		g_slice_free (NMDedupMultiHeadEntry, head_entry);
	}

	nm_dedup_multi_obj_unref (obj);
}

static guint
_remove_head (NMDedupMultiIndex *self,
              NMDedupMultiHeadEntry *head_entry,
              gboolean remove_all /* otherwise just dirty ones */,
              gboolean mark_survivors_dirty)
{
	guint n;
	gboolean head_entry_removed;
	CList *iter_entry, *iter_entry_safe;

	nm_assert (self);
	nm_assert (head_entry);
	nm_assert (head_entry->len > 0);
	nm_assert (head_entry->len == c_list_length (&head_entry->lst_entries_head));
	nm_assert (g_hash_table_lookup (self->idx_entries, head_entry) == head_entry);

	n = 0;
	c_list_for_each_safe (iter_entry, iter_entry_safe, &head_entry->lst_entries_head) {
		NMDedupMultiEntry *entry;

		entry = c_list_entry (iter_entry, NMDedupMultiEntry, lst_entries);
		if (   remove_all
		    || entry->dirty) {
			_remove_entry (self,
			               entry,
			               &head_entry_removed);
			n++;
			if (head_entry_removed)
				break;
		} else if (mark_survivors_dirty)
			nm_dedup_multi_entry_set_dirty (entry, TRUE);
	}

	return n;
}

static guint
_remove_idx_entry (NMDedupMultiIndex *self,
                   NMDedupMultiIdxType *idx_type,
                   gboolean remove_all /* otherwise just dirty ones */,
                   gboolean mark_survivors_dirty)
{
	guint n;
	CList *iter_idx, *iter_idx_safe;

	nm_assert (self);
	ASSERT_idx_type (idx_type);

	n = 0;
	c_list_for_each_safe (iter_idx, iter_idx_safe, &idx_type->lst_idx_head) {
		n += _remove_head (self,
		                   c_list_entry (iter_idx, NMDedupMultiHeadEntry, lst_idx),
		                   remove_all, mark_survivors_dirty);
	}
	return n;
}

guint
nm_dedup_multi_index_remove_entry (NMDedupMultiIndex *self,
                                   gconstpointer entry)
{
	g_return_val_if_fail (self, 0);

	nm_assert (entry);

	if (!((NMDedupMultiEntry *) entry)->is_head) {
		_remove_entry (self, (NMDedupMultiEntry *) entry, NULL);
		return 1;
	}
	return _remove_head (self, (NMDedupMultiHeadEntry *) entry, TRUE, FALSE);
}

guint
nm_dedup_multi_index_remove_obj (NMDedupMultiIndex *self,
                                 NMDedupMultiIdxType *idx_type,
                                 /*const NMDedupMultiObj * */ gconstpointer obj,
                                 /*const NMDedupMultiObj ** */ gconstpointer *out_obj)
{
	const NMDedupMultiEntry *entry;

	entry = nm_dedup_multi_index_lookup_obj (self, idx_type, obj);
	if (!entry) {
		NM_SET_OUT (out_obj, NULL);
		return 0;
	}

	/* since we are about to remove the object, we obviously pass
	 * a reference to @out_obj, the caller MUST unref the object,
	 * if he chooses to provide @out_obj. */
	NM_SET_OUT (out_obj, nm_dedup_multi_obj_ref (entry->obj));

	_remove_entry (self, (NMDedupMultiEntry *) entry, NULL);
	return 1;
}

guint
nm_dedup_multi_index_remove_head (NMDedupMultiIndex *self,
                                  NMDedupMultiIdxType *idx_type,
                                  /*const NMDedupMultiObj * */ gconstpointer obj)
{
	const NMDedupMultiHeadEntry *entry;

	entry = nm_dedup_multi_index_lookup_head (self, idx_type, obj);
	return entry
	       ? _remove_head (self, (NMDedupMultiHeadEntry *) entry, TRUE, FALSE)
	       : 0;
}

guint
nm_dedup_multi_index_remove_idx (NMDedupMultiIndex *self,
                                 NMDedupMultiIdxType *idx_type)
{
	g_return_val_if_fail (self, 0);
	g_return_val_if_fail (idx_type, 0);

	return _remove_idx_entry (self, idx_type, TRUE, FALSE);
}

/*****************************************************************************/

/**
 * nm_dedup_multi_index_lookup_obj:
 * @self: the index cache
 * @idx_type: the lookup index type
 * @obj: the object to lookup. This means the match is performed
 *   according to NMDedupMultiIdxTypeClass's idx_obj_id_equal()
 *   of @idx_type.
 *
 * Returns: the cache entry or %NULL if the entry wasn't found.
 */
const NMDedupMultiEntry *
nm_dedup_multi_index_lookup_obj (const NMDedupMultiIndex *self,
                                 const NMDedupMultiIdxType *idx_type,
                                 /*const NMDedupMultiObj * */ gconstpointer obj)
{
	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (idx_type, FALSE);
	g_return_val_if_fail (obj, FALSE);

	nm_assert (idx_type && idx_type->klass);
	return _entry_lookup_obj (self, idx_type, obj);
}

/**
 * nm_dedup_multi_index_lookup_head:
 * @self: the index cache
 * @idx_type: the lookup index type
 * @obj: the object to lookup, of type "const NMDedupMultiObj *".
 *   Depending on the idx_type, you *must* also provide a selector
 *   object, even when looking up the list head. That is, because
 *   the idx_type implementation may choose to partition the objects
 *   in distinct list, so you need a selector object to know which
 *   list head to lookup.
 *
 * Returns: the cache entry or %NULL if the entry wasn't found.
 */
const NMDedupMultiHeadEntry *
nm_dedup_multi_index_lookup_head (const NMDedupMultiIndex *self,
                                  const NMDedupMultiIdxType *idx_type,
                                  /*const NMDedupMultiObj * */ gconstpointer obj)
{
	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (idx_type, FALSE);

	return _entry_lookup_head (self, idx_type, obj);
}

/*****************************************************************************/

void
nm_dedup_multi_index_dirty_set_head (NMDedupMultiIndex *self,
                                     const NMDedupMultiIdxType *idx_type,
                                     /*const NMDedupMultiObj * */ gconstpointer obj)
{
	NMDedupMultiHeadEntry *head_entry;
	CList *iter_entry;

	g_return_if_fail (self);
	g_return_if_fail (idx_type);

	head_entry = _entry_lookup_head (self, idx_type, obj);
	if (!head_entry)
		return;

	c_list_for_each (iter_entry, &head_entry->lst_entries_head) {
		NMDedupMultiEntry *entry;

		entry = c_list_entry (iter_entry, NMDedupMultiEntry, lst_entries);
		nm_dedup_multi_entry_set_dirty (entry, TRUE);
	}
}

void
nm_dedup_multi_index_dirty_set_idx (NMDedupMultiIndex *self,
                                    const NMDedupMultiIdxType *idx_type)
{
	CList *iter_idx, *iter_entry;

	g_return_if_fail (self);
	g_return_if_fail (idx_type);

	c_list_for_each (iter_idx, &idx_type->lst_idx_head) {
		NMDedupMultiHeadEntry *head_entry;

		head_entry = c_list_entry (iter_idx, NMDedupMultiHeadEntry, lst_idx);
		c_list_for_each (iter_entry, &head_entry->lst_entries_head) {
			NMDedupMultiEntry *entry;

			entry = c_list_entry (iter_entry, NMDedupMultiEntry, lst_entries);
			nm_dedup_multi_entry_set_dirty (entry, TRUE);
		}
	}
}

/**
 * nm_dedup_multi_index_dirty_remove_idx:
 * @self: the index instance
 * @idx_type: the index-type to select the objects.
 * @mark_survivors_dirty: while the function removes all entries that are
 *   marked as dirty, if @set_dirty is true, the surviving objects
 *   will be marked dirty right away.
 *
 * Deletes all entries for @idx_type that are marked dirty. Only
 * non-dirty objects survive. If @mark_survivors_dirty is set to TRUE, the survivors
 * are marked as dirty right away.
 *
 * Returns: number of deleted entries.
 */
guint
nm_dedup_multi_index_dirty_remove_idx (NMDedupMultiIndex *self,
                                       NMDedupMultiIdxType *idx_type,
                                       gboolean mark_survivors_dirty)
{
	g_return_val_if_fail (self, 0);
	g_return_val_if_fail (idx_type, 0);

	return _remove_idx_entry (self, idx_type, FALSE, mark_survivors_dirty);
}

/*****************************************************************************/

static guint
_dict_idx_objs_hash (const NMDedupMultiObj *obj)
{
	NMHashState h;

	nm_hash_init (&h, 1748638583u);
	obj->klass->obj_full_hash_update (obj, &h);
	return nm_hash_complete (&h);
}

static gboolean
_dict_idx_objs_equal (const NMDedupMultiObj *obj_a,
                      const NMDedupMultiObj *obj_b)
{
	return    obj_a == obj_b
	       || (   obj_a->klass == obj_b->klass
	           && obj_a->klass->obj_full_equal (obj_a, obj_b));
}

void
nm_dedup_multi_index_obj_release (NMDedupMultiIndex *self,
                                  /* const NMDedupMultiObj * */ gconstpointer obj)
{
	nm_assert (self);
	nm_assert (obj);
	nm_assert (g_hash_table_lookup (self->idx_objs, obj) == obj);
	nm_assert (((const NMDedupMultiObj *) obj)->_multi_idx == self);

	((NMDedupMultiObj *) obj)->_multi_idx = NULL;
	if (!g_hash_table_remove (self->idx_objs, obj))
		nm_assert_not_reached ();
}

gconstpointer
nm_dedup_multi_index_obj_find (NMDedupMultiIndex *self,
                               /* const NMDedupMultiObj * */ gconstpointer obj)
{
	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (obj, NULL);

	return g_hash_table_lookup (self->idx_objs, obj);
}

gconstpointer
nm_dedup_multi_index_obj_intern (NMDedupMultiIndex *self,
                                 /* const NMDedupMultiObj * */ gconstpointer obj)
{
	const NMDedupMultiObj *obj_new = obj;
	const NMDedupMultiObj *obj_old;

	nm_assert (self);
	nm_assert (obj_new);

	if (obj_new->_multi_idx == self) {
		nm_assert (g_hash_table_lookup (self->idx_objs, obj_new) == obj_new);
		nm_dedup_multi_obj_ref (obj_new);
		return obj_new;
	}

	obj_old = g_hash_table_lookup (self->idx_objs, obj_new);
	nm_assert (obj_old != obj_new);

	if (obj_old) {
		nm_assert (obj_old->_multi_idx == self);
		nm_dedup_multi_obj_ref (obj_old);
		return obj_old;
	}

	if (nm_dedup_multi_obj_needs_clone (obj_new))
		obj_new = nm_dedup_multi_obj_clone (obj_new);
	else
		obj_new = nm_dedup_multi_obj_ref (obj_new);

	nm_assert (obj_new);
	nm_assert (!obj_new->_multi_idx);

	if (!g_hash_table_add (self->idx_objs, (gpointer) obj_new))
		nm_assert_not_reached ();

	((NMDedupMultiObj *) obj_new)->_multi_idx = self;
	return obj_new;
}

void
nm_dedup_multi_obj_unref (const NMDedupMultiObj *obj)
{
	if (obj) {
		nm_assert (obj->_ref_count > 0);
		nm_assert (obj->_ref_count != NM_OBJ_REF_COUNT_STACKINIT);

again:
		if (--(((NMDedupMultiObj *) obj)->_ref_count) <= 0) {
			if (obj->_multi_idx) {
				/* restore the ref-count to 1 and release the object first
				 * from the index. Then, retry again to unref. */
				((NMDedupMultiObj *) obj)->_ref_count++;
				nm_dedup_multi_index_obj_release (obj->_multi_idx, obj);
				nm_assert (obj->_ref_count == 1);
				nm_assert (!obj->_multi_idx);
				goto again;
			}

			obj->klass->obj_destroy ((NMDedupMultiObj *) obj);
		}
	}
}

gboolean
nm_dedup_multi_obj_needs_clone (const NMDedupMultiObj *obj)
{
	nm_assert (obj);

	if (   obj->_multi_idx
	    || obj->_ref_count == NM_OBJ_REF_COUNT_STACKINIT)
		return TRUE;

	if (   obj->klass->obj_needs_clone
	    && obj->klass->obj_needs_clone (obj))
		return TRUE;

	return FALSE;
}

const NMDedupMultiObj *
nm_dedup_multi_obj_clone (const NMDedupMultiObj *obj)
{
	const NMDedupMultiObj *o;

	nm_assert (obj);

	o = obj->klass->obj_clone (obj);
	nm_assert (o);
	nm_assert (o->_ref_count == 1);
	return o;
}

gconstpointer *
nm_dedup_multi_objs_to_array_head (const NMDedupMultiHeadEntry *head_entry,
                                   NMDedupMultiFcnSelectPredicate predicate,
                                   gpointer user_data,
                                   guint *out_len)
{
	gconstpointer *result;
	CList *iter;
	guint i;

	if (!head_entry) {
		NM_SET_OUT (out_len, 0);
		return NULL;
	}

	result = g_new (gconstpointer, head_entry->len + 1);
	i = 0;
	c_list_for_each (iter, &head_entry->lst_entries_head) {
		const NMDedupMultiObj *obj = c_list_entry (iter, NMDedupMultiEntry, lst_entries)->obj;

		if (   !predicate
		    || predicate (obj, user_data)) {
			nm_assert (i < head_entry->len);
			result[i++] = obj;
		}
	}

	if (i == 0) {
		g_free (result);
		NM_SET_OUT (out_len, 0);
		return NULL;
	}

	nm_assert (i <= head_entry->len);
	NM_SET_OUT (out_len, i);
	result[i++] = NULL;
	return result;
}

GPtrArray *
nm_dedup_multi_objs_to_ptr_array_head (const NMDedupMultiHeadEntry *head_entry,
                                       NMDedupMultiFcnSelectPredicate predicate,
                                       gpointer user_data)
{
	GPtrArray *result;
	CList *iter;

	if (!head_entry)
		return NULL;

	result = g_ptr_array_new_full (head_entry->len,
	                               (GDestroyNotify) nm_dedup_multi_obj_unref);
	c_list_for_each (iter, &head_entry->lst_entries_head) {
		const NMDedupMultiObj *obj = c_list_entry (iter, NMDedupMultiEntry, lst_entries)->obj;

		if (   !predicate
		    || predicate (obj, user_data))
			g_ptr_array_add (result, (gpointer) nm_dedup_multi_obj_ref (obj));
	}

	if (result->len == 0) {
		g_ptr_array_unref (result);
		return NULL;
	}
	return result;
}

/**
 * nm_dedup_multi_entry_reorder:
 * @entry: the entry to reorder. It must not be NULL (and tracked in an index).
 * @entry_order: (allow-none): an optional other entry. It MUST be in the same
 *   list as entry. If given, @entry will be ordered after/before @entry_order.
 *   If left at %NULL, @entry will be moved to the front/end of the list.
 * @order_after: if @entry_order is given, %TRUE means to move @entry after
 *   @entry_order (otherwise before).
 *   If @entry_order is %NULL, %TRUE means to move @entry to the tail of the list
 *   (otherwise the beginning). Note that "tail of the list" here means that @entry
 *   will be linked before the head of the circular list.
 *
 * Returns: %TRUE, if anything was changed. Otherwise, @entry was already at the
 * right place and nothing was done.
 */
gboolean
nm_dedup_multi_entry_reorder (const NMDedupMultiEntry *entry,
                              const NMDedupMultiEntry *entry_order,
                              gboolean order_after)
{
	nm_assert (entry);

	if (!entry_order) {
		const NMDedupMultiHeadEntry *head_entry = entry->head;

		if (order_after) {
			if (nm_c_list_move_tail ((CList *) &head_entry->lst_entries_head, (CList *) &entry->lst_entries))
				return TRUE;
		} else {
			if (nm_c_list_move_front ((CList *) &head_entry->lst_entries_head, (CList *) &entry->lst_entries))
				return TRUE;
		}
	} else {
		if (order_after) {
			if (nm_c_list_move_after ((CList *) &entry_order->lst_entries, (CList *) &entry->lst_entries))
				return TRUE;
		} else {
			if (nm_c_list_move_before ((CList *) &entry_order->lst_entries, (CList *) &entry->lst_entries))
				return TRUE;
		}
	}

	return FALSE;
}

/*****************************************************************************/

NMDedupMultiIndex *
nm_dedup_multi_index_new (void)
{
	NMDedupMultiIndex *self;

	self = g_slice_new0 (NMDedupMultiIndex);
	self->ref_count = 1;
	self->idx_entries = g_hash_table_new ((GHashFunc) _dict_idx_entries_hash, (GEqualFunc) _dict_idx_entries_equal);
	self->idx_objs    = g_hash_table_new ((GHashFunc) _dict_idx_objs_hash,    (GEqualFunc) _dict_idx_objs_equal);
	return self;
}

NMDedupMultiIndex *
nm_dedup_multi_index_ref (NMDedupMultiIndex *self)
{
	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->ref_count > 0, NULL);

	self->ref_count++;
	return self;
}

NMDedupMultiIndex *
nm_dedup_multi_index_unref (NMDedupMultiIndex *self)
{
	GHashTableIter iter;
	const NMDedupMultiIdxType *idx_type;
	NMDedupMultiEntry *entry;
	const NMDedupMultiObj *obj;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->ref_count > 0, NULL);

	if (--self->ref_count > 0)
		return NULL;

more:
	g_hash_table_iter_init (&iter, self->idx_entries);
	while (g_hash_table_iter_next (&iter, (gpointer *) &entry, NULL)) {
		if (entry->is_head)
			idx_type = ((NMDedupMultiHeadEntry *) entry)->idx_type;
		else
			idx_type = entry->head->idx_type;
		_remove_idx_entry (self, (NMDedupMultiIdxType *) idx_type, TRUE, FALSE);
		goto more;
	}

	nm_assert (g_hash_table_size (self->idx_entries) == 0);

	g_hash_table_iter_init (&iter, self->idx_objs);
	while (g_hash_table_iter_next (&iter, (gpointer *) &obj, NULL)) {
		nm_assert (obj->_multi_idx == self);
		((NMDedupMultiObj * )obj)->_multi_idx = NULL;
	}
	g_hash_table_remove_all (self->idx_objs);

	g_hash_table_unref (self->idx_entries);
	g_hash_table_unref (self->idx_objs);

	g_slice_free (NMDedupMultiIndex, self);
	return NULL;
}
