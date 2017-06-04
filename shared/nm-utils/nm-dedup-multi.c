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

/*****************************************************************************/

typedef struct {
	NMDedupMultiBox parent;
	int ref_count;
} Box;

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
	GHashTable *idx_box;
};

/*****************************************************************************/

static void _box_unref (NMDedupMultiIndex *self,
                        Box *box);

/*****************************************************************************/

static void
ASSERT_idx_type (const NMDedupMultiIdxType *idx_type)
{
	nm_assert (idx_type);
#if NM_MORE_ASSERTS > 10
	nm_assert (idx_type->klass);
	nm_assert (idx_type->klass->idx_obj_id_hash);
	nm_assert (idx_type->klass->idx_obj_id_equal);
	nm_assert (!!idx_type->klass->idx_obj_partition_hash == !!idx_type->klass->idx_obj_partition_equal);
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
_entry_lookup_obj (NMDedupMultiIndex *self,
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
_entry_lookup_head (NMDedupMultiIndex *self,
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
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMDedupMultiEntry, box) == G_STRUCT_OFFSET (NMDedupMultiHeadEntry, idx_type));
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
		*out_obj = c_list_entry (head_entry->lst_entries_head.next, NMDedupMultiEntry, lst_entries)->box->obj;
		*out_idx_type = head_entry->idx_type;
		*out_lookup_head = TRUE;
	} else {
		*out_obj = entry->box->obj;
		*out_idx_type = entry->head->idx_type;
		*out_lookup_head = FALSE;
	}

	nm_assert (NM_IN_SET (*out_lookup_head, FALSE, TRUE));
	ASSERT_idx_type (*out_idx_type);
}

static guint
_dict_idx_entries_hash (const NMDedupMultiEntry *entry)
{
	const NMDedupMultiIdxType *idx_type;
	const NMDedupMultiObj *obj;
	gboolean lookup_head;
	guint h;

	_entry_unpack (entry, &idx_type, &obj, &lookup_head);

	if (idx_type->klass->idx_obj_partition_hash) {
		nm_assert (obj);
		h = idx_type->klass->idx_obj_partition_hash (idx_type, obj);
	} else
		h = 1914869417;

	if (!lookup_head)
		h = idx_type->klass->idx_obj_id_hash (idx_type, obj);

	h = NM_HASH_COMBINE (h, GPOINTER_TO_UINT (idx_type));
	h = NM_HASH_COMBINE (h, lookup_head);
	return h;
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
      const NMDedupMultiBox *box_existing,
      const NMDedupMultiEntry **out_entry,
      const NMDedupMultiBox **out_old_box)
{
	NMDedupMultiHeadEntry *head_entry;
	const NMDedupMultiBox *box, *box_new;
	gboolean add_head_entry = FALSE;

	nm_assert (self);
	ASSERT_idx_type (idx_type);
	nm_assert (obj);
	nm_assert (NM_IN_SET (mode,
	                      NM_DEDUP_MULTI_IDX_MODE_PREPEND,
	                      NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE,
	                      NM_DEDUP_MULTI_IDX_MODE_APPEND,
	                      NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE));
	nm_assert (!box_existing || box_existing == nm_dedup_multi_box_find (self, obj));
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
		nm_dedup_multi_entry_set_dirty (entry, FALSE);

		nm_assert (!head_existing || entry->head == head_existing);

		if (entry_order) {
			nm_assert (entry_order->head == entry->head);
			nm_assert (c_list_contains (&entry->lst_entries, &entry_order->lst_entries));
			nm_assert (c_list_contains (&entry_order->lst_entries, &entry->lst_entries));
		}

		switch (mode) {
		case NM_DEDUP_MULTI_IDX_MODE_PREPEND_FORCE:
			if (entry_order) {
				if (   entry_order != entry
				    && entry->lst_entries.next != &entry_order->lst_entries) {
					c_list_unlink (&entry->lst_entries);
					c_list_link_before ((CList *) &entry_order->lst_entries, &entry->lst_entries);
				}
			} else {
				if (entry->lst_entries.prev != &entry->head->lst_entries_head) {
					c_list_unlink (&entry->lst_entries);
					c_list_link_front ((CList *) &entry->head->lst_entries_head, &entry->lst_entries);
				}
			}
			break;
		case NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE:
			if (entry_order) {
				if (   entry_order != entry
				    && entry->lst_entries.prev != &entry_order->lst_entries) {
					c_list_unlink (&entry->lst_entries);
					c_list_link_after ((CList *) &entry_order->lst_entries, &entry->lst_entries);
				}
			} else {
				if (entry->lst_entries.next != &entry->head->lst_entries_head) {
					c_list_unlink (&entry->lst_entries);
					c_list_link_tail ((CList *) &entry->head->lst_entries_head, &entry->lst_entries);
				}
			}
			break;
		case NM_DEDUP_MULTI_IDX_MODE_PREPEND:
		case NM_DEDUP_MULTI_IDX_MODE_APPEND:
			break;
		};

		if (   obj == entry->box->obj
		    || obj->klass->obj_full_equal (obj,
		                                   entry->box->obj)) {
			NM_SET_OUT (out_entry, entry);
			NM_SET_OUT (out_old_box, nm_dedup_multi_box_ref (entry->box));
			return FALSE;
		}

		if (box_existing)
			box_new = nm_dedup_multi_box_ref (box_existing);
		else
			box_new = nm_dedup_multi_box_new (self, obj);

		box = entry->box;
		entry->box = box_new;

		NM_SET_OUT (out_entry, entry);
		if (out_old_box)
			*out_old_box = box;
		else
			_box_unref (self, (Box *) box);
		return TRUE;
	}

	if (    idx_type->klass->idx_obj_partitionable
	    && !idx_type->klass->idx_obj_partitionable (idx_type, obj)) {
		/* this object cannot be partitioned by this idx_type. */
		nm_assert (!head_existing || head_existing == NM_DEDUP_MULTI_HEAD_ENTRY_MISSING);
		NM_SET_OUT (out_entry, NULL);
		NM_SET_OUT (out_old_box, NULL);
		return FALSE;
	}

	if (box_existing)
		box_new = nm_dedup_multi_box_ref (box_existing);
	else
		box_new = nm_dedup_multi_box_new (self, obj);
	obj = box_new->obj;

	if (!head_existing)
		head_entry = _entry_lookup_head (self, idx_type, obj);
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
	entry->box = box_new;
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
	    && !nm_g_hash_table_add (self->idx_entries, head_entry))
		nm_assert_not_reached ();

	if (!nm_g_hash_table_add (self->idx_entries, entry))
		nm_assert_not_reached ();

	NM_SET_OUT (out_entry, entry);
	NM_SET_OUT (out_old_box, NULL);
	return TRUE;
}

gboolean
nm_dedup_multi_index_add (NMDedupMultiIndex *self,
                          NMDedupMultiIdxType *idx_type,
                          /*const NMDedupMultiObj * */ gconstpointer obj,
                          NMDedupMultiIdxMode mode,
                          const NMDedupMultiEntry **out_entry,
                          const NMDedupMultiBox **out_old_box)
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
	             entry, mode, NULL,
	             NULL, NULL,
	             out_entry, out_old_box);
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
 *   with the pecularity that if you know that @obj is not yet tracked,
 *   you may specify %NM_DEDUP_MULTI_ENTRY_MISSING.
 * @head_existing: an optional argument to safe a lookup for the head. If specified,
 *   it must be identical to nm_dedup_multi_index_lookup_head(), with the pecularity
 *   that if the head is not yet tracked, you may specify %NM_DEDUP_MULTI_HEAD_ENTRY_MISSING
 * @box_existing: optional argument to safe the box lookup. If given, @obj and the boxed
 *   object must be identical, and @box_existing must be tracked by @self. This is to safe
 *   the additional lookup.
 * @out_entry: if give, return the added entry. This entry may have already exists (update)
 *   or be newly created. If @obj is not partitionable according to @idx_type, @obj
 *   is not to be added and it returns %NULL.
 * @out_old_box: if given, return the previously contained boxed object. It only
 *   returns a boxed object, if a matching entry was tracked previously, not if a
 *   new entry was created. Note that when passing @out_old_box you obtain a reference
 *   to the boxed object and MUST return it with nm_dedup_multi_box_unref().
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
                               const NMDedupMultiBox *box_existing,
                               const NMDedupMultiEntry **out_entry,
                               const NMDedupMultiBox **out_old_box)
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
	             box_existing,
	             out_entry, out_old_box);
}

/*****************************************************************************/

static void
_remove_entry (NMDedupMultiIndex *self,
               NMDedupMultiEntry *entry,
               gboolean *out_head_entry_removed)
{
	Box *box;
	NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIdxType *idx_type;

	nm_assert (self);
	nm_assert (entry);
	nm_assert (entry->box);
	nm_assert (entry->head);
	nm_assert (!c_list_is_empty (&entry->lst_entries));
	nm_assert (g_hash_table_lookup (self->idx_entries, entry) == entry);

	head_entry = (NMDedupMultiHeadEntry *) entry->head;
	box = (Box *) entry->box;

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

	c_list_unlink (&entry->lst_entries);
	g_slice_free (NMDedupMultiEntry, entry);

	if (head_entry) {
		nm_assert (c_list_is_empty (&head_entry->lst_entries_head));
		c_list_unlink (&head_entry->lst_idx);
		g_slice_free (NMDedupMultiHeadEntry, head_entry);
	}

	_box_unref (self, box);
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
                                 /*const NMDedupMultiObj * */ gconstpointer obj)
{
	const NMDedupMultiEntry *entry;

	entry = nm_dedup_multi_index_lookup_obj (self, idx_type, obj);
	if (!entry)
		return 0;
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
nm_dedup_multi_index_lookup_obj (NMDedupMultiIndex *self,
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
nm_dedup_multi_index_lookup_head (NMDedupMultiIndex *self,
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
_dict_idx_box_hash (const Box *box)
{
	const NMDedupMultiObj *obj = box->parent.obj;

	return obj->klass->obj_full_hash (obj);
}

static gboolean
_dict_idx_box_equal (const Box *box_a,
                     const Box *box_b)
{
	const NMDedupMultiObjClass *klass;
	const NMDedupMultiObj *obj_a = box_a->parent.obj;
	const NMDedupMultiObj *obj_b = box_b->parent.obj;

	klass = obj_a->klass;

	/* if the class differs, but at least one of them supports calls with
	 * differing klass, choose it.
	 *
	 * Implementing a klass that can compare equality for multiple
	 * types is hard to get right. E.g. hash(), equal() and get_ref()
	 * must all agree so that instances of different types look identical. */
	if (   klass != obj_b->klass
	    && !klass->obj_full_equality_allows_different_class) {
		klass = obj_b->klass;
		if (!klass->obj_full_equality_allows_different_class)
			return FALSE;
	}

	return klass->obj_full_equal (obj_a, obj_b);
}

static void
_box_unref (NMDedupMultiIndex *self,
            Box *box)
{
	nm_assert (box);
	nm_assert (box->ref_count > 0);
	nm_assert (g_hash_table_lookup (self->idx_box, box) == box);

	if (--box->ref_count > 0)
		return;

	if (!g_hash_table_remove (self->idx_box, box))
		nm_assert_not_reached ();

	((NMDedupMultiObj *) box->parent.obj)->klass->obj_put_ref ((NMDedupMultiObj *) box->parent.obj);
	g_slice_free (Box, box);
}

#define BOX_INIT(obj) \
	(&((const Box) { .parent = { .obj = obj, }, }))

static Box *
_box_find  (NMDedupMultiIndex *index,
            /* const NMDedupMultiObj * */ gconstpointer obj)
{
	nm_assert (index);
	nm_assert (obj);

	return g_hash_table_lookup (index->idx_box, BOX_INIT (obj));
}

const NMDedupMultiBox *
nm_dedup_multi_box_find  (NMDedupMultiIndex *index,
                          /* const NMDedupMultiObj * */ gconstpointer obj)
{
	g_return_val_if_fail (index, NULL);
	g_return_val_if_fail (obj, NULL);

	return (NMDedupMultiBox *) _box_find (index, obj);
}

const NMDedupMultiBox *
nm_dedup_multi_box_new (NMDedupMultiIndex *index,
                        /* const NMDedupMultiObj * */ gconstpointer obj)
{
	Box *box;
	const NMDedupMultiObj *o;

	g_return_val_if_fail (index, NULL);
	g_return_val_if_fail (obj, NULL);

	box = _box_find (index, obj);
	if (box) {
		box->ref_count++;
		return (NMDedupMultiBox *) box;
	}

	o = ((const NMDedupMultiObj *) obj)->klass->obj_get_ref (obj);
	if (!o)
		g_return_val_if_reached (NULL);

	box = g_slice_new (Box);
	box->parent.obj = o;
	box->ref_count = 1;

	nm_assert (_dict_idx_box_equal (box, BOX_INIT (obj)));
	nm_assert (_dict_idx_box_equal (BOX_INIT (obj), box));
	nm_assert (_dict_idx_box_hash (BOX_INIT (obj)) == _dict_idx_box_hash (box));

	if (!nm_g_hash_table_add (index->idx_box, box))
		nm_assert_not_reached ();

	return &box->parent;
}

const NMDedupMultiBox *
nm_dedup_multi_box_ref (const NMDedupMultiBox *box)
{
	Box *b;

	b = (Box *) box;

	g_return_val_if_fail (b, NULL);
	g_return_val_if_fail (b->ref_count > 0, NULL);

	b->ref_count++;
	return box;
}

const NMDedupMultiBox *
nm_dedup_multi_box_unref (NMDedupMultiIndex *self,
                          const NMDedupMultiBox *box)
{
	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (box, NULL);
	g_return_val_if_fail (((Box *) box)->ref_count > 0, NULL);

	_box_unref (self, (Box *) box);
	return NULL;
}

/*****************************************************************************/

NMDedupMultiIndex *
nm_dedup_multi_index_new (void)
{
	NMDedupMultiIndex *self;

	self = g_slice_new0 (NMDedupMultiIndex);
	self->ref_count = 1;
	self->idx_entries = g_hash_table_new ((GHashFunc) _dict_idx_entries_hash, (GEqualFunc) _dict_idx_entries_equal);
	self->idx_box     = g_hash_table_new ((GHashFunc) _dict_idx_box_hash,     (GEqualFunc) _dict_idx_box_equal);
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

	/* If callers took references to NMDedupMultiBox instances, they
	 * must keep NMDedupMultiIndex alive for as long as they keep
	 * the boxed reference. */
	nm_assert (g_hash_table_size (self->idx_box) == 0);

	g_hash_table_unref (self->idx_entries);
	g_hash_table_unref (self->idx_box);

	g_slice_free (NMDedupMultiIndex, self);
	return NULL;
}
