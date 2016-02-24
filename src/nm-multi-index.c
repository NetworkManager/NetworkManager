/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-multi-index.h"

#include <string.h>

struct NMMultiIndex {
	NMMultiIndexFuncEqual equal_fcn;
	NMMultiIndexFuncClone clone_fcn;
	GHashTable *hash;
};

typedef struct {
	/* when storing the first item for a multi-index id, we don't yet create
	 * the hashtable @index. Instead we store it inplace to @value0. Note that
	 * &values_data->value0 is a NULL terminated array with one item that is
	 * suitable to be returned directly from nm_multi_index_lookup(). */
	union {
		gpointer value0;
		gpointer *values;
	};
	GHashTable *index;
} ValuesData;

/******************************************************************************************/

static void
_values_data_destroy (ValuesData *values_data)
{
	if (values_data->index) {
		g_free (values_data->values);
		g_hash_table_unref (values_data->index);
	}
	g_slice_free (ValuesData, values_data);
}

static gboolean
_values_data_contains (ValuesData *values_data, gconstpointer value)
{
	return values_data->index
	       ? g_hash_table_contains (values_data->index, value)
	       : value == values_data->value0;
}

static void
_values_data_get_data (ValuesData *values_data,
                       void *const**out_data,
                       guint *out_len)
{
	guint i, len;
	gpointer *values;
	GHashTableIter iter;

	nm_assert (values_data);

	if (!values_data->index) {
		NM_SET_OUT (out_data, &values_data->value0);
		NM_SET_OUT (out_len, 1);
		return;
	}

	nm_assert (values_data->index && g_hash_table_size (values_data->index) > 0);

	if (!values_data->values) {
		len = g_hash_table_size (values_data->index);
		values = g_new (gpointer, len + 1);

		g_hash_table_iter_init (&iter, values_data->index);
		for (i = 0; g_hash_table_iter_next (&iter, &values[i], NULL); i++)
			nm_assert (i < len);
		nm_assert (i == len);
		values[i] = NULL;

		values_data->values = values;
		NM_SET_OUT (out_len, len);
	} else if (out_len)
		NM_SET_OUT (out_len, g_hash_table_size (values_data->index));

	NM_SET_OUT (out_data, values_data->values);
}

/******************************************************************************************/

/**
 * nm_multi_index_lookup():
 * @index:
 * @id:
 * @out_len: (allow-none): output the number of values
 *   that are returned.
 *
 * Returns: (transfer none): %NULL if there are no values
 *   or a %NULL terminated array of pointers.
 */
void *const*
nm_multi_index_lookup (const NMMultiIndex *index,
                       const NMMultiIndexId *id,
                       guint *out_len)
{
	ValuesData *values_data;
	void *const*values;

	g_return_val_if_fail (index, NULL);
	g_return_val_if_fail (id, NULL);

	values_data = g_hash_table_lookup (index->hash, id);
	if (!values_data) {
		if (out_len)
			*out_len = 0;
		return NULL;
	}
	_values_data_get_data (values_data, &values, out_len);
	return values;
}

gboolean
nm_multi_index_contains (const NMMultiIndex *index,
                         const NMMultiIndexId *id,
                         gconstpointer value)
{
	ValuesData *values_data;

	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (id, FALSE);
	g_return_val_if_fail (value, FALSE);

	values_data = g_hash_table_lookup (index->hash, id);
	return values_data && _values_data_contains (values_data, value);
}

const NMMultiIndexId *
nm_multi_index_lookup_first_by_value (const NMMultiIndex *index,
                                      gconstpointer value)
{
	GHashTableIter iter;
	const NMMultiIndexId *id;
	ValuesData *values_data;

	g_return_val_if_fail (index, NULL);
	g_return_val_if_fail (value, NULL);

	/* reverse-lookup needs to iterate over all hash tables. It should
	 * still be fairly quick, if the number of hash tables is small.
	 * There is no O(1) reverse lookup implemented, because this access
	 * pattern is not what NMMultiIndex is here for.
	 * You are supposed to use NMMultiIndex by always knowing which @id
	 * a @value has.
	 */

	g_hash_table_iter_init (&iter, index->hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &values_data)) {
		if (_values_data_contains (values_data, value))
			return id;
	}
	return NULL;
}

void
nm_multi_index_foreach (const NMMultiIndex *index,
                        gconstpointer value,
                        NMMultiIndexFuncForeach foreach_func,
                        gpointer user_data)
{
	GHashTableIter iter;
	const NMMultiIndexId *id;
	ValuesData *values_data;
	guint len;
	void *const*values;

	g_return_if_fail (index);
	g_return_if_fail (foreach_func);

	g_hash_table_iter_init (&iter, index->hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &values_data)) {
		if (value && !_values_data_contains (values_data, value))
			continue;

		_values_data_get_data (values_data, &values, &len);
		if (!foreach_func (id, values, len, user_data))
			return;
	}
}

void
nm_multi_index_iter_init (NMMultiIndexIter *iter,
                          const NMMultiIndex *index,
                          gconstpointer value)
{
	g_return_if_fail (index);
	g_return_if_fail (iter);

	g_hash_table_iter_init (&iter->_iter, index->hash);
	iter->_index = index;
	iter->_value = value;
}

gboolean
nm_multi_index_iter_next (NMMultiIndexIter *iter,
                          const NMMultiIndexId **out_id,
                          void *const**out_values,
                          guint *out_len)
{
	const NMMultiIndexId *id;
	ValuesData *values_data;

	g_return_val_if_fail (iter, FALSE);

	while (g_hash_table_iter_next (&iter->_iter, (gpointer *) &id, (gpointer *) &values_data)) {
		if (   !iter->_value
		    || _values_data_contains (values_data, iter->_value)) {
			if (out_values || out_len)
				_values_data_get_data (values_data, out_values, out_len);
			if (out_id)
				*out_id = id;
			return TRUE;
		}
	}
	return FALSE;
}

/******************************************************************************************/

void
nm_multi_index_id_iter_init (NMMultiIndexIdIter *iter,
                             const NMMultiIndex *index,
                             const NMMultiIndexId *id)
{
	ValuesData *values_data;

	g_return_if_fail (index);
	g_return_if_fail (iter);
	g_return_if_fail (id);

	values_data = g_hash_table_lookup (index->hash, id);
	if (!values_data)
		iter->_state = 2;
	else if (values_data->index) {
		iter->_state = 1;
		g_hash_table_iter_init (&iter->_iter, values_data->index);
	} else {
		iter->_state = 0;
		iter->_value = values_data->value0;
	}
}

gboolean
nm_multi_index_id_iter_next (NMMultiIndexIdIter *iter,
                             void **out_value)
{
	g_return_val_if_fail (iter, FALSE);

	switch (iter->_state) {
	case 0:
		iter->_state = 2;
		NM_SET_OUT (out_value, iter->_value);
		return TRUE;
	case 1:
		return g_hash_table_iter_next (&iter->_iter, out_value, NULL);
	case 2:
		iter->_state = 3;
		return FALSE;
	default:
		g_return_val_if_reached (FALSE);
	}
}

/******************************************************************************************/

static gboolean
_do_add (NMMultiIndex *index,
         const NMMultiIndexId *id,
         gconstpointer value)
{
	ValuesData *values_data;

	values_data = g_hash_table_lookup (index->hash, id);
	if (!values_data) {
		NMMultiIndexId *id_new;

		/* Contrary to GHashTable, we don't take ownership of the @id that was
		 * provided to nm_multi_index_add(). Instead we clone it via @clone_fcn
		 * when needed.
		 *
		 * The reason is, that we expect in most cases that there exists
		 * already a @id so that we don't need ownership of it (or clone it).
		 * By doing this, the caller can pass a stack allocated @id or
		 * reuse the @id for other insertions.
		 */
		id_new = index->clone_fcn (id);
		if (!id_new)
			g_return_val_if_reached (FALSE);

		values_data = g_slice_new0 (ValuesData);
		values_data->value0 = (gpointer) value;

		g_hash_table_insert (index->hash, id_new, values_data);
	} else {
		if (!values_data->index) {
			if (values_data->value0 == value)
				return FALSE;
			values_data->index = g_hash_table_new (NULL, NULL);
			g_hash_table_replace (values_data->index, (gpointer) value, (gpointer) value);
			g_hash_table_replace (values_data->index, values_data->value0, values_data->value0);
			values_data->values = NULL;
		} else {
			if (!nm_g_hash_table_replace (values_data->index, (gpointer) value, (gpointer) value))
				return FALSE;
			g_clear_pointer (&values_data->values, g_free);
		}
	}
	return TRUE;
}

static gboolean
_do_remove (NMMultiIndex *index,
            const NMMultiIndexId *id,
            gconstpointer value)
{
	ValuesData *values_data;

	values_data = g_hash_table_lookup (index->hash, id);
	if (!values_data)
		return FALSE;

	if (values_data->index) {
		if (!g_hash_table_remove (values_data->index, value))
			return FALSE;
		if (g_hash_table_size (values_data->index) == 0)
			g_hash_table_remove (index->hash, id);
		else
			g_clear_pointer (&values_data->values, g_free);
	} else {
		if (values_data->value0 != value)
			return FALSE;
		g_hash_table_remove (index->hash, id);
	}

	return TRUE;
}

gboolean
nm_multi_index_add (NMMultiIndex *index,
                    const NMMultiIndexId *id,
                    gconstpointer value)
{
	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (id, FALSE);
	g_return_val_if_fail (value, FALSE);

	return _do_add (index, id, value);
}

gboolean
nm_multi_index_remove (NMMultiIndex *index,
                       const NMMultiIndexId *id,
                       gconstpointer value)
{
	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (value, FALSE);

	if (!id)
		g_return_val_if_reached (FALSE);
	return _do_remove (index, id, value);
}

/**
 * nm_multi_index_move:
 * @index:
 * @id_old: (allow-none): remove @value at @id_old
 * @id_new: (allow-none): add @value under @id_new
 * @value: the value to add
 *
 * Similar to a remove(), followed by an add(). The difference
 * is, that we allow %NULL for both @id_old and @id_new.
 * And the return value indicates whether @value was successfully
 * removed *and* added.
 *
 * Returns: %TRUE, if the value was removed from @id_old and added
 *   as %id_new. %FALSE could mean, that @value was not added to @id_old
 *   before, or that that @value was already part of @id_new. */
gboolean
nm_multi_index_move (NMMultiIndex *index,
                     const NMMultiIndexId *id_old,
                     const NMMultiIndexId *id_new,
                     gconstpointer value)
{
	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (value, FALSE);

	if (!id_old && !id_new) {
		/* nothing to do, @value was and is not in @index. */
		return TRUE;
	} if (!id_old) {
		/* add @value to @index with @id_new */
		return _do_add (index, id_new, value);
	} else if (!id_new) {
		/* remove @value from @index with @id_old */
		return _do_remove (index, id_old, value);
	} else if (index->equal_fcn (id_old, id_new)) {
		if (_do_add (index, id_new, value)) {
			/* we would expect, that @value is already in @index,
			 * Return %FALSE, if it wasn't. */
			return FALSE;
		}
		return TRUE;
	} else {
		gboolean did_remove;

		did_remove = _do_remove (index, id_old, value);
		return _do_add (index, id_new, value) && did_remove;
	}
}

/******************************************************************************************/

guint
nm_multi_index_get_num_groups (const NMMultiIndex *index)
{
	g_return_val_if_fail (index, 0);
	return g_hash_table_size (index->hash);
}

NMMultiIndex *
nm_multi_index_new (NMMultiIndexFuncHash hash_fcn,
                    NMMultiIndexFuncEqual equal_fcn,
                    NMMultiIndexFuncClone clone_fcn,
                    NMMultiIndexFuncDestroy destroy_fcn)
{
	NMMultiIndex *index;

	g_return_val_if_fail (hash_fcn, NULL);
	g_return_val_if_fail (equal_fcn, NULL);
	g_return_val_if_fail (clone_fcn, NULL);
	g_return_val_if_fail (destroy_fcn, NULL);

	index = g_new (NMMultiIndex, 1);
	index->equal_fcn = equal_fcn;
	index->clone_fcn = clone_fcn;

	index->hash = g_hash_table_new_full ((GHashFunc) hash_fcn,
	                                     (GEqualFunc) equal_fcn,
	                                     (GDestroyNotify) destroy_fcn,
	                                     (GDestroyNotify) _values_data_destroy);
	return index;
}

void
nm_multi_index_free (NMMultiIndex *index)
{
	g_return_if_fail (index);
	g_hash_table_unref (index->hash);
	g_free (index);
}

