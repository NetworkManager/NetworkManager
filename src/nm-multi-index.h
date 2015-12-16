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

#ifndef __NM_MULTI_INDEX__
#define __NM_MULTI_INDEX__

#include "nm-default.h"

G_BEGIN_DECLS


typedef struct {
	char _dummy;
} NMMultiIndexId;

typedef struct NMMultiIndex NMMultiIndex;

typedef struct {
	GHashTableIter _iter;
	const NMMultiIndex *_index;
	gconstpointer _value;
} NMMultiIndexIter;

typedef struct {
	union {
		GHashTableIter _iter;
		gpointer _value;
	};
	guint _state;
} NMMultiIndexIdIter;

typedef gboolean (*NMMultiIndexFuncEqual) (const NMMultiIndexId *id_a, const NMMultiIndexId *id_b);
typedef guint (*NMMultiIndexFuncHash) (const NMMultiIndexId *id);
typedef NMMultiIndexId *(*NMMultiIndexFuncClone) (const NMMultiIndexId *id);
typedef void (*NMMultiIndexFuncDestroy) (NMMultiIndexId *id);

typedef gboolean (*NMMultiIndexFuncForeach) (const NMMultiIndexId *id, void *const* values, guint len, gpointer user_data);


NMMultiIndex *nm_multi_index_new (NMMultiIndexFuncHash hash_fcn,
                                  NMMultiIndexFuncEqual equal_fcn,
                                  NMMultiIndexFuncClone clone_fcn,
                                  NMMultiIndexFuncDestroy destroy_fcn);

void nm_multi_index_free (NMMultiIndex *index);

gboolean nm_multi_index_add (NMMultiIndex *index,
                             const NMMultiIndexId *id,
                             gconstpointer value);

gboolean nm_multi_index_remove (NMMultiIndex *index,
                                const NMMultiIndexId *id,
                                gconstpointer value);

gboolean nm_multi_index_move (NMMultiIndex *index,
                              const NMMultiIndexId *id_old,
                              const NMMultiIndexId *id_new,
                              gconstpointer value);

guint nm_multi_index_get_num_groups (const NMMultiIndex *index);

void *const*nm_multi_index_lookup (const NMMultiIndex *index,
                                   const NMMultiIndexId *id,
                                   guint *out_len);

gboolean nm_multi_index_contains (const NMMultiIndex *index,
                                  const NMMultiIndexId *id,
                                  gconstpointer value);

const NMMultiIndexId *nm_multi_index_lookup_first_by_value (const NMMultiIndex *index,
                                                             gconstpointer value);

void nm_multi_index_foreach (const NMMultiIndex *index,
                             gconstpointer value,
                             NMMultiIndexFuncForeach foreach_func,
                             gpointer user_data);

void nm_multi_index_iter_init (NMMultiIndexIter *iter,
                               const NMMultiIndex *index,
                               gconstpointer value);
gboolean nm_multi_index_iter_next (NMMultiIndexIter *iter,
                                   const NMMultiIndexId **out_id,
                                   void *const**out_values,
                                   guint *out_len);

void nm_multi_index_id_iter_init (NMMultiIndexIdIter *iter,
                                  const NMMultiIndex *index,
                                  const NMMultiIndexId *id);
gboolean nm_multi_index_id_iter_next (NMMultiIndexIdIter *iter,
                                      void **out_value);

G_END_DECLS

#endif /* __NM_MULTI_INDEX__ */

