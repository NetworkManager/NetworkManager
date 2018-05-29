/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT SC WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2008 - 2011 Red Hat, Inc.
 *
 */

#define NM_GLIB_COMPAT_H_TEST

#include "nm-default.h"

#include <string.h>

#include "nm-utils/c-list-util.h"
#include "nm-utils/nm-enum-utils.h"

#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-core-internal.h"
#include "nm-core-tests-enum-types.h"

#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-user.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wimax.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-simple-connection.h"
#include "nm-keyfile-internal.h"
#include "nm-utils/nm-dedup-multi.h"

#include "test-general-enums.h"

#include "nm-utils/nm-test-utils.h"

/* When passing a "bool" typed argument to a variadic function that
 * expects a gboolean, the compiler will promote the integer type
 * to have at least size (int). That way:
 *   g_object_set (obj, PROP_BOOL, bool_val, NULL);
 * will just work correctly. */
G_STATIC_ASSERT (sizeof (gboolean) == sizeof (int));
G_STATIC_ASSERT (sizeof (bool) <= sizeof (int));

/*****************************************************************************/

typedef struct _nm_packed {
	int v0;
	char v1;
	double v2;
	guint8 v3;
} TestHashStruct;

static void
_test_hash_struct (int v0, char v1, double v2, guint8 v3)
{
	const TestHashStruct s = {
		.v0 = v0,
		.v1 = v1,
		.v2 = v2,
		.v3 = v3,
	};
	NMHashState h;
	guint hh;

	nm_hash_init (&h, 100);
	nm_hash_update (&h, &s, sizeof (s));
	hh = nm_hash_complete (&h);

	nm_hash_init (&h, 100);
	nm_hash_update_val (&h, v0);
	nm_hash_update_val (&h, v1);
	nm_hash_update_val (&h, v2);
	nm_hash_update_val (&h, v3);
	g_assert_cmpint (hh, ==, nm_hash_complete (&h));

	nm_hash_init (&h, 100);
	nm_hash_update_vals (&h, v0, v1, v2, v3);
	g_assert_cmpint (hh, ==, nm_hash_complete (&h));
}

static guint
_test_hash_str (const char *str)
{
	NMHashState h;
	guint v, v2;
	const guint SEED = 10;

	nm_hash_init (&h, SEED);
	nm_hash_update_str0 (&h, str);
	v = nm_hash_complete (&h);

	/* assert that hashing a string and a buffer yields the
	 * same result.
	 *
	 * I think that is a desirable property. */
	nm_hash_init (&h, SEED);
	nm_hash_update_mem (&h, str, strlen (str));
	v2 = nm_hash_complete (&h);

	g_assert (v == v2);
	return v;
}

#define _test_hash_vals(type, ...) \
	G_STMT_START { \
		NMHashState h0, h1, h2, h3; \
		const type v[] = { __VA_ARGS__ }; \
		guint h; \
		guint i; \
		\
		nm_hash_init (&h0, 10); \
		nm_hash_init (&h1, 10); \
		nm_hash_init (&h2, 10); \
		nm_hash_init (&h3, 10); \
		\
		/* assert that it doesn't matter, whether we hash the values individually,
		 * or all at once, or via the convenience macros nm_hash_update_val()
		 * and nm_hash_update_vals(). */ \
		for (i = 0; i < G_N_ELEMENTS (v); i++) { \
			nm_hash_update (&h0, &v[i], sizeof (type)); \
			nm_hash_update_val (&h1, v[i]); \
		} \
		nm_hash_update_vals (&h2, __VA_ARGS__); \
		nm_hash_update (&h3, v, sizeof (v)); \
		\
		h = nm_hash_complete (&h0); \
		g_assert_cmpint (h, ==, nm_hash_complete (&h1)); \
		g_assert_cmpint (h, ==, nm_hash_complete (&h2)); \
		g_assert_cmpint (h, ==, nm_hash_complete (&h3)); \
	} G_STMT_END

static void
test_nm_hash (void)
{
	g_assert (nm_hash_static (0));
	g_assert (nm_hash_static (777));

	g_assert (nm_hash_str (NULL));
	g_assert (nm_hash_str (""));
	g_assert (nm_hash_str ("a"));

	g_assert (nm_hash_ptr (NULL));
	g_assert (nm_hash_ptr (""));
	g_assert (nm_hash_ptr ("a"));

	_test_hash_str ("");
	_test_hash_str ("a");
	_test_hash_str ("aa");
	_test_hash_str ("diceros bicornis longipes");

	/* assert that nm_hash_update_vals() is the same as calling nm_hash_update_val() multiple times. */
	_test_hash_vals (int, 1);
	_test_hash_vals (int, 1, 2);
	_test_hash_vals (int, 1, 2, 3);
	_test_hash_vals (int, 1, 2, 3, 4);
	_test_hash_vals (long, 1l);
	_test_hash_vals (long, 1l, 2l, 3l, 4l, 5l);

	_test_hash_struct (10, 'a', 5.4, 7);
	_test_hash_struct (-10, '\0', -5.4e49, 255);

	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint8,                       1, 0), ==, 0x002);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint8,                       1, 1), ==, 0x003);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint8,           1, 1, 0, 0, 0, 0), ==, 0x030);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint8,           1, 1, 0, 0, 0, 1), ==, 0x031);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint8,     0, 0, 1, 1, 0, 0, 0, 1), ==, 0x031);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint16,    0, 0, 1, 1, 0, 0, 0, 1), ==, 0x031);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint16, 0, 0, 0, 1, 1, 0, 0, 0, 1), ==, 0x031);
	g_assert_cmpint (NM_HASH_COMBINE_BOOLS (guint16, 1, 0, 0, 1, 1, 0, 0, 0, 1), ==, 0x131);
}

/*****************************************************************************/

static void
test_nm_g_slice_free_fcn (void)
{
	gpointer p;
	struct {
		char a1;
		char a2;
	} xx;

	p = g_slice_new (gint64);
	(nm_g_slice_free_fcn (gint64)) (p);

	p = g_slice_new (gint32);
	(nm_g_slice_free_fcn (gint32)) (p);

	p = g_slice_new (gint);
	(nm_g_slice_free_fcn (gint)) (p);

	p = g_slice_new (gint64);
	nm_g_slice_free_fcn_gint64 (p);

	p = g_slice_alloc (sizeof (xx));
	(nm_g_slice_free_fcn (xx)) (p);
}

/*****************************************************************************/

static void
_do_test_nm_utils_strsplit_set (const char *str, ...)
{
	gs_unref_ptrarray GPtrArray *args_array = g_ptr_array_new ();
	const char *const*args;
	gs_free const char **words = NULL;
	const char *arg;
	gsize i;
	va_list ap;

	va_start (ap, str);
	while ((arg = va_arg (ap, const char *)))
		g_ptr_array_add (args_array, (gpointer) arg);
	va_end (ap);
	g_ptr_array_add (args_array, NULL);

	args = (const char *const*) args_array->pdata;

	words = nm_utils_strsplit_set (str, " \t\n");

	if (!args[0]) {
		g_assert (!words);
		g_assert (   !str
		          || NM_STRCHAR_ALL (str, ch, NM_IN_SET (ch, ' ', '\t', '\n')));
		return;
	}
	g_assert (words);
	for (i = 0; args[i] || words[i]; i++) {
		g_assert (args[i]);
		g_assert (words[i]);
		g_assert (args[i][0]);
		g_assert (NM_STRCHAR_ALL (args[i], ch, !NM_IN_SET (ch, ' ', '\t', '\n')));
		g_assert_cmpstr (args[i], ==, words[i]);
	}
}

#define do_test_nm_utils_strsplit_set(str, ...) \
	_do_test_nm_utils_strsplit_set (str, ##__VA_ARGS__, NULL)

static void
test_nm_utils_strsplit_set (void)
{
	do_test_nm_utils_strsplit_set (NULL);
	do_test_nm_utils_strsplit_set ("");
	do_test_nm_utils_strsplit_set ("\t");
	do_test_nm_utils_strsplit_set (" \t\n");
	do_test_nm_utils_strsplit_set ("a", "a");
	do_test_nm_utils_strsplit_set ("a b", "a", "b");
	do_test_nm_utils_strsplit_set ("a\rb", "a\rb");
	do_test_nm_utils_strsplit_set ("  a\rb  ", "a\rb");
	do_test_nm_utils_strsplit_set ("  a bbbd afds ere", "a", "bbbd", "afds", "ere");
	do_test_nm_utils_strsplit_set ("1 2 3 4 5 6 7 8 9 0 "
	                               "1 2 3 4 5 6 7 8 9 0 "
	                               "1 2 3 4 5 6 7 8 9 0",
	                               "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
	                               "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
	                               "1", "2", "3", "4", "5", "6", "7", "8", "9", "0");
}

/*****************************************************************************/

typedef struct {
	int val;
	CList lst;
} CListSort;

static int
_c_list_sort_cmp (const CList *lst_a, const CList *lst_b, const void *user_data)
{
	const CListSort *a, *b;

	g_assert (lst_a);
	g_assert (lst_b);
	g_assert (lst_a != lst_b);

	a = c_list_entry (lst_a, CListSort, lst);
	b = c_list_entry (lst_b, CListSort, lst);

	if (a->val < b->val)
		return -1;
	if (a->val > b->val)
		return 1;
	return 0;
}

static void
_do_test_c_list_sort (CListSort *elements, guint n_list, gboolean headless)
{
	CList head, *iter, *iter_prev, *lst;
	guint i;
	const CListSort *el_prev;
	CListSort *el;

	c_list_init (&head);
	for (i = 0; i < n_list; i++) {
		el = &elements[i];
		el->val = nmtst_get_rand_int () % (2*n_list);
		c_list_link_tail (&head, &el->lst);
	}

	if (headless) {
		lst = head.next;
		c_list_unlink_stale (&head);
		lst = c_list_sort_headless (lst, _c_list_sort_cmp, NULL);
		g_assert (lst);
		g_assert (lst->next);
		g_assert (lst->prev);
		g_assert (c_list_length (lst) == n_list - 1);
		iter_prev = lst->prev;
		for (iter = lst; iter != lst; iter = iter->next) {
			g_assert (iter);
			g_assert (iter->next);
			g_assert (iter->prev == iter_prev);
		}
		c_list_link_before (lst, &head);
	} else
		c_list_sort (&head, _c_list_sort_cmp, NULL);

	g_assert (!c_list_is_empty (&head));
	g_assert (c_list_length (&head) == n_list);

	el_prev = NULL;
	c_list_for_each (iter, &head) {
		el = c_list_entry (iter, CListSort, lst);
		g_assert (el >= elements && el < &elements[n_list]);
		if (el_prev) {
			if (el_prev->val == el->val)
				g_assert (el_prev < el);
			else
				g_assert (el_prev->val < el->val);
			g_assert (iter->prev == &el_prev->lst);
			g_assert (el_prev->lst.next == iter);
		}
		el_prev = el;
	}
	g_assert (head.prev == &el_prev->lst);
}

static void
test_c_list_sort (void)
{
	const guint N_ELEMENTS = 10000;
	guint n_list, repeat;
	gs_free CListSort *elements = NULL;

	{
		CList head;

		c_list_init (&head);
		c_list_sort (&head, _c_list_sort_cmp, NULL);
		g_assert (c_list_length (&head) == 0);
		g_assert (c_list_is_empty (&head));
	}

	elements = g_new0 (CListSort, N_ELEMENTS);
	for (n_list = 1; n_list < N_ELEMENTS; n_list++) {
		if (n_list > 150) {
			n_list += nmtst_get_rand_int () % n_list;
			if (n_list >= N_ELEMENTS)
				break;
		}
		{
			const guint N_REPEAT = n_list > 50 ? 1 : 5;

			for (repeat = 0; repeat < N_REPEAT; repeat++)
				_do_test_c_list_sort (elements, n_list, nmtst_get_rand_int () % 2);
		}
	}
}

/*****************************************************************************/

typedef struct {
	NMDedupMultiObj parent;
	guint val;
	guint other;
} DedupObj;

static const NMDedupMultiObjClass dedup_obj_class;

static DedupObj *
_dedup_obj_assert (const NMDedupMultiObj *obj)
{
	DedupObj *o;

	g_assert (obj);
	o = (DedupObj *) obj;
	g_assert (o->parent.klass == &dedup_obj_class);
	g_assert (o->parent._ref_count > 0);
	g_assert (o->val > 0);
	return o;
}

static const NMDedupMultiObj *
_dedup_obj_clone (const NMDedupMultiObj *obj)
{
	DedupObj *o, *o2;

	o = _dedup_obj_assert (obj);
	o2 = g_slice_new0 (DedupObj);
	o2->parent.klass = &dedup_obj_class;
	o2->parent._ref_count = 1;
	o2->val = o->val;
	o2->other = o->other;
	return (NMDedupMultiObj *) o2;
}

static void
_dedup_obj_destroy (NMDedupMultiObj *obj)
{
	DedupObj *o = (DedupObj *) obj;

	nm_assert (o->parent._ref_count == 0);
	o->parent._ref_count = 1;
	o = _dedup_obj_assert (obj);
	g_slice_free (DedupObj, o);
}

static void
_dedup_obj_full_hash_update (const NMDedupMultiObj *obj, NMHashState *h)
{
	const DedupObj *o;

	o = _dedup_obj_assert (obj);
	nm_hash_update_vals (h,
	                     o->val,
	                     o->other);
}

static gboolean
_dedup_obj_full_equal (const NMDedupMultiObj *obj_a,
                       const NMDedupMultiObj *obj_b)
{
	const DedupObj *o_a = _dedup_obj_assert (obj_a);
	const DedupObj *o_b = _dedup_obj_assert (obj_b);

	return    o_a->val == o_b->val
	       && o_a->other == o_b->other;
}

static const NMDedupMultiObjClass dedup_obj_class = {
	.obj_clone = _dedup_obj_clone,
	.obj_destroy = _dedup_obj_destroy,
	.obj_full_hash_update = _dedup_obj_full_hash_update,
	.obj_full_equal = _dedup_obj_full_equal,
};

#define DEDUP_OBJ_INIT(val_val, other_other) \
	(&((DedupObj) { \
		.parent = { \
			.klass = &dedup_obj_class, \
			._ref_count = NM_OBJ_REF_COUNT_STACKINIT, \
		}, \
		.val = (val_val), \
		.other = (other_other), \
	}))

typedef struct {
	NMDedupMultiIdxType parent;
	guint partition_size;
	guint val_mod;
} DedupIdxType;

static const NMDedupMultiIdxTypeClass dedup_idx_type_class;

static const DedupIdxType *
_dedup_idx_assert (const NMDedupMultiIdxType *idx_type)
{
	DedupIdxType *t;

	g_assert (idx_type);
	t = (DedupIdxType *) idx_type;
	g_assert (t->parent.klass == &dedup_idx_type_class);
	g_assert (t->partition_size > 0);
	g_assert (t->val_mod > 0);
	return t;
}

static void
_dedup_idx_obj_id_hash_update (const NMDedupMultiIdxType *idx_type,
                               const NMDedupMultiObj *obj,
                               NMHashState *h)
{
	const DedupIdxType *t;
	const DedupObj *o;

	t = _dedup_idx_assert (idx_type);
	o = _dedup_obj_assert (obj);

	nm_hash_update_val (h, o->val / t->partition_size);
	nm_hash_update_val (h, o->val % t->val_mod);
}

static gboolean
_dedup_idx_obj_id_equal (const NMDedupMultiIdxType *idx_type,
                         const NMDedupMultiObj *obj_a,
                         const NMDedupMultiObj *obj_b)
{
	const DedupIdxType *t;
	const DedupObj *o_a;
	const DedupObj *o_b;

	t = _dedup_idx_assert (idx_type);
	o_a = _dedup_obj_assert (obj_a);
	o_b = _dedup_obj_assert (obj_b);

	return    (o_a->val / t->partition_size) == (o_b->val / t->partition_size)
	       && (o_a->val % t->val_mod) == (o_b->val % t->val_mod);
}

static void
_dedup_idx_obj_partition_hash_update (const NMDedupMultiIdxType *idx_type,
                                      const NMDedupMultiObj *obj,
                                      NMHashState *h)
{
	const DedupIdxType *t;
	const DedupObj *o;

	t = _dedup_idx_assert (idx_type);
	o = _dedup_obj_assert (obj);

	nm_hash_update_val (h, o->val / t->partition_size);
}

static gboolean
_dedup_idx_obj_partition_equal (const NMDedupMultiIdxType *idx_type,
                                const NMDedupMultiObj *obj_a,
                                const NMDedupMultiObj *obj_b)
{
	const DedupIdxType *t;
	const DedupObj *o_a;
	const DedupObj *o_b;

	t = _dedup_idx_assert (idx_type);
	o_a = _dedup_obj_assert (obj_a);
	o_b = _dedup_obj_assert (obj_b);

	return (o_a->val / t->partition_size) == (o_b->val / t->partition_size);
}

static const NMDedupMultiIdxTypeClass dedup_idx_type_class = {
	.idx_obj_id_hash_update = _dedup_idx_obj_id_hash_update,
	.idx_obj_id_equal = _dedup_idx_obj_id_equal,
	.idx_obj_partition_hash_update = _dedup_idx_obj_partition_hash_update,
	.idx_obj_partition_equal = _dedup_idx_obj_partition_equal,
};

static const DedupIdxType *
DEDUP_IDX_TYPE_INIT (DedupIdxType *idx_type, guint partition_size, guint val_mod)
{
	nm_dedup_multi_idx_type_init ((NMDedupMultiIdxType *) idx_type, &dedup_idx_type_class);
	idx_type->val_mod = val_mod;
	idx_type->partition_size = partition_size;
	return idx_type;
}

static gboolean
_dedup_idx_add (NMDedupMultiIndex *idx, const DedupIdxType *idx_type, const DedupObj *obj, NMDedupMultiIdxMode mode, const NMDedupMultiEntry **out_entry)
{
	g_assert (idx);
	_dedup_idx_assert ((NMDedupMultiIdxType *) idx_type);
	if (obj)
		_dedup_obj_assert ((NMDedupMultiObj *) obj);
	return nm_dedup_multi_index_add (idx, (NMDedupMultiIdxType *) idx_type,
	                                 obj, mode, out_entry, NULL);
}

static void
_dedup_head_entry_assert (const NMDedupMultiHeadEntry *entry)
{
	g_assert (entry);
	g_assert (entry->len > 0);
	g_assert (entry->len == c_list_length (&entry->lst_entries_head));
	g_assert (entry->idx_type);
	g_assert (entry->is_head);
}

static const DedupObj *
_dedup_entry_assert (const NMDedupMultiEntry *entry)
{
	g_assert (entry);
	g_assert (!c_list_is_empty (&entry->lst_entries));
	g_assert (entry->head);
	g_assert (!entry->is_head);
	g_assert (entry->head != (gpointer) entry);
	_dedup_head_entry_assert (entry->head);
	return _dedup_obj_assert (entry->obj);
}

static const DedupIdxType *
_dedup_entry_get_idx_type (const NMDedupMultiEntry *entry)
{
	_dedup_entry_assert (entry);

	g_assert (entry->head);
	g_assert (entry->head->idx_type);
	return _dedup_idx_assert (entry->head->idx_type);
}

static void
_dedup_entry_assert_all (const NMDedupMultiEntry *entry, gssize expected_idx, const DedupObj *const*expected_obj)
{
	gsize n, i;
	CList *iter;

	g_assert (entry);
	_dedup_entry_assert (entry);

	g_assert (expected_obj);
	n = NM_PTRARRAY_LEN (expected_obj);

	g_assert (n == c_list_length (&entry->lst_entries));

	g_assert (expected_idx >= -1 && expected_idx < n);
	g_assert (entry->head);
	if (expected_idx == -1)
		g_assert (entry->head == (gpointer) entry);
	else
		g_assert (entry->head != (gpointer) entry);

	i = 0;
	c_list_for_each (iter, &entry->head->lst_entries_head) {
		const NMDedupMultiEntry *entry_current = c_list_entry (iter, NMDedupMultiEntry, lst_entries);
		const DedupObj *obj_current;
		const DedupIdxType *idx_type = _dedup_entry_get_idx_type (entry_current);

		obj_current = _dedup_entry_assert (entry_current);
		g_assert (obj_current);
		g_assert (i < n);
		if (expected_idx == i)
			g_assert (entry_current == entry);
		g_assert (idx_type->parent.klass->idx_obj_partition_equal (&idx_type->parent,
		                                                           entry_current->obj,
		                                                           c_list_entry (entry->head->lst_entries_head.next, NMDedupMultiEntry, lst_entries)->obj));
		i++;
	}
}
#define _dedup_entry_assert_all(entry, expected_idx, ...) _dedup_entry_assert_all (entry, expected_idx, (const DedupObj *const[]) { __VA_ARGS__, NULL })

static void
test_dedup_multi (void)
{
	NMDedupMultiIndex *idx;
	DedupIdxType IDX_20_3_a_stack;
	const DedupIdxType *const IDX_20_3_a = DEDUP_IDX_TYPE_INIT (&IDX_20_3_a_stack, 20, 3);
	const NMDedupMultiEntry *entry1;

	idx = nm_dedup_multi_index_new ();

	g_assert (_dedup_idx_add (idx, IDX_20_3_a, DEDUP_OBJ_INIT (1, 1), NM_DEDUP_MULTI_IDX_MODE_APPEND, &entry1));
	_dedup_entry_assert_all (entry1, 0, DEDUP_OBJ_INIT (1, 1));

	g_assert (nm_dedup_multi_index_obj_find (idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT (1, 1)));
	g_assert (!nm_dedup_multi_index_obj_find (idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT (1, 2)));

	g_assert (_dedup_idx_add (idx, IDX_20_3_a, DEDUP_OBJ_INIT (1, 2), NM_DEDUP_MULTI_IDX_MODE_APPEND, &entry1));
	_dedup_entry_assert_all (entry1, 0, DEDUP_OBJ_INIT (1, 2));

	g_assert (!nm_dedup_multi_index_obj_find (idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT (1, 1)));
	g_assert (nm_dedup_multi_index_obj_find (idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT (1, 2)));

	g_assert (_dedup_idx_add (idx, IDX_20_3_a, DEDUP_OBJ_INIT (2, 2), NM_DEDUP_MULTI_IDX_MODE_APPEND, &entry1));
	_dedup_entry_assert_all (entry1, 1, DEDUP_OBJ_INIT (1, 2), DEDUP_OBJ_INIT (2, 2));

	nm_dedup_multi_index_unref (idx);
}

/*****************************************************************************/

static NMConnection *
_connection_new_from_dbus (GVariant *dict, GError **error)
{
	return _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_NORMALIZE, error);
}

static void
vpn_check_func (const char *key, const char *value, gpointer user_data)
{
	if (!strcmp (key, "foobar1")) {
		g_assert_cmpstr (value, ==, "blahblah1");
		return;
	}

	if (!strcmp (key, "foobar2")) {
		g_assert_cmpstr (value, ==, "blahblah2");
		return;
	}

	if (!strcmp (key, "foobar3")) {
		g_assert_cmpstr (value, ==, "blahblah3");
		return;
	}

	if (!strcmp (key, "foobar4")) {
		g_assert_cmpstr (value, ==, "blahblah4");
		return;
	}

	g_assert_not_reached ();
}

static void
vpn_check_empty_func (const char *key, const char *value, gpointer user_data)
{
	g_assert_not_reached ();
}

static void
test_setting_vpn_items (void)
{
	gs_unref_object NMSettingVpn *s_vpn = NULL;

	s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
	g_assert (s_vpn);

	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_data_item (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_data_item (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_data_item (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_func, NULL);
	nm_setting_vpn_remove_data_item (s_vpn, "foobar1");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar2");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar3");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar4");

	nm_setting_vpn_add_secret (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_secret (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_secret (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_secret (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_func, NULL);
	nm_setting_vpn_remove_secret (s_vpn, "foobar1");
	nm_setting_vpn_remove_secret (s_vpn, "foobar2");
	nm_setting_vpn_remove_secret (s_vpn, "foobar3");
	nm_setting_vpn_remove_secret (s_vpn, "foobar4");

	/* Try to add some blank values and make sure they are rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (key != NULL));
	nm_setting_vpn_add_data_item (s_vpn, NULL, NULL);
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strlen (key) > 0));
	nm_setting_vpn_add_data_item (s_vpn, "", "");
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (item != NULL));
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", NULL);
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strlen (item) > 0));
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "");
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (key != NULL));
	nm_setting_vpn_add_data_item (s_vpn, NULL, "blahblah1");
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strlen (key) > 0));
	nm_setting_vpn_add_data_item (s_vpn, "", "blahblah1");
	g_test_assert_expected_messages ();

	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_empty_func, NULL);

	/* Try to add some blank secrets and make sure they are rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (key != NULL));
	nm_setting_vpn_add_secret (s_vpn, NULL, NULL);
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strlen (key) > 0));
	nm_setting_vpn_add_secret (s_vpn, "", "");
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (secret != NULL));
	nm_setting_vpn_add_secret (s_vpn, "foobar1", NULL);
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strlen (secret) > 0));
	nm_setting_vpn_add_secret (s_vpn, "foobar1", "");
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (key != NULL));
	nm_setting_vpn_add_secret (s_vpn, NULL, "blahblah1");
	g_test_assert_expected_messages ();

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strlen (key) > 0));
	nm_setting_vpn_add_secret (s_vpn, "", "blahblah1");
	g_test_assert_expected_messages ();

	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_empty_func, NULL);
}

static void
test_setting_vpn_update_secrets (void)
{
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	GVariantBuilder settings_builder, vpn_builder, secrets_builder;
	GVariant *settings;
	gboolean success;
	GError *error = NULL;
	const char *tmp;
	const char *key1 = "foobar";
	const char *key2 = "blahblah";
	const char *val1 = "value1";
	const char *val2 = "value2";

	connection = nm_simple_connection_new ();
	s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	g_variant_builder_init (&settings_builder, NM_VARIANT_TYPE_CONNECTION);
	g_variant_builder_init (&vpn_builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_init (&secrets_builder, G_VARIANT_TYPE ("a{ss}"));

	g_variant_builder_add (&secrets_builder, "{ss}", key1, val1);
	g_variant_builder_add (&secrets_builder, "{ss}", key2, val2);

	g_variant_builder_add (&vpn_builder, "{sv}",
	                       NM_SETTING_VPN_SECRETS,
	                       g_variant_builder_end (&secrets_builder));
	g_variant_builder_add (&settings_builder, "{sa{sv}}",
	                       NM_SETTING_VPN_SETTING_NAME,
	                       &vpn_builder);
	settings = g_variant_builder_end (&settings_builder);

	success = nm_connection_update_secrets (connection, NM_SETTING_VPN_SETTING_NAME, settings, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Read the secrets back out */
	tmp = nm_setting_vpn_get_secret (s_vpn, key1);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, val1);

	tmp = nm_setting_vpn_get_secret (s_vpn, key2);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, val2);

	g_variant_unref (settings);
	g_object_unref (connection);
}

#define TO_DEL_NUM 50
typedef struct {
	NMSettingVpn *s_vpn;
	char *to_del[TO_DEL_NUM];
	guint called;
} IterInfo;

static void
del_iter_func (const char *key, const char *value, gpointer user_data)
{
	IterInfo *info = user_data;
	int i;

	/* Record how many times this function gets called; it should get called
	 * exactly as many times as there are keys in the hash table, regardless
	 * of what keys we delete from the table.
	 */
	info->called++;

	/* During the iteration, remove a bunch of stuff from the table */
	if (info->called == 1) {
		for (i = 0; i < TO_DEL_NUM; i++)
			nm_setting_vpn_remove_data_item (info->s_vpn, info->to_del[i]);
	}
}

static void
test_setting_vpn_modify_during_foreach (void)
{
	NMSettingVpn *s_vpn;
	IterInfo info;
	char *key, *val;
	int i, u = 0;

	s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
	g_assert (s_vpn);

	for (i = 0; i < TO_DEL_NUM * 2; i++) {
		key = g_strdup_printf ("adsfasdfadf%d", i);
		val = g_strdup_printf ("42263236236awt%d", i);
		nm_setting_vpn_add_data_item (s_vpn, key, val);

		/* Cache some keys to delete */
		if (i % 2)
			info.to_del[u++] = g_strdup (key);

		g_free (key);
		g_free (val);
	}

	/* Iterate over current table keys */
	info.s_vpn = s_vpn;
	info.called = 0;
	nm_setting_vpn_foreach_data_item (s_vpn, del_iter_func, &info);

	/* Make sure all the things we removed during iteration are really gone */
	for (i = 0; i < TO_DEL_NUM; i++) {
		g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, info.to_del[i]), ==, NULL);
		g_free (info.to_del[i]);
	}

	/* And make sure the foreach callback was called the same number of times
	 * as there were keys in the table at the beginning of the foreach.
	 */
	g_assert_cmpint (info.called, ==, TO_DEL_NUM * 2);

	g_object_unref (s_vpn);
}

static void
test_setting_ip4_config_labels (void)
{
	NMSettingIPConfig *s_ip4;
	NMIPAddress *addr;
	GVariant *label;
	GPtrArray *addrs;
	char **labels;
	NMConnection *conn;
	GVariant *dict, *dict2, *setting_dict, *value;
	GError *error = NULL;

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	/* addr 1 */
	addr = nm_ip_address_new (AF_INET, "1.2.3.4", 24, &error);
	g_assert_no_error (error);

	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);

	/* The 'address-labels' property should be omitted from the serialization if
	 * there are no non-NULL labels.
	 */
	conn = nmtst_create_minimal_connection ("label test", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nm_connection_add_setting (conn, nm_setting_duplicate (NM_SETTING (s_ip4)));
	dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);
	g_object_unref (conn);

	setting_dict = g_variant_lookup_value (dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (setting_dict != NULL);

	value = g_variant_lookup_value (setting_dict, "address-labels", NULL);
	g_assert (value == NULL);

	g_variant_unref (setting_dict);
	g_variant_unref (dict);

	/* Now back to constructing the original s_ip4... */

	/* addr 2 */
	addr = nm_ip_address_new (AF_INET, "2.3.4.5", 24, &error);
	g_assert_no_error (error);
	nm_ip_address_set_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string ("eth0:1"));

	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));

	addr = nm_setting_ip_config_get_address (s_ip4, 1);
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label != NULL);
	g_assert_cmpstr (g_variant_get_string (label, NULL), ==, "eth0:1");

	/* addr 3 */
	addr = nm_ip_address_new (AF_INET, "3.4.5.6", 24, &error);
	g_assert_no_error (error);
	nm_ip_address_set_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL, NULL);

	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));

	addr = nm_setting_ip_config_get_address (s_ip4, 2);
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);

	/* Remove addr 1 and re-verify remaining addresses */
	nm_setting_ip_config_remove_address (s_ip4, 0);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "2.3.4.5");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label != NULL);
	g_assert_cmpstr (g_variant_get_string (label, NULL), ==, "eth0:1");

	addr = nm_setting_ip_config_get_address (s_ip4, 1);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "3.4.5.6");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);

	/* If we serialize as the daemon, the labels should appear in the D-Bus
	 * serialization under both 'address-labels' and 'address-data'.
	 */
	conn = nmtst_create_minimal_connection ("label test", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nm_connection_add_setting (conn, NM_SETTING (s_ip4));
	_nm_utils_is_manager_process = TRUE;
	dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);
	_nm_utils_is_manager_process = FALSE;
	g_object_unref (conn);

	setting_dict = g_variant_lookup_value (dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (setting_dict != NULL);

	value = g_variant_lookup_value (setting_dict, "address-labels", G_VARIANT_TYPE_STRING_ARRAY);
	g_assert (value != NULL);
	g_variant_get (value, "^as", &labels);
	g_assert_cmpint (g_strv_length (labels), ==, 2);
	g_assert_cmpstr (labels[0], ==, "eth0:1");
	g_assert_cmpstr (labels[1], ==, "");
	g_variant_unref (value);
	g_strfreev (labels);

	value = g_variant_lookup_value (setting_dict, "address-data", G_VARIANT_TYPE ("aa{sv}"));
	addrs = nm_utils_ip_addresses_from_variant (value, AF_INET);
	g_variant_unref (value);
	g_assert (addrs != NULL);
	g_assert_cmpint (addrs->len, ==, 2);
	addr = addrs->pdata[0];
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label != NULL);
	g_assert_cmpstr (g_variant_get_string (label, NULL), ==, "eth0:1");
	addr = addrs->pdata[1];
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);
	g_ptr_array_unref (addrs);

	g_variant_unref (setting_dict);

	/* We should be able to deserialize the labels from either 'address-labels'
	 * or 'address-data'.
	 */
	dict2 = g_variant_ref (dict);

	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                                   "address-data");
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_no_error (error);
	g_variant_unref (dict);

	s_ip4 = nm_connection_get_setting_ip4_config (conn);

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "2.3.4.5");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label != NULL);
	g_assert_cmpstr (g_variant_get_string (label, NULL), ==, "eth0:1");

	addr = nm_setting_ip_config_get_address (s_ip4, 1);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "3.4.5.6");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);

	g_object_unref (conn);

	NMTST_VARIANT_EDITOR (dict2,
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                                   "address-labels");
	                      );
	conn = _connection_new_from_dbus (dict2, &error);
	g_assert_no_error (error);
	g_variant_unref (dict2);

	s_ip4 = nm_connection_get_setting_ip4_config (conn);

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "2.3.4.5");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert_cmpstr (g_variant_get_string (label, NULL), ==, "eth0:1");

	addr = nm_setting_ip_config_get_address (s_ip4, 1);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "3.4.5.6");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);

	/* Test explicit property assignment */
	g_object_get (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_ADDRESSES, &addrs,
	              NULL);

	nm_setting_ip_config_clear_addresses (s_ip4);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);

	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_ADDRESSES, addrs,
	              NULL);
	g_ptr_array_unref (addrs);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 2);

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "2.3.4.5");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label != NULL);
	g_assert_cmpstr (g_variant_get_string (label, NULL), ==, "eth0:1");

	addr = nm_setting_ip_config_get_address (s_ip4, 1);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "3.4.5.6");
	label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
	g_assert (label == NULL);

	g_object_unref (conn);
}

static void
test_setting_ip4_config_address_data (void)
{
	NMSettingIPConfig *s_ip4;
	NMIPAddress *addr;
	GPtrArray *addrs;
	NMConnection *conn;
	GVariant *dict, *setting_dict, *value;
	GError *error = NULL;

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	/* addr 1 */
	addr = nm_ip_address_new (AF_INET, "1.2.3.4", 24, &error);
	g_assert_no_error (error);
	nm_ip_address_set_attribute (addr, "one", g_variant_new_string ("foo"));
	nm_ip_address_set_attribute (addr, "two", g_variant_new_int32 (42));

	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));

	/* addr 2 */
	addr = nm_ip_address_new (AF_INET, "2.3.4.5", 24, &error);
	g_assert_no_error (error);

	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);
	nmtst_assert_setting_verifies (NM_SETTING (s_ip4));

	/* The client-side D-Bus serialization should include the attributes in
	 * "address-data", and should not have an "addresses" property.
	 */
	conn = nmtst_create_minimal_connection ("address-data test", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nm_connection_add_setting (conn, NM_SETTING (s_ip4));
	dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);

	setting_dict = g_variant_lookup_value (dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (setting_dict != NULL);

	value = g_variant_lookup_value (setting_dict, "addresses", NULL);
	g_assert (value == NULL);

	value = g_variant_lookup_value (setting_dict, "address-data", G_VARIANT_TYPE ("aa{sv}"));
	addrs = nm_utils_ip_addresses_from_variant (value, AF_INET);
	g_variant_unref (value);
	g_assert (addrs != NULL);
	g_assert_cmpint (addrs->len, ==, 2);

	addr = addrs->pdata[0];
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "1.2.3.4");
	value = nm_ip_address_get_attribute (addr, "one");
	g_assert (value != NULL);
	g_assert_cmpstr (g_variant_get_string (value, NULL), ==, "foo");
	value = nm_ip_address_get_attribute (addr, "two");
	g_assert (value != NULL);
	g_assert_cmpint (g_variant_get_int32 (value), ==, 42);

	g_ptr_array_unref (addrs);
	g_variant_unref (setting_dict);
	g_variant_unref (dict);

	/* The daemon-side serialization should include both 'addresses' and 'address-data' */
	_nm_utils_is_manager_process = TRUE;
	dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);
	_nm_utils_is_manager_process = FALSE;

	setting_dict = g_variant_lookup_value (dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (setting_dict != NULL);

	value = g_variant_lookup_value (setting_dict, "addresses", G_VARIANT_TYPE ("aau"));
	g_assert (value != NULL);
	g_variant_unref (value);

	value = g_variant_lookup_value (setting_dict, "address-data", G_VARIANT_TYPE ("aa{sv}"));
	g_assert (value != NULL);
	g_variant_unref (value);

	g_variant_unref (setting_dict);
	g_object_unref (conn);

	/* When we reserialize that dictionary as a client, 'address-data' will be preferred. */
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_no_error (error);

	s_ip4 = nm_connection_get_setting_ip4_config (conn);

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "1.2.3.4");
	value = nm_ip_address_get_attribute (addr, "one");
	g_assert (value != NULL);
	g_assert_cmpstr (g_variant_get_string (value, NULL), ==, "foo");
	value = nm_ip_address_get_attribute (addr, "two");
	g_assert (value != NULL);
	g_assert_cmpint (g_variant_get_int32 (value), ==, 42);

	/* But on the server side, 'addresses' will have precedence. */
	_nm_utils_is_manager_process = TRUE;
	conn = _connection_new_from_dbus (dict, &error);
	_nm_utils_is_manager_process = FALSE;
	g_assert_no_error (error);
	g_variant_unref (dict);

	s_ip4 = nm_connection_get_setting_ip4_config (conn);

	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "1.2.3.4");
	value = nm_ip_address_get_attribute (addr, "one");
	g_assert (value == NULL);
	value = nm_ip_address_get_attribute (addr, "two");
	g_assert (value == NULL);

	g_object_unref (conn);
}

static void
test_setting_ip_route_attributes (void)
{
	GVariant *variant;
	gboolean res, known;

#define TEST_ATTR(name, type, value, family, exp_res, exp_known) \
	variant = g_variant_new_ ## type (value); \
	res = nm_ip_route_attribute_validate (name, variant, family, &known, NULL); \
	g_assert (res == exp_res); \
	g_assert (known == exp_known); \
	g_variant_unref (variant);

	TEST_ATTR ("foo", uint32, 12, AF_INET, FALSE, FALSE);

	TEST_ATTR ("tos", byte,   127, AF_INET, TRUE, TRUE);
	TEST_ATTR ("tos", string, "0x28", AF_INET, FALSE, TRUE);

	TEST_ATTR ("cwnd",  uint32, 10,    AF_INET, TRUE,  TRUE);
	TEST_ATTR ("cwnd",  string, "11",  AF_INET, FALSE, TRUE);

	TEST_ATTR ("lock-mtu", boolean, TRUE, AF_INET, TRUE,  TRUE);
	TEST_ATTR ("lock-mtu", uint32,  1,    AF_INET, FALSE, TRUE);

	TEST_ATTR ("from", string, "fd01::1",     AF_INET6, TRUE,  TRUE);
	TEST_ATTR ("from", string, "fd01::1/64",  AF_INET6, TRUE,  TRUE);
	TEST_ATTR ("from", string, "fd01::1/128", AF_INET6, TRUE,  TRUE);
	TEST_ATTR ("from", string, "fd01::1/129", AF_INET6, FALSE, TRUE);
	TEST_ATTR ("from", string, "fd01::1/a",   AF_INET6, FALSE, TRUE);
	TEST_ATTR ("from", string, "abc/64",      AF_INET6, FALSE, TRUE);
	TEST_ATTR ("from", string, "1.2.3.4",     AF_INET,  FALSE, TRUE);
	TEST_ATTR ("from", string, "1.2.3.4",     AF_INET6, FALSE, TRUE);

	TEST_ATTR ("src", string, "1.2.3.4",    AF_INET,  TRUE,  TRUE);
	TEST_ATTR ("src", string, "1.2.3.4",    AF_INET6, FALSE, TRUE);
	TEST_ATTR ("src", string, "1.2.3.0/24", AF_INET,  FALSE, TRUE);
	TEST_ATTR ("src", string, "fd01::12",   AF_INET6, TRUE,  TRUE);

#undef TEST_ATTR
}

static void
test_setting_gsm_apn_spaces (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;
	const char *tmp;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	/* Trailing space */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar ", NULL);
	tmp = nm_setting_gsm_get_apn (s_gsm);
	g_assert_cmpstr (tmp, ==, "foobar");

	/* Leading space */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, " foobar", NULL);
	tmp = nm_setting_gsm_get_apn (s_gsm);
	g_assert_cmpstr (tmp, ==, "foobar");
}

static void
test_setting_gsm_apn_bad_chars (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);

	/* Make sure a valid APN works */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar123.-baz", NULL);
	g_assert (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL));

	/* Random invalid chars */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "@#%$@#%@#%", NULL);
	g_assert (!nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL));

	/* Spaces */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar baz", NULL);
	g_assert (!nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL));

	/* 0 characters long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "", NULL);
	g_assert (!nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL));

	/* 65-character long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl1", NULL);
	g_assert (!nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL));
}

static void
test_setting_gsm_apn_underscore (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);

	/* 65-character long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar_baz", NULL);
	nmtst_assert_setting_verifies (NM_SETTING (s_gsm));
}

static void
test_setting_gsm_without_number (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, NULL, NULL);
	nmtst_assert_setting_verifies (NM_SETTING (s_gsm));

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "", NULL);
	nmtst_assert_setting_verify_fails (NM_SETTING (s_gsm), NM_CONNECTION_ERROR,
	                                   NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
test_setting_gsm_sim_operator_id (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	/* Valid */
	g_object_set (s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "12345", NULL);
	nmtst_assert_setting_verifies (NM_SETTING (s_gsm));

	g_object_set (s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "123456", NULL);
	nmtst_assert_setting_verifies (NM_SETTING (s_gsm));

	/* Invalid */
	g_object_set (s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "", NULL);
	nmtst_assert_setting_verify_fails (NM_SETTING (s_gsm), NM_CONNECTION_ERROR,
	                                   NM_CONNECTION_ERROR_INVALID_PROPERTY);

	g_object_set (s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "     ", NULL);
	nmtst_assert_setting_verify_fails (NM_SETTING (s_gsm), NM_CONNECTION_ERROR,
	                                   NM_CONNECTION_ERROR_INVALID_PROPERTY);

	g_object_set (s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "abcdef", NULL);
	nmtst_assert_setting_verify_fails (NM_SETTING (s_gsm), NM_CONNECTION_ERROR,
	                                   NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static NMSettingWirelessSecurity *
make_test_wsec_setting (const char *detail)
{
	NMSettingWirelessSecurity *s_wsec;

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "foobarbaz",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "random psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS, NM_SETTING_SECRET_FLAG_NOT_SAVED,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, "aaaaaaaaaa",
	              NULL);
	return s_wsec;
}

static gboolean
_variant_contains (GVariant *vardict, const char *key)
{
	gs_unref_variant GVariant *value = NULL;

	value = g_variant_lookup_value (vardict, key, NULL);
	return !!value;
}

static void
test_setting_to_dbus_all (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GVariant *dict;

	s_wsec = make_test_wsec_setting ("setting-to-dbus-all");

	dict = _nm_setting_to_dbus (NM_SETTING (s_wsec), NULL, NM_CONNECTION_SERIALIZE_ALL);

	/* Make sure all keys are there */
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT));
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME));
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_PSK));
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0));

	g_variant_unref (dict);
	g_object_unref (s_wsec);
}

static void
test_setting_to_dbus_no_secrets (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GVariant *dict;

	s_wsec = make_test_wsec_setting ("setting-to-dbus-no-secrets");

	dict = _nm_setting_to_dbus (NM_SETTING (s_wsec), NULL, NM_CONNECTION_SERIALIZE_NO_SECRETS);

	/* Make sure non-secret keys are there */
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT));
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME));

	/* Make sure secrets are not there */
	g_assert (!_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_PSK));
	g_assert (!_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0));

	g_variant_unref (dict);
	g_object_unref (s_wsec);
}

static void
test_setting_to_dbus_only_secrets (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GVariant *dict;

	s_wsec = make_test_wsec_setting ("setting-to-dbus-only-secrets");

	dict = _nm_setting_to_dbus (NM_SETTING (s_wsec), NULL, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);

	/* Make sure non-secret keys are not there */
	g_assert (!_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT));
	g_assert (!_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME));

	/* Make sure secrets are there */
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_PSK));
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0));

	g_variant_unref (dict);
	g_object_unref (s_wsec);
}

static void
test_setting_to_dbus_transform (void)
{
	NMSetting *s_wired;
	GVariant *dict, *val;
	const char *test_mac_address = "11:22:33:44:55:66";
	const guint8 *dbus_mac_address;
	guint8 cmp_mac_address[ETH_ALEN];
	gsize len;

	s_wired = nm_setting_wired_new ();
	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, test_mac_address,
	              NULL);

	g_assert_cmpstr (nm_setting_wired_get_mac_address (NM_SETTING_WIRED (s_wired)), ==, test_mac_address);

	dict = _nm_setting_to_dbus (s_wired, NULL, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (dict != NULL);

	val = g_variant_lookup_value (dict, NM_SETTING_WIRED_MAC_ADDRESS, G_VARIANT_TYPE_BYTESTRING);
	g_assert (val != NULL);

	dbus_mac_address = g_variant_get_fixed_array (val, &len, 1);
	g_assert_cmpint (len, ==, ETH_ALEN);

	nm_utils_hwaddr_aton (test_mac_address, cmp_mac_address, ETH_ALEN);
	g_assert (memcmp (dbus_mac_address, cmp_mac_address, ETH_ALEN) == 0);

	g_variant_unref (val);
	g_variant_unref (dict);
	g_object_unref (s_wired);
}

static void
test_setting_to_dbus_enum (void)
{
	NMSetting *s_ip6, *s_wsec, *s_serial;
	GVariant *dict, *val;

	/* enum */
	s_ip6 = nm_setting_ip6_config_new ();
	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_IP6_PRIVACY, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
	              NULL);

	dict = _nm_setting_to_dbus (s_ip6, NULL, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (dict != NULL);

	val = g_variant_lookup_value (dict, NM_SETTING_IP6_CONFIG_IP6_PRIVACY, G_VARIANT_TYPE_INT32);
	g_assert (val != NULL);
	g_assert_cmpint (g_variant_get_int32 (val), ==, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
	g_variant_unref (val);

	g_variant_unref (dict);
	g_object_unref (s_ip6);

	/* flags (and a transformed enum) */
	s_wsec = nm_setting_wireless_security_new ();
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_KEY,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, (NM_SETTING_SECRET_FLAG_AGENT_OWNED |
	                                                           NM_SETTING_SECRET_FLAG_NOT_SAVED),
	              NULL);

	dict = _nm_setting_to_dbus (s_wsec, NULL, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (dict != NULL);

	val = g_variant_lookup_value (dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, G_VARIANT_TYPE_UINT32);
	g_assert (val != NULL);
	g_assert_cmpint (g_variant_get_uint32 (val), ==, NM_WEP_KEY_TYPE_KEY);
	g_variant_unref (val);

	val = g_variant_lookup_value (dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, G_VARIANT_TYPE_UINT32);
	g_assert (val != NULL);
	g_assert_cmpint (g_variant_get_uint32 (val), ==, (NM_SETTING_SECRET_FLAG_AGENT_OWNED |
	                                                  NM_SETTING_SECRET_FLAG_NOT_SAVED));
	g_variant_unref (val);

	g_variant_unref (dict);
	g_object_unref (s_wsec);

	/* another transformed enum */
	s_serial = nm_setting_serial_new ();
	g_object_set (s_serial,
	              NM_SETTING_SERIAL_PARITY, NM_SETTING_SERIAL_PARITY_ODD,
	              NULL);

	dict = _nm_setting_to_dbus (s_serial, NULL, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (dict != NULL);

	val = g_variant_lookup_value (dict, NM_SETTING_SERIAL_PARITY, G_VARIANT_TYPE_BYTE);
	g_assert (val != NULL);
	g_assert_cmpint (g_variant_get_byte (val), ==, 'o');
	g_variant_unref (val);

	g_variant_unref (dict);
	g_object_unref (s_serial);
}

static void
test_connection_to_dbus_setting_name (void)
{
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	GVariant *dict;

	connection = nm_simple_connection_new ();
	s_wsec = make_test_wsec_setting ("connection-to-dbus-setting-name");
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	/* Make sure the keys of the first level dict are setting names, not
	 * the GType name of the setting objects.
	 */
	g_assert (_variant_contains (dict, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME));

	g_variant_unref (dict);
	g_object_unref (connection);
}

static void
test_connection_to_dbus_deprecated_props (void)
{
	NMConnection *connection;
	NMSetting *s_wireless;
	GBytes *ssid;
	NMSettingWirelessSecurity *s_wsec;
	GVariant *dict, *wireless_dict, *sec_val;

	connection = nmtst_create_minimal_connection ("test-connection-to-dbus-deprecated-props",
	                                              NULL,
	                                              NM_SETTING_WIRELESS_SETTING_NAME,
	                                              NULL);

	s_wireless = nm_setting_wireless_new ();
	ssid = g_bytes_new ("1234567", 7);
	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NULL);
	g_bytes_unref (ssid);
	nm_connection_add_setting (connection, s_wireless);

	/* Serialization should not have an 802-11-wireless.security property */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (dict != NULL);

	wireless_dict = g_variant_lookup_value (dict, NM_SETTING_WIRELESS_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (wireless_dict != NULL);

	sec_val = g_variant_lookup_value (wireless_dict, "security", NULL);
	g_assert (sec_val == NULL);

	g_variant_unref (wireless_dict);
	g_variant_unref (dict);

	/* Now add an NMSettingWirelessSecurity and try again */
	s_wsec = make_test_wsec_setting ("test-connection-to-dbus-deprecated-props");
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (dict != NULL);

	wireless_dict = g_variant_lookup_value (dict, NM_SETTING_WIRELESS_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (wireless_dict != NULL);

	sec_val = g_variant_lookup_value (wireless_dict, "security", NULL);
	g_assert (g_variant_is_of_type (sec_val, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (sec_val, NULL), ==, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	g_variant_unref (sec_val);
	g_variant_unref (wireless_dict);
	g_variant_unref (dict);
	g_object_unref (connection);
}

static void
test_setting_new_from_dbus (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GVariant *dict;

	s_wsec = make_test_wsec_setting ("setting-new-from-dbus");
	dict = _nm_setting_to_dbus (NM_SETTING (s_wsec), NULL, NM_CONNECTION_SERIALIZE_ALL);
	g_object_unref (s_wsec);

	s_wsec = (NMSettingWirelessSecurity *) _nm_setting_new_from_dbus (NM_TYPE_SETTING_WIRELESS_SECURITY, dict, NULL, NM_SETTING_PARSE_FLAGS_NONE, NULL);
	g_variant_unref (dict);

	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_leap_username (s_wsec), ==, "foobarbaz");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "random psk");
	g_object_unref (s_wsec);
}

static void
test_setting_new_from_dbus_transform (void)
{
	NMSetting *s_wired;
	GVariant *dict;
	GVariantBuilder builder;
	const char *test_mac_address = "11:22:33:44:55:66";
	guint8 dbus_mac_address[ETH_ALEN];
	GError *error = NULL;

	nm_utils_hwaddr_aton (test_mac_address, dbus_mac_address, ETH_ALEN);

	g_variant_builder_init (&builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_WIRED_MAC_ADDRESS,
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                  dbus_mac_address, ETH_ALEN, 1));
	dict = g_variant_builder_end (&builder);

	s_wired = _nm_setting_new_from_dbus (NM_TYPE_SETTING_WIRED, dict, NULL, NM_SETTING_PARSE_FLAGS_NONE, &error);
	g_assert_no_error (error);

	g_assert_cmpstr (nm_setting_wired_get_mac_address (NM_SETTING_WIRED (s_wired)), ==, test_mac_address);

	g_variant_unref (dict);
	g_object_unref (s_wired);
}

static void
test_setting_new_from_dbus_enum (void)
{
	NMSettingIP6Config *s_ip6;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingSerial *s_serial;
	GVariant *dict;
	GVariantBuilder builder;
	GError *error = NULL;

	/* enum */
	g_variant_builder_init (&builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
	                       g_variant_new_int32 (NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR));
	dict = g_variant_builder_end (&builder);

	s_ip6 = (NMSettingIP6Config *) _nm_setting_new_from_dbus (NM_TYPE_SETTING_IP6_CONFIG, dict, NULL, NM_SETTING_PARSE_FLAGS_NONE, &error);
	g_assert_no_error (error);

	g_assert_cmpint (nm_setting_ip6_config_get_ip6_privacy (s_ip6), ==, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);

	g_variant_unref (dict);
	g_object_unref (s_ip6);

	/* flags (and a transformed enum) */
	g_variant_builder_init (&builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
	                       g_variant_new_uint32 (NM_WEP_KEY_TYPE_KEY));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
	                       g_variant_new_uint32 (NM_SETTING_SECRET_FLAG_AGENT_OWNED |
	                                             NM_SETTING_SECRET_FLAG_NOT_SAVED));
	dict = g_variant_builder_end (&builder);

	s_wsec = (NMSettingWirelessSecurity *) _nm_setting_new_from_dbus (NM_TYPE_SETTING_WIRELESS_SECURITY, dict, NULL, NM_SETTING_PARSE_FLAGS_NONE, &error);
	g_assert_no_error (error);

	g_assert_cmpint (nm_setting_wireless_security_get_wep_key_type (s_wsec), ==, NM_WEP_KEY_TYPE_KEY);
	g_assert_cmpint (nm_setting_wireless_security_get_wep_key_flags (s_wsec), ==, (NM_SETTING_SECRET_FLAG_AGENT_OWNED |
	                                                                               NM_SETTING_SECRET_FLAG_NOT_SAVED));

	g_variant_unref (dict);
	g_object_unref (s_wsec);

	/* another transformed enum */
	g_variant_builder_init (&builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_SERIAL_PARITY,
	                       g_variant_new_byte ('E'));
	dict = g_variant_builder_end (&builder);

	s_serial = (NMSettingSerial *) _nm_setting_new_from_dbus (NM_TYPE_SETTING_SERIAL, dict, NULL, NM_SETTING_PARSE_FLAGS_NONE, &error);
	g_assert_no_error (error);

	g_assert_cmpint (nm_setting_serial_get_parity (s_serial), ==, NM_SETTING_SERIAL_PARITY_EVEN);

	g_variant_unref (dict);
	g_object_unref (s_serial);
}

static void
test_setting_new_from_dbus_bad (void)
{
	NMSetting *setting;
	NMConnection *conn;
	GBytes *ssid;
	GPtrArray *addrs;
	GVariant *orig_dict, *dict;
	GError *error = NULL;

	/* We want to test:
	 * - ordinary scalar properties
	 * - string properties
	 * - GBytes-valued properties (which are handled specially by set_property_from_dbus())
	 * - enum/flags-valued properties
	 * - overridden properties
	 * - transformed properties
	 *
	 * No single setting class has examples of all of these, so we need two settings.
	 */

	conn = nm_simple_connection_new ();

	setting = nm_setting_connection_new ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, "test",
	              NM_SETTING_CONNECTION_UUID, "83c5a841-1759-4cdb-bfce-8d4087956497",
	              NULL);
	nm_connection_add_setting (conn, setting);

	setting = nm_setting_wireless_new ();
	ssid = g_bytes_new ("my-ssid", 7);
	g_object_set (setting,
	              /* scalar */
	              NM_SETTING_WIRELESS_RATE, 100,
	              /* string */
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              /* GBytes */
	              NM_SETTING_WIRELESS_SSID, ssid,
	              /* transformed */
	              NM_SETTING_WIRELESS_BSSID, "00:11:22:33:44:55",
	              NULL);
	g_bytes_unref (ssid);
	nm_connection_add_setting (conn, setting);

	setting = nm_setting_ip6_config_new ();
	addrs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);
	g_ptr_array_add (addrs, nm_ip_address_new (AF_INET6, "1234::5678", 64, NULL));
	g_object_set (setting,
	              /* enum */
	              NM_SETTING_IP6_CONFIG_IP6_PRIVACY, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR,
	              /* overridden */
	              NM_SETTING_IP_CONFIG_ADDRESSES, addrs,
	              /* (needed in order to verify()) */
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);
	g_ptr_array_unref (addrs);
	nm_connection_add_setting (conn, setting);

	orig_dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);
	g_object_unref (conn);

	/* sanity-check */
	conn = _connection_new_from_dbus (orig_dict, &error);
	g_assert_no_error (error);
	g_assert (conn);
	g_object_unref (conn);

	/* Compatible mismatches */

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_WIRELESS_SETTING_NAME,
	                                                     NM_SETTING_WIRELESS_RATE,
	                                                     "i", 10);
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert (conn);
	g_assert_no_error (error);
	setting = nm_connection_get_setting (conn, NM_TYPE_SETTING_WIRELESS);
	g_assert (setting);
	g_assert_cmpint (nm_setting_wireless_get_rate (NM_SETTING_WIRELESS (setting)), ==, 10);
	g_object_unref (conn);
	g_variant_unref (dict);

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                                     NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
	                                                     "i", NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert (conn);
	g_assert_no_error (error);
	setting = nm_connection_get_setting (conn, NM_TYPE_SETTING_IP6_CONFIG);
	g_assert (setting);
	g_assert_cmpint (nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (setting)), ==, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
	g_object_unref (conn);
	g_variant_unref (dict);

	/* Incompatible mismatches */

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_WIRELESS_SETTING_NAME,
	                                                     NM_SETTING_WIRELESS_RATE,
	                                                     "s", "ten");
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "802-11-wireless.rate:"));
	g_clear_error (&error);
	g_variant_unref (dict);

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_WIRELESS_SETTING_NAME,
	                                                     NM_SETTING_WIRELESS_MODE,
	                                                     "b", FALSE);
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "802-11-wireless.mode:"));
	g_clear_error (&error);
	g_variant_unref (dict);

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_WIRELESS_SETTING_NAME,
	                                                     NM_SETTING_WIRELESS_SSID,
	                                                     "s", "fred");
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "802-11-wireless.ssid:"));
	g_clear_error (&error);
	g_variant_unref (dict);

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_WIRELESS_SETTING_NAME,
	                                                     NM_SETTING_WIRELESS_BSSID,
	                                                     "i", 42);
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "802-11-wireless.bssid:"));
	g_clear_error (&error);
	g_variant_unref (dict);

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                                     NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
	                                                     "s", "private");
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "ipv6.ip6-privacy:"));
	g_clear_error (&error);
	g_variant_unref (dict);

	dict = g_variant_ref (orig_dict);
	NMTST_VARIANT_EDITOR (dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                                     NM_SETTING_IP_CONFIG_ADDRESSES,
	                                                     "s", "1234::5678");
	                      );
	conn = _connection_new_from_dbus (dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "ipv6.addresses:"));
	g_clear_error (&error);
	g_variant_unref (dict);

	g_variant_unref (orig_dict);
}

static NMConnection *
new_test_connection (void)
{
	NMConnection *connection;
	NMSetting *setting;
	char *uuid;
	guint64 timestamp = time (NULL);

	connection = nm_simple_connection_new ();

	setting = nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_ID, "foobar",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_wired_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_WIRED_MTU, 1592,
	              NULL);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, "eyeofthetiger",
	              NULL);
	nm_connection_add_setting (connection, setting);

	return connection;
}

static GVariant *
new_connection_dict (char **out_uuid,
                     const char **out_expected_id,
                     const char **out_expected_ip6_method)
{
	GVariantBuilder conn_builder, setting_builder;

	g_variant_builder_init (&conn_builder, NM_VARIANT_TYPE_CONNECTION);

	*out_uuid = nm_utils_uuid_generate ();
	*out_expected_id = "My happy connection";
	*out_expected_ip6_method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;

	/* Connection setting */
	g_variant_builder_init (&setting_builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_NAME,
	                       g_variant_new_string (NM_SETTING_CONNECTION_SETTING_NAME));
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_CONNECTION_ID,
	                       g_variant_new_string (*out_expected_id));
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_CONNECTION_UUID,
	                       g_variant_new_string (*out_uuid));
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_CONNECTION_TYPE,
	                       g_variant_new_string (NM_SETTING_WIRED_SETTING_NAME));

	g_variant_builder_add (&conn_builder, "{sa{sv}}",
	                       NM_SETTING_CONNECTION_SETTING_NAME,
	                       &setting_builder);

	/* Wired setting */
	g_variant_builder_init (&setting_builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&conn_builder, "{sa{sv}}",
	                       NM_SETTING_WIRED_SETTING_NAME,
	                       &setting_builder);

	/* IP6 */
	g_variant_builder_init (&setting_builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_IP_CONFIG_METHOD,
	                       g_variant_new_string (*out_expected_ip6_method));
	g_variant_builder_add (&conn_builder, "{sa{sv}}",
	                       NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                       &setting_builder);

	return g_variant_builder_end (&conn_builder);
}

static void
test_connection_replace_settings (void)
{
	NMConnection *connection;
	GVariant *new_settings;
	GError *error = NULL;
	gboolean success;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip6;
	char *uuid = NULL;
	const char *expected_id = NULL, *expected_method = NULL;

	connection = new_test_connection ();

	new_settings = new_connection_dict (&uuid, &expected_id, &expected_method);
	g_assert (new_settings);

	/* Replace settings and test */
	success = nm_connection_replace_settings (connection, new_settings, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, uuid);

	g_assert (nm_connection_get_setting_wired (connection));
	g_assert (!nm_connection_get_setting_ip4_config (connection));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, expected_method);

	g_free (uuid);
	g_variant_unref (new_settings);
	g_object_unref (connection);
}

static void
test_connection_replace_settings_from_connection (void)
{
	NMConnection *connection, *replacement;
	NMSettingConnection *s_con;
	NMSetting *setting;
	GBytes *ssid;
	char *uuid = NULL;
	const char *expected_id = "Awesome connection";

	connection = new_test_connection ();
	g_assert (connection);

	replacement = nm_simple_connection_new ();
	g_assert (replacement);

	/* New connection setting */
	setting = nm_setting_connection_new ();
	g_assert (setting);

	uuid = nm_utils_uuid_generate ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, expected_id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	nm_connection_add_setting (replacement, setting);

	/* New wifi setting */
	setting = nm_setting_wireless_new ();
	g_assert (setting);

	ssid = g_bytes_new ("1234567", 7);
	g_object_set (setting,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_bytes_unref (ssid);
	nm_connection_add_setting (replacement, setting);

	/* Replace settings and test */
	nm_connection_replace_settings_from_connection (connection, replacement);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, uuid);

	g_assert (!nm_connection_get_setting_wired (connection));
	g_assert (!nm_connection_get_setting_ip6_config (connection));
	g_assert (nm_connection_get_setting_wireless (connection));

	g_free (uuid);
	g_object_unref (replacement);
	g_object_unref (connection);
}

static void
test_connection_replace_settings_bad (void)
{
	NMConnection *connection, *new_connection;
	GVariant *new_settings;
	GVariantBuilder builder, setting_builder;
	GError *error = NULL;
	gboolean success;
	NMSettingConnection *s_con;

	new_connection = new_test_connection ();
	g_assert (nm_connection_verify (new_connection, NULL));
	s_con = nm_connection_get_setting_connection (new_connection);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, NULL,
	              NM_SETTING_CONNECTION_ID, "bad-connection",
	              NULL);
	g_assert (!nm_connection_verify (new_connection, NULL));

	/* nm_connection_replace_settings_from_connection() should succeed */
	connection = new_test_connection ();
	nm_connection_replace_settings_from_connection (connection, new_connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "bad-connection");
	g_assert (!nm_connection_verify (connection, NULL));
	g_object_unref (connection);

	/* nm_connection_replace_settings() should succeed */
	new_settings = nm_connection_to_dbus (new_connection, NM_CONNECTION_SERIALIZE_ALL);
	g_assert (new_settings != NULL);

	connection = new_test_connection ();
	success = nm_connection_replace_settings (connection, new_settings, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (nm_connection_get_id (connection), ==, "bad-connection");
	g_assert (!nm_connection_verify (connection, NULL));
	g_object_unref (connection);
	g_variant_unref (new_settings);

	/* But given an invalid dict, it should fail */
	g_variant_builder_init (&builder, NM_VARIANT_TYPE_CONNECTION);
	g_variant_builder_init (&setting_builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&builder, "{sa{sv}}",
	                       "ip-over-avian-carrier",
	                       &setting_builder);
	new_settings = g_variant_builder_end (&builder);

	connection = new_test_connection ();
	success = nm_connection_replace_settings (connection, new_settings, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);
	g_clear_error (&error);
	g_assert (!success);

	g_assert (nm_connection_verify (connection, NULL));
	g_object_unref (connection);

	g_variant_unref (new_settings);
	g_object_unref (new_connection);
}

static void
test_connection_new_from_dbus (void)
{
	NMConnection *connection;
	GVariant *new_settings;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip6;
	char *uuid = NULL;
	const char *expected_id = NULL, *expected_method = NULL;

	new_settings = new_connection_dict (&uuid, &expected_id, &expected_method);
	g_assert (new_settings);

	/* Replace settings and test */
	connection = _connection_new_from_dbus (new_settings, &error);
	g_assert_no_error (error);
	g_assert (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, uuid);

	g_assert (nm_connection_get_setting_wired (connection));
	g_assert (nm_connection_get_setting_ip4_config (connection));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, expected_method);

	g_free (uuid);
	g_variant_unref (new_settings);
	g_object_unref (connection);
}

static void
check_permission (NMSettingConnection *s_con,
                  guint32 idx,
                  const char *expected_uname)
{
	gboolean success;
	const char *ptype = NULL, *pitem = NULL, *detail = NULL;

	success = nm_setting_connection_get_permission (s_con, 0, &ptype, &pitem, &detail);
	g_assert (success);

	g_assert_cmpstr (ptype, ==, "user");

	g_assert (pitem);
	g_assert_cmpstr (pitem, ==, expected_uname);

	g_assert (!detail);
}

#define TEST_UNAME "asdfasfasdf"

static void
test_setting_connection_permissions_helpers (void)
{
	NMSettingConnection *s_con;
	gboolean success;
	char buf[9] = { 0x61, 0x62, 0x63, 0xff, 0xfe, 0xfd, 0x23, 0x01, 0x00 };
	char **perms;
	const char *expected_perm = "user:" TEST_UNAME ":";

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	/* Ensure a bad [type] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strcmp (ptype, "user") == 0));
	success = nm_setting_connection_add_permission (s_con, "foobar", "blah", NULL);
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure a bad [type] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (ptype));
	success = nm_setting_connection_add_permission (s_con, NULL, "blah", NULL);
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure a bad [item] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (uname));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (p != NULL));
	success = nm_setting_connection_add_permission (s_con, "user", NULL, NULL);
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure a bad [item] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (uname[0] != '\0'));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (p != NULL));
	success = nm_setting_connection_add_permission (s_con, "user", "", NULL);
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure an [item] with ':' is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strchr (uname, ':') == NULL));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (p != NULL));
	success = nm_setting_connection_add_permission (s_con, "user", "ad:asdf", NULL);
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure a non-UTF-8 [item] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (g_utf8_validate (uname, -1, NULL) == TRUE));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (p != NULL));
	success = nm_setting_connection_add_permission (s_con, "user", buf, NULL);
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure a non-NULL [detail] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (detail == NULL));
	success = nm_setting_connection_add_permission (s_con, "user", "dafasdf", "asdf");
	g_test_assert_expected_messages ();
	g_assert (!success);

	/* Ensure a valid call results in success */
	success = nm_setting_connection_add_permission (s_con, "user", TEST_UNAME, NULL);
	g_assert (success);

	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 1);

	check_permission (s_con, 0, TEST_UNAME);

	/* Check the actual GObject property just to be paranoid */
	g_object_get (G_OBJECT (s_con), NM_SETTING_CONNECTION_PERMISSIONS, &perms, NULL);
	g_assert (perms);
	g_assert_cmpint (g_strv_length (perms), ==, 1);
	g_assert_cmpstr (perms[0], ==, expected_perm);
	g_strfreev (perms);

	/* Now remove that permission and ensure we have 0 permissions */
	nm_setting_connection_remove_permission (s_con, 0);
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	g_object_unref (s_con);
}

static void
add_permission_property (NMSettingConnection *s_con,
                         const char *ptype,
                         const char *pitem,
                         int pitem_len,
                         const char *detail)
{
	GString *str;
	char *perms[2];

	str = g_string_sized_new (50);
	if (ptype)
		g_string_append (str, ptype);
	g_string_append_c (str, ':');

	if (pitem) {
		if (pitem_len >= 0)
			g_string_append_len (str, pitem, pitem_len);
		else
			g_string_append (str, pitem);
	}

	g_string_append_c (str, ':');

	if (detail)
		g_string_append (str, detail);

	perms[0] = str->str;
	perms[1] = NULL;
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_PERMISSIONS, perms, NULL);

	g_string_free (str, TRUE);
}

static void
test_setting_connection_permissions_property (void)
{
	NMSettingConnection *s_con;
	gboolean success;
	char buf[9] = { 0x61, 0x62, 0x63, 0xff, 0xfe, 0xfd, 0x23, 0x01, 0x00 };

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	/* Ensure a bad [type] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strncmp (str, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0));
	add_permission_property (s_con, "foobar", "blah", -1, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure a bad [type] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (strncmp (str, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0));
	add_permission_property (s_con, NULL, "blah", -1, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure a bad [item] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (last_colon > str));
	add_permission_property (s_con, "user", NULL, -1, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure a bad [item] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (last_colon > str));
	add_permission_property (s_con, "user", "", -1, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure an [item] with ':' in the middle is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (str[i] != ':'));
	add_permission_property (s_con, "user", "ad:asdf", -1, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure an [item] with ':' at the end is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (str[i] != ':'));
	add_permission_property (s_con, "user", "adasdfaf:", -1, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure a non-UTF-8 [item] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (g_utf8_validate (str, -1, NULL) == TRUE));
	add_permission_property (s_con, "user", buf, (int) sizeof (buf), NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure a non-NULL [detail] is rejected */
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (*(last_colon + 1) == '\0'));
	add_permission_property (s_con, "user", "dafasdf", -1, "asdf");
	g_test_assert_expected_messages ();
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	/* Ensure a valid call results in success */
	success = nm_setting_connection_add_permission (s_con, "user", TEST_UNAME, NULL);
	g_assert (success);
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 1);

	check_permission (s_con, 0, TEST_UNAME);

	/* Now remove that permission and ensure we have 0 permissions */
	nm_setting_connection_remove_permission (s_con, 0);
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 0);

	g_object_unref (s_con);
}

static void
test_connection_compare_same (void)
{
	NMConnection *a, *b;

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);
	g_assert (nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_key_only_in_a (void)
{
	NMConnection *a, *b;
	NMSettingConnection *s_con;

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);
	s_con = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 0, NULL);

	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_setting_only_in_a (void)
{
	NMConnection *a, *b;

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);
	nm_connection_remove_setting (b, NM_TYPE_SETTING_IP4_CONFIG);
	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_key_only_in_b (void)
{
	NMConnection *a, *b;
	NMSettingConnection *s_con;

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);
	s_con = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 0, NULL);

	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_setting_only_in_b (void)
{
	NMConnection *a, *b;

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);
	nm_connection_remove_setting (a, NM_TYPE_SETTING_IP4_CONFIG);
	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

typedef struct {
	const char *key_name;
	guint32 result;
} DiffKey;

typedef struct {
	const char *name;
	DiffKey keys[30];
} DiffSetting;

#define ARRAY_LEN(a)  (sizeof (a) / sizeof (a[0]))

static void
ensure_diffs (GHashTable *diffs, const DiffSetting *check, gsize n_check)
{
	guint i;

	g_assert (g_hash_table_size (diffs) == n_check);

	/* Loop through the settings */
	for (i = 0; i < n_check; i++) {
		GHashTable *setting_hash;
		guint z = 0;

		setting_hash = g_hash_table_lookup (diffs, check[i].name);
		g_assert (setting_hash);

		/* Get the number of keys to check */
		while (check[i].keys[z].key_name)
			z++;
		g_assert (g_hash_table_size (setting_hash) == z);

		/* Now compare the actual keys */
		for (z = 0; check[i].keys[z].key_name; z++) {
			NMSettingDiffResult result;

			result = GPOINTER_TO_UINT (g_hash_table_lookup (setting_hash, check[i].keys[z].key_name));
			g_assert (result == check[i].keys[z].result);
		}
	}
}

static void
test_connection_diff_a_only (void)
{
	NMConnection *connection;
	GHashTable *out_diffs = NULL;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_CONNECTION_SETTING_NAME, {
			{ NM_SETTING_CONNECTION_ID,                   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_UUID,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_STABLE_ID,            NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_INTERFACE_NAME,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_TYPE,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_TIMESTAMP,            NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTOCONNECT,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES,  NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_READ_ONLY,            NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_PERMISSIONS,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_ZONE,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_MASTER,               NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_SLAVE_TYPE,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_SECONDARIES,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_METERED,              NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_LLDP,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTH_RETRIES,         NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_MDNS,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN }
		} },
		{ NM_SETTING_WIRED_SETTING_NAME, {
			{ NM_SETTING_WIRED_PORT,                  NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_SPEED,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_DUPLEX,                NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_AUTO_NEGOTIATE,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MAC_ADDRESS,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_CLONED_MAC_ADDRESS,    NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MTU,                   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_SUBCHANNELS,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_NETTYPE,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_OPTIONS,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_WAKE_ON_LAN,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD,  NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
		{ NM_SETTING_IP4_CONFIG_SETTING_NAME, {
			{ NM_SETTING_IP_CONFIG_METHOD,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DNS,                NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DNS_SEARCH,         NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DNS_OPTIONS,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_ADDRESSES,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_GATEWAY,            NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_ROUTES,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_ROUTE_METRIC,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_ROUTE_TABLE,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,    NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,    NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DHCP_TIMEOUT,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_FQDN,         NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_NEVER_DEFAULT,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_MAY_FAIL,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DAD_TIMEOUT,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP_CONFIG_DNS_PRIORITY,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	connection = new_test_connection ();

	same = nm_connection_diff (connection, NULL, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (connection);
}

static void
test_connection_diff_same (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	gboolean same;

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);

	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_different (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	NMSettingIPConfig *s_ip4;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_IP4_CONFIG_SETTING_NAME, {
			{ NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_DIFF_RESULT_IN_A | NM_SETTING_DIFF_RESULT_IN_B },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);
	s_ip4 = nm_connection_get_setting_ip4_config (a);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_no_secrets (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	NMSetting *s_pppoe;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_PPPOE_SETTING_NAME, {
			{ NM_SETTING_PPPOE_PASSWORD, NM_SETTING_DIFF_RESULT_IN_B },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	s_pppoe = nm_setting_pppoe_new ();
	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_USERNAME, "thomas",
	              NULL);
	nm_connection_add_setting (a, s_pppoe);

	b = nm_simple_connection_new_clone (a);

	/* Add a secret to B */
	s_pppoe = NM_SETTING (nm_connection_get_setting_pppoe (b));
	g_assert (s_pppoe);
	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_PASSWORD, "secretpassword",
	              NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);

	/* Now make sure the diff returns results if secrets are not ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_inferrable (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	gboolean same;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *uuid;
	const DiffSetting settings[] = {
		{ NM_SETTING_CONNECTION_SETTING_NAME, {
			{ NM_SETTING_CONNECTION_INTERFACE_NAME, NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	b = nm_simple_connection_new_clone (a);

	/* Change the UUID, wired MTU, and set ignore-auto-dns */
	s_con = nm_connection_get_setting_connection (a);
	g_assert (s_con);
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, "really neat connection",
	              NULL);
	g_free (uuid);

	s_wired = nm_connection_get_setting_wired (a);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired), NM_SETTING_WIRED_MTU, 300, NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (a);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4), NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, TRUE, NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_INFERRABLE, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);

	/* And change a INFERRABLE property to ensure that it shows up in the diff results */
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, "usb0", NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_INFERRABLE, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (a);
	g_object_unref (b);
}

static void
add_generic_settings (NMConnection *connection, const char *ctype)
{
	NMSetting *setting;
	char *uuid;

	uuid = nm_utils_uuid_generate ();

	setting = nm_setting_connection_new ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, "asdfasdfadf",
	              NM_SETTING_CONNECTION_TYPE, ctype,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NULL);
	nm_connection_add_setting (connection, setting);

	g_free (uuid);

	setting = nm_setting_ip4_config_new ();
	g_object_set (setting, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_ip6_config_new ();
	g_object_set (setting, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, setting);
}

static void
test_connection_good_base_types (void)
{
	NMConnection *connection;
	NMSetting *setting;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const char *bdaddr = "11:22:33:44:55:66";

	/* Try a basic wired connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_WIRED_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* Try a wired PPPoE connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_PPPOE_SETTING_NAME);
	setting = nm_setting_pppoe_new ();
	g_object_set (setting, NM_SETTING_PPPOE_USERNAME, "bob smith", NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* Wifi connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_WIRELESS_SETTING_NAME);

	setting = nm_setting_wireless_new ();
	ssid = g_bytes_new ("1234567", 7);
	g_object_set (setting,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_bytes_unref (ssid);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* Bluetooth connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_BLUETOOTH_SETTING_NAME);

	setting = nm_setting_bluetooth_new ();
	g_object_set (setting,
	              NM_SETTING_BLUETOOTH_BDADDR, bdaddr,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
	              NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* WiMAX connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_WIMAX_SETTING_NAME);
	setting = nm_setting_wimax_new ();
	g_object_set (setting, NM_SETTING_WIMAX_NETWORK_NAME, "CLEAR", NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* GSM connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_GSM_SETTING_NAME);

	setting = nm_setting_gsm_new ();
	g_object_set (setting,
	              NM_SETTING_GSM_NUMBER, "*99#",
	              NM_SETTING_GSM_APN, "metered.billing.sucks",
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* CDMA connection */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_CDMA_SETTING_NAME);

	setting = nm_setting_cdma_new ();
	g_object_set (setting,
	              NM_SETTING_CDMA_NUMBER, "#777",
	              NM_SETTING_CDMA_USERNAME, "foobar@vzw.com",
	              NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);
}

static void
test_connection_bad_base_types (void)
{
	NMConnection *connection;
	NMSetting *setting;
	gboolean success;
	GError *error = NULL;

	/* Test various non-base connection types to make sure they are rejected;
	 * using a fake 'wired' connection so the rest of it verifies
	 */

	/* Connection setting */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_CONNECTION_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "connection.type: "));
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* PPP setting */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_PPP_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);
	setting = nm_setting_ppp_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "connection.type: "));
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* Serial setting */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_SERIAL_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);
	setting = nm_setting_serial_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "connection.type: "));
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* IP4 setting */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_IP4_CONFIG_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "connection.type: "));
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* IP6 setting */
	connection = nm_simple_connection_new ();
	add_generic_settings (connection, NM_SETTING_IP6_CONFIG_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (g_str_has_prefix (error->message, "connection.type: "));
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);
}

static void
test_setting_compare_id (void)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	old = nm_setting_connection_new ();
	g_object_set (old,
	              NM_SETTING_CONNECTION_ID, "really awesome cool connection",
	              NM_SETTING_CONNECTION_UUID, "fbbd59d5-acab-4e30-8f86-258d272617e7",
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NULL);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_CONNECTION_ID, "some different connection id", NULL);

	/* First make sure they are different */
	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success == FALSE);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_IGNORE_ID);
	g_assert (success);
}

static void
test_setting_compare_addresses (void)
{
	gs_unref_object NMSetting *s1 = NULL, *s2 = NULL;
	gboolean success;
	NMIPAddress *a;
	GHashTable *result = NULL;

	s1 = nm_setting_ip4_config_new ();
	s2 = nm_setting_ip4_config_new ();

	a = nm_ip_address_new (AF_INET, "192.168.7.5", 24, NULL);

	nm_ip_address_set_attribute (a, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string ("xoxoxo"));
	nm_setting_ip_config_add_address ((NMSettingIPConfig *) s1, a);

	nm_ip_address_set_attribute (a, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string ("hello"));
	nm_setting_ip_config_add_address ((NMSettingIPConfig *) s2, a);

	nm_ip_address_unref (a);

	if (nmtst_get_rand_int () % 2)
		NMTST_SWAP (s1, s2);

	success = nm_setting_compare (s1, s2, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (!success);

	success = nm_setting_diff (s1, s2, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, &result);
	g_assert (!success);
	g_clear_pointer (&result, g_hash_table_unref);
}

static void
test_setting_compare_routes (void)
{
	gs_unref_object NMSetting *s1 = NULL, *s2 = NULL;
	gboolean success;
	NMIPRoute *r;
	GHashTable *result = NULL;

	s1 = nm_setting_ip4_config_new ();
	s2 = nm_setting_ip4_config_new ();

	r = nm_ip_route_new (AF_INET, "192.168.12.0", 24, "192.168.11.1", 473, NULL);

	nm_ip_route_set_attribute (r, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string ("xoxoxo"));
	nm_setting_ip_config_add_route ((NMSettingIPConfig *) s1, r);

	nm_ip_route_set_attribute (r, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string ("hello"));
	nm_setting_ip_config_add_route ((NMSettingIPConfig *) s2, r);

	nm_ip_route_unref (r);

	if (nmtst_get_rand_int () % 2)
		NMTST_SWAP (s1, s2);

	success = nm_setting_compare (s1, s2, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (!success);

	success = nm_setting_diff (s1, s2, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, &result);
	g_assert (!success);
	g_clear_pointer (&result, g_hash_table_unref);
}

static void
test_setting_compare_wired_cloned_mac_address (void)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;
	gs_free char *str1 = NULL;

	old = nm_setting_wired_new ();
	g_object_set (old,
	              NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "stable",
	              NULL);

	g_assert_cmpstr ("stable", ==, nm_setting_wired_get_cloned_mac_address ((NMSettingWired *) old));
	g_object_get (old, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, &str1, NULL);
	g_assert_cmpstr ("stable", ==, str1);
	g_clear_pointer (&str1, g_free);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "11:22:33:44:55:66", NULL);

	g_assert_cmpstr ("11:22:33:44:55:66", ==, nm_setting_wired_get_cloned_mac_address ((NMSettingWired *) new));
	g_object_get (new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, &str1, NULL);
	g_assert_cmpstr ("11:22:33:44:55:66", ==, str1);
	g_clear_pointer (&str1, g_free);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (!success);
	g_clear_object (&new);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "stable-bia", NULL);

	g_assert_cmpstr ("stable-bia", ==, nm_setting_wired_get_cloned_mac_address ((NMSettingWired *) new));
	g_object_get (new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, &str1, NULL);
	g_assert_cmpstr ("stable-bia", ==, str1);
	g_clear_pointer (&str1, g_free);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (!success);
	g_clear_object (&new);
}

static void
test_setting_compare_wireless_cloned_mac_address (void)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;
	gs_free char *str1 = NULL;

	old = nm_setting_wireless_new ();
	g_object_set (old,
	              NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "stable",
	              NULL);

	g_assert_cmpstr ("stable", ==, nm_setting_wireless_get_cloned_mac_address ((NMSettingWireless *) old));
	g_object_get (old, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, &str1, NULL);
	g_assert_cmpstr ("stable", ==, str1);
	g_clear_pointer (&str1, g_free);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "11:22:33:44:55:66", NULL);

	g_assert_cmpstr ("11:22:33:44:55:66", ==, nm_setting_wireless_get_cloned_mac_address ((NMSettingWireless *) new));
	g_object_get (new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, &str1, NULL);
	g_assert_cmpstr ("11:22:33:44:55:66", ==, str1);
	g_clear_pointer (&str1, g_free);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (!success);
	g_clear_object (&new);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "stable-bia", NULL);

	g_assert_cmpstr ("stable-bia", ==, nm_setting_wireless_get_cloned_mac_address ((NMSettingWireless *) new));
	g_object_get (new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, &str1, NULL);
	g_assert_cmpstr ("stable-bia", ==, str1);
	nm_clear_g_free (&str1);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (!success);
	g_clear_object (&new);
}

static void
test_setting_compare_timestamp (void)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	old = nm_setting_connection_new ();
	g_object_set (old,
	              NM_SETTING_CONNECTION_ID, "ignore timestamp connection",
	              NM_SETTING_CONNECTION_UUID, "b047a198-0e0a-4f0e-a653-eea09bb35e40",
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 1234567890,
	              NULL);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 1416316539, NULL);

	/* First make sure they are different */
	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success == FALSE);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP);
	g_assert (success);
}

typedef struct {
	NMSettingSecretFlags secret_flags;
	NMSettingCompareFlags comp_flags;
	gboolean remove_secret;
} TestDataCompareSecrets;

static TestDataCompareSecrets *
test_data_compare_secrets_new (NMSettingSecretFlags secret_flags,
                               NMSettingCompareFlags comp_flags,
                               gboolean remove_secret)
{
	TestDataCompareSecrets *data = g_new0 (TestDataCompareSecrets, 1);

	data->secret_flags = secret_flags;
	data->comp_flags = comp_flags;
	data->remove_secret = remove_secret;
	return data;
}

static void
test_setting_compare_secrets (gconstpointer test_data)
{
	const TestDataCompareSecrets *data = test_data;
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	/* Make sure that a connection with transient/unsaved secrets compares
	 * successfully to the same connection without those secrets.
	 */

	old = nm_setting_wireless_security_new ();
	g_object_set (old,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "really cool psk",
	              NULL);
	nm_setting_set_secret_flags (old, NM_SETTING_WIRELESS_SECURITY_PSK, data->secret_flags, NULL);

	/* Clear the PSK from the duplicated setting */
	new = nm_setting_duplicate (old);
	if (data->remove_secret) {
		g_object_set (new, NM_SETTING_WIRELESS_SECURITY_PSK, NULL, NULL);

		success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
		g_assert (success == FALSE);
	}

	success = nm_setting_compare (old, new, data->comp_flags);
	g_assert (success);
}

static void
test_setting_compare_vpn_secrets (gconstpointer test_data)
{
	const TestDataCompareSecrets *data = test_data;
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	/* Make sure that a connection with transient/unsaved secrets compares
	 * successfully to the same connection without those secrets.
	 */

	old = nm_setting_vpn_new ();
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "foobarbaz", "really secret password");
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "asdfasdfasdf", "really adfasdfasdfasdf");
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "0123456778", "abcdefghijklmnpqrstuvqxyz");
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "borkbork", "yet another really secret password");
	nm_setting_set_secret_flags (old, "borkbork", data->secret_flags, NULL);

	/* Clear "borkbork" from the duplicated setting */
	new = nm_setting_duplicate (old);
	if (data->remove_secret) {
		nm_setting_vpn_remove_secret (NM_SETTING_VPN (new), "borkbork");

		/* First make sure they are different */
		success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
		g_assert (success == FALSE);
	}

	success = nm_setting_compare (old, new, data->comp_flags);
	g_assert (success);
}

static void
test_hwaddr_aton_ether_normal (void)
{
	guint8 buf[100];
	guint8 expected[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

	g_assert (nm_utils_hwaddr_aton ("00:11:22:33:44:55", buf, ETH_ALEN) != NULL);
	g_assert (memcmp (buf, expected, sizeof (expected)) == 0);
}

static void
test_hwaddr_aton_ib_normal (void)
{
	guint8 buf[100];
	const char *source = "00:11:22:33:44:55:66:77:88:99:01:12:23:34:45:56:67:78:89:90";
	guint8 expected[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x90 };

	g_assert (nm_utils_hwaddr_aton (source, buf, INFINIBAND_ALEN) != NULL);
	g_assert (memcmp (buf, expected, sizeof (expected)) == 0);
}

static void
test_hwaddr_aton_no_leading_zeros (void)
{
	guint8 buf[100];
	guint8 expected[ETH_ALEN] = { 0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05 };

	g_assert (nm_utils_hwaddr_aton ("0:1a:2B:3:44:5", buf, ETH_ALEN) != NULL);
	g_assert (memcmp (buf, expected, sizeof (expected)) == 0);
}

static void
test_hwaddr_aton_malformed (void)
{
	guint8 buf[100];

	g_assert (nm_utils_hwaddr_aton ("0:1a:2B:3:a@%%", buf, ETH_ALEN) == NULL);
}

static void
test_hwaddr_equal (void)
{
	const char *string = "00:1a:2b:03:44:05";
	const char *upper_string = "00:1A:2B:03:44:05";
	const char *bad_string = "0:1a:2b:3:44:5";
	const guint8 binary[ETH_ALEN] = { 0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05 };
	const char *other_string = "1a:2b:03:44:05:00";
	const guint8 other_binary[ETH_ALEN] = { 0x1A, 0x2B, 0x03, 0x44, 0x05, 0x00 };
	const char *long_string = "00:1a:2b:03:44:05:06:07";
	const guint8 long_binary[8] = { 0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05, 0x06, 0x07 };
	const char *null_string = "00:00:00:00:00:00";
	const guint8 null_binary[ETH_ALEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	g_assert (nm_utils_hwaddr_matches (string, -1, string, -1));
	g_assert (nm_utils_hwaddr_matches (string, -1, upper_string, -1));
	g_assert (nm_utils_hwaddr_matches (string, -1, bad_string, -1));
	g_assert (nm_utils_hwaddr_matches (string, -1, binary, sizeof (binary)));
	g_assert (!nm_utils_hwaddr_matches (string, -1, other_string, -1));
	g_assert (!nm_utils_hwaddr_matches (string, -1, other_binary, sizeof (other_binary)));
	g_assert (!nm_utils_hwaddr_matches (string, -1, long_string, -1));
	g_assert (!nm_utils_hwaddr_matches (string, -1, long_binary, sizeof (long_binary)));
	g_assert (!nm_utils_hwaddr_matches (string, -1, null_string, -1));
	g_assert (!nm_utils_hwaddr_matches (string, -1, null_binary, sizeof (null_binary)));
	g_assert (!nm_utils_hwaddr_matches (string, -1, NULL, ETH_ALEN));

	g_assert (nm_utils_hwaddr_matches (binary, sizeof (binary), string, -1));
	g_assert (nm_utils_hwaddr_matches (binary, sizeof (binary), upper_string, -1));
	g_assert (nm_utils_hwaddr_matches (binary, sizeof (binary), bad_string, -1));
	g_assert (nm_utils_hwaddr_matches (binary, sizeof (binary), binary, sizeof (binary)));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), other_string, -1));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), other_binary, sizeof (other_binary)));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), long_string, -1));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), long_binary, sizeof (long_binary)));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), null_string, -1));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), null_binary, sizeof (null_binary)));
	g_assert (!nm_utils_hwaddr_matches (binary, sizeof (binary), NULL, ETH_ALEN));

	g_assert (!nm_utils_hwaddr_matches (null_string, -1, string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, upper_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, bad_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, binary, sizeof (binary)));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, other_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, other_binary, sizeof (other_binary)));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, long_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_string, -1, long_binary, sizeof (long_binary)));
	g_assert (nm_utils_hwaddr_matches (null_string, -1, null_string, -1));
	g_assert (nm_utils_hwaddr_matches (null_string, -1, null_binary, sizeof (null_binary)));
	g_assert (nm_utils_hwaddr_matches (null_string, -1, NULL, ETH_ALEN));

	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), upper_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), bad_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), binary, sizeof (binary)));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), other_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), other_binary, sizeof (other_binary)));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), long_string, -1));
	g_assert (!nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), long_binary, sizeof (long_binary)));
	g_assert (nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), null_string, -1));
	g_assert (nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), null_binary, sizeof (null_binary)));
	g_assert (nm_utils_hwaddr_matches (null_binary, sizeof (null_binary), NULL, ETH_ALEN));
}

static void
test_hwaddr_canonical (void)
{
	const char *string = "00:1A:2B:03:44:05";
	const char *lower_string = "00:1a:2b:03:44:05";
	const char *short_string = "0:1a:2b:3:44:5";
	const char *hyphen_string = "00-1a-2b-03-44-05";
	const char *invalid_string = "00:1A:2B";
	char *canonical;

	canonical = nm_utils_hwaddr_canonical (string, ETH_ALEN);
	g_assert_cmpstr (canonical, ==, string);
	g_free (canonical);

	canonical = nm_utils_hwaddr_canonical (lower_string, ETH_ALEN);
	g_assert_cmpstr (canonical, ==, string);
	g_free (canonical);

	canonical = nm_utils_hwaddr_canonical (short_string, ETH_ALEN);
	g_assert_cmpstr (canonical, ==, string);
	g_free (canonical);

	canonical = nm_utils_hwaddr_canonical (hyphen_string, ETH_ALEN);
	g_assert_cmpstr (canonical, ==, string);
	g_free (canonical);

	canonical = nm_utils_hwaddr_canonical (invalid_string, ETH_ALEN);
	g_assert_cmpstr (canonical, ==, NULL);

	canonical = nm_utils_hwaddr_canonical (invalid_string, -1);
	g_assert_cmpstr (canonical, ==, invalid_string);
	g_free (canonical);
}

static void
test_connection_changed_cb (NMConnection *connection, gboolean *data)
{
	*data = TRUE;
}

static void
test_ip4_prefix_to_netmask (void)
{
	int i;

	for (i = 0; i<=32; i++) {
		guint32 netmask = _nm_utils_ip4_prefix_to_netmask (i);
		int plen = nm_utils_ip4_netmask_to_prefix (netmask);

		g_assert_cmpint (i, ==, plen);
		{
			guint32 msk = 0x80000000;
			guint32 netmask2 = 0;
			guint32 prefix = i;
			while (prefix > 0) {
				netmask2 |= msk;
				msk >>= 1;
				prefix--;
			}
			g_assert_cmpint (netmask, ==, (guint32) htonl (netmask2));
		}
	}
}

static void
test_ip4_netmask_to_prefix (void)
{
	int i, j;

	GRand *rand = g_rand_new ();

	g_rand_set_seed (rand, 1);

	for (i = 2; i<=32; i++) {
		guint32 netmask = _nm_utils_ip4_prefix_to_netmask (i);
		guint32 netmask_lowest_bit = netmask & ~_nm_utils_ip4_prefix_to_netmask (i-1);

		g_assert_cmpint (i, ==, nm_utils_ip4_netmask_to_prefix (netmask));

		for (j = 0; j < 2*i; j++) {
			guint32 r = g_rand_int (rand);
			guint32 netmask_holey;
			guint32 prefix_holey;

			netmask_holey = (netmask & r) | netmask_lowest_bit;

			if (netmask_holey == netmask)
				continue;

			/* create an invalid netmask with holes and check that the function
			 * returns the longest prefix. */
			prefix_holey = nm_utils_ip4_netmask_to_prefix (netmask_holey);

			g_assert_cmpint (i, ==, prefix_holey);
		}
	}

	g_rand_free (rand);
}

#define ASSERT_CHANGED(statement) \
G_STMT_START { \
	changed = FALSE; \
	statement; \
	g_assert (changed); \
} G_STMT_END

#define ASSERT_UNCHANGED(statement) \
G_STMT_START { \
	changed = FALSE; \
	statement; \
	g_assert (!changed); \
} G_STMT_END

static void
test_connection_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;

	connection = new_test_connection ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	/* Add new setting */
	ASSERT_CHANGED (nm_connection_add_setting (connection, nm_setting_vlan_new ()));

	/* Remove existing setting */
	ASSERT_CHANGED (nm_connection_remove_setting (connection, NM_TYPE_SETTING_VLAN));

	/* Remove non-existing setting */
	ASSERT_UNCHANGED (nm_connection_remove_setting (connection, NM_TYPE_SETTING_VLAN));

	g_object_unref (connection);
}

static void
test_setting_connection_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingConnection *s_con;
	gs_free char *uuid = NULL;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	ASSERT_CHANGED (g_object_set (s_con, NM_SETTING_CONNECTION_ID, "adfadfasdfaf", NULL));

	ASSERT_CHANGED (nm_setting_connection_add_permission (s_con, "user", "billsmith", NULL));
	ASSERT_CHANGED (nm_setting_connection_remove_permission (s_con, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (iter != NULL));
	ASSERT_UNCHANGED (nm_setting_connection_remove_permission (s_con, 1));
	g_test_assert_expected_messages ();

	uuid = nm_utils_uuid_generate ();
	ASSERT_CHANGED (nm_setting_connection_add_secondary (s_con, uuid));
	ASSERT_CHANGED (nm_setting_connection_remove_secondary (s_con, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_connection_remove_secondary (s_con, 1));
	g_test_assert_expected_messages ();

	g_object_unref (connection);
}

static void
test_setting_bond_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingBond *s_bond;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));

	ASSERT_CHANGED (nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, "10"));
	ASSERT_CHANGED (nm_setting_bond_remove_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY));
	ASSERT_UNCHANGED (nm_setting_bond_remove_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY));

	g_object_unref (connection);
}

static void
test_setting_ip4_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingIPConfig *s_ip4;
	NMIPAddress *addr;
	NMIPRoute *route;
	GError *error = NULL;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	ASSERT_CHANGED (nm_setting_ip_config_add_dns (s_ip4, "11.22.0.0"));
	ASSERT_CHANGED (nm_setting_ip_config_remove_dns (s_ip4, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->dns->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_dns (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_dns (s_ip4, "33.44.0.0");
	ASSERT_CHANGED (nm_setting_ip_config_clear_dns (s_ip4));

	ASSERT_CHANGED (nm_setting_ip_config_add_dns_search (s_ip4, "foobar.com"));
	ASSERT_CHANGED (nm_setting_ip_config_remove_dns_search (s_ip4, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->dns_search->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_dns_search (s_ip4, 1));
	g_test_assert_expected_messages ();

	ASSERT_CHANGED (nm_setting_ip_config_add_dns_search (s_ip4, "foobar.com"));
	ASSERT_CHANGED (nm_setting_ip_config_clear_dns_searches (s_ip4));

	addr = nm_ip_address_new (AF_INET, "22.33.0.0", 24, &error);
	g_assert_no_error (error);
	ASSERT_CHANGED (nm_setting_ip_config_add_address (s_ip4, addr));
	ASSERT_CHANGED (nm_setting_ip_config_remove_address (s_ip4, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->addresses->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_address (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_address (s_ip4, addr);
	ASSERT_CHANGED (nm_setting_ip_config_clear_addresses (s_ip4));

	route = nm_ip_route_new (AF_INET, "22.33.0.0", 24, NULL, 0, &error);
	g_assert_no_error (error);

	ASSERT_CHANGED (nm_setting_ip_config_add_route (s_ip4, route));
	ASSERT_CHANGED (nm_setting_ip_config_remove_route (s_ip4, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->routes->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_route (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_route (s_ip4, route);
	ASSERT_CHANGED (nm_setting_ip_config_clear_routes (s_ip4));

	ASSERT_CHANGED (nm_setting_ip_config_add_dns_option (s_ip4, "debug"));
	ASSERT_CHANGED (nm_setting_ip_config_remove_dns_option (s_ip4, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->dns_options->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_dns_option (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_ip_address_unref (addr);
	nm_ip_route_unref (route);
	g_object_unref (connection);
}

static void
test_setting_ip6_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingIPConfig *s_ip6;
	NMIPAddress *addr;
	NMIPRoute *route;
	GError *error = NULL;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	ASSERT_CHANGED (nm_setting_ip_config_add_dns (s_ip6, "1:2:3::4:5:6"));
	ASSERT_CHANGED (nm_setting_ip_config_remove_dns (s_ip6, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->dns->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_dns (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_dns (s_ip6, "1:2:3::4:5:6");
	ASSERT_CHANGED (nm_setting_ip_config_clear_dns (s_ip6));

	ASSERT_CHANGED (nm_setting_ip_config_add_dns_search (s_ip6, "foobar.com"));
	ASSERT_CHANGED (nm_setting_ip_config_remove_dns_search (s_ip6, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->dns_search->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_dns_search (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_dns_search (s_ip6, "foobar.com");
	ASSERT_CHANGED (nm_setting_ip_config_clear_dns_searches (s_ip6));

	addr = nm_ip_address_new (AF_INET6, "1:2:3::4:5:6", 64, &error);
	g_assert_no_error (error);

	ASSERT_CHANGED (nm_setting_ip_config_add_address (s_ip6, addr));
	ASSERT_CHANGED (nm_setting_ip_config_remove_address (s_ip6, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->addresses->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_address (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_address (s_ip6, addr);
	ASSERT_CHANGED (nm_setting_ip_config_clear_addresses (s_ip6));

	route = nm_ip_route_new (AF_INET6, "1:2:3::4:5:6", 128, NULL, 0, &error);
	g_assert_no_error (error);

	ASSERT_CHANGED (nm_setting_ip_config_add_route (s_ip6, route));
	ASSERT_CHANGED (nm_setting_ip_config_remove_route (s_ip6, 0));

	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx >= 0 && idx < priv->routes->len));
	ASSERT_UNCHANGED (nm_setting_ip_config_remove_route (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip_config_add_route (s_ip6, route);
	ASSERT_CHANGED (nm_setting_ip_config_clear_routes (s_ip6));

	nm_ip_address_unref (addr);
	nm_ip_route_unref (route);
	g_object_unref (connection);
}

static void
test_setting_vlan_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingVlan *s_vlan;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vlan));

	ASSERT_CHANGED (nm_setting_vlan_add_priority (s_vlan, NM_VLAN_INGRESS_MAP, 1, 3));
	ASSERT_CHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_INGRESS_MAP, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx < g_slist_length (list)));
	ASSERT_UNCHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_INGRESS_MAP, 1));
	g_test_assert_expected_messages ();
	ASSERT_CHANGED (nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_INGRESS_MAP, "1:3"));
	ASSERT_CHANGED (nm_setting_vlan_clear_priorities (s_vlan, NM_VLAN_INGRESS_MAP));

	ASSERT_CHANGED (nm_setting_vlan_add_priority (s_vlan, NM_VLAN_EGRESS_MAP, 1, 3));
	ASSERT_CHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_EGRESS_MAP, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (idx < g_slist_length (list)));
	ASSERT_UNCHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_EGRESS_MAP, 1));
	g_test_assert_expected_messages ();
	ASSERT_CHANGED (nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_EGRESS_MAP, "1:3"));
	ASSERT_CHANGED (nm_setting_vlan_clear_priorities (s_vlan, NM_VLAN_EGRESS_MAP));

	g_object_unref (connection);
}

static void
test_setting_vpn_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingVpn *s_vpn;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	ASSERT_CHANGED (nm_setting_vpn_add_data_item (s_vpn, "foobar", "baz"));
	ASSERT_CHANGED (nm_setting_vpn_remove_data_item (s_vpn, "foobar"));
	ASSERT_UNCHANGED (nm_setting_vpn_remove_data_item (s_vpn, "not added"));

	ASSERT_CHANGED (nm_setting_vpn_add_secret (s_vpn, "foobar", "baz"));
	ASSERT_CHANGED (nm_setting_vpn_remove_secret (s_vpn, "foobar"));
	ASSERT_UNCHANGED (nm_setting_vpn_remove_secret (s_vpn, "not added"));

	g_object_unref (connection);
}

static void
test_setting_wired_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingWired *s_wired;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	ASSERT_CHANGED (nm_setting_wired_add_s390_option (s_wired, "portno", "1"));
	ASSERT_CHANGED (nm_setting_wired_remove_s390_option (s_wired, "portno"));
	ASSERT_UNCHANGED (nm_setting_wired_remove_s390_option (s_wired, "layer2"));

	g_object_unref (connection);
}

static void
test_setting_wireless_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingWireless *s_wifi;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ASSERT_CHANGED (nm_setting_wireless_add_seen_bssid (s_wifi, "00:11:22:33:44:55"));

	g_object_unref (connection);
}

static void
test_setting_wireless_security_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingWirelessSecurity *s_wsec;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	/* Protos */
	ASSERT_CHANGED (nm_setting_wireless_security_add_proto (s_wsec, "wpa"));
	ASSERT_CHANGED (nm_setting_wireless_security_remove_proto (s_wsec, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_wireless_security_remove_proto (s_wsec, 1));
	g_test_assert_expected_messages ();

	nm_setting_wireless_security_add_proto (s_wsec, "wep");
	ASSERT_CHANGED (nm_setting_wireless_security_clear_protos (s_wsec));

	/* Pairwise ciphers */
	ASSERT_CHANGED (nm_setting_wireless_security_add_pairwise (s_wsec, "tkip"));
	ASSERT_CHANGED (nm_setting_wireless_security_remove_pairwise (s_wsec, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_wireless_security_remove_pairwise (s_wsec, 1));
	g_test_assert_expected_messages ();

	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	ASSERT_CHANGED (nm_setting_wireless_security_clear_pairwise (s_wsec));

	/* Group ciphers */
	ASSERT_CHANGED (nm_setting_wireless_security_add_group (s_wsec, "ccmp"));
	ASSERT_CHANGED (nm_setting_wireless_security_remove_group (s_wsec, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_wireless_security_remove_group (s_wsec, 1));
	g_test_assert_expected_messages ();

	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	ASSERT_CHANGED (nm_setting_wireless_security_clear_groups (s_wsec));

	/* WEP key secret flags */
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key0", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key1", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key2", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key3", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));

	g_object_unref (connection);
}

static void
test_setting_802_1x_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSetting8021x *s_8021x;

	connection = nm_simple_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	/* EAP methods */
	ASSERT_CHANGED (nm_setting_802_1x_add_eap_method (s_8021x, "tls"));
	ASSERT_CHANGED (nm_setting_802_1x_remove_eap_method (s_8021x, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_802_1x_remove_eap_method (s_8021x, 1));
	g_test_assert_expected_messages ();

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");
	ASSERT_CHANGED (nm_setting_802_1x_clear_eap_methods (s_8021x));

	/* alternate subject matches */
	ASSERT_CHANGED (nm_setting_802_1x_add_altsubject_match (s_8021x, "EMAIL:server@example.com"));
	ASSERT_CHANGED (nm_setting_802_1x_remove_altsubject_match (s_8021x, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_802_1x_remove_altsubject_match (s_8021x, 1));
	g_test_assert_expected_messages ();

	nm_setting_802_1x_add_altsubject_match (s_8021x, "EMAIL:server@example.com");
	ASSERT_CHANGED (nm_setting_802_1x_clear_altsubject_matches (s_8021x));

	/* phase2 alternate subject matches */
	ASSERT_CHANGED (nm_setting_802_1x_add_phase2_altsubject_match (s_8021x, "EMAIL:server@example.com"));
	ASSERT_CHANGED (nm_setting_802_1x_remove_phase2_altsubject_match (s_8021x, 0));
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (elt != NULL));
	ASSERT_UNCHANGED (nm_setting_802_1x_remove_phase2_altsubject_match (s_8021x, 1));
	g_test_assert_expected_messages ();

	nm_setting_802_1x_add_phase2_altsubject_match (s_8021x, "EMAIL:server@example.com");
	ASSERT_CHANGED (nm_setting_802_1x_clear_phase2_altsubject_matches (s_8021x));

	g_object_unref (connection);
}

static void
test_setting_old_uuid (void)
{
	gs_unref_object NMSetting *setting = NULL;

	/* NetworkManager-0.9.4.0 generated 40-character UUIDs with no dashes,
	 * like this one. Test that we maintain compatibility. */
	const char *uuid = "f43bec2cdd60e5da381ebb1eb1fa39f3cc52660c";

	setting = nm_setting_connection_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_ID, "uuidtest",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	nmtst_assert_setting_verifies (NM_SETTING (setting));
}

/*****************************************************************************/

static void
test_connection_normalize_uuid (void)
{
	gs_unref_object NMConnection *con = NULL;

	con = nmtst_create_minimal_connection ("test1", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);

	nmtst_assert_connection_verifies_and_normalizable (con);

	g_object_set (nm_connection_get_setting_connection (con),
	              NM_SETTING_CONNECTION_UUID, NULL,
	              NULL);
	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
}

/*****************************************************************************/

/*
 * Test normalization of interface-name
 */
static void
test_connection_normalize_virtual_iface_name (void)
{
	NMConnection *con = NULL;
	NMSettingConnection *s_con;
	NMSettingVlan *s_vlan;
	GVariant *connection_dict, *setting_dict, *var;
	GError *error = NULL;
	const char *IFACE_NAME = "iface";
	const char *IFACE_VIRT = "iface-X";

	con = nmtst_create_minimal_connection ("test1",
	                                       "22001632-bbb4-4616-b277-363dce3dfb5b",
	                                       NM_SETTING_VLAN_SETTING_NAME,
	                                       &s_con);

	nm_connection_add_setting (con,
	    g_object_new (NM_TYPE_SETTING_IP4_CONFIG,
	                  NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	                  NULL));

	nm_connection_add_setting (con,
	    g_object_new (NM_TYPE_SETTING_IP6_CONFIG,
	                  NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	                  NULL));

	s_vlan = nm_connection_get_setting_vlan (con);

	g_object_set (G_OBJECT (s_vlan),
	              NM_SETTING_VLAN_PARENT, "eth0",
	              NULL);

	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, IFACE_NAME, NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, IFACE_NAME);

	connection_dict = nm_connection_to_dbus (con, NM_CONNECTION_SERIALIZE_ALL);
	g_object_unref (con);

	/* Serialized form should include vlan.interface-name as well. */
	setting_dict = g_variant_lookup_value (connection_dict, NM_SETTING_VLAN_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (setting_dict != NULL);
	var = g_variant_lookup_value (setting_dict, "interface-name", NULL);
	g_assert (var != NULL);
	g_assert (g_variant_is_of_type (var, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (var, NULL), ==, IFACE_NAME);

	g_variant_unref (setting_dict);
	g_variant_unref (var);

	/* If vlan.interface-name is invalid, deserialization will fail. */
	NMTST_VARIANT_EDITOR (connection_dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_VLAN_SETTING_NAME,
	                                                     "interface-name",
	                                                     "s",
	                                                     ":::this-is-not-a-valid-interface-name:::");
	                      );

	con = _connection_new_from_dbus (connection_dict, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_clear_error (&error);

	/* If vlan.interface-name is valid, but doesn't match, it will be ignored. */
	NMTST_VARIANT_EDITOR (connection_dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_VLAN_SETTING_NAME,
	                                                     "interface-name",
	                                                     "s",
	                                                     IFACE_VIRT);
	                      );

	con = _connection_new_from_dbus (connection_dict, &error);
	g_assert_no_error (error);

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, IFACE_NAME);
	s_con = nm_connection_get_setting_connection (con);
	g_assert_cmpstr (nm_setting_connection_get_interface_name (s_con), ==, IFACE_NAME);
	g_object_unref (con);

	/* But removing connection.interface-name should result in vlan.connection-name
	 * being "promoted".
	 */
	NMTST_VARIANT_EDITOR (connection_dict,
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_CONNECTION_SETTING_NAME,
	                                                   NM_SETTING_CONNECTION_INTERFACE_NAME);
	                      );

	con = _connection_new_from_dbus (connection_dict, &error);
	g_assert_no_error (error);

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, IFACE_VIRT);
	s_con = nm_connection_get_setting_connection (con);
	g_assert_cmpstr (nm_setting_connection_get_interface_name (s_con), ==, IFACE_VIRT);
	g_object_unref (con);

	g_variant_unref (connection_dict);
}

static void
_test_connection_normalize_type_normalizable_setting (const char *type,
                                                      void (*prepare_normalizable_fcn) (NMConnection *con))
{
	NMSettingConnection *s_con;
	NMSetting *s_base;
	GType base_type;
	gs_unref_object NMConnection *con = NULL;
	gs_free char *id = g_strdup_printf ("%s[%s]", G_STRFUNC, type);

	base_type = nm_setting_lookup_type (type);
	g_assert (base_type != G_TYPE_INVALID);
	g_assert (_nm_setting_type_get_base_type_priority (base_type) != NM_SETTING_PRIORITY_INVALID);

	con = nmtst_create_minimal_connection (id, NULL, NULL, &s_con);

	nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);

	g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, type, NULL);

	if (prepare_normalizable_fcn)
		prepare_normalizable_fcn (con);

	g_assert (!nm_connection_get_setting_by_name (con, type));
	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING);
	nmtst_connection_normalize (con);

	s_base = nm_connection_get_setting_by_name (con, type);
	g_assert (s_base);
	g_assert (G_OBJECT_TYPE (s_base) == base_type);
}

static void
_test_connection_normalize_type_unnormalizable_setting (const char *type)
{
	NMSettingConnection *s_con;
	GType base_type;
	gs_unref_object NMConnection *con = NULL;
	gs_free char *id = g_strdup_printf ("%s[%s]", G_STRFUNC, type);

	base_type = nm_setting_lookup_type (type);
	g_assert (base_type != G_TYPE_INVALID);
	g_assert (_nm_setting_type_get_base_type_priority (base_type) != NM_SETTING_PRIORITY_INVALID);

	con = nmtst_create_minimal_connection (id, NULL, NULL, &s_con);

	nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);

	g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, type, NULL);

	nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING);
}

static void
_test_connection_normalize_type_normalizable_type (const char *type,
                                                   NMSetting *(*add_setting_fcn) (NMConnection *con))
{
	NMSettingConnection *s_con;
	NMSetting *s_base;
	GType base_type;
	gs_unref_object NMConnection *con = NULL;
	gs_free char *id = g_strdup_printf ("%s[%s]", G_STRFUNC, type);

	base_type = nm_setting_lookup_type (type);
	g_assert (base_type != G_TYPE_INVALID);
	g_assert (_nm_setting_type_get_base_type_priority (base_type) != NM_SETTING_PRIORITY_INVALID);

	con = nmtst_create_minimal_connection (id, NULL, NULL, &s_con);

	nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);

	if (add_setting_fcn)
		s_base = add_setting_fcn (con);
	else {
		s_base = NM_SETTING (g_object_new (base_type, NULL));
		nm_connection_add_setting (con, s_base);
	}

	g_assert (!nm_setting_connection_get_connection_type (s_con));
	g_assert (nm_connection_get_setting_by_name (con, type) == s_base);

	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
	nmtst_connection_normalize (con);

	g_assert_cmpstr (nm_connection_get_connection_type (con), ==, type);
	g_assert (nm_connection_get_setting_by_name (con, type) == s_base);
}

static NMSetting *
_add_setting_fcn_adsl (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_ADSL,
	                        NM_SETTING_ADSL_USERNAME, "test-user",
	                        NM_SETTING_ADSL_PROTOCOL, NM_SETTING_ADSL_PROTOCOL_PPPOA,
	                        NM_SETTING_ADSL_ENCAPSULATION, NM_SETTING_ADSL_ENCAPSULATION_VCMUX,
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_bluetooth (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_BLUETOOTH,
	                        NM_SETTING_BLUETOOTH_BDADDR, "11:22:33:44:55:66",
	                        NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_bond (NMConnection *con)
{
	NMSetting *setting;
	NMSettingConnection *s_con;

	setting = g_object_new (NM_TYPE_SETTING_BOND, NULL);

	nm_connection_add_setting (con, setting);

	s_con = nm_connection_get_setting_connection (con);

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "test-bond",
	              NULL);

	return setting;
}

static NMSetting *
_add_setting_fcn_bridge (NMConnection *con)
{
	NMSetting *setting;
	NMSettingConnection *s_con;

	setting = g_object_new (NM_TYPE_SETTING_BRIDGE, NULL);

	nm_connection_add_setting (con, setting);

	s_con = nm_connection_get_setting_connection (con);

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "test-bridge",
	              NULL);

	return setting;
}

static NMSetting *
_add_setting_fcn_cdma (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_CDMA,
	                        NM_SETTING_CDMA_NUMBER, "test-number",
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_infiniband (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_INFINIBAND,
	                        NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected",
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_olpc_mesh (NMConnection *con)
{
	NMSetting *setting;
	const char *ssid_data = "ssid-test";
	GBytes *ssid;

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));
	setting = g_object_new (NM_TYPE_SETTING_OLPC_MESH,
	                        NM_SETTING_OLPC_MESH_SSID, ssid,
	                        NM_SETTING_OLPC_MESH_CHANNEL, 1,
	                        NULL);
	g_bytes_unref (ssid);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_team (NMConnection *con)
{
	NMSetting *setting;
	NMSettingConnection *s_con;

	setting = g_object_new (NM_TYPE_SETTING_TEAM, NULL);

	nm_connection_add_setting (con, setting);

	s_con = nm_connection_get_setting_connection (con);

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "test-team",
	              NULL);

	return setting;
}

static NMSetting *
_add_setting_fcn_vlan (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_VLAN,
	                        NM_SETTING_VLAN_PARENT, "test-parent",
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_vpn (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_VPN,
	                        NM_SETTING_VPN_SERVICE_TYPE, "test-vpn-service-type",
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_wimax (NMConnection *con)
{
	NMSetting *setting;

	setting = g_object_new (NM_TYPE_SETTING_WIMAX,
	                        NM_SETTING_WIMAX_NETWORK_NAME, "test-network",
	                        NULL);

	nm_connection_add_setting (con, setting);
	return setting;
}

static NMSetting *
_add_setting_fcn_wireless (NMConnection *con)
{
	NMSetting *setting;
	const char *ssid_data = "ssid-test";
	GBytes *ssid;

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));
	setting = g_object_new (NM_TYPE_SETTING_WIRELESS,
	                        NM_SETTING_WIRELESS_SSID, ssid,
	                        NULL);
	g_bytes_unref (ssid);

	nm_connection_add_setting (con, setting);
	return setting;
}

static void
_prepare_normalizable_fcn_vlan (NMConnection *con)
{
	nm_connection_add_setting (con, g_object_new (NM_TYPE_SETTING_WIRED,
	                                              NM_SETTING_WIRED_MAC_ADDRESS, "11:22:33:44:55:66",
	                                              NULL));
}

static void
test_connection_normalize_type (void)
{
	guint i;
	struct {
		const char *type;
		gboolean normalizable;
		NMSetting *(*add_setting_fcn) (NMConnection *con);
		void (*prepare_normalizable_fcn) (NMConnection *con);
	} types[] = {
		{ NM_SETTING_GENERIC_SETTING_NAME, TRUE },
		{ NM_SETTING_GSM_SETTING_NAME, TRUE },
		{ NM_SETTING_WIRED_SETTING_NAME, TRUE },
		{ NM_SETTING_VLAN_SETTING_NAME, TRUE, _add_setting_fcn_vlan, _prepare_normalizable_fcn_vlan },

		{ NM_SETTING_ADSL_SETTING_NAME, FALSE, _add_setting_fcn_adsl },
		{ NM_SETTING_BLUETOOTH_SETTING_NAME, FALSE, _add_setting_fcn_bluetooth },
		{ NM_SETTING_BOND_SETTING_NAME, FALSE, _add_setting_fcn_bond },
		{ NM_SETTING_BRIDGE_SETTING_NAME, FALSE, _add_setting_fcn_bridge },
		{ NM_SETTING_CDMA_SETTING_NAME, FALSE, _add_setting_fcn_cdma },
		{ NM_SETTING_INFINIBAND_SETTING_NAME, FALSE, _add_setting_fcn_infiniband },
		{ NM_SETTING_OLPC_MESH_SETTING_NAME, FALSE, _add_setting_fcn_olpc_mesh },
		{ NM_SETTING_TEAM_SETTING_NAME, FALSE, _add_setting_fcn_team },
		{ NM_SETTING_VLAN_SETTING_NAME, FALSE, _add_setting_fcn_vlan },
		{ NM_SETTING_VPN_SETTING_NAME, FALSE, _add_setting_fcn_vpn },
		{ NM_SETTING_WIMAX_SETTING_NAME, FALSE, _add_setting_fcn_wimax },
		{ NM_SETTING_WIRELESS_SETTING_NAME, FALSE, _add_setting_fcn_wireless },
		{ 0 },
	};

	for (i = 0; types[i].type; i++) {
		const char *type = types[i].type;

		if (types[i].normalizable)
			_test_connection_normalize_type_normalizable_setting (type, types[i].prepare_normalizable_fcn);
		else
			_test_connection_normalize_type_unnormalizable_setting (type);
		_test_connection_normalize_type_normalizable_type (type, types[i].add_setting_fcn);
	}
}

static void
test_connection_normalize_slave_type_1 (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingConnection *s_con;

	con = nmtst_create_minimal_connection ("test_connection_normalize_slave_type_1",
	                                       "cc4cd5df-45dc-483e-b291-6b76c2338ecb",
	                                       NM_SETTING_WIRED_SETTING_NAME, &s_con);

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_MASTER, "master0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, "invalid-type",
	              NULL);

	nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (!nm_connection_get_setting_by_name (con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_SLAVE_TYPE, "bridge",
	              NULL);

	g_assert (!nm_connection_get_setting_by_name (con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING);
	nmtst_connection_normalize (con);
	g_assert (nm_connection_get_setting_by_name (con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
}

static void
test_connection_normalize_slave_type_2 (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingConnection *s_con;

	con = nmtst_create_minimal_connection ("test_connection_normalize_slave_type_2",
	                                       "40bea008-ca72-439a-946b-e65f827656f9",
	                                       NM_SETTING_WIRED_SETTING_NAME, &s_con);

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_MASTER, "master0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, "invalid-type",
	              NULL);

	nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (!nm_connection_get_setting_by_name (con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NULL,
	              NULL);
	nm_connection_add_setting (con, nm_setting_bridge_port_new ());

	g_assert (nm_connection_get_setting_by_name (con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NULL);
	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
	nmtst_connection_normalize (con);
	g_assert (nm_connection_get_setting_by_name (con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
}

static void
test_connection_normalize_infiniband_mtu (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingInfiniband *s_infini;

	con = nmtst_create_minimal_connection ("test_connection_normalize_infiniband_mtu", NULL,
	                                       NM_SETTING_INFINIBAND_SETTING_NAME, NULL);

	s_infini = nm_connection_get_setting_infiniband (con);
	g_object_set (s_infini,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected",
	              NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);

	g_object_set (s_infini,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
	              NM_SETTING_INFINIBAND_MTU, (guint) 2044,
	              NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);
	nmtst_connection_normalize (con);
	g_assert_cmpint (2044, ==, nm_setting_infiniband_get_mtu (s_infini));

	g_object_set (s_infini,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
	              NM_SETTING_INFINIBAND_MTU, (guint) 2045,
	              NULL);
	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	nmtst_connection_normalize (con);
	g_assert_cmpint (2044, ==, nm_setting_infiniband_get_mtu (s_infini));

	g_object_set (s_infini,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected",
	              NM_SETTING_INFINIBAND_MTU, (guint) 65520,
	              NULL);
	nmtst_assert_connection_verifies_without_normalization (con);
	g_assert_cmpint (65520, ==, nm_setting_infiniband_get_mtu (s_infini));

	g_object_set (s_infini,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected",
	              NM_SETTING_INFINIBAND_MTU, (guint) 65521,
	              NULL);
	nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	nmtst_connection_normalize (con);
	g_assert_cmpint (65520, ==, nm_setting_infiniband_get_mtu (s_infini));
}

static void
test_connection_normalize_gateway_never_default (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMIPAddress *addr;
	gs_free_error GError *error = NULL;

	con = nmtst_create_minimal_connection ("test1", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.1", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.254",
	              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, FALSE,
	              NULL);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nm_connection_add_setting (con, (NMSetting *) s_ip4);
	nm_connection_add_setting (con, (NMSetting *) s_ip6);
	nm_connection_add_setting (con, nm_setting_proxy_new ());

	nmtst_assert_connection_verifies_without_normalization (con);
	g_assert_cmpstr ("1.1.1.254", ==, nm_setting_ip_config_get_gateway (s_ip4));

	/* Now set never-default to TRUE and check that the gateway is
	 * removed during normalization
	 * */
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, TRUE,
	              NULL);

	nmtst_assert_connection_verifies_after_normalization (con,
	                                                      NM_CONNECTION_ERROR,
	                                                      NM_CONNECTION_ERROR_INVALID_PROPERTY);
	nmtst_connection_normalize (con);
	g_assert_cmpstr (NULL, ==, nm_setting_ip_config_get_gateway (s_ip4));
}

static void
test_connection_normalize_may_fail (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingIPConfig *s_ip4, *s_ip6;

	con = nmtst_create_minimal_connection ("test2", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
	              NULL);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
	              NULL);

	nm_connection_add_setting (con, (NMSetting *) s_ip4);
	nm_connection_add_setting (con, (NMSetting *) s_ip6);

	nmtst_assert_connection_verifies_and_normalizable (con);

	/* Now set method=disabled/ignore and check that may-fail becomes TRUE
	 * after normalization
	 * */
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	nmtst_assert_connection_verifies (con);
	nmtst_connection_normalize (con);
	g_assert_cmpint (nm_setting_ip_config_get_may_fail (s_ip4), ==, TRUE);
	g_assert_cmpint (nm_setting_ip_config_get_may_fail (s_ip6), ==, TRUE);
}

static void
test_connection_normalize_shared_addresses (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMIPAddress *addr;
	gs_free_error GError *error = NULL;

	con = nmtst_create_minimal_connection ("test1", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_SHARED,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.1", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nm_connection_add_setting (con, (NMSetting *) s_ip4);
	nm_connection_add_setting (con, (NMSetting *) s_ip6);

	nmtst_assert_connection_verifies_and_normalizable (con);

	/* Now we add other addresses and check that they are
	 * removed during normalization
	 * */
	addr = nm_ip_address_new (AF_INET, "2.2.2.2", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	addr = nm_ip_address_new (AF_INET, "3.3.3.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	nmtst_assert_connection_verifies_after_normalization (con,
	                                                      NM_CONNECTION_ERROR,
	                                                      NM_CONNECTION_ERROR_INVALID_PROPERTY);
	nmtst_connection_normalize (con);
	g_assert_cmpuint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert_cmpstr (nm_ip_address_get_address (addr), ==, "1.1.1.1");
}

static void
test_connection_normalize_ovs_interface_type_system (gconstpointer test_data)
{
	const guint TEST_CASE = GPOINTER_TO_UINT (test_data);
	gs_unref_object NMConnection *con = NULL;
	NMSettingConnection *s_con;
	NMSettingOvsInterface *s_ovs_if;

	con = nmtst_create_minimal_connection ("test_connection_normalize_ovs_interface_type_system",
	                                       NULL,
	                                       NM_SETTING_WIRED_SETTING_NAME, &s_con);

	switch (TEST_CASE) {
	case 1:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);

		nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING);

		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_WIRED_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		s_ovs_if = nm_connection_get_setting_ovs_interface (con);
		g_assert (s_ovs_if);
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "system");
		break;
	case 2:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);

		s_ovs_if = NM_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_if));

		nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);

		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_WIRED_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		g_assert (s_ovs_if == nm_connection_get_setting_ovs_interface (con));
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "system");
		break;
	case 3:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);

		s_ovs_if = NM_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_if));

		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "system",
		              NULL);
		nmtst_assert_connection_verifies_without_normalization (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_WIRED_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		break;
	case 4:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);

		s_ovs_if = NM_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_if));

		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "internal",
		              NULL);
		/* the setting doesn't verify, because the interface-type must be "system". */
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
		break;
	case 5:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NULL);

		s_ovs_if = NM_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_if));

		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "system",
		              NULL);
		nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_WIRED_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		g_assert (s_con == nm_connection_get_setting_connection (con));
		g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_OVS_PORT_SETTING_NAME);
		break;
	case 6:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
		              NULL);

		s_ovs_if = NM_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_if));

		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "system",
		              NULL);
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
		break;
	case 7:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
		              NULL);

		nm_connection_add_setting (con, nm_setting_bridge_port_new ());

		s_ovs_if = NM_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_if));

		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "system",
		              NULL);
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
		break;
	default:
		g_assert_not_reached ();
		break;
	}
}

static void
test_connection_normalize_ovs_interface_type_ovs_interface (gconstpointer test_data)
{
	const guint TEST_CASE = GPOINTER_TO_UINT (test_data);
	gs_unref_object NMConnection *con = NULL;
	NMSettingConnection *s_con;
	NMSettingOvsInterface *s_ovs_if;
	NMSettingOvsPatch *s_ovs_patch;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;

	con = nmtst_create_minimal_connection ("test_connection_normalize_ovs_interface_type_ovs_interface",
	                                       NULL,
	                                       NM_SETTING_OVS_INTERFACE_SETTING_NAME, &s_con);
	s_ovs_if = nm_connection_get_setting_ovs_interface (con);
	g_assert (s_ovs_if);

	switch (TEST_CASE) {
	case 1:
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
		break;
	case 2:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NULL);
		nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                                           NM_SETTING_PROXY_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		g_assert (s_con == nm_connection_get_setting_connection (con));
		g_assert (s_ovs_if == nm_connection_get_setting_ovs_interface (con));
		g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_OVS_PORT_SETTING_NAME);
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "internal");
		break;
	case 3:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                                           NM_SETTING_PROXY_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		g_assert (s_con == nm_connection_get_setting_connection (con));
		g_assert (s_ovs_if == nm_connection_get_setting_ovs_interface (con));
		g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_OVS_PORT_SETTING_NAME);
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "internal");
		break;
	case 4:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "internal",
		              NULL);
		nmtst_assert_connection_verifies_after_normalization (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                                           NM_SETTING_PROXY_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		g_assert (s_con == nm_connection_get_setting_connection (con));
		g_assert (s_ovs_if == nm_connection_get_setting_ovs_interface (con));
		g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_OVS_PORT_SETTING_NAME);
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "internal");
		break;
	case 5:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "internal",
		              NULL);
		nm_connection_add_setting (con, nm_setting_ip4_config_new ());
		nm_connection_add_setting (con, nm_setting_ip6_config_new ());
		nm_connection_add_setting (con, nm_setting_proxy_new ());
		s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting_ip4_config (con));
		s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting_ip6_config (con));
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, "auto",
		              NULL);
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, "auto",
		              NULL);
		nmtst_assert_connection_verifies_without_normalization (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                                           NM_SETTING_PROXY_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		break;
	case 6:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "internal",
		              NULL);
		nmtst_assert_connection_verifies_and_normalizable (con);
		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                                           NM_SETTING_PROXY_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME);
		g_assert (s_con == nm_connection_get_setting_connection (con));
		g_assert (s_ovs_if == nm_connection_get_setting_ovs_interface (con));
		g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_OVS_PORT_SETTING_NAME);
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "internal");
		break;
	case 7:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "system",
		              NULL);
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
		break;
	case 8:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "bogus",
		              NULL);
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
		break;
	case 9:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "patch",
		              NULL);
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING);
		break;
	case 10:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "patch",
		              NULL);
		nm_connection_add_setting (con, nm_setting_ovs_patch_new ());
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
		break;
	case 11:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NM_SETTING_CONNECTION_INTERFACE_NAME, "adsf",
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "patch",
		              NULL);
		nm_connection_add_setting (con, nm_setting_ovs_patch_new ());
		nmtst_assert_connection_unnormalizable (con, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);
		break;
	case 12:
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, "master0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_OVS_PORT_SETTING_NAME,
		              NM_SETTING_CONNECTION_INTERFACE_NAME, "adsf",
		              NULL);
		g_object_set (s_ovs_if,
		              NM_SETTING_OVS_INTERFACE_TYPE, "patch",
		              NULL);
		s_ovs_patch = NM_SETTING_OVS_PATCH (nm_setting_ovs_patch_new ());
		nm_connection_add_setting (con, NM_SETTING (s_ovs_patch));
		g_object_set (s_ovs_patch,
		              NM_SETTING_OVS_PATCH_PEER, "1.2.3.4",
		              NULL);
		nmtst_assert_connection_verifies_and_normalizable (con);
		nmtst_connection_normalize (con);
		nmtst_assert_connection_has_settings (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                                           NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                                           NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                                           NM_SETTING_PROXY_SETTING_NAME,
		                                           NM_SETTING_OVS_INTERFACE_SETTING_NAME,
		                                           NM_SETTING_OVS_PATCH_SETTING_NAME);
		g_assert (s_con == nm_connection_get_setting_connection (con));
		g_assert (s_ovs_if == nm_connection_get_setting_ovs_interface (con));
		g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_OVS_PORT_SETTING_NAME);
		g_assert_cmpstr (nm_setting_ovs_interface_get_interface_type (s_ovs_if), ==, "patch");
		break;
	default:
		g_assert_not_reached ();
	}
}

static void
test_setting_ip4_gateway (void)
{
	NMConnection *conn;
	NMSettingIPConfig *s_ip4;
	NMIPAddress *addr;
	GVariant *conn_dict, *ip4_dict, *value;
	GVariantIter iter;
	GVariant *addr_var;
	guint32 addr_vals_0[] = { htonl (0xc0a8010a), 0x00000018, htonl (0x00000000) };
	guint32 addr_vals_1[] = { htonl (0xc0a8010b), 0x00000018, htonl (0xc0a80101) };
	GVariantBuilder addrs_builder;
	GError *error = NULL;

	g_assert_cmpstr (nm_utils_inet4_ntop (addr_vals_0[0], NULL), ==, "192.168.1.10");

	/* When serializing on the daemon side, ipv4.gateway is copied to the first
	 * entry of ipv4.addresses
	 */
	conn = nmtst_create_minimal_connection ("test_setting_ip4_gateway", NULL,
	                                        NM_SETTING_WIRED_SETTING_NAME, NULL);
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "192.168.1.1",
	              NULL);
	nm_connection_add_setting (conn, NM_SETTING (s_ip4));

	addr = nm_ip_address_new (AF_INET, "192.168.1.10", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	_nm_utils_is_manager_process = TRUE;
	conn_dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);
	_nm_utils_is_manager_process = FALSE;
	g_object_unref (conn);

	ip4_dict = g_variant_lookup_value (conn_dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (ip4_dict != NULL);

	value = g_variant_lookup_value (ip4_dict, NM_SETTING_IP_CONFIG_GATEWAY, G_VARIANT_TYPE_STRING);
	g_assert (value != NULL);
	g_assert_cmpstr (g_variant_get_string (value, NULL), ==, "192.168.1.1");
	g_variant_unref (value);

	value = g_variant_lookup_value (ip4_dict, NM_SETTING_IP_CONFIG_ADDRESSES, G_VARIANT_TYPE ("aau"));
	g_assert (value != NULL);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "@au", &addr_var)) {
		const guint32 *addr_array;
		gsize length;

		addr_array = g_variant_get_fixed_array (addr_var, &length, sizeof (guint32));
		g_assert_cmpint (length, ==, 3);
		g_assert_cmpstr (nm_utils_inet4_ntop (addr_array[2], NULL), ==, "192.168.1.1");
		g_variant_unref (addr_var);
	}
	g_variant_unref (value);

	g_variant_unref (ip4_dict);

	/* When deserializing an old-style connection, the first non-0 gateway in
	 * ipv4.addresses is copied to :gateway.
	 */
	NMTST_VARIANT_EDITOR (conn_dict,
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                                   NM_SETTING_IP_CONFIG_GATEWAY);
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                                   "address-data");
	                      );

	conn = _connection_new_from_dbus (conn_dict, &error);
	g_assert_no_error (error);

	s_ip4 = (NMSettingIPConfig *) nm_connection_get_setting_ip4_config (conn);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.1.1");

	g_object_unref (conn);

	/* Try again with the gateway in the second address. */
	g_variant_builder_init (&addrs_builder, G_VARIANT_TYPE ("aau"));
	g_variant_builder_add (&addrs_builder, "@au",
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
	                                                  addr_vals_0, 3, 4));
	g_variant_builder_add (&addrs_builder, "@au",
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
	                                                  addr_vals_1, 3, 4));

	NMTST_VARIANT_EDITOR (conn_dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                                     "addresses", "aau", &addrs_builder);
	                      );

	conn = _connection_new_from_dbus (conn_dict, &error);
	g_assert_no_error (error);
	g_variant_unref (conn_dict);

	s_ip4 = (NMSettingIPConfig *) nm_connection_get_setting_ip4_config (conn);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.1.1");

	g_object_unref (conn);
}

static void
test_setting_ip6_gateway (void)
{
	NMConnection *conn;
	NMSettingIPConfig *s_ip6;
	NMIPAddress *addr;
	GVariant *conn_dict, *ip6_dict, *value;
	GVariantIter iter;
	GVariant *gateway_var;
	GVariantBuilder addrs_builder;
	guint8 addr_bytes_0[] = { 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a };
	guint8 addr_bytes_1[] = { 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b };
	guint8 gateway_bytes_1[] = { 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	GError *error = NULL;

	/* When serializing on the daemon side, ipv6.gateway is copied to the first
	 * entry of ipv6.addresses
	 */
	conn = nmtst_create_minimal_connection ("test_setting_ip6_gateway", NULL,
	                                        NM_SETTING_WIRED_SETTING_NAME, NULL);
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "abcd::1",
	              NULL);
	nm_connection_add_setting (conn, NM_SETTING (s_ip6));

	addr = nm_ip_address_new (AF_INET6, "abcd::10", 64, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr);
	nm_ip_address_unref (addr);

	_nm_utils_is_manager_process = TRUE;
	conn_dict = nm_connection_to_dbus (conn, NM_CONNECTION_SERIALIZE_ALL);
	_nm_utils_is_manager_process = FALSE;
	g_object_unref (conn);

	ip6_dict = g_variant_lookup_value (conn_dict, NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	g_assert (ip6_dict != NULL);

	value = g_variant_lookup_value (ip6_dict, NM_SETTING_IP_CONFIG_GATEWAY, G_VARIANT_TYPE_STRING);
	g_assert (value != NULL);
	g_assert_cmpstr (g_variant_get_string (value, NULL), ==, "abcd::1");
	g_variant_unref (value);

	value = g_variant_lookup_value (ip6_dict, NM_SETTING_IP_CONFIG_ADDRESSES, G_VARIANT_TYPE ("a(ayuay)"));
	g_assert (value != NULL);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "(@ayu@ay)", NULL, NULL, &gateway_var)) {
		const guint8 *gateway_bytes;
		gsize length;

		gateway_bytes = g_variant_get_fixed_array (gateway_var, &length, 1);
		g_assert_cmpint (length, ==, 16);
		g_assert_cmpstr (nm_utils_inet6_ntop ((struct in6_addr *) gateway_bytes, NULL), ==, "abcd::1");
		g_variant_unref (gateway_var);
	}
	g_variant_unref (value);

	g_variant_unref (ip6_dict);

	/* When deserializing an old-style connection, the first non-0 gateway in
	 * ipv6.addresses is copied to :gateway.
	 */
	NMTST_VARIANT_EDITOR (conn_dict,
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                                   NM_SETTING_IP_CONFIG_GATEWAY);
	                      NMTST_VARIANT_DROP_PROPERTY (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                                   "address-data");
	                      );

	conn = _connection_new_from_dbus (conn_dict, &error);
	g_assert_no_error (error);

	s_ip6 = (NMSettingIPConfig *) nm_connection_get_setting_ip6_config (conn);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, "abcd::1");

	g_object_unref (conn);

	/* Try again with the gateway in the second address. */
	g_variant_builder_init (&addrs_builder, G_VARIANT_TYPE ("a(ayuay)"));
	g_variant_builder_add (&addrs_builder, "(@ayu@ay)",
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                  addr_bytes_0, 16, 1),
	                       64,
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                  &in6addr_any, 16, 1));
	g_variant_builder_add (&addrs_builder, "(@ayu@ay)",
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                  addr_bytes_1, 16, 1),
	                       64,
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                  gateway_bytes_1, 16, 1));

	NMTST_VARIANT_EDITOR (conn_dict,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                                     "addresses", "a(ayuay)", &addrs_builder);
	                      );

	conn = _connection_new_from_dbus (conn_dict, &error);
	g_assert_no_error (error);
	g_variant_unref (conn_dict);

	s_ip6 = (NMSettingIPConfig *) nm_connection_get_setting_ip6_config (conn);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, "abcd::1");

	g_object_unref (conn);
}

typedef struct {
	const char *str;
	const guint8 expected[20];
	const guint expected_len;
} HexItem;

static void
test_setting_compare_default_strv (void)
{
	gs_unref_object NMConnection *c1 = NULL, *c2 = NULL;
	char **strv;
	NMSettingIPConfig *s_ip2, *s_ip1;
	gboolean compare;
	GHashTable *out_settings = NULL;

	c1 = nmtst_create_minimal_connection ("test_compare_default_strv", NULL,
	                                      NM_SETTING_WIRED_SETTING_NAME, NULL);
	nmtst_assert_connection_verifies_and_normalizable (c1);
	nmtst_connection_normalize (c1);

	c2 = nm_simple_connection_new_clone (c1);
	nmtst_assert_connection_verifies_without_normalization (c2);

	nmtst_assert_connection_equals (c1, FALSE, c2, FALSE);

	s_ip1 = nm_connection_get_setting_ip4_config (c1);
	s_ip2 = nm_connection_get_setting_ip4_config (c2);

	nm_setting_ip_config_clear_dns_options (s_ip2, FALSE);
	g_object_get (G_OBJECT (s_ip2), NM_SETTING_IP_CONFIG_DNS_OPTIONS, &strv, NULL);
	g_assert (!strv);
	nmtst_assert_connection_equals (c1, FALSE, c2, FALSE);

	nm_setting_ip_config_clear_dns_options (s_ip2, TRUE);
	g_object_get (G_OBJECT (s_ip2), NM_SETTING_IP_CONFIG_DNS_OPTIONS, &strv, NULL);
	g_assert (strv && !strv[0]);
	g_strfreev (strv);

	compare = nm_setting_diff ((NMSetting *) s_ip1, (NMSetting *) s_ip2, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, &out_settings);
	g_assert (!compare);
	g_assert (out_settings);
	g_assert (g_hash_table_contains (out_settings, NM_SETTING_IP_CONFIG_DNS_OPTIONS));
	g_hash_table_unref (out_settings);
	out_settings = NULL;

	compare = nm_connection_diff (c1, c2, NM_SETTING_COMPARE_FLAG_EXACT, &out_settings);
	g_assert (!compare);
	g_assert (out_settings);
	g_hash_table_unref (out_settings);
	out_settings = NULL;
}

/*****************************************************************************/

static void
test_setting_user_data (void)
{
	gs_unref_object NMSettingUser *s_user = NULL;

	s_user = NM_SETTING_USER (nm_setting_user_new ());
}

/*****************************************************************************/

static void
test_hexstr2bin (void)
{
	static const HexItem items[] = {
		{ "aaBBCCddDD10496a",     { 0xaa, 0xbb, 0xcc, 0xdd, 0xdd, 0x10, 0x49, 0x6a }, 8 },
		{ "aa:bb:cc:dd:10:49:6a", { 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x49, 0x6a },       7 },
		{ "0xccddeeff",           { 0xcc, 0xdd, 0xee, 0xff },                         4 },
		{ "1:2:66:77:80",         { 0x01, 0x02, 0x66, 0x77, 0x80 },                   5 },
		{ "e",                    { 0x0e },                                           1 },
		{ "ef",                   { 0xef },                                           1 },
		{ "efa" },
		{ "efad",                 { 0xef, 0xad },                                     2 },
		{ "ef:a",                 { 0xef, 0x0a },                                     2 },
		{ "aabb1199:" },
		{ ":aabb1199" },
		{ "aabb$$dd" },
		{ "aab:ccc:ddd" },
		{ "aab::ccc:ddd" },
	};
	GBytes *b;
	guint i;

	for (i = 0; i < G_N_ELEMENTS (items); i++) {
		b = nm_utils_hexstr2bin (items[i].str);
		if (items[i].expected_len) {
			g_assert (b);
			g_assert_cmpint (g_bytes_get_size (b), ==, items[i].expected_len);
			g_assert (memcmp (g_bytes_get_data (b, NULL), items[i].expected, g_bytes_get_size (b)) == 0);
			g_bytes_unref (b);
		} else
			g_assert (b == NULL);
	}
}

/*****************************************************************************/

static void
_do_strquote (const char *str, gsize buf_len, const char *expected)
{
	char canary = (char) nmtst_get_rand_int ();
	gs_free char *buf_full = g_malloc (buf_len + 2);
	char *buf = &buf_full[1];
	const char *b;

	buf[-1] = canary;
	buf[buf_len] = canary;

	if (buf_len == 0) {
		b = nm_strquote (NULL, 0, str);
		g_assert (b == NULL);
		g_assert (expected == NULL);
		b = nm_strquote (buf, 0, str);
		g_assert (b == buf);
	} else {
		b = nm_strquote (buf, buf_len, str);
		g_assert (b == buf);
		g_assert (strlen (b) < buf_len);
		g_assert_cmpstr (expected, ==, b);
	}

	g_assert (buf[-1] == canary);
	g_assert (buf[buf_len] == canary);
}

static void
test_nm_strquote (void)
{
	_do_strquote (NULL, 0, NULL);
	_do_strquote ("", 0, NULL);
	_do_strquote ("a", 0, NULL);
	_do_strquote ("ab", 0, NULL);

	_do_strquote (NULL, 1, "");
	_do_strquote (NULL, 2, "(");
	_do_strquote (NULL, 3, "(n");
	_do_strquote (NULL, 4, "(nu");
	_do_strquote (NULL, 5, "(nul");
	_do_strquote (NULL, 6, "(null");
	_do_strquote (NULL, 7, "(null)");
	_do_strquote (NULL, 8, "(null)");
	_do_strquote (NULL, 100, "(null)");

	_do_strquote ("", 1, "");
	_do_strquote ("", 2, "^");
	_do_strquote ("", 3, "\"\"");
	_do_strquote ("", 4, "\"\"");
	_do_strquote ("", 5, "\"\"");
	_do_strquote ("", 100, "\"\"");

	_do_strquote ("a", 1, "");
	_do_strquote ("a", 2, "^");
	_do_strquote ("a", 3, "\"^");
	_do_strquote ("a", 4, "\"a\"");
	_do_strquote ("a", 5, "\"a\"");
	_do_strquote ("a", 6, "\"a\"");
	_do_strquote ("a", 100, "\"a\"");

	_do_strquote ("ab", 1, "");
	_do_strquote ("ab", 2, "^");
	_do_strquote ("ab", 3, "\"^");
	_do_strquote ("ab", 4, "\"a^");
	_do_strquote ("ab", 5, "\"ab\"");
	_do_strquote ("ab", 6, "\"ab\"");
	_do_strquote ("ab", 7, "\"ab\"");
	_do_strquote ("ab", 100, "\"ab\"");

	_do_strquote ("abc", 1, "");
	_do_strquote ("abc", 2, "^");
	_do_strquote ("abc", 3, "\"^");
	_do_strquote ("abc", 4, "\"a^");
	_do_strquote ("abc", 5, "\"ab^");
	_do_strquote ("abc", 6, "\"abc\"");
	_do_strquote ("abc", 7, "\"abc\"");
	_do_strquote ("abc", 100, "\"abc\"");
}

/*****************************************************************************/

#define UUID_NIL        "00000000-0000-0000-0000-000000000000"
#define UUID_NS_DNS     "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

static void
_test_uuid (int uuid_type, const char *expected_uuid, const char *str, gssize slen, gpointer type_args)
{
	gs_free char *uuid_test = NULL;

	uuid_test = nm_utils_uuid_generate_from_string (str, slen, uuid_type, type_args);

	g_assert (uuid_test);
	g_assert (nm_utils_is_uuid (uuid_test));

	if (strcmp (uuid_test, expected_uuid)) {
		g_error ("UUID test failed: type=%d; text=%s, len=%lld, uuid=%s, expected=%s", uuid_type,
		         str, (long long) slen, uuid_test, expected_uuid);
	}

	if (slen < 0) {
		/* also test that passing slen==-1 yields the same result as passing strlen(str). */
		_test_uuid (uuid_type, expected_uuid, str, strlen (str), type_args);
	} else if (str && slen == 0) {
		/* also test if we accept NULL for slen==0 */
		_test_uuid (uuid_type, expected_uuid, NULL, 0, type_args);
	}

	if (uuid_type == NM_UTILS_UUID_TYPE_VARIANT3 && !type_args) {
		/* For NM_UTILS_UUID_TYPE_VARIANT3, a missing @type_args is equal to UUID_NIL */
		_test_uuid (uuid_type, expected_uuid, str, slen, UUID_NIL);
	}
}

static void
test_nm_utils_uuid_generate_from_string (void)
{
	_test_uuid (NM_UTILS_UUID_TYPE_LEGACY, "d41d8cd9-8f00-b204-e980-0998ecf8427e", "", -1, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_LEGACY, "0cc175b9-c0f1-b6a8-31c3-99e269772661", "a", -1, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_LEGACY, "098f6bcd-4621-d373-cade-4e832627b4f6", "test", -1, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_LEGACY, "70350f60-27bc-e371-3f6b-76473084309b", "a\0b", 3, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_LEGACY, "59c0547b-7fe2-1c15-2cce-e328e8bf6742", "/etc/NetworkManager/system-connections/em1", -1, NULL);

	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "4ae71336-e44b-39bf-b9d2-752e234818a5", "", -1, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "0531103a-d8fc-3dd4-b972-d98e4750994e", "a", -1, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "96e17d7a-ac89-38cf-95e1-bf5098da34e1", "test", -1, NULL);
	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "8156568e-4ae6-3f34-a93e-18e2c6cbbf78", "a\0b", 3, NULL);

	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "c87ee674-4ddc-3efe-a74e-dfe25da5d7b3", "", -1, UUID_NS_DNS);
	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "4c104dd0-4821-30d5-9ce3-0e7a1f8b7c0d", "a", -1, UUID_NS_DNS);
	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "45a113ac-c7f2-30b0-90a5-a399ab912716", "test", -1, UUID_NS_DNS);
	_test_uuid (NM_UTILS_UUID_TYPE_VARIANT3, "002a0ada-f547-375a-bab5-896a11d1927e", "a\0b", 3, UUID_NS_DNS);
}

/*****************************************************************************/

static void
__test_uuid (const char *expected_uuid, const char *str, gssize slen, char *uuid_test)
{
	g_assert (uuid_test);
	g_assert (nm_utils_is_uuid (uuid_test));

	if (strcmp (uuid_test, expected_uuid)) {
		g_error ("UUID test failed (1): text=%s, len=%lld, expected=%s, uuid_test=%s",
		         str, (long long) slen, expected_uuid, uuid_test);
	}
	g_free (uuid_test);

	uuid_test = nm_utils_uuid_generate_from_string (str, slen, NM_UTILS_UUID_TYPE_VARIANT3, NM_UTILS_UUID_NS);

	g_assert (uuid_test);
	g_assert (nm_utils_is_uuid (uuid_test));

	if (strcmp (uuid_test, expected_uuid)) {
		g_error ("UUID test failed (2): text=%s; len=%lld, expected=%s, uuid2=%s",
		         str, (long long) slen, expected_uuid, uuid_test);
	}
	g_free (uuid_test);
}

#define _test_uuid(expected_uuid, str, strlen, ...) __test_uuid (expected_uuid, str, strlen, _nm_utils_uuid_generate_from_strings(__VA_ARGS__, NULL))

static void
test_nm_utils_uuid_generate_from_strings (void)
{
	_test_uuid ("b07c334a-399b-32de-8d50-58e4e08f98e3", "",         0, NULL);
	_test_uuid ("b8a426cb-bcb5-30a3-bd8f-6786fea72df9", "\0",       1, "");
	_test_uuid ("12a4a982-7aae-39e1-951e-41aeb1250959", "a\0",      2, "a");
	_test_uuid ("69e22c7e-f89f-3a43-b239-1cb52ed8db69", "aa\0",     3, "aa");
	_test_uuid ("59829fd3-5ad5-3d90-a7b0-4911747e4088", "\0\0",     2, "",   "");
	_test_uuid ("01ad0e06-6c50-3384-8d86-ddab81421425", "a\0\0",    3, "a",  "");
	_test_uuid ("e1ed8647-9ed3-3ec8-8c6d-e8204524d71d", "aa\0\0",   4, "aa", "");
	_test_uuid ("fb1c7cd6-275c-3489-9382-83b900da8af0", "\0a\0",    3, "",   "a");
	_test_uuid ("5d79494e-c4ba-31a6-80a2-d6016ccd7e17", "a\0a\0",   4, "a",  "a");
	_test_uuid ("fd698d86-1b60-3ebe-855f-7aada9950a8d", "aa\0a\0",  5, "aa", "a");
	_test_uuid ("8c573b48-0f01-30ba-bb94-c5f59f4fe517", "\0aa\0",   4, "",   "aa");
	_test_uuid ("2bdd3d46-eb83-3c53-a41b-a724d04b5544", "a\0aa\0",  5, "a",  "aa");
	_test_uuid ("13d4b780-07c1-3ba7-b449-81c4844ef039", "aa\0aa\0", 6, "aa", "aa");
	_test_uuid ("dd265bf7-c05a-3037-9939-b9629858a477", "a\0b\0",   4, "a",  "b");
}

/*****************************************************************************/

static void
test_nm_utils_ascii_str_to_int64_check (const char *str, guint base, gint64 min,
                                        gint64 max, gint64 fallback, int exp_errno,
                                        gint64 exp_val)
{
	gint64 v;

	errno = 1;
	v = _nm_utils_ascii_str_to_int64 (str, base, min, max, fallback);
	g_assert_cmpint (errno, ==, exp_errno);
	g_assert_cmpint (v, ==, exp_val);
}

static void
test_nm_utils_ascii_str_to_int64_do (const char *str, guint base, gint64 min,
                                     gint64 max, gint64 fallback, int exp_errno,
                                     gint64 exp_val)
{
	const char *sign = "";
	const char *val;
	static const char *whitespaces[] = {
		"",
		" ",
		"\r\n\t",
		" \r\n\t ",
		" \r\n\t \t\r\n\t",
		NULL,
	};
	static const char *nulls[] = {
		"",
		"0",
		"00",
		"0000",
		"0000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		NULL,
	};
	const char **ws_pre, **ws_post, **null;
	guint i;

	if (str == NULL || exp_errno != 0) {
		test_nm_utils_ascii_str_to_int64_check (str, base, min, max, fallback, exp_errno, exp_val);
		return;
	}

	if (strncmp (str, "-", 1) == 0)
		sign = "-";

	val = str + strlen (sign);

	for (ws_pre = whitespaces; *ws_pre; ws_pre++) {
		for (ws_post = whitespaces; *ws_post; ws_post++) {
			for (null = nulls; *null; null++) {
				for (i = 0; ; i++) {
					char *s;
					const char *str_base = "";

					if (base == 16) {
						if (i == 1)
							str_base = "0x";
						else if (i > 1)
							break;
					} else if (base == 8) {
						if (i == 1)
							str_base = "0";
						else if (i > 1)
							break;
					} else if (base == 0) {
						if (i > 0)
							break;
						/* with base==0, a leading zero would be interpreted as octal. Only test without *null */
						if ((*null)[0])
							break;
					} else {
						if (i > 0)
							break;
					}

					s = g_strdup_printf ("%s%s%s%s%s%s", *ws_pre, sign, str_base, *null, val, *ws_post);

					test_nm_utils_ascii_str_to_int64_check (s, base, min, max, fallback, exp_errno, exp_val);
					g_free (s);
				}
			}
		}
	}
}

static void
test_nm_utils_ascii_str_to_int64 (void)
{
	test_nm_utils_ascii_str_to_int64_do (NULL, 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("", 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("1x", 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("4711", 10, 0, 10000, -1, 0, 4711);
	test_nm_utils_ascii_str_to_int64_do ("10000", 10, 0, 10000, -1, 0, 10000);
	test_nm_utils_ascii_str_to_int64_do ("10001", 10, 0, 10000, -1, ERANGE, -1);
	test_nm_utils_ascii_str_to_int64_do ("FF", 16, 0, 10000, -1, 0, 255);
	test_nm_utils_ascii_str_to_int64_do ("FF", 10, 0, 10000, -2, EINVAL, -2);
	test_nm_utils_ascii_str_to_int64_do ("9223372036854775807", 10, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do ("7FFFFFFFFFFFFFFF", 16, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do ("9223372036854775808", 10, 0, G_MAXINT64, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("-9223372036854775808", 10, G_MININT64, 0, -2, 0, G_MININT64);
	test_nm_utils_ascii_str_to_int64_do ("-9223372036854775808", 10, G_MININT64+1, 0, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("-9223372036854775809", 10, G_MININT64, 0, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("1.0", 10, 1, 1, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("1x0", 16, -10, 10, -100, EINVAL, -100);
	test_nm_utils_ascii_str_to_int64_do ("0", 16, -10, 10, -100, 0, 0);
	test_nm_utils_ascii_str_to_int64_do ("10001111", 2, -1000, 1000, -100000, 0, 0x8F);
	test_nm_utils_ascii_str_to_int64_do ("-10001111", 2, -1000, 1000, -100000, 0, -0x8F);
	test_nm_utils_ascii_str_to_int64_do ("1111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7F);
	test_nm_utils_ascii_str_to_int64_do ("111111111111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFF);
	test_nm_utils_ascii_str_to_int64_do ("11111111111111111111111111111111111111111111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFFFFFFFFFF);
	test_nm_utils_ascii_str_to_int64_do ("111111111111111111111111111111111111111111111111111111111111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFFFFFFFFFFFFFF);
	test_nm_utils_ascii_str_to_int64_do ("100000000000000000000000000000000000000000000000000000000000000", 2, G_MININT64, G_MAXINT64, -1, 0,  0x4000000000000000);
	test_nm_utils_ascii_str_to_int64_do ("1000000000000000000000000000000000000000000000000000000000000000", 2, G_MININT64, G_MAXINT64, -1, ERANGE, -1);
	test_nm_utils_ascii_str_to_int64_do ("-100000000000000000000000000000000000000000000000000000000000000", 2, G_MININT64, G_MAXINT64, -1, 0,  -0x4000000000000000);
	test_nm_utils_ascii_str_to_int64_do ("111111111111111111111111111111111111111111111111111111111111111",  2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFFFFFFFFFFFFFF);
	test_nm_utils_ascii_str_to_int64_do ("-100000000000000000000000000000000000000000000000000000000000000",  2, G_MININT64, G_MAXINT64, -1, 0,  -0x4000000000000000);
	test_nm_utils_ascii_str_to_int64_do ("0x70",  10, G_MININT64, G_MAXINT64, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("4711",  0, G_MININT64, G_MAXINT64, -1, 0, 4711);
	test_nm_utils_ascii_str_to_int64_do ("04711",  0, G_MININT64, G_MAXINT64, -1, 0, 04711);
	test_nm_utils_ascii_str_to_int64_do ("0x4711",  0, G_MININT64, G_MAXINT64, -1, 0, 0x4711);
	test_nm_utils_ascii_str_to_int64_do ("080",  0, G_MININT64, G_MAXINT64, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("070",  0, G_MININT64, G_MAXINT64, -1, 0, 7*8);
	test_nm_utils_ascii_str_to_int64_do ("0x70",  0, G_MININT64, G_MAXINT64, -1, 0, 0x70);
}

/*****************************************************************************/

static void
test_nm_utils_strstrdictkey (void)
{
#define _VALUES_STATIC(_v1, _v2) { .v1 = _v1, .v2 = _v2, .v_static = _nm_utils_strstrdictkey_static (_v1, _v2), }
	const struct {
		const char *v1;
		const char *v2;
		NMUtilsStrStrDictKey *v_static;
	} *val1, *val2, values[] = {
		{ NULL, NULL },
		{ "", NULL },
		{ NULL, "" },
		{ "a", NULL },
		{ NULL, "a" },
		_VALUES_STATIC ("", ""),
		_VALUES_STATIC ("a", ""),
		_VALUES_STATIC ("", "a"),
		_VALUES_STATIC ("a", "b"),
	};
	guint i, j;

	for (i = 0; i < G_N_ELEMENTS (values); i++) {
		gs_free NMUtilsStrStrDictKey *key1 = NULL;

		val1 = &values[i];

		key1 = _nm_utils_strstrdictkey_create (val1->v1, val1->v2);
		if (val1->v_static) {
			g_assert (_nm_utils_strstrdictkey_equal (key1, val1->v_static));
			g_assert (_nm_utils_strstrdictkey_equal (val1->v_static, key1));
			g_assert_cmpint (_nm_utils_strstrdictkey_hash (key1), ==, _nm_utils_strstrdictkey_hash (val1->v_static));
		}

		for (j = 0; j < G_N_ELEMENTS (values); j++) {
			gs_free NMUtilsStrStrDictKey *key2 = NULL;

			val2 = &values[j];
			key2 = _nm_utils_strstrdictkey_create (val2->v1, val2->v2);
			if (i != j) {
				g_assert (!_nm_utils_strstrdictkey_equal (key1, key2));
				g_assert (!_nm_utils_strstrdictkey_equal (key2, key1));
			}
		}
	}
}

/*****************************************************************************/

static guint
_g_strv_length (gconstpointer arr)
{
	return arr ? g_strv_length ((char **) arr) : 0;
}

static void
test_nm_ptrarray_len (void)
{
#define _PTRARRAY_cmp(len, arr) \
	G_STMT_START { \
		g_assert_cmpint (len, ==, NM_PTRARRAY_LEN (arr)); \
		g_assert_cmpint (len, ==, _g_strv_length (arr)); \
	} G_STMT_END
#define _PTRARRAY_LEN0(T) \
	G_STMT_START { \
		T **vnull = NULL; \
		T *const*vnull1 = NULL; \
		T *const*const vnull2 = NULL; \
		T *v0[] = { NULL }; \
		T *const*v01 = v0; \
		T *const*const v02 = v0; \
		T **const v03 = v0; \
		\
		_PTRARRAY_cmp (0, vnull); \
		_PTRARRAY_cmp (0, vnull1); \
		_PTRARRAY_cmp (0, vnull2); \
		_PTRARRAY_cmp (0, v0); \
		_PTRARRAY_cmp (0, v01); \
		_PTRARRAY_cmp (0, v02); \
		_PTRARRAY_cmp (0, v03); \
	} G_STMT_END

	_PTRARRAY_LEN0 (char);
	_PTRARRAY_LEN0 (const char);
	_PTRARRAY_LEN0 (int);
	_PTRARRAY_LEN0 (const int);
	_PTRARRAY_LEN0 (void *);
	_PTRARRAY_LEN0 (void);
	_PTRARRAY_LEN0 (const void);

#define _PTRARRAY_LENn(T) \
	G_STMT_START { \
		T x[5] = { 0 }; \
		\
		T *v1[] = { &x[0], NULL }; \
		T *const*v11 = v1; \
		T *const*const v12 = v1; \
		T **const v13 = v1; \
		\
		T *v2[] = { &x[0], &x[1], NULL }; \
		T *const*v21 = v2; \
		T *const*const v22 = v2; \
		T **const v23 = v2; \
		\
		_PTRARRAY_cmp (1, v1); \
		_PTRARRAY_cmp (1, v11); \
		_PTRARRAY_cmp (1, v12); \
		_PTRARRAY_cmp (1, v13); \
		\
		_PTRARRAY_cmp (2, v2); \
		_PTRARRAY_cmp (2, v21); \
		_PTRARRAY_cmp (2, v22); \
		_PTRARRAY_cmp (2, v23); \
	} G_STMT_END

	_PTRARRAY_LENn (char);
	_PTRARRAY_LENn (const char);
	_PTRARRAY_LENn (int);
	_PTRARRAY_LENn (const int);
	_PTRARRAY_LENn (void *);
}

/*****************************************************************************/

static void
test_nm_utils_dns_option_validate_do (char *option, gboolean ipv6, const NMUtilsDNSOptionDesc *descs,
                                      gboolean exp_result, char *exp_name, gboolean exp_value)
{
	char *name;
	long value = 0;
	gboolean result;

	result = _nm_utils_dns_option_validate (option, &name, &value, ipv6, descs);

	g_assert (result == exp_result);
	g_assert_cmpstr (name, ==, exp_name);
	g_assert (value == exp_value);

	g_free (name);
}

static const NMUtilsDNSOptionDesc opt_descs[] = {
	/* name                   num      ipv6 */
	{ "opt1",                 FALSE,   FALSE },
	{ "opt2",                 TRUE,    FALSE },
	{ "opt3",                 FALSE,   TRUE  },
	{ "opt4",                 TRUE,    TRUE  },
	{ NULL,                   FALSE,   FALSE }
};

static void
test_nm_utils_dns_option_validate (void)
{
	/*                                    opt            ipv6    descs        result name       value */
	test_nm_utils_dns_option_validate_do ("",            FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do (":",           FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do (":1",          FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do (":val",        FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt",         FALSE,  NULL,        TRUE,  "opt",     -1);
	test_nm_utils_dns_option_validate_do ("opt:",        FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt:12",      FALSE,  NULL,        TRUE,  "opt",     12);
	test_nm_utils_dns_option_validate_do ("opt:12 ",     FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt:val",     FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt:2val",    FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt:2:3",     FALSE,  NULL,        FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt-6",       FALSE,  NULL,        TRUE,  "opt-6",   -1);

	test_nm_utils_dns_option_validate_do ("opt1",        FALSE,  opt_descs,   TRUE,  "opt1",    -1);
	test_nm_utils_dns_option_validate_do ("opt1",        TRUE,   opt_descs,   TRUE,  "opt1",    -1);
	test_nm_utils_dns_option_validate_do ("opt1:3",      FALSE,  opt_descs,   FALSE,  NULL,     -1);

	test_nm_utils_dns_option_validate_do ("opt2",        FALSE,  opt_descs,   FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt2:5",      FALSE,  opt_descs,   TRUE,  "opt2",    5);

	test_nm_utils_dns_option_validate_do ("opt3",        FALSE,  opt_descs,   FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt3",        TRUE,   opt_descs,   TRUE,  "opt3",    -1);

	test_nm_utils_dns_option_validate_do ("opt4",        FALSE,  opt_descs,   FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt4",        TRUE,   opt_descs,   FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt4:40",     FALSE,  opt_descs,   FALSE, NULL,      -1);
	test_nm_utils_dns_option_validate_do ("opt4:40",     TRUE,   opt_descs,   TRUE,  "opt4",    40);
}

static void
test_nm_utils_dns_option_find_idx (void)
{
	GPtrArray *options;

	options = g_ptr_array_new ();

	g_ptr_array_add (options, "debug");
	g_ptr_array_add (options, "timeout:5");
	g_ptr_array_add (options, "edns0");

	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "debug"),      ==, 0);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "debug:1"),    ==, 0);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "timeout"),    ==, 1);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "timeout:5"),  ==, 1);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "timeout:2"),  ==, 1);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "edns0"),      ==, 2);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, "rotate"),     ==, -1);
	g_assert_cmpint (_nm_utils_dns_option_find_idx (options, ""),           ==, -1);

	g_ptr_array_free (options, TRUE);
}

/*****************************************************************************/

static void
_json_config_check_valid (const char *conf, gboolean expected)
{
	gs_free_error GError *error = NULL;
	gboolean res;

	res = nm_utils_is_json_object (conf, &error);
	g_assert_cmpint (res, ==, expected);
	g_assert (res || error);
}

static void
test_nm_utils_check_valid_json (void)
{
	_json_config_check_valid (NULL, FALSE);
	_json_config_check_valid ("", FALSE);
#if WITH_JSON_VALIDATION
	_json_config_check_valid ("{ }", TRUE);
	_json_config_check_valid ("{ \"a\" : 1 }", TRUE);
	_json_config_check_valid ("{ \"a\" : }", FALSE);
#else
	/* Without JSON library everything except empty string is considered valid */
	_json_config_check_valid ("{ }", TRUE);
	_json_config_check_valid ("{'%!-a1} ", TRUE);
	_json_config_check_valid (" {'%!-a1}", TRUE);
	_json_config_check_valid ("{'%!-a1", FALSE);
#endif
}

static void
_team_config_equal_check (const char *conf1,
                          const char *conf2,
                          gboolean port_config,
                          gboolean expected)
{
	g_assert_cmpint (_nm_utils_team_config_equal (conf1, conf2, port_config), ==, expected);
}

static void
test_nm_utils_team_config_equal (void)
{
#if WITH_JSON_VALIDATION
	_team_config_equal_check ("", "", TRUE, TRUE);
	_team_config_equal_check ("{}",
	                          "{ }",
	                          TRUE,
	                          TRUE);
	_team_config_equal_check ("{}",
	                          "{",
	                          TRUE,
	                          FALSE);

	/* team config */
	_team_config_equal_check ("{ }",
	                          "{ \"runner\" :  { \"name\" : \"roundrobin\"} }",
	                          FALSE,
	                          TRUE);
	_team_config_equal_check ("{ }",
	                          "{ \"runner\" :  { \"name\" : \"random\"} }",
	                          FALSE,
	                          FALSE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"roundrobin\"} }",
	                          "{ \"runner\" :  { \"name\" : \"random\"} }",
	                          FALSE,
	                          FALSE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"random\"} }",
	                          "{ \"runner\" :  { \"name\" : \"random\"} }",
	                          FALSE,
	                          TRUE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"loadbalance\"} }",
	                          "{ \"runner\" :  { \"name\" : \"loadbalance\"} }",
	                          FALSE,
	                          TRUE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"random\"}, \"ports\" : { \"eth0\" : {} } }",
	                          "{ \"runner\" :  { \"name\" : \"random\"}, \"ports\" : { \"eth1\" : {} } }",
	                          FALSE,
	                          TRUE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"lacp\"} }",
	                          "{ \"runner\" :  { \"name\" : \"lacp\", \"tx_hash\" : [ \"eth\", \"ipv4\", \"ipv6\" ] } }",
	                          FALSE,
	                          TRUE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"roundrobin\"} }",
	                          "{ \"runner\" :  { \"name\" : \"roundrobin\", \"tx_hash\" : [ \"eth\", \"ipv4\", \"ipv6\" ] } }",
	                          FALSE,
	                          FALSE);
	_team_config_equal_check ("{ \"runner\" :  { \"name\" : \"lacp\"} }",
	                          "{ \"runner\" :  { \"name\" : \"lacp\", \"tx_hash\" : [ \"eth\" ] } }",
	                          FALSE,
	                          FALSE);

	/* team port config */
	_team_config_equal_check ("{ }",
	                          "{ \"link_watch\" :  { \"name\" : \"ethtool\"} }",
	                          TRUE,
	                          TRUE);
	_team_config_equal_check ("{ }",
	                          "{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
	                          TRUE,
	                          FALSE);
	_team_config_equal_check ("{ \"link_watch\" :  { \"name\" : \"ethtool\"} }",
	                          "{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
	                          TRUE,
	                          FALSE);
	_team_config_equal_check ("{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
	                          "{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
	                          TRUE,
	                          TRUE);
	_team_config_equal_check ("{ \"link_watch\" :  { \"name\" : \"arp_ping\"}, \"ports\" : { \"eth0\" : {} } }",
	                          "{ \"link_watch\" :  { \"name\" : \"arp_ping\"}, \"ports\" : { \"eth1\" : {} } }",
	                          TRUE,
	                          TRUE);
#else
	/* Without JSON library, strings are compared for equality */
	_team_config_equal_check ("", "", TRUE, TRUE);
	_team_config_equal_check ("", " ", TRUE, FALSE);
	_team_config_equal_check ("{ \"a\": 1 }", "{ \"a\": 1 }", TRUE, TRUE);
	_team_config_equal_check ("{ \"a\": 1 }", "{ \"a\":   1 }", TRUE, FALSE);
#endif
}

/*****************************************************************************/

enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED {
	_DUMMY_1 = -1,
};

enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED {
	_DUMMY_2,
};

enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED_64 {
	_DUMMY_3 = (1LL << 40),
};

enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED_64 {
	_DUMMY_4a = -1,
	_DUMMY_4b = (1LL << 40),
};

#define test_nm_utils_is_power_of_two_do(type, x, expect) \
	G_STMT_START { \
		typeof (x) x1 = (x); \
		type x2 = (type) x1; \
		\
		g_assert_cmpint (expect, ==, nm_utils_is_power_of_two (x1)); \
		if (   ((typeof (x1)) x2) == x1 \
		    && ((typeof (x2)) x1) == x2 \
		    && x2 > 0) { \
			/* x2 equals @x, and is positive. Compare to @expect */ \
			g_assert_cmpint (expect, ==, nm_utils_is_power_of_two (x2)); \
		} else if (!(x2 > 0)) { \
			/* a non positive value is always FALSE. */ \
			g_assert_cmpint (FALSE, ==, nm_utils_is_power_of_two (x2)); \
		} \
		if (x2) { \
			x2 = -x2; \
			if (!(x2 > 0)) { \
				/* for negative values, we return FALSE. */ \
				g_assert_cmpint (FALSE, ==, nm_utils_is_power_of_two (x2)); \
			} \
		} \
	} G_STMT_END

static void
test_nm_utils_is_power_of_two (void)
{
	guint64 xyes, xno;
	gint i, j;
	GRand *rand = nmtst_get_rand ();
	int numbits;

	for (i = -1; i < 64; i++) {

		/* find a (positive) x which is a power of two. */
		if (i == -1)
			xyes = 0;
		else {
			xyes = (((guint64) 1) << i);
			g_assert (xyes != 0);
		}

		xno = xyes;
		if (xyes != 0) {
again:
			/* Find another @xno, that is not a power of two. Do that,
			 * by randomly setting bits. */
			numbits = g_rand_int_range (rand, 1, 65);
			while (xno != ~((guint64) 0) && numbits > 0) {
				guint64 v = (((guint64) 1) << g_rand_int_range (rand, 0, 64));

				if ((xno | v) != xno) {
					xno |= v;
					--numbits;
				}
			}
			if (xno == xyes)
				goto again;
		}

		for (j = 0; j < 2; j++) {
			gboolean expect = j == 0;
			guint64 x = expect ? xyes : xno;

			if (expect && xyes == 0)
				continue;

			/* check if @x is as @expect, when casted to a certain data type. */
			test_nm_utils_is_power_of_two_do (gint8, x, expect);
			test_nm_utils_is_power_of_two_do (guint8, x, expect);
			test_nm_utils_is_power_of_two_do (gint16, x, expect);
			test_nm_utils_is_power_of_two_do (guint16, x, expect);
			test_nm_utils_is_power_of_two_do (gint32, x, expect);
			test_nm_utils_is_power_of_two_do (guint32, x, expect);
			test_nm_utils_is_power_of_two_do (gint64, x, expect);
			test_nm_utils_is_power_of_two_do (guint64, x, expect);
			test_nm_utils_is_power_of_two_do (char, x, expect);
			test_nm_utils_is_power_of_two_do (unsigned char, x, expect);
			test_nm_utils_is_power_of_two_do (signed char, x, expect);
			test_nm_utils_is_power_of_two_do (enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED, x, expect);
			test_nm_utils_is_power_of_two_do (enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED, x, expect);
			test_nm_utils_is_power_of_two_do (enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED_64, x, expect);
			test_nm_utils_is_power_of_two_do (enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED_64, x, expect);
		}
	}
}

/*****************************************************************************/

static int
_test_find_binary_search_cmp (gconstpointer a, gconstpointer b, gpointer dummy)
{
	int ia, ib;

	ia = GPOINTER_TO_INT (a);
	ib = GPOINTER_TO_INT (b);

	if (ia == ib)
		return 0;
	if (ia < ib)
		return -1;
	return 1;
}

static void
_test_find_binary_search_do (const int *array, gsize len)
{
	gsize i;
	gssize idx, idx_first, idx_last;
	gs_free gconstpointer *parray = g_new (gconstpointer, len);
	const int NEEDLE = 0;
	gconstpointer pneedle = GINT_TO_POINTER (NEEDLE);
	gssize expected_result;

	for (i = 0; i < len; i++)
		parray[i] = GINT_TO_POINTER (array[i]);

	expected_result = _nm_utils_ptrarray_find_first (parray, len, pneedle);

	idx = _nm_utils_ptrarray_find_binary_search (parray, len, pneedle, _test_find_binary_search_cmp, NULL, &idx_first, &idx_last);
	if (expected_result >= 0) {
		g_assert_cmpint (expected_result, ==, idx);
	} else {
		gssize idx2 = ~idx;
		g_assert_cmpint (idx, <, 0);

		g_assert (idx2 >= 0);
		g_assert (idx2 <= len);
		g_assert (idx2 - 1 < 0 || _test_find_binary_search_cmp (parray[idx2 - 1], pneedle, NULL) < 0);
		g_assert (idx2 >= len || _test_find_binary_search_cmp (parray[idx2], pneedle, NULL) > 0);
	}
	g_assert_cmpint (idx, ==, idx_first);
	g_assert_cmpint (idx, ==, idx_last);
	for (i = 0; i < len; i++) {
		int cmp;

		cmp = _test_find_binary_search_cmp (parray[i], pneedle, NULL);
		if (cmp == 0) {
			g_assert (pneedle == parray[i]);
			g_assert (idx >= 0);
			g_assert (i == idx);
		} else {
			g_assert (pneedle != parray[i]);
			if (cmp < 0) {
				if (idx < 0)
					g_assert (i < ~idx);
				else
					g_assert (i < idx);
			} else {
				if (idx < 0)
					g_assert (i >= ~idx);
				else
					g_assert (i >= idx);
			}
		}
	}
}

static void
_test_find_binary_search_do_uint32 (const int *int_array, gsize len)
{
	gssize idx;
	const int OFFSET = 100;
	const int NEEDLE = 0 + OFFSET;
	gssize expected_result = -1;
	guint32 array[30];

	g_assert (len <= G_N_ELEMENTS (array));

	/* the test data has negative values. Shift them... */
	for (idx = 0; idx < len; idx++) {
		int v = int_array[idx];

		g_assert (v > -OFFSET);
		g_assert (v < OFFSET);
		g_assert (idx == 0 || v > int_array[idx - 1]);
		array[idx] = (guint32) (int_array[idx] + OFFSET);
		if (array[idx] == NEEDLE)
			expected_result = idx;
	}

	idx = _nm_utils_array_find_binary_search (array,
	                                          sizeof (guint32),
	                                          len,
	                                          &NEEDLE,
	                                          nm_cmp_uint32_p_with_data,
	                                          NULL);
	if (expected_result >= 0)
		g_assert_cmpint (expected_result, ==, idx);
	else {
		gssize idx2 = ~idx;
		g_assert_cmpint (idx, <, 0);

		g_assert (idx2 >= 0);
		g_assert (idx2 <= len);
		g_assert (idx2 - 1 < 0 || array[idx2 - 1] < NEEDLE);
		g_assert (idx2 >= len || array[idx2] > NEEDLE);
	}
}
#define test_find_binary_search_do(...) \
	G_STMT_START { \
		const int _array[] = { __VA_ARGS__ }; \
		_test_find_binary_search_do (_array, G_N_ELEMENTS (_array)); \
		_test_find_binary_search_do_uint32 (_array, G_N_ELEMENTS (_array)); \
	} G_STMT_END

static void
test_nm_utils_ptrarray_find_binary_search (void)
{
	test_find_binary_search_do (            0);
	test_find_binary_search_do (        -1, 0);
	test_find_binary_search_do (    -2, -1, 0);
	test_find_binary_search_do (-3, -2, -1, 0);
	test_find_binary_search_do (            0, 1);
	test_find_binary_search_do (            0, 1, 2);
	test_find_binary_search_do (        -1, 0, 1, 2);
	test_find_binary_search_do (    -2, -1, 0, 1, 2);
	test_find_binary_search_do (-3, -2, -1, 0, 1, 2);
	test_find_binary_search_do (-3, -2, -1, 0, 1, 2);
	test_find_binary_search_do (-3, -2, -1, 0, 1, 2, 3);
	test_find_binary_search_do (-3, -2, -1, 0, 1, 2, 3, 4);

	test_find_binary_search_do (        -1);
	test_find_binary_search_do (    -2, -1);
	test_find_binary_search_do (-3, -2, -1);
	test_find_binary_search_do (            1);
	test_find_binary_search_do (            1, 2);
	test_find_binary_search_do (        -1, 1, 2);
	test_find_binary_search_do (    -2, -1, 1, 2);
	test_find_binary_search_do (-3, -2, -1, 1, 2);
	test_find_binary_search_do (-3, -2, -1, 1, 2);
	test_find_binary_search_do (-3, -2, -1, 1, 2, 3);
	test_find_binary_search_do (-3, -2, -1, 1, 2, 3, 4);
}

/*****************************************************************************/

#define BIN_SEARCH_W_DUPS_LEN    100
#define BIN_SEARCH_W_DUPS_JITTER 10

static int
_test_bin_search2_cmp (gconstpointer pa,
                       gconstpointer pb,
                       gpointer user_data)
{
	int a = GPOINTER_TO_INT (pa);
	int b = GPOINTER_TO_INT (pb);

	g_assert (a >= 0 && a <= BIN_SEARCH_W_DUPS_LEN + BIN_SEARCH_W_DUPS_JITTER);
	g_assert (b >= 0 && b <= BIN_SEARCH_W_DUPS_LEN + BIN_SEARCH_W_DUPS_JITTER);
	NM_CMP_DIRECT (a, b);
	return 0;
}

static int
_test_bin_search2_cmp_p (gconstpointer pa,
                         gconstpointer pb,
                         gpointer user_data)
{
	return _test_bin_search2_cmp (*((gpointer *) pa), *((gpointer *) pb), NULL);
}

static void
test_nm_utils_ptrarray_find_binary_search_with_duplicates (void)
{
	gssize idx, idx2, idx_first2, idx_first, idx_last;
	int i_test, i_len, i;
	gssize j;
	gconstpointer arr[BIN_SEARCH_W_DUPS_LEN];
	const int N_TEST = 10;

	for (i_test = 0; i_test < N_TEST; i_test++) {
		for (i_len = 0; i_len < BIN_SEARCH_W_DUPS_LEN; i_len++) {

			/* fill with random numbers... surely there are some duplicates
			 * there... or maybe even there are none... */
			for (i = 0; i < i_len; i++)
				arr[i] = GINT_TO_POINTER (nmtst_get_rand_int () % (i_len + BIN_SEARCH_W_DUPS_JITTER));
			g_qsort_with_data (arr,
			                   i_len,
			                   sizeof (gpointer),
			                   _test_bin_search2_cmp_p,
			                   NULL);
			for (i = 0; i < i_len + BIN_SEARCH_W_DUPS_JITTER; i++) {
				gconstpointer p = GINT_TO_POINTER (i);

				idx = _nm_utils_ptrarray_find_binary_search (arr, i_len, p, _test_bin_search2_cmp, NULL, &idx_first, &idx_last);

				idx_first2 = _nm_utils_ptrarray_find_first (arr, i_len, p);

				idx2 = _nm_utils_array_find_binary_search (arr, sizeof (gpointer), i_len, &p, _test_bin_search2_cmp_p, NULL);
				g_assert_cmpint (idx, ==, idx2);

				if (idx_first2 < 0) {
					g_assert_cmpint (idx, <, 0);
					g_assert_cmpint (idx, ==, idx_first);
					g_assert_cmpint (idx, ==, idx_last);
					idx = ~idx;
					g_assert_cmpint (idx, >=, 0);
					g_assert_cmpint (idx, <=, i_len);
					if (i_len == 0)
						g_assert_cmpint (idx, ==, 0);
					else {
						g_assert (idx == i_len || GPOINTER_TO_INT (arr[idx]) > i);
						g_assert (idx == 0     || GPOINTER_TO_INT (arr[idx - 1]) < i);
					}
				} else {
					g_assert_cmpint (idx_first, ==, idx_first2);
					g_assert_cmpint (idx_first, >=, 0);
					g_assert_cmpint (idx_last, <, i_len);
					g_assert_cmpint (idx_first, <=, idx_last);
					g_assert_cmpint (idx, >=, idx_first);
					g_assert_cmpint (idx, <=, idx_last);
					for (j = idx_first; j < idx_last; j++)
						g_assert (GPOINTER_TO_INT (arr[j]) == i);
					g_assert (idx_first == 0 || GPOINTER_TO_INT (arr[idx_first - 1]) < i);
					g_assert (idx_last == i_len - 1 || GPOINTER_TO_INT (arr[idx_last + 1]) > i);
				}
			}
		}
	}
}

/*****************************************************************************/

static void
_test_nm_utils_enum_to_str_do_full (GType type,
                                    int flags,
                                    const char *exp_str,
                                    const NMUtilsEnumValueInfo *value_infos)
{
	gs_free char *str = NULL;
	int flags2;
	gs_free char *err_token = NULL;
	gboolean result;

	g_assert (exp_str);

	str = _nm_utils_enum_to_str_full (type, flags, ", ", value_infos);
	g_assert_cmpstr (str, ==, exp_str);

	if (!value_infos) {
		gs_free char *str2 = NULL;

		str2 = nm_utils_enum_to_str (type, flags);
		g_assert_cmpstr (str2, ==, exp_str);
	}

	result = _nm_utils_enum_from_str_full (type, str, &flags2, &err_token, value_infos);
	g_assert (result == TRUE);
	g_assert_cmpint (flags2, ==, flags);
	g_assert_cmpstr (err_token, ==, NULL);
}

#define _test_nm_utils_enum_to_str_do(...) _test_nm_utils_enum_to_str_do_full (__VA_ARGS__, NULL)

static void
_test_nm_utils_enum_from_str_do_full (GType type,
                                     const char *str,
                                     gboolean exp_result,
                                     int exp_flags,
                                     const char *exp_err_token,
                                     const NMUtilsEnumValueInfo *value_infos)
{
	int flags;
	gs_free char *err_token = NULL;
	gboolean result;

	result = _nm_utils_enum_from_str_full (type, str, &flags, &err_token, value_infos);

	g_assert (result == exp_result);
	g_assert_cmpint (flags, ==, exp_flags);
	g_assert_cmpstr (err_token, ==, exp_err_token);

	if (!value_infos) {
		int flags2;
		gs_free char *err_token2 = NULL;
		gboolean result2;

		result2 = nm_utils_enum_from_str (type, str, &flags2, &err_token2);
		g_assert (result2 == exp_result);
		g_assert_cmpint (flags2, ==, exp_flags);
		g_assert_cmpstr (err_token2, ==, exp_err_token);
	}

	if (result) {
		int flags2;
		gs_free char *str2 = NULL;
		gs_free char *err_token2 = NULL;

		str2 = _nm_utils_enum_to_str_full (type, flags, ", ", value_infos);
		g_assert (str2);

		result = _nm_utils_enum_from_str_full (type, str2, &flags2, &err_token2, value_infos);
		g_assert (result == TRUE);
		g_assert_cmpint (flags2, ==, flags);
		g_assert_cmpstr (err_token, ==, NULL);
	}
}

#define _test_nm_utils_enum_from_str_do(...) _test_nm_utils_enum_from_str_do_full(__VA_ARGS__, NULL)

static void
_test_nm_utils_enum_get_values_do (GType type, int from, int to, const char *exp_str)
{
	gs_free const char **strv = NULL;
	gs_free char *str = NULL;

	g_assert (exp_str);

	strv = nm_utils_enum_get_values (type, from, to);
	g_assert (strv);
	str = g_strjoinv (",", (char **) strv);
	g_assert_cmpstr (str, ==, exp_str);
}

static void
test_nm_utils_enum (void)
{
	GType bool_enum = nm_test_general_bool_enum_get_type();
	GType meta_flags = nm_test_general_meta_flags_get_type();
	GType color_flags = nm_test_general_color_flags_get_type();
	static const NMUtilsEnumValueInfo color_value_infos[] = {
		{
			.nick = "nick-4d",
			.value = 0x4D,
		},
		{
			.nick = "nick-5",
			.value = 5,
		},
		{
			.nick = "nick-red",
			.value = NM_TEST_GENERAL_COLOR_FLAGS_RED,
		},
		{ 0 },
	};

	_test_nm_utils_enum_to_str_do (bool_enum, NM_TEST_GENERAL_BOOL_ENUM_YES, "yes");
	_test_nm_utils_enum_to_str_do (bool_enum, NM_TEST_GENERAL_BOOL_ENUM_UNKNOWN, "unknown");
	_test_nm_utils_enum_to_str_do (bool_enum, NM_TEST_GENERAL_BOOL_ENUM_INVALID, "4");
	_test_nm_utils_enum_to_str_do (bool_enum, NM_TEST_GENERAL_BOOL_ENUM_67, "67");
	_test_nm_utils_enum_to_str_do (bool_enum, NM_TEST_GENERAL_BOOL_ENUM_46, "64");

	_test_nm_utils_enum_to_str_do (meta_flags, NM_TEST_GENERAL_META_FLAGS_NONE, "none");
	_test_nm_utils_enum_to_str_do (meta_flags, NM_TEST_GENERAL_META_FLAGS_BAZ, "baz");
	_test_nm_utils_enum_to_str_do (meta_flags, NM_TEST_GENERAL_META_FLAGS_FOO |
	                                           NM_TEST_GENERAL_META_FLAGS_BAR |
	                                           NM_TEST_GENERAL_META_FLAGS_BAZ, "foo, bar, baz");
	_test_nm_utils_enum_to_str_do (meta_flags, 0xFF, "foo, bar, baz, 0xf8");
	_test_nm_utils_enum_to_str_do (meta_flags, NM_TEST_GENERAL_META_FLAGS_0x8, "0x8");
	_test_nm_utils_enum_to_str_do (meta_flags, NM_TEST_GENERAL_META_FLAGS_0x4, "0x10");

	_test_nm_utils_enum_to_str_do (color_flags, NM_TEST_GENERAL_COLOR_FLAGS_RED, "red");
	_test_nm_utils_enum_to_str_do (color_flags, NM_TEST_GENERAL_COLOR_FLAGS_WHITE, "0x1");
	_test_nm_utils_enum_to_str_do (color_flags, NM_TEST_GENERAL_COLOR_FLAGS_RED |
	                                            NM_TEST_GENERAL_COLOR_FLAGS_GREEN, "red, green");

	_test_nm_utils_enum_to_str_do_full (color_flags,
	                                      NM_TEST_GENERAL_COLOR_FLAGS_RED
	                                    | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
	                                    "nick-red, green",
	                                    color_value_infos);

	_test_nm_utils_enum_to_str_do_full (color_flags,
	                                      0x4D
	                                    |  NM_TEST_GENERAL_COLOR_FLAGS_RED
	                                    | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
	                                    "nick-4d",
	                                    color_value_infos);

	_test_nm_utils_enum_to_str_do_full (color_flags,
	                                      5
	                                    | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
	                                    "nick-5, green",
	                                    color_value_infos);

	_test_nm_utils_enum_from_str_do (bool_enum, "", FALSE, 0, NULL);
	_test_nm_utils_enum_from_str_do (bool_enum, " ", FALSE, 0, NULL);
	_test_nm_utils_enum_from_str_do (bool_enum, "invalid", FALSE, 0, "invalid");
	_test_nm_utils_enum_from_str_do (bool_enum, "yes", TRUE, NM_TEST_GENERAL_BOOL_ENUM_YES, NULL);
	_test_nm_utils_enum_from_str_do (bool_enum, "no", TRUE, NM_TEST_GENERAL_BOOL_ENUM_NO, NULL);
	_test_nm_utils_enum_from_str_do (bool_enum, "yes,no", FALSE, 0, "yes,no");

	_test_nm_utils_enum_from_str_do (meta_flags, "", TRUE, 0, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, " ", TRUE, 0, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, "foo", TRUE, NM_TEST_GENERAL_META_FLAGS_FOO, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, "foo,baz", TRUE, NM_TEST_GENERAL_META_FLAGS_FOO |
	                                                              NM_TEST_GENERAL_META_FLAGS_BAZ, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, "foo, baz", TRUE, NM_TEST_GENERAL_META_FLAGS_FOO |
	                                                               NM_TEST_GENERAL_META_FLAGS_BAZ, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, "foo,,bar", TRUE, NM_TEST_GENERAL_META_FLAGS_FOO |
	                                                               NM_TEST_GENERAL_META_FLAGS_BAR, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, "foo,baz,quux,bar", FALSE, 0, "quux");
	_test_nm_utils_enum_from_str_do (meta_flags, "foo,0x6", TRUE, NM_TEST_GENERAL_META_FLAGS_FOO | 0x6, NULL);
	_test_nm_utils_enum_from_str_do (meta_flags, "0x30,0x08,foo", TRUE, 0x39, NULL);

	_test_nm_utils_enum_from_str_do (color_flags, "green", TRUE, NM_TEST_GENERAL_COLOR_FLAGS_GREEN, NULL);
	_test_nm_utils_enum_from_str_do (color_flags, "blue,red", TRUE, NM_TEST_GENERAL_COLOR_FLAGS_BLUE |
	                                                                NM_TEST_GENERAL_COLOR_FLAGS_RED, NULL);
	_test_nm_utils_enum_from_str_do (color_flags, "blue,white", FALSE, 0, "white");

	_test_nm_utils_enum_from_str_do_full (color_flags,
	                                      "nick-red",
	                                      TRUE,
	                                      NM_TEST_GENERAL_COLOR_FLAGS_RED,
	                                      NULL,
	                                      color_value_infos);

	_test_nm_utils_enum_from_str_do_full (color_flags,
	                                      "0x4D",
	                                      TRUE,
	                                      0x4D,
	                                      NULL,
	                                      color_value_infos);

	_test_nm_utils_enum_from_str_do_full (color_flags,
	                                      "green,nick-4d",
	                                      TRUE,
	                                        0x4D
	                                      | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
	                                      NULL,
	                                      color_value_infos);

	_test_nm_utils_enum_from_str_do_full (color_flags,
	                                      "nick-4d,nick-red,nick-5,green,nick-red",
	                                      TRUE,
	                                        0x4D
	                                      | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
	                                      NULL,
	                                      color_value_infos);

	_test_nm_utils_enum_get_values_do (bool_enum, 0, G_MAXINT, "no,yes,maybe,unknown,67,64");
	_test_nm_utils_enum_get_values_do (bool_enum, NM_TEST_GENERAL_BOOL_ENUM_YES,
	                                   NM_TEST_GENERAL_BOOL_ENUM_MAYBE, "yes,maybe");
	_test_nm_utils_enum_get_values_do (meta_flags, 0, G_MAXINT, "none,foo,bar,baz,0x8,0x10");
	_test_nm_utils_enum_get_values_do (color_flags, 0, G_MAXINT, "blue,red,green");
}

/*****************************************************************************/

static void
do_test_utils_str_utf8safe (const char *str, const char *expected, NMUtilsStrUtf8SafeFlags flags)
{
	const char *str_safe, *s;
	gs_free char *str2 = NULL;
	gs_free char *str3 = NULL;

	str_safe = nm_utils_str_utf8safe_escape (str, flags, &str2);

	str3 = nm_utils_str_utf8safe_escape_cp (str, flags);
	g_assert_cmpstr (str3, ==, str_safe);
	g_assert ((!str && !str3) || (str != str3));
	g_clear_pointer (&str3, g_free);

	if (expected == NULL) {
		g_assert (str_safe == str);
		g_assert (!str2);
		if (str) {
			g_assert (!strchr (str, '\\'));
			g_assert (g_utf8_validate (str, -1, NULL));
		}

		g_assert (str == nm_utils_str_utf8safe_unescape (str_safe, &str3));
		g_assert (!str3);

		str3 = nm_utils_str_utf8safe_unescape_cp (str_safe);
		if (str) {
			g_assert (str3 != str);
			g_assert_cmpstr (str3, ==, str);
		} else
			g_assert (!str3);
		g_clear_pointer (&str3, g_free);
		return;
	}

	g_assert (str);
	g_assert (str_safe != str);
	g_assert (str_safe == str2);
	g_assert (   strchr (str, '\\')
	          || !g_utf8_validate (str, -1, NULL)
	          || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII)
	              && NM_STRCHAR_ANY (str, ch, (guchar) ch >= 127))
	          || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL)
	              && NM_STRCHAR_ANY (str, ch, (guchar) ch < ' ')));
	g_assert (g_utf8_validate (str_safe, -1, NULL));

	str3 = g_strcompress (str_safe);
	g_assert_cmpstr (str, ==, str3);
	g_clear_pointer (&str3, g_free);

	str3 = nm_utils_str_utf8safe_unescape_cp (str_safe);
	g_assert (str3 != str);
	g_assert_cmpstr (str3, ==, str);
	g_clear_pointer (&str3, g_free);

	s = nm_utils_str_utf8safe_unescape (str_safe, &str3);
	g_assert (str3 != str);
	g_assert (s == str3);
	g_assert_cmpstr (str3, ==, str);
	g_clear_pointer (&str3, g_free);

	g_assert_cmpstr (str_safe, ==, expected);
}

static void
test_utils_str_utf8safe (void)
{
	do_test_utils_str_utf8safe (NULL, NULL,                                       NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("", NULL,                                         NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\314", "\\314",                                  NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\314\315x\315\315x", "\\314\\315x\\315\\315x",   NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\314\315xx", "\\314\\315xx",                     NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\314xx", "\\314xx",                              NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\xa0", "\\240",                                  NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\xe2\x91\xa0", NULL,                             NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\xe2\xe2\x91\xa0", "\\342\xe2\x91\xa0",          NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("\xe2\xe2\x91\xa0\xa0", "\\342\xe2\x91\xa0\\240", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("a", NULL,                                        NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("ab", NULL,                                       NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("ab\314", "ab\\314",                              NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("ab\314adsf", "ab\\314adsf",                      NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("abadsf", NULL,                                   NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("abäb", NULL,                                     NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("x\xa0", "x\\240",                                NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("Ä\304ab\\äb", "Ä\\304ab\\\\äb",                  NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("Äab\\äb", "Äab\\\\äb",                           NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("ÄÄab\\äb", "ÄÄab\\\\äb",                         NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("㈞abä㈞b", NULL,                                 NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
	do_test_utils_str_utf8safe ("abäb", "ab\\303\\244b",                          NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII);
	do_test_utils_str_utf8safe ("ab\ab", "ab\\007b",                              NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL);
}

/*****************************************************************************/

static int
_test_nm_in_set_get (int *call_counter, gboolean allow_called, int value)
{
	g_assert (call_counter);
	*call_counter += 1;
	if (!allow_called)
		g_assert_not_reached ();
	return value;
}

static void
_test_nm_in_set_assert (int *call_counter, int expected)
{
	g_assert (call_counter);
	g_assert_cmpint (expected, ==, *call_counter);
	*call_counter = 0;
}

static void
test_nm_in_set (void)
{
	int call_counter = 0;

#define G(x) _test_nm_in_set_get (&call_counter, TRUE,  x)
#define N(x) _test_nm_in_set_get (&call_counter, FALSE,  x)
#define _ASSERT(expected, expr) \
	G_STMT_START { \
		_test_nm_in_set_assert (&call_counter, 0); \
		g_assert (expr); \
		_test_nm_in_set_assert (&call_counter, (expected)); \
	} G_STMT_END
	_ASSERT (1, !NM_IN_SET (-1, G( 1)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1)));

	_ASSERT (2, !NM_IN_SET (-1, G( 1), G( 2)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N( 2)));
	_ASSERT (2,  NM_IN_SET (-1, G( 1), G(-1)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N(-1)));

	_ASSERT (3, !NM_IN_SET (-1, G( 1), G( 2), G( 3)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N( 2), N( 3)));
	_ASSERT (2,  NM_IN_SET (-1, G( 1), G(-1), N( 3)));
	_ASSERT (3,  NM_IN_SET (-1, G( 1), G( 2), G(-1)));
	_ASSERT (2,  NM_IN_SET (-1, G( 1), G(-1), N(-1)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N( 2), N(-1)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N(-1), N( 3)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N(-1), N(-1)));

	_ASSERT (4, !NM_IN_SET (-1, G( 1), G( 2), G( 3), G( 4)));
	_ASSERT (1,  NM_IN_SET (-1, G(-1), N( 2), N( 3), N( 4)));
	_ASSERT (2,  NM_IN_SET (-1, G( 1), G(-1), N( 3), N( 4)));
	_ASSERT (3,  NM_IN_SET (-1, G( 1), G( 2), G(-1), N( 4)));
	_ASSERT (4,  NM_IN_SET (-1, G( 1), G( 2), G( 3), G(-1)));

	_ASSERT (4,  NM_IN_SET (-1, G( 1), G( 2), G( 3), G(-1), G( 5)));
	_ASSERT (5,  NM_IN_SET (-1, G( 1), G( 2), G( 3), G( 4), G(-1)));
	_ASSERT (6,  NM_IN_SET (-1, G( 1), G( 2), G( 3), G( 4), G( 5), G( -1)));

	_ASSERT (1, !NM_IN_SET_SE (-1, G( 1)));
	_ASSERT (1,  NM_IN_SET_SE (-1, G(-1)));

	_ASSERT (2, !NM_IN_SET_SE (-1, G( 1), G( 2)));
	_ASSERT (2,  NM_IN_SET_SE (-1, G(-1), G( 2)));
	_ASSERT (2,  NM_IN_SET_SE (-1, G( 1), G(-1)));
	_ASSERT (2,  NM_IN_SET_SE (-1, G(-1), G(-1)));

	_ASSERT (3, !NM_IN_SET_SE (-1, G( 1), G( 2), G( 3)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G(-1), G( 2), G( 3)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G( 1), G(-1), G( 3)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G( 1), G( 2), G(-1)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G( 1), G(-1), G(-1)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G(-1), G( 2), G(-1)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G(-1), G(-1), G( 3)));
	_ASSERT (3,  NM_IN_SET_SE (-1, G(-1), G(-1), G(-1)));

	_ASSERT (4, !NM_IN_SET_SE (-1, G( 1), G( 2), G( 3), G( 4)));
	_ASSERT (4,  NM_IN_SET_SE (-1, G(-1), G( 2), G( 3), G( 4)));
	_ASSERT (4,  NM_IN_SET_SE (-1, G( 1), G(-1), G( 3), G( 4)));
	_ASSERT (4,  NM_IN_SET_SE (-1, G( 1), G( 2), G(-1), G( 4)));
	_ASSERT (4,  NM_IN_SET_SE (-1, G( 1), G( 2), G( 3), G(-1)));

	_ASSERT (5,  NM_IN_SET_SE (-1, G( 1), G( 2), G( 3), G(-1), G( 5)));
	_ASSERT (6,  NM_IN_SET_SE (-1, G( 1), G( 2), G( 3), G( 4), G( 5), G(-1)));

	(void) NM_IN_SET ("a",  "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16");
#undef G
#undef N
#undef _ASSERT
}

/*****************************************************************************/

static const char *
_test_nm_in_set_getstr (int *call_counter, gboolean allow_called, const char *value)
{
	g_assert (call_counter);
	*call_counter += 1;
	if (!allow_called)
		g_assert_not_reached ();
	return value;
}

static void
test_nm_in_strset (void)
{
	int call_counter = 0;

#define G(x) _test_nm_in_set_getstr (&call_counter, TRUE,  x)
#define N(x) _test_nm_in_set_getstr (&call_counter, FALSE,  x)
#define _ASSERT(expected, expr) \
	G_STMT_START { \
		_test_nm_in_set_assert (&call_counter, 0); \
		g_assert (expr); \
		_test_nm_in_set_assert (&call_counter, (expected)); \
	} G_STMT_END
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL)));
	_ASSERT (1, !NM_IN_STRSET ("a",  G(NULL)));
	_ASSERT (1, !NM_IN_STRSET (NULL, G("a")));

	_ASSERT (1,  NM_IN_STRSET_SE (NULL, G(NULL)));
	_ASSERT (1, !NM_IN_STRSET_SE ("a",  G(NULL)));
	_ASSERT (1, !NM_IN_STRSET_SE (NULL, G("a")));

	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N(NULL)));
	_ASSERT (2, !NM_IN_STRSET ("a",  G(NULL), G(NULL)));
	_ASSERT (2,  NM_IN_STRSET (NULL, G("a"),  G(NULL)));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("a")));
	_ASSERT (2,  NM_IN_STRSET ("a",  G(NULL), G("a")));
	_ASSERT (2, !NM_IN_STRSET (NULL, G("a"),  G("a")));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("b")));
	_ASSERT (2, !NM_IN_STRSET ("a",  G(NULL), G("b")));
	_ASSERT (2, !NM_IN_STRSET (NULL, G("a"),  G("b")));

	_ASSERT (2,  NM_IN_STRSET_SE (NULL, G(NULL), G(NULL)));
	_ASSERT (2, !NM_IN_STRSET_SE ("a",  G(NULL), G(NULL)));
	_ASSERT (2,  NM_IN_STRSET_SE (NULL, G("a"),  G(NULL)));
	_ASSERT (2,  NM_IN_STRSET_SE (NULL, G(NULL), G("a")));
	_ASSERT (2,  NM_IN_STRSET_SE ("a",  G(NULL), G("a")));
	_ASSERT (2, !NM_IN_STRSET_SE (NULL, G("a"),  G("a")));
	_ASSERT (2,  NM_IN_STRSET_SE (NULL, G(NULL), G("b")));
	_ASSERT (2, !NM_IN_STRSET_SE ("a",  G(NULL), G("b")));
	_ASSERT (2, !NM_IN_STRSET_SE (NULL, G("a"),  G("b")));

	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N(NULL), N(NULL)));
	_ASSERT (3, !NM_IN_STRSET ("a",  G(NULL), G(NULL), G(NULL)));
	_ASSERT (2,  NM_IN_STRSET (NULL, G("a"),  G(NULL), N(NULL)));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("a"),  N(NULL)));
	_ASSERT (2,  NM_IN_STRSET ("a",  G(NULL), G("a"),  N(NULL)));
	_ASSERT (3,  NM_IN_STRSET (NULL, G("a"),  G("a"),  G(NULL)));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("b"),  N(NULL)));
	_ASSERT (3, !NM_IN_STRSET ("a",  G(NULL), G("b"),  G(NULL)));
	_ASSERT (3,  NM_IN_STRSET (NULL, G("a"),  G("b"),  G(NULL)));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N(NULL), N("a")));
	_ASSERT (3,  NM_IN_STRSET ("a",  G(NULL), G(NULL), G("a")));
	_ASSERT (2,  NM_IN_STRSET (NULL, G("a"),  G(NULL), N("a")));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("a"),  N("a")));
	_ASSERT (2,  NM_IN_STRSET ("a",  G(NULL), G("a"),  N("a")));
	_ASSERT (3, !NM_IN_STRSET (NULL, G("a"),  G("a"),  G("a")));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("b"),  N("a")));
	_ASSERT (3,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("a")));
	_ASSERT (3, !NM_IN_STRSET (NULL, G("a"),  G("b"),  G("a")));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N(NULL), N("b")));
	_ASSERT (3, !NM_IN_STRSET ("a",  G(NULL), G(NULL), G("b")));
	_ASSERT (2,  NM_IN_STRSET (NULL, G("a"),  G(NULL), N("b")));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("a"),  N("b")));
	_ASSERT (2,  NM_IN_STRSET ("a",  G(NULL), G("a"),  N("b")));
	_ASSERT (3, !NM_IN_STRSET (NULL, G("a"),  G("a"),  G("b")));
	_ASSERT (1,  NM_IN_STRSET (NULL, G(NULL), N("b"),  N("b")));
	_ASSERT (3, !NM_IN_STRSET ("a",  G(NULL), G("b"),  G("b")));
	_ASSERT (3, !NM_IN_STRSET (NULL, G("a"),  G("b"),  G("b")));

	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G(NULL), G(NULL)));
	_ASSERT (3, !NM_IN_STRSET_SE ("a",  G(NULL), G(NULL), G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G("a"),  G(NULL), G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G("a"),  G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE ("a",  G(NULL), G("a"),  G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G("a"),  G("a"),  G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G("b"),  G(NULL)));
	_ASSERT (3, !NM_IN_STRSET_SE ("a",  G(NULL), G("b"),  G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G("a"),  G("b"),  G(NULL)));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G(NULL), G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE ("a",  G(NULL), G(NULL), G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G("a"),  G(NULL), G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G("a"),  G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE ("a",  G(NULL), G("a"),  G("a")));
	_ASSERT (3, !NM_IN_STRSET_SE (NULL, G("a"),  G("a"),  G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G("b"),  G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE ("a",  G(NULL), G("b"),  G("a")));
	_ASSERT (3, !NM_IN_STRSET_SE (NULL, G("a"),  G("b"),  G("a")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G(NULL), G("b")));
	_ASSERT (3, !NM_IN_STRSET_SE ("a",  G(NULL), G(NULL), G("b")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G("a"),  G(NULL), G("b")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G("a"),  G("b")));
	_ASSERT (3,  NM_IN_STRSET_SE ("a",  G(NULL), G("a"),  G("b")));
	_ASSERT (3, !NM_IN_STRSET_SE (NULL, G("a"),  G("a"),  G("b")));
	_ASSERT (3,  NM_IN_STRSET_SE (NULL, G(NULL), G("b"),  G("b")));
	_ASSERT (3, !NM_IN_STRSET_SE ("a",  G(NULL), G("b"),  G("b")));
	_ASSERT (3, !NM_IN_STRSET_SE (NULL, G("a"),  G("b"),  G("b")));

	_ASSERT (3,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("a"),  N("a")));
	_ASSERT (4,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("a")));
	_ASSERT (4, !NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("d")));

	_ASSERT (4,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("a"),  N("a")));
	_ASSERT (5,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("d"),  G("a")));
	_ASSERT (5, !NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("d"),  G("e")));

	_ASSERT (5,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("d"),  G("a"),  N("a")));
	_ASSERT (6,  NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("d"),  G("e"),  G("a")));
	_ASSERT (6, !NM_IN_STRSET ("a",  G(NULL), G("b"),  G("c"),  G("d"),  G("e"),  G("f")));

	(void) NM_IN_STRSET ("a",  "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16");
#undef G
#undef N
#undef _ASSERT
}

static void
test_route_attributes_parse (void)
{
	GHashTable *ht;
	GError *error = NULL;
	GVariant *variant;

	ht = nm_utils_parse_variant_attributes ("mtu=1400  src=1.2.3.4 cwnd=14",
	                                        ' ', '=', FALSE,
	                                        nm_ip_route_get_variant_attribute_spec (),
	                                        &error);
	g_assert_no_error (error);
	g_assert (ht);
	g_hash_table_unref (ht);

	ht = nm_utils_parse_variant_attributes ("mtu=1400 src=1.2.3.4 cwnd=14 \\",
	                                         ' ', '=', FALSE,
	                                         nm_ip_route_get_variant_attribute_spec (),
	                                         &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED);
	g_assert (!ht);
	g_clear_error (&error);

	ht = nm_utils_parse_variant_attributes ("mtu.1400 src.1\\.2\\.3\\.4 ",
	                                         ' ', '.', FALSE,
	                                         nm_ip_route_get_variant_attribute_spec (),
	                                         &error);
	g_assert (ht);
	g_assert_no_error (error);
	variant = g_hash_table_lookup (ht, NM_IP_ROUTE_ATTRIBUTE_MTU);
	g_assert (variant);
	g_assert (g_variant_is_of_type (variant, G_VARIANT_TYPE_UINT32));
	g_assert_cmpuint (g_variant_get_uint32 (variant), ==, 1400);

	variant = g_hash_table_lookup (ht, NM_IP_ROUTE_ATTRIBUTE_SRC);
	g_assert (variant);
	g_assert (g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (variant, NULL), ==, "1.2.3.4");
	g_hash_table_unref (ht);

	ht = nm_utils_parse_variant_attributes ("from:fd01\\:\\:42\\/64/initrwnd:21",
	                                         '/', ':', FALSE,
	                                         nm_ip_route_get_variant_attribute_spec (),
	                                         &error);
	g_assert (ht);
	g_assert_no_error (error);
	variant = g_hash_table_lookup (ht, NM_IP_ROUTE_ATTRIBUTE_INITRWND);
	g_assert (variant);
	g_assert (g_variant_is_of_type (variant, G_VARIANT_TYPE_UINT32));
	g_assert_cmpuint (g_variant_get_uint32 (variant), ==, 21);

	variant = g_hash_table_lookup (ht, NM_IP_ROUTE_ATTRIBUTE_FROM);
	g_assert (variant);
	g_assert (g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (variant, NULL), ==, "fd01::42/64");
	g_hash_table_unref (ht);
}

static void
test_route_attributes_format (void)
{
	gs_unref_hashtable GHashTable *ht = NULL;
	char *str;

	ht = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                            NULL, (GDestroyNotify) g_variant_unref);

	str = nm_utils_format_variant_attributes (NULL, ' ', '=');
	g_assert_cmpstr (str, ==, NULL);

	str = nm_utils_format_variant_attributes (ht, ' ', '=');
	g_assert_cmpstr (str, ==, NULL);

	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_MTU, g_variant_new_uint32 (5000));
	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_INITRWND, g_variant_new_uint32 (20));
	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_LOCK_MTU, g_variant_new_boolean (TRUE));
	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_SRC, g_variant_new_string ("aaaa:bbbb::1"));
	str = nm_utils_format_variant_attributes (ht, ' ', '=');
	g_assert_cmpstr (str, ==, "initrwnd=20 lock-mtu=true mtu=5000 src=aaaa:bbbb::1");
	g_hash_table_remove_all (ht);
	g_free (str);

	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_WINDOW, g_variant_new_uint32 (30000));
	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_INITCWND, g_variant_new_uint32 (21));
	g_hash_table_insert (ht, NM_IP_ROUTE_ATTRIBUTE_FROM, g_variant_new_string ("aaaa:bbbb:cccc:dddd::/64"));
	str = nm_utils_format_variant_attributes (ht, '/', ':');
	g_assert_cmpstr (str, ==, "from:aaaa\\:bbbb\\:cccc\\:dddd\\:\\:\\/64/initcwnd:21/window:30000");
	g_hash_table_remove_all (ht);
	g_free (str);
}

/*****************************************************************************/

static gboolean
do_test_nm_set_out_called (gint *call_count)
{
	(*call_count)++;
	return TRUE;
}

static void
test_nm_set_out (void)
{
	gboolean val;
	gboolean *p_val;
	int call_count;

	/* NM_SET_OUT() has an unexpected non-function like behavior
	 * wrt. side-effects of the value argument. Test it */

	p_val = &val;
	call_count = 0;
	NM_SET_OUT (p_val, do_test_nm_set_out_called (&call_count));
	g_assert_cmpint (call_count, ==, 1);

	p_val = NULL;
	call_count = 0;
	NM_SET_OUT (p_val, do_test_nm_set_out_called (&call_count));
	g_assert_cmpint (call_count, ==, 0);

	/* test that we successfully re-defined _G_BOOLEAN_EXPR() */
#define _T1(a) \
	({ \
		g_assert (a > 2); \
		a; \
	})
	g_assert (_T1 (3) > 1);
#undef _T1
}

/*****************************************************************************/

static void
test_get_start_time_for_pid (void)
{
	guint64 x_start_time;
	char x_state;
	pid_t x_ppid;

	x_start_time = nm_utils_get_start_time_for_pid (getpid (), &x_state, &x_ppid);

	g_assert (x_start_time > 0);
	g_assert (x_ppid == getppid ());
	g_assert (!NM_IN_SET (x_state, '\0', ' '));
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/core/general/test_nm_hash", test_nm_hash);
	g_test_add_func ("/core/general/test_nm_g_slice_free_fcn", test_nm_g_slice_free_fcn);
	g_test_add_func ("/core/general/test_c_list_sort", test_c_list_sort);
	g_test_add_func ("/core/general/test_dedup_multi", test_dedup_multi);
	g_test_add_func ("/core/general/test_utils_str_utf8safe", test_utils_str_utf8safe);
	g_test_add_func ("/core/general/test_nm_utils_strsplit_set", test_nm_utils_strsplit_set);
	g_test_add_func ("/core/general/test_nm_in_set", test_nm_in_set);
	g_test_add_func ("/core/general/test_nm_in_strset", test_nm_in_strset);
	g_test_add_func ("/core/general/test_setting_vpn_items", test_setting_vpn_items);
	g_test_add_func ("/core/general/test_setting_vpn_update_secrets", test_setting_vpn_update_secrets);
	g_test_add_func ("/core/general/test_setting_vpn_modify_during_foreach", test_setting_vpn_modify_during_foreach);
	g_test_add_func ("/core/general/test_setting_ip4_config_labels", test_setting_ip4_config_labels);
	g_test_add_func ("/core/general/test_setting_ip4_config_address_data", test_setting_ip4_config_address_data);
	g_test_add_func ("/core/general/test_setting_ip_route_attributes", test_setting_ip_route_attributes);
	g_test_add_func ("/core/general/test_setting_gsm_apn_spaces", test_setting_gsm_apn_spaces);
	g_test_add_func ("/core/general/test_setting_gsm_apn_bad_chars", test_setting_gsm_apn_bad_chars);
	g_test_add_func ("/core/general/test_setting_gsm_apn_underscore", test_setting_gsm_apn_underscore);
	g_test_add_func ("/core/general/test_setting_gsm_without_number", test_setting_gsm_without_number);
	g_test_add_func ("/core/general/test_setting_gsm_sim_operator_id", test_setting_gsm_sim_operator_id);
	g_test_add_func ("/core/general/test_setting_to_dbus_all", test_setting_to_dbus_all);
	g_test_add_func ("/core/general/test_setting_to_dbus_no_secrets", test_setting_to_dbus_no_secrets);
	g_test_add_func ("/core/general/test_setting_to_dbus_only_secrets", test_setting_to_dbus_only_secrets);
	g_test_add_func ("/core/general/test_setting_to_dbus_transform", test_setting_to_dbus_transform);
	g_test_add_func ("/core/general/test_setting_to_dbus_enum", test_setting_to_dbus_enum);
	g_test_add_func ("/core/general/test_setting_compare_id", test_setting_compare_id);
	g_test_add_func ("/core/general/test_setting_compare_addresses", test_setting_compare_addresses);
	g_test_add_func ("/core/general/test_setting_compare_routes", test_setting_compare_routes);
	g_test_add_func ("/core/general/test_setting_compare_wired_cloned_mac_address", test_setting_compare_wired_cloned_mac_address);
	g_test_add_func ("/core/general/test_setting_compare_wirless_cloned_mac_address", test_setting_compare_wireless_cloned_mac_address);
	g_test_add_func ("/core/general/test_setting_compare_timestamp", test_setting_compare_timestamp);
#define ADD_FUNC(name, func, secret_flags, comp_flags, remove_secret) \
	g_test_add_data_func_full ("/core/general/" G_STRINGIFY (func) "_" name, \
	                           test_data_compare_secrets_new (secret_flags, comp_flags, remove_secret), \
	                           func, g_free)
	ADD_FUNC ("agent_owned", test_setting_compare_secrets, NM_SETTING_SECRET_FLAG_AGENT_OWNED, NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS, TRUE);
	ADD_FUNC ("not_saved", test_setting_compare_secrets, NM_SETTING_SECRET_FLAG_NOT_SAVED, NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS, TRUE);
	ADD_FUNC ("secrets", test_setting_compare_secrets, NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, TRUE);
	ADD_FUNC ("exact", test_setting_compare_secrets, NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_EXACT, FALSE);
	ADD_FUNC ("agent_owned", test_setting_compare_vpn_secrets, NM_SETTING_SECRET_FLAG_AGENT_OWNED, NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS, TRUE);
	ADD_FUNC ("not_saved", test_setting_compare_vpn_secrets, NM_SETTING_SECRET_FLAG_NOT_SAVED, NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS, TRUE);
	ADD_FUNC ("secrets", test_setting_compare_vpn_secrets, NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, TRUE);
	ADD_FUNC ("exact", test_setting_compare_vpn_secrets, NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_EXACT, FALSE);
	g_test_add_func ("/core/general/test_setting_old_uuid", test_setting_old_uuid);

	g_test_add_func ("/core/general/test_connection_to_dbus_setting_name", test_connection_to_dbus_setting_name);
	g_test_add_func ("/core/general/test_connection_to_dbus_deprecated_props", test_connection_to_dbus_deprecated_props);
	g_test_add_func ("/core/general/test_setting_new_from_dbus", test_setting_new_from_dbus);
	g_test_add_func ("/core/general/test_setting_new_from_dbus_transform", test_setting_new_from_dbus_transform);
	g_test_add_func ("/core/general/test_setting_new_from_dbus_enum", test_setting_new_from_dbus_enum);
	g_test_add_func ("/core/general/test_setting_new_from_dbus_bad", test_setting_new_from_dbus_bad);
	g_test_add_func ("/core/general/test_connection_replace_settings", test_connection_replace_settings);
	g_test_add_func ("/core/general/test_connection_replace_settings_from_connection", test_connection_replace_settings_from_connection);
	g_test_add_func ("/core/general/test_connection_replace_settings_bad", test_connection_replace_settings_bad);
	g_test_add_func ("/core/general/test_connection_new_from_dbus", test_connection_new_from_dbus);
	g_test_add_func ("/core/general/test_connection_normalize_virtual_iface_name", test_connection_normalize_virtual_iface_name);
	g_test_add_func ("/core/general/test_connection_normalize_uuid", test_connection_normalize_uuid);
	g_test_add_func ("/core/general/test_connection_normalize_type", test_connection_normalize_type);
	g_test_add_func ("/core/general/test_connection_normalize_slave_type_1", test_connection_normalize_slave_type_1);
	g_test_add_func ("/core/general/test_connection_normalize_slave_type_2", test_connection_normalize_slave_type_2);
	g_test_add_func ("/core/general/test_connection_normalize_infiniband_mtu", test_connection_normalize_infiniband_mtu);
	g_test_add_func ("/core/general/test_connection_normalize_gateway_never_default", test_connection_normalize_gateway_never_default);
	g_test_add_func ("/core/general/test_connection_normalize_may_fail", test_connection_normalize_may_fail);
	g_test_add_func ("/core/general/test_connection_normalize_shared_addresses", test_connection_normalize_shared_addresses);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/1", GUINT_TO_POINTER (1), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/2", GUINT_TO_POINTER (2), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/3", GUINT_TO_POINTER (3), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/4", GUINT_TO_POINTER (4), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/5", GUINT_TO_POINTER (5), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/6", GUINT_TO_POINTER (6), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_system/7", GUINT_TO_POINTER (7), test_connection_normalize_ovs_interface_type_system);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/1",  GUINT_TO_POINTER (1),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/2",  GUINT_TO_POINTER (2),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/3",  GUINT_TO_POINTER (3),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/4",  GUINT_TO_POINTER (4),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/5",  GUINT_TO_POINTER (5),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/6",  GUINT_TO_POINTER (6),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/7",  GUINT_TO_POINTER (7),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/8",  GUINT_TO_POINTER (8),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/9",  GUINT_TO_POINTER (9),  test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/10", GUINT_TO_POINTER (10), test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/11", GUINT_TO_POINTER (11), test_connection_normalize_ovs_interface_type_ovs_interface);
	g_test_add_data_func ("/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/12", GUINT_TO_POINTER (12), test_connection_normalize_ovs_interface_type_ovs_interface);

	g_test_add_func ("/core/general/test_setting_connection_permissions_helpers", test_setting_connection_permissions_helpers);
	g_test_add_func ("/core/general/test_setting_connection_permissions_property", test_setting_connection_permissions_property);

	g_test_add_func ("/core/general/test_connection_compare_same", test_connection_compare_same);
	g_test_add_func ("/core/general/test_connection_compare_key_only_in_a", test_connection_compare_key_only_in_a);
	g_test_add_func ("/core/general/test_connection_compare_setting_only_in_a", test_connection_compare_setting_only_in_a);
	g_test_add_func ("/core/general/test_connection_compare_key_only_in_b", test_connection_compare_key_only_in_b);
	g_test_add_func ("/core/general/test_connection_compare_setting_only_in_b", test_connection_compare_setting_only_in_b);

	g_test_add_func ("/core/general/test_connection_diff_a_only", test_connection_diff_a_only);
	g_test_add_func ("/core/general/test_connection_diff_same", test_connection_diff_same);
	g_test_add_func ("/core/general/test_connection_diff_different", test_connection_diff_different);
	g_test_add_func ("/core/general/test_connection_diff_no_secrets", test_connection_diff_no_secrets);
	g_test_add_func ("/core/general/test_connection_diff_inferrable", test_connection_diff_inferrable);
	g_test_add_func ("/core/general/test_connection_good_base_types", test_connection_good_base_types);
	g_test_add_func ("/core/general/test_connection_bad_base_types", test_connection_bad_base_types);

	g_test_add_func ("/core/general/test_hwaddr_aton_ether_normal", test_hwaddr_aton_ether_normal);
	g_test_add_func ("/core/general/test_hwaddr_aton_ib_normal", test_hwaddr_aton_ib_normal);
	g_test_add_func ("/core/general/test_hwaddr_aton_no_leading_zeros", test_hwaddr_aton_no_leading_zeros);
	g_test_add_func ("/core/general/test_hwaddr_aton_malformed", test_hwaddr_aton_malformed);
	g_test_add_func ("/core/general/test_hwaddr_equal", test_hwaddr_equal);
	g_test_add_func ("/core/general/test_hwaddr_canonical", test_hwaddr_canonical);

	g_test_add_func ("/core/general/test_ip4_prefix_to_netmask", test_ip4_prefix_to_netmask);
	g_test_add_func ("/core/general/test_ip4_netmask_to_prefix", test_ip4_netmask_to_prefix);

	g_test_add_func ("/core/general/test_connection_changed_signal", test_connection_changed_signal);
	g_test_add_func ("/core/general/test_setting_connection_changed_signal", test_setting_connection_changed_signal);
	g_test_add_func ("/core/general/test_setting_bond_changed_signal", test_setting_bond_changed_signal);
	g_test_add_func ("/core/general/test_setting_ip4_changed_signal", test_setting_ip4_changed_signal);
	g_test_add_func ("/core/general/test_setting_ip6_changed_signal", test_setting_ip6_changed_signal);
	g_test_add_func ("/core/general/test_setting_vlan_changed_signal", test_setting_vlan_changed_signal);
	g_test_add_func ("/core/general/test_setting_vpn_changed_signal", test_setting_vpn_changed_signal);
	g_test_add_func ("/core/general/test_setting_wired_changed_signal", test_setting_wired_changed_signal);
	g_test_add_func ("/core/general/test_setting_wireless_changed_signal", test_setting_wireless_changed_signal);
	g_test_add_func ("/core/general/test_setting_wireless_security_changed_signal", test_setting_wireless_security_changed_signal);
	g_test_add_func ("/core/general/test_setting_802_1x_changed_signal", test_setting_802_1x_changed_signal);
	g_test_add_func ("/core/general/test_setting_ip4_gateway", test_setting_ip4_gateway);
	g_test_add_func ("/core/general/test_setting_ip6_gateway", test_setting_ip6_gateway);
	g_test_add_func ("/core/general/test_setting_compare_default_strv", test_setting_compare_default_strv);
	g_test_add_func ("/core/general/test_setting_user_data", test_setting_user_data);

	g_test_add_func ("/core/general/hexstr2bin", test_hexstr2bin);
	g_test_add_func ("/core/general/nm_strquote", test_nm_strquote);
	g_test_add_func ("/core/general/test_nm_utils_uuid_generate_from_string", test_nm_utils_uuid_generate_from_string);
	g_test_add_func ("/core/general/_nm_utils_uuid_generate_from_strings", test_nm_utils_uuid_generate_from_strings);

	g_test_add_func ("/core/general/_nm_utils_ascii_str_to_int64", test_nm_utils_ascii_str_to_int64);
	g_test_add_func ("/core/general/nm_utils_is_power_of_two", test_nm_utils_is_power_of_two);
	g_test_add_func ("/core/general/_nm_utils_ptrarray_find_binary_search", test_nm_utils_ptrarray_find_binary_search);
	g_test_add_func ("/core/general/_nm_utils_ptrarray_find_binary_search_with_duplicates", test_nm_utils_ptrarray_find_binary_search_with_duplicates);
	g_test_add_func ("/core/general/_nm_utils_strstrdictkey", test_nm_utils_strstrdictkey);
	g_test_add_func ("/core/general/nm_ptrarray_len", test_nm_ptrarray_len);

	g_test_add_func ("/core/general/_nm_utils_dns_option_validate", test_nm_utils_dns_option_validate);
	g_test_add_func ("/core/general/_nm_utils_dns_option_find_idx", test_nm_utils_dns_option_find_idx);
	g_test_add_func ("/core/general/_nm_utils_validate_json", test_nm_utils_check_valid_json);
	g_test_add_func ("/core/general/_nm_utils_team_config_equal", test_nm_utils_team_config_equal);
	g_test_add_func ("/core/general/test_nm_utils_enum", test_nm_utils_enum);
	g_test_add_func ("/core/general/nm-set-out", test_nm_set_out);
	g_test_add_func ("/core/general/route_attributes/parse", test_route_attributes_parse);
	g_test_add_func ("/core/general/route_attributes/format", test_route_attributes_format);

	g_test_add_func ("/core/general/get_start_time_for_pid", test_get_start_time_for_pid);

	return g_test_run ();
}

