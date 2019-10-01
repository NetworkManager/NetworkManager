// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_C_LIST_H__
#define __NM_C_LIST_H__

#include "c-list/src/c-list.h"

/*****************************************************************************/

#define nm_c_list_contains_entry(list, what, member) \
	({ \
		typeof (what) _what = (what); \
		\
		_what && c_list_contains (list, &_what->member); \
	})

/*****************************************************************************/

typedef struct {
	CList lst;
	void *data;
} NMCListElem;

static inline NMCListElem *
nm_c_list_elem_new_stale (void *data)
{
	NMCListElem *elem;

	elem = g_slice_new (NMCListElem);
	elem->data = data;
	return elem;
}

static inline gboolean
nm_c_list_elem_free_full (NMCListElem *elem, GDestroyNotify free_fcn)
{
	if (!elem)
		return FALSE;
	c_list_unlink_stale (&elem->lst);
	if (free_fcn)
		free_fcn (elem->data);
	g_slice_free (NMCListElem, elem);
	return TRUE;
}

static inline gboolean
nm_c_list_elem_free (NMCListElem *elem)
{
	return nm_c_list_elem_free_full (elem, NULL);
}

static inline void *
nm_c_list_elem_free_steal (NMCListElem *elem)
{
	gpointer data;

	if (!elem)
		return NULL;
	data = elem->data;
	nm_c_list_elem_free_full (elem, NULL);
	return data;
}

static inline void
nm_c_list_elem_free_all (CList *head, GDestroyNotify free_fcn)
{
	NMCListElem *elem;

	while ((elem = c_list_first_entry (head, NMCListElem, lst)))
		nm_c_list_elem_free_full (elem, free_fcn);
}

#define nm_c_list_elem_find_first(head, arg, predicate) \
	({ \
		CList *const _head = (head); \
		NMCListElem *_result = NULL; \
		NMCListElem *_elem; \
		\
		c_list_for_each_entry (_elem, _head, lst) { \
			void *const arg = _elem->data; \
			\
			if (predicate) { \
				_result = _elem; \
				break; \
			} \
		} \
		_result; \
	})

/**
 * nm_c_list_elem_find_first_ptr:
 * @head: the @CList head of a list containing #NMCListElem elements.
 *   Note that the head is not itself part of the list.
 * @needle: the needle pointer.
 *
 * Iterates the list and returns the first #NMCListElem with the matching @needle,
 * using pointer equality.
 *
 * Returns: the found list element or %NULL if not found.
 */
static inline NMCListElem *
nm_c_list_elem_find_first_ptr (CList *head, gconstpointer needle)
{
	return nm_c_list_elem_find_first (head, x, x == needle);
}

/*****************************************************************************/

/**
 * nm_c_list_move_before:
 * @lst: the list element to which @elem will be prepended.
 * @elem: the list element to move.
 *
 * This unlinks @elem from the current list and linkes it before
 * @lst. This is like c_list_link_before(), except that @elem must
 * be initialized and linked. Note that @elem may be linked in @lst
 * or in another list. In both cases it gets moved.
 *
 * Returns: %TRUE if there were any changes. %FALSE if elem was already
 *   linked at the right place.
 */
static inline gboolean
nm_c_list_move_before (CList *lst, CList *elem)
{
	nm_assert (lst);
	nm_assert (elem);

	if (   lst != elem
	    && lst->prev != elem) {
		c_list_unlink_stale (elem);
		c_list_link_before (lst, elem);
		return TRUE;
	}
	return FALSE;
}
#define nm_c_list_move_tail(lst, elem) nm_c_list_move_before (lst, elem)

/**
 * nm_c_list_move_after:
 * @lst: the list element to which @elem will be prepended.
 * @elem: the list element to move.
 *
 * This unlinks @elem from the current list and linkes it after
 * @lst. This is like c_list_link_after(), except that @elem must
 * be initialized and linked. Note that @elem may be linked in @lst
 * or in another list. In both cases it gets moved.
 *
 * Returns: %TRUE if there were any changes. %FALSE if elem was already
 *   linked at the right place.
 */
static inline gboolean
nm_c_list_move_after (CList *lst, CList *elem)
{
	nm_assert (lst);
	nm_assert (elem);

	if (   lst != elem
	    && lst->next != elem) {
		c_list_unlink_stale (elem);
		c_list_link_after (lst, elem);
		return TRUE;
	}
	return FALSE;
}
#define nm_c_list_move_front(lst, elem) nm_c_list_move_after (lst, elem)

#define nm_c_list_free_all(lst, type, member, destroy_fcn) \
	G_STMT_START { \
		CList *const _lst = (lst); \
		type *_elem; \
		\
		while ((_elem = c_list_first_entry (_lst, type, member))) { \
			destroy_fcn (_elem); \
		} \
	} G_STMT_END

#endif /* __NM_C_LIST_H__ */
