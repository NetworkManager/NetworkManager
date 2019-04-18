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
 * (C) Copyright 2014 Red Hat, Inc.
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

static inline void *
nm_c_list_elem_get (CList *lst)
{
	if (!lst)
		return NULL;
	return c_list_entry (lst, NMCListElem, lst)->data;
}

static inline void
nm_c_list_elem_free (NMCListElem *elem)
{
	if (elem) {
		c_list_unlink_stale (&elem->lst);
		g_slice_free (NMCListElem, elem);
	}
}

static inline void
nm_c_list_elem_free_all (CList *head, GDestroyNotify free_fcn)
{
	NMCListElem *elem;

	while ((elem = c_list_first_entry (head, NMCListElem, lst))) {
		if (free_fcn)
			free_fcn (elem->data);
		c_list_unlink_stale (&elem->lst);
		g_slice_free (NMCListElem, elem);
	}
}

/*****************************************************************************/

static inline gboolean
nm_c_list_move_before (CList *lst, CList *elem)
{
	nm_assert (lst);
	nm_assert (elem);
	nm_assert (c_list_contains (lst, elem));

	if (   lst != elem
	    && lst->prev != elem) {
		c_list_unlink_stale (elem);
		c_list_link_before (lst, elem);
		return TRUE;
	}
	return FALSE;
}
#define nm_c_list_move_tail(lst, elem) nm_c_list_move_before (lst, elem)

static inline gboolean
nm_c_list_move_after (CList *lst, CList *elem)
{
	nm_assert (lst);
	nm_assert (elem);
	nm_assert (c_list_contains (lst, elem));

	if (   lst != elem
	    && lst->next != elem) {
		c_list_unlink_stale (elem);
		c_list_link_after (lst, elem);
		return TRUE;
	}
	return FALSE;
}
#define nm_c_list_move_front(lst, elem) nm_c_list_move_after (lst, elem)

#endif /* __NM_C_LIST_H__ */
