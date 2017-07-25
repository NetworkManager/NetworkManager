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

#include "c-list-util.h"

/*****************************************************************************/

/**
 * c_list_relink:
 * @lst: the head list entry
 *
 * Takes an invalid list, that has undefined prev pointers.
 * Only the next pointers are valid, and the tail's next
 * pointer points to %NULL instead of the head.
 *
 * c_list_relink() fixes the list by updating all prev pointers
 * and close the circular linking by pointing the tails' next
 * pointer to @lst.
 *
 * The use of this function is to do a bulk update, that lets the
 * list degredate by not updating the prev pointers. At the end,
 * the list can be fixed by c_list_relink().
 */
void
c_list_relink (CList *lst)
{
	CList *ls, *ls_prev;

	ls_prev = lst;
	ls = lst->next;
	do {
		ls->prev = ls_prev;
		ls_prev = ls;
		ls = ls->next;
	} while (ls);
	ls_prev->next = lst;
	lst->prev = ls_prev;
}

/*****************************************************************************/

static CList *
_c_list_sort (CList *ls,
              CListSortCmp cmp,
              const void *user_data)
{
	CList *ls1, *ls2;
	CList head;

	if (!ls->next)
		return ls;

	/* split list in two halfs @ls1 and @ls2. */
	ls1 = ls;
	ls2 = ls;
	ls = ls->next;
	while (ls) {
		ls = ls->next;
		if (!ls)
			break;
		ls = ls->next;
		ls2 = ls2->next;
	}
	ls = ls2;
	ls2 = ls->next;
	ls->next = NULL;

	/* recurse */
	ls1 = _c_list_sort (ls1, cmp, user_data);
	if (!ls2)
		return ls1;

	ls2 = _c_list_sort (ls2, cmp, user_data);

	/* merge */
	ls = &head;
	for (;;) {
		/* while invoking the @cmp function, the list
		 * elements are not properly linked. Don't try to access
		 * their next/prev pointers. */
		if (cmp (ls1, ls2, user_data) <= 0) {
			ls->next = ls1;
			ls = ls1;
			ls1 = ls1->next;
			if (!ls1)
				break;
		} else {
			ls->next = ls2;
			ls = ls2;
			ls2 = ls2->next;
			if (!ls2)
				break;
		}
	}
	ls->next = ls1 ?: ls2;

	return head.next;
}

/**
 * c_list_sort_headless:
 * @lst: the list.
 * @cmp: compare function for sorting. While comparing two
 *   CList elements, their next/prev pointers are in undefined
 *   state.
 * @user_data: user data for @cmp.
 *
 * Sorts the list @lst according to @cmp. Contrary to
 * c_list_sort(), @lst is not the list head but a
 * valid entry as well. This function returns the new
 * list head.
 */
CList *
c_list_sort_headless (CList *lst,
                      CListSortCmp cmp,
                      const void *user_data)
{
	if (!c_list_is_empty (lst)) {
		lst->prev->next = NULL;
		lst = _c_list_sort (lst, cmp, user_data);
		c_list_relink (lst);
	}
	return lst;
}

/**
 * c_list_sort:
 * @head: the list head.
 * @cmp: compare function for sorting. While comparing two
 *   CList elements, their next/prev pointers are in undefined
 *   state.
 * @user_data: user data for @cmp.
 *
 * Sorts the list @head according to @cmp.
 */
void
c_list_sort (CList *head,
             CListSortCmp cmp,
             const void *user_data)
{
	if (   !c_list_is_empty (head)
	    && head->next->next != head) {
		head->prev->next = NULL;
		head->next = _c_list_sort (head->next, cmp, user_data);
		c_list_relink (head);
	}
}
