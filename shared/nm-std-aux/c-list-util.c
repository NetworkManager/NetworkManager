// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
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
_c_list_srt_split (CList *ls)
{
	CList *ls2;

	ls2 = ls;
	ls = ls->next;
	if (!ls)
		return NULL;
	do {
		ls = ls->next;
		if (!ls)
			break;
		ls = ls->next;
		ls2 = ls2->next;
	} while (ls);
	ls = ls2->next;
	ls2->next = NULL;
	return ls;
}

static CList *
_c_list_srt_merge (CList *ls1,
                   CList *ls2,
                   CListSortCmp cmp,
                   const void *user_data)
{
	CList *ls;
	CList head;

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

typedef struct {
	CList *ls1;
	CList *ls2;
	char ls1_sorted;
} SortStack;

static CList *
_c_list_sort (CList *ls,
              CListSortCmp cmp,
              const void *user_data)
{
	/* reserve a huge stack-size. We need roughly log2(n) entries, hence this
	 * is much more we will ever need. We don't guard for stack-overflow either. */
	SortStack stack_arr[70];
	SortStack *stack_head = stack_arr;

	stack_arr[0].ls1 = ls;

	/* A simple top-down, non-recursive, stable merge-sort.
	 *
	 * Maybe natural merge-sort would be better, to do better for
	 * partially sorted lists. */
_split:
	stack_head[0].ls2 = _c_list_srt_split (stack_head[0].ls1);
	if (stack_head[0].ls2) {
		stack_head[0].ls1_sorted = 0;
		stack_head[1].ls1 = stack_head[0].ls1;
		stack_head++;
		goto _split;
	}

_backtrack:
	if (stack_head == stack_arr)
		return stack_arr[0].ls1;

	stack_head--;
	if (!stack_head[0].ls1_sorted) {
		stack_head[0].ls1 = stack_head[1].ls1;
		stack_head[0].ls1_sorted = 1;
		stack_head[1].ls1 = stack_head[0].ls2;
		stack_head++;
		goto _split;
	}

	stack_head[0].ls1 = _c_list_srt_merge (stack_head[0].ls1, stack_head[1].ls1, cmp, user_data);
	goto _backtrack;
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
