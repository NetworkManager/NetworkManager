// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __C_LIST_UTIL_H__
#define __C_LIST_UTIL_H__

#include "c-list/src/c-list.h"

/*****************************************************************************/

void c_list_relink (CList *lst);

typedef int (*CListSortCmp) (const CList *a,
                             const CList *b,
                             const void *user_data);

CList *c_list_sort_headless (CList *lst,
                             CListSortCmp cmp,
                             const void *user_data);

void c_list_sort (CList *head,
                  CListSortCmp cmp,
                  const void *user_data);

/* c_list_length_is:
 * @list: the #CList list head
 * @check_len: the length to compare
 *
 * Returns: basically the same as (c_list_length (@list) == @check_len),
 *   but does not require to iterate the entire list first. There is only
 *   one real use: to find out whether there is exactly one element in the
 *   list, by passing @check_len as 1.
 */
static inline int
c_list_length_is (const CList *list, unsigned long check_len) {
	unsigned long n = 0;
	const CList *iter;

	c_list_for_each (iter, list) {
		++n;
		if (n > check_len)
			return 0;
	}

	return n == check_len;
}

#endif /* __C_LIST_UTIL_H__ */
