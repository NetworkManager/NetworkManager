/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-ptr-array.h"

#include "libnm-std-aux/nm-std-utils.h"

/*****************************************************************************/

#define _MALLOCSIZE_FROM_RESERVED(reserved) \
    (G_STRUCT_OFFSET(NMPtrArray, ptrs) + (sizeof(gpointer) * ((reserved) + 1u)))

G_STATIC_ASSERT(sizeof(NMPtrArrayStack) <= NM_UTILS_GET_NEXT_REALLOC_SIZE_104);
G_STATIC_ASSERT(G_N_ELEMENTS(((NMPtrArrayStack *) NULL)->_ptrs) > 1);
G_STATIC_ASSERT(G_N_ELEMENTS(((NMPtrArrayStack *) NULL)->_ptrs)
                == _NM_PTR_ARRAY_MALLOCSIZE_TO_RESERVED(NM_UTILS_GET_NEXT_REALLOC_SIZE_104) + 1u);

G_STATIC_ASSERT(G_STRUCT_OFFSET(NMPtrArray, ptrs) == G_STRUCT_OFFSET(NMPtrArrayStack, _ptrs));

static gsize
_mallocsize_from_reserved(gsize reserved)
{
    nm_assert(reserved < ((G_MAXSIZE - G_STRUCT_OFFSET(NMPtrArray, ptrs)) / sizeof(gpointer)) - 1u);

    return _MALLOCSIZE_FROM_RESERVED(reserved);
}

static gsize
_mallocsize_to_reserved(gsize size)
{
    gsize reserved;

    reserved = _NM_PTR_ARRAY_MALLOCSIZE_TO_RESERVED(size);
    nm_assert(size >= _mallocsize_from_reserved(reserved));
    return reserved;
}

NMPtrArray *
nm_ptr_array_new(GDestroyNotify destroy_fcn, gsize reserved)
{
    NMPtrArray *arr;

    if (reserved < 3u)
        reserved = 3u;

    arr = g_malloc(_mallocsize_from_reserved(reserved));

    *((gsize *) &arr->len)     = 0;
    arr->_reserved             = reserved;
    arr->_destroy_fcn          = destroy_fcn;
    *((bool *) &arr->is_stack) = FALSE;
    arr->ptrs[0]               = NULL;

    return arr;
}

void
nm_ptr_array_add_n(NMPtrArray **p_arr, gsize n, gpointer *ptrs)
{
    NMPtrArray *arr;
    gsize       new_reserved;
    gsize       new_len;

    nm_assert(p_arr);
    nm_assert(*p_arr);

    if (n == 0)
        return;

    arr = *p_arr;

    nm_assert(n < G_MAXSIZE - arr->len);
    new_len = arr->len + n;

    nm_assert(new_len > arr->len);

    /* Note that arr->_reserved does not count the element for the
     * last trailing NULL. That is, arr->ptrs[arr->_reserved] is valid.
     * In other words, new_len may be as large as arr->reserved before
     * we need to reallocate, and `arr->ptrs[new_len] = NULL` is correct. */

    if (new_len > arr->_reserved) {
        gsize n_bytes;

        /* We grow the total buffer size using nm_utils_get_next_realloc_size().
         * This quite aggressively increases the buffer size. The idea is that
         * NMPtrArray is mostly used for short lived purposes, and it's OK to
         * waste some space to reduce re-allocation. */
        n_bytes = nm_utils_get_next_realloc_size(TRUE, _mallocsize_from_reserved(new_len));

        new_reserved = _mallocsize_to_reserved(n_bytes);

        nm_assert(new_len <= new_reserved);
        nm_assert(n_bytes >= _mallocsize_from_reserved(new_reserved));

        if (arr->is_stack) {
            NMPtrArray *arr2 = arr;

            arr = g_malloc(_mallocsize_from_reserved(new_reserved));
            memcpy(arr, arr2, _mallocsize_from_reserved(arr2->_reserved));
            *((bool *) &arr->is_stack) = FALSE;
        } else {
            arr = g_realloc(arr, _mallocsize_from_reserved(new_reserved));
        }
        arr->_reserved = new_reserved;

        *p_arr = arr;
    }

    memcpy(&arr->ptrs[arr->len], ptrs, sizeof(gpointer) * n);
    arr->ptrs[new_len]     = NULL;
    *((gsize *) &arr->len) = new_len;
}

void
nm_ptr_array_clear(NMPtrArray *arr)
{
    if (!arr)
        return;

    if (arr->len == 0)
        return;

    if (!arr->_destroy_fcn) {
        (*((gsize *) &arr->len)) = 0;
        arr->ptrs[0]             = NULL;
        return;
    }

    do {
        gsize    idx;
        gpointer p;

        idx = (--(*((gsize *) &arr->len)));

        p = g_steal_pointer(&arr->ptrs[idx]);

        if (p)
            arr->_destroy_fcn(p);
    } while (arr->len > 0);
}

void
nm_ptr_array_destroy(NMPtrArray *arr)
{
    if (!arr)
        return;

    nm_ptr_array_clear(arr);
    if (!arr->is_stack)
        g_free(arr);
}
