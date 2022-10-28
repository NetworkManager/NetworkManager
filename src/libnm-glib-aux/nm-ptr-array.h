/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_PTR_ARRAY_H__
#define __NM_PTR_ARRAY_H__

typedef struct _NMPtrArray {
    const gsize len;

    /* How many elements are allocated/reserved for the ptrs array.
     * Note that there is always an extra space reserved for the
     * NULL termination afterwards. It means, "len" can grow up
     * until (including) _reserved, before reallocation is necessary.
     *
     * In other words, arr->ptrs[arr->_reserved] is allocated and reserved
     * for the trailing NULL (but may be uninitialized if the array is shorter). */
    gsize _reserved;

    GDestroyNotify _destroy_fcn;

    const bool is_stack;

    /* This will be the NULL terminated list of pointers. If you
     * know what you are doing, you can also steal elements from
     * the list. */
    gpointer ptrs[];
} NMPtrArray;

#define _NM_PTR_ARRAY_MALLOCSIZE_TO_RESERVED(size) \
    ((((size) -G_STRUCT_OFFSET(NMPtrArray, ptrs)) / sizeof(gpointer)) - 1u)

#define NM_PTR_ARRAY_STACK_RESERVED \
    _NM_PTR_ARRAY_MALLOCSIZE_TO_RESERVED(NM_UTILS_GET_NEXT_REALLOC_SIZE_104)

/* For cases where we don't need to pass a NMPtrArray to the caller, we can
 * start with a stack-allocated array. That one starts with 8 pointers
 * reserved (or 104 bytes) on the stack (on x64_86). 104 is also the magic
 * number that is suitable for reallocation. See NM_UTILS_GET_NEXT_REALLOC_SIZE_104.
 *
 * Usage:
 *     NMPtrArrayStack arr_stack = NM_PTR_ARRAY_STACK_INIT(g_free);
 *     nm_auto_ptrarray *arr = &arr_stack.arr;
 *     ...
 *     collect_pointers(args, &arr);
 *     ...
 *     do_something_with_pointers(arr);
 **/
typedef struct {
    NMPtrArray arr;
    gpointer   _ptrs[NM_PTR_ARRAY_STACK_RESERVED + 1];
} NMPtrArrayStack;

#define NM_PTR_ARRAY_STACK_INIT(destroy_fcn)                      \
    ((NMPtrArrayStack){                                           \
        .arr =                                                    \
            {                                                     \
                .len          = 0,                                \
                ._reserved    = NM_PTR_ARRAY_STACK_RESERVED,      \
                ._destroy_fcn = ((GDestroyNotify) (destroy_fcn)), \
                .is_stack     = TRUE,                             \
            },                                                    \
        ._ptrs = {NULL},                                          \
    })

NMPtrArray *nm_ptr_array_new(GDestroyNotify destroy_fcn, gsize reserved);

void nm_ptr_array_add_n(NMPtrArray **arr, gsize n, gpointer *ptrs);

static inline void
nm_ptr_array_add(NMPtrArray **p_arr, gpointer ptr)
{
    NMPtrArray *arr;

    nm_assert(p_arr);
    nm_assert(*p_arr);

    arr = *p_arr;

    if (G_LIKELY(arr->len < arr->_reserved)) {
        /* Fast-path. We don't need to reallocate. */
        arr->ptrs[arr->len] = ptr;
        *((gsize *) &arr->len) += 1;
        arr->ptrs[arr->len] = NULL;
        return;
    }

    nm_ptr_array_add_n(p_arr, 1, &ptr);
}

static inline NMPtrArray *
nm_ptr_array_set_free_func(NMPtrArray *arr, GDestroyNotify destroy_fcn)
{
    nm_assert(arr);

    arr->_destroy_fcn = destroy_fcn;
    return arr;
}

void nm_ptr_array_clear(NMPtrArray *arr);

void nm_ptr_array_destroy(NMPtrArray *arr);

NM_AUTO_DEFINE_FCN0(NMPtrArray *, _nm_auto_ptrarray, nm_ptr_array_destroy);
#define nm_auto_ptrarray nm_auto(_nm_auto_ptrarray)

#endif /* __NM_PTR_ARRAY_H__ */
