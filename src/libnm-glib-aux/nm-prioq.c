/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Taken from systemd's Prioq.
 *
 * Priority Queue
 * The prioq object implements a priority queue. That is, it orders objects by
 * their priority and allows O(1) access to the object with the highest
 * priority. Insertion and removal are Θ(log n). Optionally, the caller can
 * provide a pointer to an index which will be kept up-to-date by the prioq.
 *
 * The underlying algorithm used in this implementation is a Heap.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-prioq.h"

#include <errno.h>
#include <stdlib.h>

/*****************************************************************************/

struct _NMPrioqItem {
    void     *data;
    unsigned *idx;
};

/*****************************************************************************/

void
nm_prioq_init(NMPrioq *q, GCompareFunc compare_func)
{
    nm_assert(q);
    nm_assert(compare_func);

    *q = (NMPrioq){
        ._priv =
            {
                .compare_func      = compare_func,
                .compare_data      = NULL,
                .compare_with_data = FALSE,
                .items             = NULL,
                .n_items           = 0,
                .n_allocated       = 0,
            },
    };
}

void
nm_prioq_init_with_data(NMPrioq *q, GCompareDataFunc compare_func, gpointer compare_data)
{
    nm_assert(q);
    nm_assert(compare_func);

    *q = (NMPrioq){
        ._priv =
            {
                .compare_data_func = compare_func,
                .compare_data      = compare_data,
                .compare_with_data = TRUE,
                .items             = NULL,
                .n_items           = 0,
                .n_allocated       = 0,
            },
    };
}

void
nm_prioq_destroy(NMPrioq *q)
{
    if (!q || !q->_priv.compare_func)
        return;

    free(q->_priv.items);
    q->_priv.compare_func = NULL;
}

/*****************************************************************************/

static int
compare(NMPrioq *q, unsigned a, unsigned b)
{
    nm_assert(q);
    nm_assert(q->_priv.compare_func);
    nm_assert(a != b);
    nm_assert(a < q->_priv.n_items);
    nm_assert(b < q->_priv.n_items);

    if (q->_priv.compare_with_data) {
        return q->_priv.compare_data_func(q->_priv.items[a].data,
                                          q->_priv.items[b].data,
                                          q->_priv.compare_data);
    }

    return q->_priv.compare_func(q->_priv.items[a].data, q->_priv.items[b].data);
}

static void
swap(NMPrioq *q, unsigned j, unsigned k)
{
    nm_assert(q);
    nm_assert(j < q->_priv.n_items);
    nm_assert(k < q->_priv.n_items);

    nm_assert(!q->_priv.items[j].idx || *(q->_priv.items[j].idx) == j);
    nm_assert(!q->_priv.items[k].idx || *(q->_priv.items[k].idx) == k);

    NM_SWAP(&q->_priv.items[j].data, &q->_priv.items[k].data);
    NM_SWAP(&q->_priv.items[j].idx, &q->_priv.items[k].idx);

    if (q->_priv.items[j].idx)
        *q->_priv.items[j].idx = j;

    if (q->_priv.items[k].idx)
        *q->_priv.items[k].idx = k;
}

static unsigned
shuffle_up(NMPrioq *q, unsigned idx)
{
    nm_assert(q);
    nm_assert(idx < q->_priv.n_items);

    while (idx > 0) {
        unsigned k;

        k = (idx - 1) / 2;

        if (compare(q, k, idx) <= 0)
            break;

        swap(q, idx, k);
        idx = k;
    }

    return idx;
}

static unsigned
shuffle_down(NMPrioq *q, unsigned idx)
{
    nm_assert(q);

    for (;;) {
        unsigned j;
        unsigned k;
        unsigned s;

        k = (idx + 1) * 2; /* right child */
        j = k - 1;         /* left child */

        if (j >= q->_priv.n_items)
            break;

        if (compare(q, j, idx) < 0) {
            /* So our left child is smaller than we are, let's
             * remember this fact */
            s = j;
        } else
            s = idx;

        if ((k < q->_priv.n_items) && compare(q, k, s) < 0) {
            /* So our right child is smaller than we are, let's
             * remember this fact */
            s = k;
        }

        /* s now points to the smallest of the three items */

        if (s == idx)
            /* No swap necessary, we're done */
            break;

        swap(q, idx, s);
        idx = s;
    }

    return idx;
}

void
nm_prioq_put(NMPrioq *q, void *data, unsigned *idx)
{
    unsigned k;

    nm_assert(q);

    if (q->_priv.n_items >= q->_priv.n_allocated) {
        q->_priv.n_allocated = NM_MAX((q->_priv.n_items + 1u) * 2u, 16u);
        q->_priv.items       = g_renew(struct _NMPrioqItem, q->_priv.items, q->_priv.n_allocated);
    }

    k = q->_priv.n_items++;

    q->_priv.items[k] = (struct _NMPrioqItem){
        .data = data,
        .idx  = idx,
    };
    if (idx)
        *idx = k;

    shuffle_up(q, k);
}

static void
remove_item(NMPrioq *q, struct _NMPrioqItem *i)
{
    struct _NMPrioqItem *l;
    unsigned             k;

    nm_assert(q);
    nm_assert(i);
    nm_assert(q->_priv.n_items > 0);
    nm_assert(i >= q->_priv.items);
    nm_assert(i < &q->_priv.items[q->_priv.n_items]);

    l = &q->_priv.items[q->_priv.n_items - 1u];

    if (i == l) {
        /* Last entry, let's just remove it */
        q->_priv.n_items--;
        return;
    }

    /* Not last entry, let's replace the last entry with
     * this one, and reshuffle */
    k = i - q->_priv.items;

    *i = *l;
    if (i->idx)
        *i->idx = k;
    q->_priv.n_items--;

    k = shuffle_down(q, k);
    shuffle_up(q, k);
}

_nm_pure static struct _NMPrioqItem *
find_item(NMPrioq *q, void *data, unsigned *idx)
{
    struct _NMPrioqItem *i;

    nm_assert(q);

    if (q->_priv.n_items <= 0)
        return NULL;

    if (idx) {
        if (*idx == NM_PRIOQ_IDX_NULL || *idx >= q->_priv.n_items)
            return NULL;

        i = &q->_priv.items[*idx];
        if (i->data == data)
            return i;
    } else {
        for (i = q->_priv.items; i < &q->_priv.items[q->_priv.n_items]; i++) {
            if (i->data == data)
                return i;
        }
    }

    return NULL;
}

gboolean
nm_prioq_remove(NMPrioq *q, void *data, unsigned *idx)
{
    struct _NMPrioqItem *i;

    nm_assert(q);

    i = find_item(q, data, idx);
    if (!i)
        return FALSE;

    remove_item(q, i);
    return TRUE;
}

gboolean
nm_prioq_reshuffle(NMPrioq *q, void *data, unsigned *idx)
{
    struct _NMPrioqItem *i;
    unsigned             k;

    nm_assert(q);

    i = find_item(q, data, idx);
    if (!i)
        return FALSE;

    k = i - q->_priv.items;
    k = shuffle_down(q, k);
    shuffle_up(q, k);
    return TRUE;
}

void *
nm_prioq_peek_by_index(NMPrioq *q, unsigned idx)
{
    nm_assert(q);

    if (idx >= q->_priv.n_items)
        return NULL;

    return q->_priv.items[idx].data;
}

void *
nm_prioq_pop(NMPrioq *q)
{
    void *data;

    nm_assert(q);

    if (q->_priv.n_items <= 0)
        return NULL;

    data = q->_priv.items[0].data;
    remove_item(q, &q->_priv.items[0]);
    return data;
}
