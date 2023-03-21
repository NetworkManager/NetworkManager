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

/*****************************************************************************/

typedef struct _NMPrioqItem {
    void     *data;
    unsigned *idx;
} PrioqItem;

/*****************************************************************************/

#define _nm_assert_q(q)                                         \
    G_STMT_START                                                \
    {                                                           \
        const NMPrioq *const _q2 = (q);                         \
                                                                \
        nm_assert(_q2);                                         \
        nm_assert(_q2->_priv.n_items == 0 || _q2->_priv.items); \
        nm_assert(_q2->_priv.compare_func);                     \
    }                                                           \
    G_STMT_END

#define _nm_assert_item(q, item)                                \
    G_STMT_START                                                \
    {                                                           \
        const NMPrioq *const   _q    = (q);                     \
        const PrioqItem *const _item = (item);                  \
                                                                \
        _nm_assert_q(_q);                                       \
                                                                \
        nm_assert(_item >= _q->_priv.items);                    \
        nm_assert(_item < &_q->_priv.items[_q->_priv.n_items]); \
    }                                                           \
    G_STMT_END

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

    _nm_assert_q(q);

    while (q->_priv.n_items > 0) {
        PrioqItem *i = &q->_priv.items[--q->_priv.n_items];

        if (i->idx)
            *i->idx = NM_PRIOQ_IDX_NULL;
    }

    free(q->_priv.items);
    q->_priv.compare_func = NULL;
}

/*****************************************************************************/

static int
compare(NMPrioq *q, unsigned a, unsigned b)
{
    _nm_assert_q(q);
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
    _nm_assert_q(q);
    nm_assert(j < q->_priv.n_items);
    nm_assert(k < q->_priv.n_items);
    nm_assert(!q->_priv.items[j].idx || *(q->_priv.items[j].idx) == j);
    nm_assert(!q->_priv.items[k].idx || *(q->_priv.items[k].idx) == k);

    NM_SWAP(&q->_priv.items[j], &q->_priv.items[k]);

    if (q->_priv.items[j].idx)
        *q->_priv.items[j].idx = j;

    if (q->_priv.items[k].idx)
        *q->_priv.items[k].idx = k;
}

static unsigned
shuffle_up(NMPrioq *q, unsigned idx)
{
    _nm_assert_q(q);
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
    _nm_assert_q(q);

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

    _nm_assert_q(q);
    nm_assert(q->_priv.n_items < G_MAXUINT);

    if (G_UNLIKELY(q->_priv.n_items >= q->_priv.n_allocated)) {
        q->_priv.n_allocated = NM_MAX((q->_priv.n_items + 1u) * 2u, 16u);
        q->_priv.items       = g_renew(PrioqItem, q->_priv.items, q->_priv.n_allocated);
    }

    k = q->_priv.n_items++;

    q->_priv.items[k] = (PrioqItem){
        .data = data,
        .idx  = idx,
    };

    if (idx)
        *idx = k;

    shuffle_up(q, k);
}

static void
remove_item(NMPrioq *q, PrioqItem *i)
{
    PrioqItem *l;
    unsigned   k;

    _nm_assert_item(q, i);

    if (i->idx)
        *i->idx = NM_PRIOQ_IDX_NULL;

    q->_priv.n_items--;

    l = &q->_priv.items[q->_priv.n_items];

    if (i == l) {
        /* Last entry, nothing to do. */
        return;
    }

    /* Not last entry, let's replace this entry with the last one, and
     * reshuffle */

    k = i - q->_priv.items;

    *i = *l;

    if (i->idx)
        *i->idx = k;

    k = shuffle_down(q, k);
    shuffle_up(q, k);
}

static PrioqItem *
find_item(NMPrioq *q, void *data, unsigned *idx)
{
    PrioqItem *i;

    _nm_assert_q(q);

    if (G_UNLIKELY(!idx)) {
        /* We allow using NMPrioq without "idx". In that case, it does a linear
         * search for the data. */
        for (i = q->_priv.items; i < &q->_priv.items[q->_priv.n_items]; i++) {
            if (i->data == data)
                return i;
        }
        return NULL;
    }

    /* If the user however provides an "idx" pointer, then we assert that it is
     * consistent. That is, if data is not in the queue, then we require that
     * "*idx" is NM_PRIOQ_IDX_NULL, and otherwise we require that we really
     * find "data" at index "*idx".
     *
     * This means, when the user calls nm_prioq_{remove,update,reshuffle}()
     * with an "idx", then they must make sure that the index is consistent.
     * Usually this means they are required to initialize the index to
     * NM_PRIOQ_IDX_NULL while the data is not in the heap.
     *
     * This is done to assert more, and requires a stricter usage of the API
     * (in the hope to find misuses of the index). */

    if (*idx >= q->_priv.n_items) {
        nm_assert(*idx == NM_PRIOQ_IDX_NULL);
        return NULL;
    }

    i = &q->_priv.items[*idx];

    if (i->data != data)
        return nm_assert_unreachable_val(NULL);

    return i;
}

gboolean
nm_prioq_remove(NMPrioq *q, void *data, unsigned *idx)
{
    PrioqItem *i;

    _nm_assert_q(q);

    i = find_item(q, data, idx);
    if (!i)
        return FALSE;

    remove_item(q, i);
    return TRUE;
}

static void
reshuffle_item(NMPrioq *q, PrioqItem *i)
{
    unsigned k;

    _nm_assert_item(q, i);

    k = i - q->_priv.items;
    k = shuffle_down(q, k);
    shuffle_up(q, k);
}

gboolean
nm_prioq_reshuffle(NMPrioq *q, void *data, unsigned *idx)
{
    PrioqItem *i;

    _nm_assert_q(q);

    i = find_item(q, data, idx);
    if (!i)
        return FALSE;

    reshuffle_item(q, i);
    return TRUE;
}

void
nm_prioq_update(NMPrioq *q, void *data, unsigned *idx, bool queued /* or else remove */)
{
    PrioqItem *i;

    _nm_assert_q(q);

    i = find_item(q, data, idx);

    if (!i) {
        if (queued)
            nm_prioq_put(q, data, idx);
        return;
    }

    if (!queued) {
        remove_item(q, i);
        return;
    }

    reshuffle_item(q, i);
}

void *
nm_prioq_peek_by_index(NMPrioq *q, unsigned idx)
{
    _nm_assert_q(q);

    if (idx >= q->_priv.n_items)
        return NULL;

    return q->_priv.items[idx].data;
}

void *
nm_prioq_pop(NMPrioq *q)
{
    void *data;

    _nm_assert_q(q);

    if (q->_priv.n_items <= 0)
        return NULL;

    data = q->_priv.items[0].data;
    remove_item(q, &q->_priv.items[0]);
    return data;
}
