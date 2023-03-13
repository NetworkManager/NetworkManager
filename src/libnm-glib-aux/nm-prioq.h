/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_PRIOQ_H__
#define __NM_PRIOQ_H__

#define NM_PRIOQ_IDX_NULL G_MAXUINT

struct _NMPrioqItem;

typedef struct {
    struct {
        union {
            GCompareDataFunc compare_data_func;
            GCompareFunc     compare_func;
        };

        gpointer compare_data;

        struct _NMPrioqItem *items;

        unsigned n_items;
        unsigned n_allocated;

        bool compare_with_data;
    } _priv;
} NMPrioq;

#define NM_PRIOQ_ZERO             \
    {                             \
        ._priv = {                \
            .compare_func = NULL, \
        },                        \
    }

void nm_prioq_init(NMPrioq *q, GCompareFunc compare_func);
void nm_prioq_init_with_data(NMPrioq *q, GCompareDataFunc compare_func, gpointer compare_data);

void nm_prioq_destroy(NMPrioq *q);

#define nm_auto_prioq nm_auto(nm_prioq_destroy)

void     nm_prioq_put(NMPrioq *q, void *data, unsigned *idx);
gboolean nm_prioq_remove(NMPrioq *q, void *data, unsigned *idx);
gboolean nm_prioq_reshuffle(NMPrioq *q, void *data, unsigned *idx);

void nm_prioq_update(NMPrioq *q, void *data, unsigned *idx, bool queued /* or else remove */);

void *nm_prioq_peek_by_index(NMPrioq *q, unsigned idx) _nm_pure;

static inline void *
nm_prioq_peek(NMPrioq *q)
{
    return nm_prioq_peek_by_index(q, 0);
}

void *nm_prioq_pop(NMPrioq *q);

#define nm_prioq_for_each(q, p) for (unsigned _i = 0; (p = nm_prioq_peek_by_index((q), _i)); _i++)

_nm_pure static inline unsigned
nm_prioq_size(NMPrioq *q)
{
    nm_assert(q);
    return q->_priv.n_items;
}

_nm_pure static inline gboolean
nm_prioq_isempty(NMPrioq *q)
{
    return nm_prioq_size(q) <= 0;
}

#endif /* __NM_PRIOQ_H__ */
