/*
 * Tests to compare against POSIX RB-Trees
 * POSIX provides balanced binary trees via the tsearch(3p) API. glibc
 * implements them as RB-Trees. This file compares the performance of both.
 *
 * The semantic differences are:
 *
 *   o The tsearch(3p) API does memory allocation of node structures itself,
 *     rather than allowing the caller to embed it.
 *
 *   o The c-rbtree API exposes the tree structure, allowing efficient tree
 *     operations. Furthermore, it allows tree creation/deletion without taking
 *     the expensive insert/remove paths. For instance, imagine you want to
 *     create an rb-tree from a set of objects you have. With c-rbtree you can
 *     do that without a single rotation or tree-restructuring in O(n), while
 *     tsearch(3p) requires O(n log n).
 *
 *   o The tsearch(3p) API requires one pointer-chase on each node access. This
 *     is inherent to the design as it does not allow embedding the node in the
 *     parent object. This slows down the API considerably.
 *
 *   o The tsearch(3p) API does not allow multiple entries with the same key.
 *
 *   o The tsearch(3p) API requires node lookup during removal. This does not
 *     affect the worst-case runtime, but does reduce absolute performance.
 *
 *   o The tsearch(3p) API does not allow O(1) tests whether a node is linked
 *     or not. It requires a separate state variable per node.
 *
 *   o The tsearch(3p) API does not allow walking the tree with context. The
 *     only accessor twalk(3p) provides no tree context nor caller context to
 *     the callback function.
 *
 *   o The glibc implementation of tsearch(3p) uses RB-Trees without parent
 *     pointers. Hence, tree traversal requires back-tracking. Performance is
 *     similar, but it reduces memory consumption (though, at the same time it
 *     stores the key pointer, and allocates the node on the heap, so overall
 *     the memory consumption is higher still).
 *     But the more important issue is, a node itself is not enough context as
 *     tree iterator, but the full depth parent pointers are needed as well.
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <inttypes.h>
#include <limits.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "c-rbtree.h"
#include "c-rbtree-private.h"

typedef struct {
        int key;
        CRBNode rb;
} Node;

#define node_from_rb(_rb) ((Node *)((char *)(_rb) - offsetof(Node, rb)))
#define node_from_key(_key) ((Node *)((char *)(_key) - offsetof(Node, key)))

static void shuffle(Node **nodes, size_t n_memb) {
        unsigned int i, j;
        Node *t;

        for (i = 0; i < n_memb; ++i) {
                j = rand() % n_memb;
                t = nodes[j];
                nodes[j] = nodes[i];
                nodes[i] = t;
        }
}

static int compare(CRBTree *t, void *k, CRBNode *n) {
        int key = (int)(unsigned long)k;
        Node *node = node_from_rb(n);

        return key - node->key;
}

static uint64_t now(void) {
        struct timespec ts;
        int r;

        r = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
        c_assert(r >= 0);
        return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

/*
 * POSIX tsearch(3p) based RB-Tree API
 *
 * This implements a small rb-tree API alongside c-rbtree but based on
 * tsearch(3p) and friends.
 *
 * Note that we don't care for OOM here, nor do we implement all the same
 * features as c-rbtree. This just does basic insertion, removal, and lookup
 * without any conflict detection.
 *
 * This also hard-codes 'Node' as object type that can be stored in the tree.
 */

typedef struct PosixRBTree PosixRBTree;

struct PosixRBTree {
        void *root;
};

static int posix_rbtree_compare(const void *a, const void *b) {
        return *(const int *)a - *(const int *)b;
}

static void posix_rbtree_add(PosixRBTree *t, const Node *node) {
        void *res;

        res = tsearch(&node->key, &t->root, posix_rbtree_compare);
        c_assert(*(int **)res == &node->key);
}

static void posix_rbtree_remove(PosixRBTree *t, const Node *node) {
        void *res;

        res = tdelete(&node->key, &t->root, posix_rbtree_compare);
        c_assert(res);
}

static Node *posix_rbtree_find(PosixRBTree *t, int key) {
        void *res;

        res = tfind(&key, &t->root, posix_rbtree_compare);
        return res ? node_from_key(*(int **)res) : NULL;
}

static void posix_rbtree_visit(const void *n, const VISIT o, const int depth) {
        static int v;

        /* HACK: twalk() has no context; use static context; reset on root */
        if (depth == 0 && (o == preorder || o == leaf))
                v = 0;

        switch (o) {
        case postorder:
        case leaf:
                c_assert(v <= node_from_key(*(int **)n)->key);
                v = node_from_key(*(int **)n)->key;
                break;
        default:
                break;
        }
}

static void posix_rbtree_traverse(PosixRBTree *t) {
        twalk(t->root, posix_rbtree_visit);
}

/*
 * Comparison between c-rbtree and tsearch(3p)
 *
 * Based on the tsearch(3p) API above, this now implements some comparisons
 * between c-rbtree and the POSIX API.
 *
 * The semantic differences are explained above. This does mostly performance
 * comparisons.
 */

static void test_posix(void) {
        uint64_t ts, ts_c1, ts_c2, ts_c3, ts_c4;
        uint64_t ts_p1, ts_p2, ts_p3, ts_p4;
        PosixRBTree pt = {};
        CRBNode **slot, *p;
        CRBTree t = {};
        Node *nodes[2048];
        unsigned long i;
        int v;

        /* allocate and initialize all nodes */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                nodes[i] = malloc(sizeof(*nodes[i]));
                c_assert(nodes[i]);
                nodes[i]->key = i;
                c_rbnode_init(&nodes[i]->rb);
        }

        /* shuffle nodes */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* add all nodes, and verify that each node is linked */
        ts = now();
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                slot = c_rbtree_find_slot(&t, compare, (void *)(unsigned long)nodes[i]->key, &p);
                c_assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);
        }
        ts_c1 = now() - ts;

        ts = now();
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                posix_rbtree_add(&pt, nodes[i]);
        ts_p1 = now() - ts;

        /* shuffle nodes again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* traverse tree in-order */
        ts = now();
        i = 0;
        v = 0;
        for (p = c_rbtree_first(&t); p; p = c_rbnode_next(p)) {
                ++i;

                c_assert(v <= node_from_rb(p)->key);
                v = node_from_rb(p)->key;
        }
        c_assert(i == sizeof(nodes) / sizeof(*nodes));
        ts_c2 = now() - ts;

        ts = now();
        posix_rbtree_traverse(&pt);
        ts_p2 = now() - ts;

        /* shuffle nodes again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* lookup all nodes (in different order) */
        ts = now();
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                c_assert(nodes[i] == c_rbtree_find_entry(&t, compare,
                                                       (void *)(unsigned long)nodes[i]->key,
                                                       Node, rb));
        ts_c3 = now() - ts;

        ts = now();
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                c_assert(nodes[i] == posix_rbtree_find(&pt, nodes[i]->key));
        ts_p3 = now() - ts;

        /* shuffle nodes again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all nodes (in different order) */
        ts = now();
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                c_rbnode_unlink(&nodes[i]->rb);
        ts_c4 = now() - ts;

        ts = now();
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                posix_rbtree_remove(&pt, nodes[i]);
        ts_p4 = now() - ts;

        /* free nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                free(nodes[i]);

        fprintf(stderr, "              insertion  traversal     lookup    removal\n");
        fprintf(stderr, "   c-rbtree: %8"PRIu64"ns %8"PRIu64"ns %8"PRIu64"ns %8"PRIu64"ns\n",
                ts_c1, ts_c2, ts_c3, ts_c4);
        fprintf(stderr, "tsearch(3p): %8"PRIu64"ns %8"PRIu64"ns %8"PRIu64"ns %8"PRIu64"ns\n",
                ts_p1, ts_p2, ts_p3, ts_p4);
}

int main(int argc, char **argv) {
        /* we want stable tests, so use fixed seed */
        srand(0xdeadbeef);

        test_posix();
        return 0;
}
