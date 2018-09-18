/*
 * RB-Tree based Map
 * This implements a basic Map between integer keys and objects. It uses the
 * lookup and insertion helpers, rather than open-coding it.
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "c-rbtree.h"
#include "c-rbtree-private.h"

typedef struct {
        unsigned long key;
        unsigned int marker;
        CRBNode rb;
} Node;

#define node_from_rb(_rb) ((Node *)((char *)(_rb) - offsetof(Node, rb)))

static int test_compare(CRBTree *t, void *k, CRBNode *n) {
        unsigned long key = (unsigned long)k;
        Node *node = node_from_rb(n);

        return (key < node->key) ? -1 : (key > node->key) ? 1 : 0;
}

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

static void test_map(void) {
        CRBNode **slot, *p, *safe_p;
        CRBTree t = {};
        Node *n, *safe_n, *nodes[2048];
        unsigned long i, v;

        /* allocate and initialize all nodes */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                nodes[i] = malloc(sizeof(*nodes[i]));
                assert(nodes[i]);
                nodes[i]->key = i;
                nodes[i]->marker = 0;
                c_rbnode_init(&nodes[i]->rb);
        }

        /* shuffle nodes */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* add all nodes, and verify that each node is linked */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                assert(!c_rbnode_is_linked(&nodes[i]->rb));
                assert(!c_rbtree_find_entry(&t, test_compare, (void *)nodes[i]->key, Node, rb));

                slot = c_rbtree_find_slot(&t, test_compare, (void *)nodes[i]->key, &p);
                assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);

                assert(c_rbnode_is_linked(&nodes[i]->rb));
                assert(nodes[i] == c_rbtree_find_entry(&t, test_compare, (void *)nodes[i]->key, Node, rb));
        }

        /* verify in-order traversal works */
        i = 0;
        v = 0;
        for (p = c_rbtree_first(&t); p; p = c_rbnode_next(p)) {
                ++i;
                assert(!node_from_rb(p)->marker);
                node_from_rb(p)->marker = 1;

                assert(v <= node_from_rb(p)->key);
                v = node_from_rb(p)->key;

                assert(!c_rbnode_next(p) || p == c_rbnode_prev(c_rbnode_next(p)));
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify reverse in-order traversal works */
        i = 0;
        v = -1;
        for (p = c_rbtree_last(&t); p; p = c_rbnode_prev(p)) {
                ++i;
                assert(node_from_rb(p)->marker);
                node_from_rb(p)->marker = 0;

                assert(v >= node_from_rb(p)->key);
                v = node_from_rb(p)->key;
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify post-order traversal works */
        i = 0;
        for (p = c_rbtree_first_postorder(&t); p; p = c_rbnode_next_postorder(p)) {
                ++i;
                assert(!node_from_rb(p)->marker);
                assert(!c_rbnode_parent(p) || !node_from_rb(c_rbnode_parent(p))->marker);
                assert(!p->left || node_from_rb(p->left)->marker);
                assert(!p->right || node_from_rb(p->right)->marker);
                node_from_rb(p)->marker = 1;

                assert(!c_rbnode_next_postorder(p) || p == c_rbnode_prev_postorder(c_rbnode_next_postorder(p)));
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify pre-order (inverse post-order) traversal works */
        i = 0;
        for (p = c_rbtree_last_postorder(&t); p; p = c_rbnode_prev_postorder(p)) {
                ++i;
                assert(node_from_rb(p)->marker);
                assert(!c_rbnode_parent(p) || !node_from_rb(c_rbnode_parent(p))->marker);
                assert(!p->left || node_from_rb(p->left)->marker);
                assert(!p->right || node_from_rb(p->right)->marker);
                node_from_rb(p)->marker = 0;
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify in-order traversal works via helper */
        i = 0;
        v = 0;
        c_rbtree_for_each(p, &t) {
                ++i;
                assert(!node_from_rb(p)->marker);
                node_from_rb(p)->marker = 1;

                assert(v <= node_from_rb(p)->key);
                v = node_from_rb(p)->key;

                assert(!c_rbnode_next(p) || p == c_rbnode_prev(c_rbnode_next(p)));
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify in-order traversal works via entry-helper */
        i = 0;
        v = 0;
        c_rbtree_for_each_entry(n, &t, rb) {
                ++i;
                assert(n->marker);
                n->marker = 0;

                assert(v <= n->key);
                v = n->key;
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify post-order traversal works via helper */
        i = 0;
        c_rbtree_for_each_postorder(p, &t) {
                ++i;
                assert(!node_from_rb(p)->marker);
                assert(!c_rbnode_parent(p) || !node_from_rb(c_rbnode_parent(p))->marker);
                assert(!p->left || node_from_rb(p->left)->marker);
                assert(!p->right || node_from_rb(p->right)->marker);
                node_from_rb(p)->marker = 1;

                assert(!c_rbnode_next_postorder(p) || p == c_rbnode_prev_postorder(c_rbnode_next_postorder(p)));
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* verify post-order traversal works via entry-helper */
        i = 0;
        c_rbtree_for_each_entry_postorder(n, &t, rb) {
                ++i;
                assert(n->marker);
                assert(!c_rbnode_parent(&n->rb) || node_from_rb(c_rbnode_parent(&n->rb))->marker);
                assert(!n->rb.left || !node_from_rb(n->rb.left)->marker);
                assert(!n->rb.right || !node_from_rb(n->rb.right)->marker);
                n->marker = 0;
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));

        /* shuffle nodes again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all nodes (in different order) */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                assert(c_rbnode_is_linked(&nodes[i]->rb));
                assert(nodes[i] == c_rbtree_find_entry(&t, test_compare, (void *)nodes[i]->key, Node, rb));

                c_rbnode_unlink(&nodes[i]->rb);

                assert(!c_rbnode_is_linked(&nodes[i]->rb));
                assert(!c_rbtree_find_entry(&t, test_compare, (void *)nodes[i]->key, Node, rb));
        }
        assert(c_rbtree_is_empty(&t));

        /* add all nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                slot = c_rbtree_find_slot(&t, test_compare, (void *)nodes[i]->key, &p);
                assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);
        }

        /* remove all nodes via helper */
        i = 0;
        c_rbtree_for_each_safe(p, safe_p, &t) {
                ++i;
                c_rbnode_unlink(p);
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));
        assert(c_rbtree_is_empty(&t));

        /* add all nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                slot = c_rbtree_find_slot(&t, test_compare, (void *)nodes[i]->key, &p);
                assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);
        }

        /* remove all nodes via entry-helper */
        i = 0;
        c_rbtree_for_each_entry_safe(n, safe_n, &t, rb) {
                ++i;
                c_rbnode_unlink(&n->rb);
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));
        assert(c_rbtree_is_empty(&t));

        /* add all nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                slot = c_rbtree_find_slot(&t, test_compare, (void *)nodes[i]->key, &p);
                assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);
        }

        /* remove all nodes via unlink-helper */
        i = 0;
        c_rbtree_for_each_safe_postorder_unlink(p, safe_p, &t) {
                ++i;
                assert(!c_rbnode_is_linked(p));
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));
        assert(c_rbtree_is_empty(&t));

        /* add all nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                slot = c_rbtree_find_slot(&t, test_compare, (void *)nodes[i]->key, &p);
                assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);
        }

        /* remove all nodes via entry-unlink-helper */
        i = 0;
        c_rbtree_for_each_entry_safe_postorder_unlink(n, safe_n, &t, rb) {
                ++i;
                assert(!c_rbnode_is_linked(&n->rb));
        }
        assert(i == sizeof(nodes) / sizeof(*nodes));
        assert(c_rbtree_is_empty(&t));

        /* free nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                assert(!nodes[i]->marker);
                free(nodes[i]);
        }

        assert(c_rbtree_is_empty(&t));
}

int main(int argc, char **argv) {
        /* we want stable tests, so use fixed seed */
        srand(0xdeadbeef);

        test_map();
        return 0;
}
