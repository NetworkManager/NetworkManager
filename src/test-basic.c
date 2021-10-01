/*
 * Tests for Basic Tree Operations
 * This test does some basic tree operations and verifies their correctness. It
 * validates the RB-Tree invariants after each operation, to guarantee the
 * stability of the tree.
 *
 * For testing purposes, we use the memory address of a node as its key, and
 * order nodes in ascending order.
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "c-rbtree.h"
#include "c-rbtree-private.h"

static size_t validate(CRBTree *t) {
        unsigned int i_black, n_black;
        CRBNode *n, *p, *o;
        size_t count = 0;

        c_assert(t);
        c_assert(!t->root || c_rbnode_is_black(t->root));

        /* traverse to left-most child, count black nodes */
        i_black = 0;
        n = t->root;
        while (n && n->left) {
                if (c_rbnode_is_black(n))
                        ++i_black;
                n = n->left;
        }
        n_black = i_black;

        /*
         * Traverse tree and verify correctness:
         *  1) A node is either red or black
         *  2) The root is black
         *  3) All leaves are black
         *  4) Every red node must have two black child nodes
         *  5) Every path to a leaf contains the same number of black nodes
         *
         * Note that NULL nodes are considered black, which is why we don't
         * check for 3).
         */
        o = NULL;
        while (n) {
                ++count;

                /* verify natural order */
                c_assert(n > o);
                o = n;

                /* verify consistency */
                c_assert(!n->right || c_rbnode_parent(n->right) == n);
                c_assert(!n->left || c_rbnode_parent(n->left) == n);

                /* verify 2) */
                if (!c_rbnode_parent(n))
                        c_assert(c_rbnode_is_black(n));

                if (c_rbnode_is_red(n)) {
                        /* verify 4) */
                        c_assert(!n->left || c_rbnode_is_black(n->left));
                        c_assert(!n->right || c_rbnode_is_black(n->right));
                } else {
                        /* verify 1) */
                        c_assert(c_rbnode_is_black(n));
                }

                /* verify 5) */
                if (!n->left && !n->right)
                        c_assert(i_black == n_black);

                /* get next node */
                if (n->right) {
                        n = n->right;
                        if (c_rbnode_is_black(n))
                                ++i_black;

                        while (n->left) {
                                n = n->left;
                                if (c_rbnode_is_black(n))
                                        ++i_black;
                        }
                } else {
                        while ((p = c_rbnode_parent(n)) && n == p->right) {
                                n = p;
                                if (c_rbnode_is_black(p->right))
                                        --i_black;
                        }

                        n = p;
                        if (p && c_rbnode_is_black(p->left))
                                --i_black;
                }
        }

        return count;
}

static void insert(CRBTree *t, CRBNode *n) {
        CRBNode **i, *p;

        c_assert(t);
        c_assert(n);
        c_assert(!c_rbnode_is_linked(n));

        i = &t->root;
        p = NULL;
        while (*i) {
                p = *i;
                if (n < *i) {
                        i = &(*i)->left;
                } else {
                        c_assert(n > *i);
                        i = &(*i)->right;
                }
        }

        c_rbtree_add(t, p, i, n);
}

static void shuffle(CRBNode **nodes, size_t n_memb) {
        unsigned int i, j;
        CRBNode *t;

        for (i = 0; i < n_memb; ++i) {
                j = rand() % n_memb;
                t = nodes[j];
                nodes[j] = nodes[i];
                nodes[i] = t;
        }
}

static void test_shuffle(void) {
        CRBNode *nodes[512];
        CRBTree t = {};
        unsigned int i, j;
        size_t n;

        /* allocate and initialize all nodes */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                nodes[i] = malloc(sizeof(*nodes[i]));
                c_assert(nodes[i]);
                c_rbnode_init(nodes[i]);
        }

        /* shuffle nodes and validate *empty* tree */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));
        n = validate(&t);
        c_assert(n == 0);

        /* add all nodes and validate after each insertion */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                insert(&t, nodes[i]);
                n = validate(&t);
                c_assert(n == i + 1);
        }

        /* shuffle nodes again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all nodes (in different order) and validate on each round */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                c_rbnode_unlink(nodes[i]);
                n = validate(&t);
                c_assert(n == sizeof(nodes) / sizeof(*nodes) - i - 1);
        }

        /* shuffle nodes and validate *empty* tree again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));
        n = validate(&t);
        c_assert(n == 0);

        /* add all nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                insert(&t, nodes[i]);
                n = validate(&t);
                c_assert(n == i + 1);
        }

        /* 4 times, remove half of the nodes and add them again */
        for (j = 0; j < 4; ++j) {
                /* shuffle nodes again */
                shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

                /* remove half of the nodes */
                for (i = 0; i < sizeof(nodes) / sizeof(*nodes) / 2; ++i) {
                        c_rbnode_unlink(nodes[i]);
                        n = validate(&t);
                        c_assert(n == sizeof(nodes) / sizeof(*nodes) - i - 1);
                }

                /* shuffle the removed half */
                shuffle(nodes, sizeof(nodes) / sizeof(*nodes) / 2);

                /* add the removed half again */
                for (i = 0; i < sizeof(nodes) / sizeof(*nodes) / 2; ++i) {
                        insert(&t, nodes[i]);
                        n = validate(&t);
                        c_assert(n == sizeof(nodes) / sizeof(*nodes) / 2 + i + 1);
                }
        }

        /* shuffle nodes again */
        shuffle(nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                c_rbnode_unlink(nodes[i]);
                n = validate(&t);
                c_assert(n == sizeof(nodes) / sizeof(*nodes) - i - 1);
        }

        /* free nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                free(nodes[i]);
}

int main(int argc, char **argv) {
        unsigned int i;

        /* we want stable tests, so use fixed seed */
        srand(0xdeadbeef);

        /*
         * The tests are pseudo random; run them multiple times, each run will
         * have different orders and thus different results.
         */
        for (i = 0; i < 4; ++i)
                test_shuffle();

        return 0;
}
