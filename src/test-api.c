/*
 * Tests for Public API
 * This test, unlikely the others, is linked against the real, distributed,
 * shared library. Its sole purpose is to test for symbol availability.
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c-rbtree.h"

typedef struct TestNode {
        CRBNode rb;
} TestNode;

static void test_api(void) {
        CRBTree t = C_RBTREE_INIT, t2 = C_RBTREE_INIT;
        CRBNode *i, *is, n = C_RBNODE_INIT(n), m = C_RBNODE_INIT(m);
        TestNode *ie, *ies;

        assert(c_rbtree_is_empty(&t));
        assert(!c_rbnode_is_linked(&n));
        assert(!c_rbnode_entry(NULL, TestNode, rb));

        /* init, is_linked, add, link, {unlink{,_stale}} */

        c_rbtree_add(&t, NULL, &t.root, &n);
        assert(c_rbnode_is_linked(&n));

        c_rbnode_link(&n, &n.left, &m);
        assert(c_rbnode_is_linked(&m));

        c_rbnode_unlink(&m);
        assert(!c_rbnode_is_linked(&m));

        c_rbtree_add(&t, NULL, &t.root, &n);
        assert(c_rbnode_is_linked(&n));

        c_rbnode_link(&n, &n.left, &m);
        assert(c_rbnode_is_linked(&m));

        c_rbnode_unlink_stale(&m);
        assert(c_rbnode_is_linked(&m)); /* @m wasn't touched */

        c_rbnode_init(&n);
        assert(!c_rbnode_is_linked(&n));

        c_rbnode_init(&m);
        assert(!c_rbnode_is_linked(&m));

        c_rbtree_init(&t);
        assert(c_rbtree_is_empty(&t));

        /* move */

        c_rbtree_move(&t2, &t);

        /* first, last, leftmost, rightmost, next, prev */

        assert(!c_rbtree_first(&t));
        assert(!c_rbtree_last(&t));
        assert(&n == c_rbnode_leftmost(&n));
        assert(&n == c_rbnode_rightmost(&n));
        assert(!c_rbnode_next(&n));
        assert(!c_rbnode_prev(&n));

        /* postorder traversal */

        assert(!c_rbtree_first_postorder(&t));
        assert(!c_rbtree_last_postorder(&t));
        assert(&n == c_rbnode_leftdeepest(&n));
        assert(&n == c_rbnode_rightdeepest(&n));
        assert(!c_rbnode_next_postorder(&n));
        assert(!c_rbnode_prev_postorder(&n));

        /* iterators */

        c_rbtree_for_each(i, &t)
                assert(!i);
        c_rbtree_for_each_safe(i, is, &t)
                assert(!i);
        c_rbtree_for_each_entry(ie, &t, rb)
                assert(!ie);
        c_rbtree_for_each_entry_safe(ie, ies, &t, rb)
                assert(!ie);

        c_rbtree_for_each_postorder(i, &t)
                assert(!i);
        c_rbtree_for_each_safe_postorder(i, is, &t)
                assert(!i);
        c_rbtree_for_each_entry_postorder(ie, &t, rb)
                assert(!ie);
        c_rbtree_for_each_entry_safe_postorder(ie, ies, &t, rb)
                assert(!ie);

        c_rbtree_for_each_safe_postorder_unlink(i, is, &t)
                assert(!i);
        c_rbtree_for_each_entry_safe_postorder_unlink(ie, ies, &t, rb)
                assert(!ie);
}

int main(int argc, char **argv) {
        test_api();
        return 0;
}
