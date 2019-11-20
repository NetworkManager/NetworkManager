/*
 * RB-Tree Implementation
 * This implements the insertion/removal of elements in RB-Trees. You're highly
 * recommended to have an RB-Tree documentation at hand when reading this. Both
 * insertion and removal can be split into a handful of situations that can
 * occur. Those situations are enumerated as "Case 1" to "Case n" here, and
 * follow closely the cases described in most RB-Tree documentations. This file
 * does not explain why it is enough to handle just those cases, nor does it
 * provide a proof of correctness. Dig out your algorithm 101 handbook if
 * you're interested.
 *
 * This implementation is *not* straightforward. Usually, a handful of
 * rotation, reparent, swap and link helpers can be used to implement the
 * rebalance operations. However, those often perform unnecessary writes.
 * Therefore, this implementation hard-codes all the operations. You're highly
 * recommended to look at the two basic helpers before reading the code:
 *     c_rbnode_swap_child()
 *     c_rbnode_set_parent_and_flags()
 * Those are the only helpers used, hence, you should really know what they do
 * before digging into the code.
 *
 * For a highlevel documentation of the API, see the header file and docbook
 * comments.
 */

#include <assert.h>
#include <c-stdaux.h>
#include <stdalign.h>
#include <stddef.h>
#include "c-rbtree.h"
#include "c-rbtree-private.h"

/*
 * We use alignas(8) to enforce 64bit alignment of structure fields. This is
 * according to ISO-C11, so we rely on the compiler to implement this. However,
 * at the same time we don't want to exceed native malloc() alignment on target
 * platforms. Hence, we also verify against max_align_t.
 */
static_assert(alignof(CRBNode) <= alignof(max_align_t), "Invalid RBNode alignment");
static_assert(alignof(CRBNode) >= 8, "Invalid CRBNode alignment");
static_assert(alignof(CRBTree) <= alignof(max_align_t), "Invalid RBTree alignment");
static_assert(alignof(CRBTree) >= 8, "Invalid CRBTree alignment");

/**
 * c_rbnode_leftmost() - return leftmost child
 * @n:          current node, or NULL
 *
 * This returns the leftmost child of @n. If @n is NULL, this will return NULL.
 * In all other cases, this function returns a valid pointer. That is, if @n
 * does not have any left children, this returns @n.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to leftmost child, or NULL.
 */
_c_public_ CRBNode *c_rbnode_leftmost(CRBNode *n) {
        if (n)
                while (n->left)
                        n = n->left;
        return n;
}

/**
 * c_rbnode_rightmost() - return rightmost child
 * @n:          current node, or NULL
 *
 * This returns the rightmost child of @n. If @n is NULL, this will return
 * NULL. In all other cases, this function returns a valid pointer. That is, if
 * @n does not have any right children, this returns @n.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to rightmost child, or NULL.
 */
_c_public_ CRBNode *c_rbnode_rightmost(CRBNode *n) {
        if (n)
                while (n->right)
                        n = n->right;
        return n;
}

/**
 * c_rbnode_leftdeepest() - return left-deepest child
 * @n:          current node, or NULL
 *
 * This returns the left-deepest child of @n. If @n is NULL, this will return
 * NULL. In all other cases, this function returns a valid pointer. That is, if
 * @n does not have any children, this returns @n.
 *
 * The left-deepest child is defined as the deepest child without any left
 * (grand-...)siblings.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to left-deepest child, or NULL.
 */
_c_public_ CRBNode *c_rbnode_leftdeepest(CRBNode *n) {
        if (n) {
                for (;;) {
                        if (n->left)
                                n = n->left;
                        else if (n->right)
                                n = n->right;
                        else
                                break;
                }
        }
        return n;
}

/**
 * c_rbnode_rightdeepest() - return right-deepest child
 * @n:          current node, or NULL
 *
 * This returns the right-deepest child of @n. If @n is NULL, this will return
 * NULL. In all other cases, this function returns a valid pointer. That is, if
 * @n does not have any children, this returns @n.
 *
 * The right-deepest child is defined as the deepest child without any right
 * (grand-...)siblings.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to right-deepest child, or NULL.
 */
_c_public_ CRBNode *c_rbnode_rightdeepest(CRBNode *n) {
        if (n) {
                for (;;) {
                        if (n->right)
                                n = n->right;
                        else if (n->left)
                                n = n->left;
                        else
                                break;
                }
        }
        return n;
}

/**
 * c_rbnode_next() - return next node
 * @n:          current node, or NULL
 *
 * An RB-Tree always defines a linear order of its elements. This function
 * returns the logically next node to @n. If @n is NULL, the last node or
 * unlinked, this returns NULL.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to next node, or NULL.
 */
_c_public_ CRBNode *c_rbnode_next(CRBNode *n) {
        CRBNode *p;

        if (!c_rbnode_is_linked(n))
                return NULL;
        if (n->right)
                return c_rbnode_leftmost(n->right);

        while ((p = c_rbnode_parent(n)) && n == p->right)
                n = p;

        return p;
}

/**
 * c_rbnode_prev() - return previous node
 * @n:          current node, or NULL
 *
 * An RB-Tree always defines a linear order of its elements. This function
 * returns the logically previous node to @n. If @n is NULL, the first node or
 * unlinked, this returns NULL.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to previous node, or NULL.
 */
_c_public_ CRBNode *c_rbnode_prev(CRBNode *n) {
        CRBNode *p;

        if (!c_rbnode_is_linked(n))
                return NULL;
        if (n->left)
                return c_rbnode_rightmost(n->left);

        while ((p = c_rbnode_parent(n)) && n == p->left)
                n = p;

        return p;
}

/**
 * c_rbnode_next_postorder() - return next node in post-order
 * @n:          current node, or NULL
 *
 * This returns the next node to @n, based on a left-to-right post-order
 * traversal. If @n is NULL, the root node, or unlinked, this returns NULL.
 *
 * This implements a left-to-right post-order traversal: First visit the left
 * child of a node, then the right, and lastly the node itself. Children are
 * traversed recursively.
 *
 * This function can be used to implement a left-to-right post-order traversal:
 *
 *     for (n = c_rbtree_first_postorder(t); n; n = c_rbnode_next_postorder(n))
 *             visit(n);
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to next node, or NULL.
 */
_c_public_ CRBNode *c_rbnode_next_postorder(CRBNode *n) {
        CRBNode *p;

        if (!c_rbnode_is_linked(n))
                return NULL;

        p = c_rbnode_parent(n);
        if (p && n == p->left && p->right)
                return c_rbnode_leftdeepest(p->right);

        return p;
}

/**
 * c_rbnode_prev_postorder() - return previous node in post-order
 * @n:          current node, or NULL
 *
 * This returns the previous node to @n, based on a left-to-right post-order
 * traversal. That is, it is the inverse operation to c_rbnode_next_postorder().
 * If @n is NULL, the left-deepest node, or unlinked, this returns NULL.
 *
 * This function returns the logical previous node in a directed post-order
 * traversal. That is, it effectively does a pre-order traversal (since a
 * reverse post-order traversal is a pre-order traversal). This function does
 * NOT do a right-to-left post-order traversal! In other words, the following
 * invariant is guaranteed, if c_rbnode_next_postorder(n) is non-NULL:
 *
 *     n == c_rbnode_prev_postorder(c_rbnode_next_postorder(n))
 *
 * This function can be used to implement a right-to-left pre-order traversal,
 * using the fact that a reverse post-order traversal is also a valid pre-order
 * traversal:
 *
 *     for (n = c_rbtree_last_postorder(t); n; n = c_rbnode_prev_postorder(n))
 *             visit(n);
 *
 * This would effectively perform a right-to-left pre-order traversal: first
 * visit a parent, then its right child, then its left child. Both children are
 * traversed recursively.
 *
 * Worst case runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to previous node in post-order, or NULL.
 */
_c_public_ CRBNode *c_rbnode_prev_postorder(CRBNode *n) {
        CRBNode *p;

        if (!c_rbnode_is_linked(n))
                return NULL;
        if (n->right)
                return n->right;
        if (n->left)
                return n->left;

        while ((p = c_rbnode_parent(n))) {
                if (p->left && n != p->left)
                        return p->left;
                n = p;
        }

        return NULL;
}

/**
 * c_rbtree_first() - return first node
 * @t:          tree to operate on
 *
 * An RB-Tree always defines a linear order of its elements. This function
 * returns the logically first node in @t. If @t is empty, NULL is returned.
 *
 * Fixed runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to first node, or NULL.
 */
_c_public_ CRBNode *c_rbtree_first(CRBTree *t) {
        c_assert(t);
        return c_rbnode_leftmost(t->root);
}

/**
 * c_rbtree_last() - return last node
 * @t:          tree to operate on
 *
 * An RB-Tree always defines a linear order of its elements. This function
 * returns the logically last node in @t. If @t is empty, NULL is returned.
 *
 * Fixed runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to last node, or NULL.
 */
_c_public_ CRBNode *c_rbtree_last(CRBTree *t) {
        c_assert(t);
        return c_rbnode_rightmost(t->root);
}

/**
 * c_rbtree_first_postorder() - return first node in post-order
 * @t:          tree to operate on
 *
 * This returns the first node of a left-to-right post-order traversal. That
 * is, it returns the left-deepest leaf. If the tree is empty, this returns
 * NULL.
 *
 * This can also be interpreted as the last node of a right-to-left pre-order
 * traversal.
 *
 * Fixed runtime (n: number of elements in tree): O(log(n))
 *
 * Return: Pointer to first node in post-order, or NULL.
 */
_c_public_ CRBNode *c_rbtree_first_postorder(CRBTree *t) {
        c_assert(t);
        return c_rbnode_leftdeepest(t->root);
}

/**
 * c_rbtree_last_postorder() - return last node in post-order
 * @t:          tree to operate on
 *
 * This returns the last node of a left-to-right post-order traversal. That is,
 * it always returns the root node, or NULL if the tree is empty.
 *
 * This can also be interpreted as the first node of a right-to-left pre-order
 * traversal.
 *
 * Fixed runtime (n: number of elements in tree): O(1)
 *
 * Return: Pointer to last node in post-order, or NULL.
 */
_c_public_ CRBNode *c_rbtree_last_postorder(CRBTree *t) {
        c_assert(t);
        return t->root;
}

static inline void c_rbtree_store(CRBNode **ptr, CRBNode *addr) {
        /*
         * We use volatile accesses whenever we STORE @left or @right members
         * of a node. This guarantees that any parallel, lockless lookup gets
         * to see those stores in the correct order, which itself guarantees
         * that there're no temporary loops during tree rotation.
         * Note that you still need to properly synchronize your accesses via
         * seqlocks, rcu, whatever. We just guarantee that you get *some*
         * result on a lockless traversal and never run into endless loops, or
         * undefined behavior.
         */
        *(volatile CRBNode **)ptr = addr;
}

/*
 * Set the flags and parent of a node. This should be treated as a simple
 * assignment of the 'flags' and 'parent' fields of the node. No other magic is
 * applied. But since both fields share its backing memory, this helper
 * function is provided.
 */
static inline void c_rbnode_set_parent_and_flags(CRBNode *n, CRBNode *p, unsigned long flags) {
        n->__parent_and_flags = (unsigned long)p | flags;
}

/*
 * Nodes in the tree do not separately store a point to the tree root. That is,
 * there is no way to access the tree-root in O(1) given an arbitrary node.
 * Fortunately, this is usually not required. The only situation where this is
 * needed is when rotating the root-node itself.
 *
 * In case of the root node, c_rbnode_parent() returns NULL. We use this fact
 * to re-use the parent-pointer storage of the root node to point to the
 * CRBTree root. This way, we can rotate the root-node (or add/remove it)
 * without requiring a separate tree-root pointer.
 *
 * However, to keep the tree-modification functions simple, we hide this detail
 * whenever possible. This means, c_rbnode_parent() will continue to return
 * NULL, and tree modifications will boldly reset the pointer to NULL on
 * rotation. Hence, the only way to retain this pointer is to call
 * c_rbnode_pop_root() on a possible root-node before rotating. This returns
 * NULL if the node in question is not the root node. Otherwise, it returns the
 * tree-root, and clears the pointer/flag from the node in question. This way,
 * you can perform tree operations as usual. Afterwards, use
 * c_rbnode_push_root() to restore the root-pointer on any possible new root.
 */
static inline CRBTree *c_rbnode_pop_root(CRBNode *n) {
        CRBTree *t = NULL;

        if (c_rbnode_is_root(n)) {
                t = c_rbnode_raw(n);
                n->__parent_and_flags = c_rbnode_flags(n) & ~C_RBNODE_ROOT;
        }

        return t;
}

/* counter-part to c_rbnode_pop_root() */
static inline CRBTree *c_rbnode_push_root(CRBNode *n, CRBTree *t) {
        if (t) {
                if (n)
                        n->__parent_and_flags = (unsigned long)t
                                                | c_rbnode_flags(n)
                                                | C_RBNODE_ROOT;
                c_rbtree_store(&t->root, n);
        }

        return NULL;
}

/*
 * This function partially swaps a child node with another one. That is, this
 * function changes the parent of @old to point to @new. That is, you use it
 * when swapping @old with @new, to update the parent's left/right pointer.
 * This function does *NOT* perform a full swap, nor does it touch any 'parent'
 * pointer.
 *
 * The sole purpose of this function is to shortcut left/right conditionals
 * like this:
 *
 *     if (old == old->parent->left)
 *             old->parent->left = new;
 *     else
 *             old->parent->right = new;
 *
 * That's it! If @old is the root node, this will do nothing. The caller must
 * employ c_rbnode_pop_root() and c_rbnode_push_root().
 */
static inline void c_rbnode_swap_child(CRBNode *old, CRBNode *new) {
        CRBNode *p = c_rbnode_parent(old);

        if (p) {
                if (p->left == old)
                        c_rbtree_store(&p->left, new);
                else
                        c_rbtree_store(&p->right, new);
        }
}

/**
 * c_rbtree_move() - move tree
 * @to:         destination tree
 * @from:       source tree
 *
 * This imports the entire tree from @from into @to. @to must be empty! @from
 * will be empty afterwards.
 *
 * Note that this operates in O(1) time. Only the root-entry is updated to
 * point to the new tree-root.
 */
_c_public_ void c_rbtree_move(CRBTree *to, CRBTree *from) {
        CRBTree *t;

        c_assert(!to->root);

        if (from->root) {
                t = c_rbnode_pop_root(from->root);
                c_assert(t == from);

                to->root = from->root;
                from->root = NULL;

                c_rbnode_push_root(to->root, to);
        }
}

static inline void c_rbtree_paint_terminal(CRBNode *n) {
        CRBNode *p, *g, *gg, *x;
        CRBTree *t;

        /*
         * Case 4:
         * This path assumes @n is red, @p is red, but the uncle is unset or
         * black. This implies @g exists and is black.
         *
         * This case requires up to 2 rotations to restore the tree invariants.
         * That is, it runs in O(1) time and fully restores the RB-Tree
         * invariants, all at the cost of performing at mots 2 rotations.
         */

        p = c_rbnode_parent(n);
        g = c_rbnode_parent(p);
        gg = c_rbnode_parent(g);

        c_assert(c_rbnode_is_red(p));
        c_assert(c_rbnode_is_black(g));
        c_assert(p == g->left || !g->left || c_rbnode_is_black(g->left));
        c_assert(p == g->right || !g->right || c_rbnode_is_black(g->right));

        if (p == g->left) {
                if (n == p->right) {
                        /*
                         * We're the right red child of a red parent, which is
                         * a left child. Rotate on parent and consider us to be
                         * the old parent and the old parent to be us, making us
                         * the left child instead of the right child so we can
                         * handle it the same as below. Rotating two red nodes
                         * changes none of the invariants.
                         */
                        x = n->left;
                        c_rbtree_store(&p->right, x);
                        c_rbtree_store(&n->left, p);
                        if (x)
                                c_rbnode_set_parent_and_flags(x, p, c_rbnode_flags(x));
                        c_rbnode_set_parent_and_flags(p, n, c_rbnode_flags(p));
                        p = n;
                }

                /* 'n' is invalid from here on! */

                /*
                 * We're the red left child of a red parent, black grandparent
                 * and uncle. Rotate parent on grandparent and switch their
                 * colors, making the parent black and the grandparent red. The
                 * root of this subtree was changed from the grandparent to the
                 * parent, but the color remained black, so the number of black
                 * nodes on each path stays the same. However, we got rid of
                 * the double red path as we are still the (red) child of the
                 * parent, which has now turned black. Note that had we been
                 * the right child, rather than the left child, we would now be
                 * the left child of the old grandparent, and we would still
                 * have a double red path. As the new grandparent remains
                 * black, we're done.
                 */
                x = p->right;
                t = c_rbnode_pop_root(g);
                c_rbtree_store(&g->left, x);
                c_rbtree_store(&p->right, g);
                c_rbnode_swap_child(g, p);
                if (x)
                        c_rbnode_set_parent_and_flags(x, g, c_rbnode_flags(x) & ~C_RBNODE_RED);
                c_rbnode_set_parent_and_flags(p, gg, c_rbnode_flags(p) & ~C_RBNODE_RED);
                c_rbnode_set_parent_and_flags(g, p, c_rbnode_flags(g) | C_RBNODE_RED);
                c_rbnode_push_root(p, t);
        } else /* if (p == g->right) */ { /* same as above, but mirrored */
                if (n == p->left) {
                        x = n->right;
                        c_rbtree_store(&p->left, n->right);
                        c_rbtree_store(&n->right, p);
                        if (x)
                                c_rbnode_set_parent_and_flags(x, p, c_rbnode_flags(x));
                        c_rbnode_set_parent_and_flags(p, n, c_rbnode_flags(p));
                        p = n;
                }

                x = p->left;
                t = c_rbnode_pop_root(g);
                c_rbtree_store(&g->right, x);
                c_rbtree_store(&p->left, g);
                c_rbnode_swap_child(g, p);
                if (x)
                        c_rbnode_set_parent_and_flags(x, g, c_rbnode_flags(x) & ~C_RBNODE_RED);
                c_rbnode_set_parent_and_flags(p, gg, c_rbnode_flags(p) & ~C_RBNODE_RED);
                c_rbnode_set_parent_and_flags(g, p, c_rbnode_flags(g) | C_RBNODE_RED);
                c_rbnode_push_root(p, t);
        }
}

static inline CRBNode *c_rbtree_paint_path(CRBNode *n) {
        CRBNode *p, *g, *u;

        for (;;) {
                p = c_rbnode_parent(n);
                if (!p) {
                        /*
                         * Case 1:
                         * We reached the root. Mark it black and be done. As
                         * all leaf-paths share the root, the ratio of black
                         * nodes on each path stays the same.
                         */
                        c_rbnode_set_parent_and_flags(n, c_rbnode_raw(n), c_rbnode_flags(n) & ~C_RBNODE_RED);
                        return NULL;
                } else if (c_rbnode_is_black(p)) {
                        /*
                         * Case 2:
                         * The parent is already black. As our node is red, we
                         * did not change the number of black nodes on any
                         * path, nor do we have multiple consecutive red nodes.
                         * There is nothing to be done.
                         */
                        return NULL;
                }

                g = c_rbnode_parent(p);
                u = (p == g->left) ? g->right : g->left;
                if (!u || !c_rbnode_is_red(u)) {
                        /*
                         * Case 4:
                         * The parent is red, but its uncle is black. By
                         * rotating the parent above the uncle, we distribute
                         * the red nodes and thus restore the tree invariants.
                         * No recursive fixup will be needed afterwards. Hence,
                         * just let the caller know about @n and make them do
                         * the rotations.
                         */
                        return n;
                }

                /*
                 * Case 3:
                 * Parent and uncle are both red, and grandparent is black.
                 * Repaint parent and uncle black, the grandparent red and
                 * recurse into the grandparent. Note that this is the only
                 * recursive case. That is, this step restores the tree
                 * invariants for the sub-tree below @p (including @n), but
                 * needs to continue the re-coloring two levels up.
                 */
                c_rbnode_set_parent_and_flags(p, g, c_rbnode_flags(p) & ~C_RBNODE_RED);
                c_rbnode_set_parent_and_flags(u, g, c_rbnode_flags(u) & ~C_RBNODE_RED);
                c_rbnode_set_parent_and_flags(g, c_rbnode_raw(g), c_rbnode_flags(g) | C_RBNODE_RED);
                n = g;
        }
}

static inline void c_rbtree_paint(CRBNode *n) {
        /*
         * When a new node is inserted into an RB-Tree, we always link it as a
         * tail-node and paint it red. This way, the node will not violate the
         * rb-tree invariants regarding the number of black nodes on all paths.
         *
         * However, a red node must never have another bordering red-node (ie.,
         * child or parent). Since the node is newly linked, it does not have
         * any children. Therefore, all we need to do is fix the path upwards
         * through all parents until we hit a black parent or can otherwise fix
         * the coloring.
         *
         * This function first walks up the path from @n towards the tree root
         * (done in c_rbtree_paint_path()). This recolors its parent/uncle, if
         * possible, until it hits a sub-tree that cannot be fixed via
         * re-coloring. After c_rbtree_paint_path() returns, there are two
         * possible outcomes:
         *
         *         1) @n is NULL, in which case the tree invariants were
         *            restored by mere recoloring. Nothing is to be done.
         *
         *         2) @n is non-NULL, but points to a red ancestor of the
         *            original node. In this case we need to restore the tree
         *            invariants via a simple left or right rotation. This will
         *            be done by c_rbtree_paint_terminal().
         *
         * As a summary, this function runs O(log(n)) re-coloring operations in
         * the worst case, followed by O(1) rotations as final restoration. The
         * amortized cost, however, is O(1), since re-coloring only recurses
         * upwards if it hits a red uncle (which can only happen if a previous
         * operation terminated its operation on that layer).
         * While amortized painting of inserted nodes is O(1), finding the
         * correct spot to link the node (before painting it) still requires a
         * search in the binary tree in O(log(n)).
         */
        n = c_rbtree_paint_path(n);
        if (n)
                c_rbtree_paint_terminal(n);
}

/**
 * c_rbnode_link() - link node into tree
 * @p:          parent node to link under
 * @l:          left/right slot of @p to link at
 * @n:          node to add
 *
 * This links @n into an tree underneath another node. The caller must provide
 * the exact spot where to link the node. That is, the caller must traverse the
 * tree based on their search order. Once they hit a leaf where to insert the
 * node, call this function to link it and rebalance the tree.
 *
 * For this to work, the caller must provide a pointer to the parent node. If
 * the tree might be empty, you must resort to c_rbtree_add().
 *
 * In most cases you are better off using c_rbtree_add(). See there for details
 * how tree-insertion works.
 */
_c_public_ void c_rbnode_link(CRBNode *p, CRBNode **l, CRBNode *n) {
        c_assert(p);
        c_assert(l);
        c_assert(n);
        c_assert(l == &p->left || l == &p->right);

        c_rbnode_set_parent_and_flags(n, p, C_RBNODE_RED);
        c_rbtree_store(&n->left, NULL);
        c_rbtree_store(&n->right, NULL);
        c_rbtree_store(l, n);

        c_rbtree_paint(n);
}

/**
 * c_rbtree_add() - add node to tree
 * @t:          tree to operate one
 * @p:          parent node to link under, or NULL
 * @l:          left/right slot of @p (or root) to link at
 * @n:          node to add
 *
 * This links @n into the tree given as @t. The caller must provide the exact
 * spot where to link the node. That is, the caller must traverse the tree
 * based on their search order. Once they hit a leaf where to insert the node,
 * call this function to link it and rebalance the tree.
 *
 * A typical insertion would look like this (@t is your tree, @n is your node):
 *
 *        CRBNode **i, *p;
 *
 *        i = &t->root;
 *        p = NULL;
 *        while (*i) {
 *                p = *i;
 *                if (compare(n, *i) < 0)
 *                        i = &(*i)->left;
 *                else
 *                        i = &(*i)->right;
 *        }
 *
 *        c_rbtree_add(t, p, i, n);
 *
 * Once the node is linked into the tree, a simple lookup on the same tree can
 * be coded like this:
 *
 *        CRBNode *i;
 *
 *        i = t->root;
 *        while (i) {
 *                int v = compare(n, i);
 *                if (v < 0)
 *                        i = (*i)->left;
 *                else if (v > 0)
 *                        i = (*i)->right;
 *                else
 *                        break;
 *        }
 *
 * When you add nodes to a tree, the memory contents of the node do not matter.
 * That is, there is no need to initialize the node via c_rbnode_init().
 * However, if you relink nodes multiple times during their lifetime, it is
 * usually very convenient to use c_rbnode_init() and c_rbnode_unlink() (rather
 * than c_rbnode_unlink_stale()). In those cases, you should validate that a
 * node is unlinked before you call c_rbtree_add().
 */
_c_public_ void c_rbtree_add(CRBTree *t, CRBNode *p, CRBNode **l, CRBNode *n) {
        c_assert(t);
        c_assert(l);
        c_assert(n);
        c_assert(!p || l == &p->left || l == &p->right);
        c_assert(p || l == &t->root);

        c_rbnode_set_parent_and_flags(n, p, C_RBNODE_RED);
        c_rbtree_store(&n->left, NULL);
        c_rbtree_store(&n->right, NULL);

        if (p)
                c_rbtree_store(l, n);
        else
                c_rbnode_push_root(n, t);

        c_rbtree_paint(n);
}

static inline void c_rbnode_rebalance_terminal(CRBNode *p, CRBNode *previous) {
        CRBNode *s, *x, *y, *g;
        CRBTree *t;

        if (previous == p->left) {
                s = p->right;
                if (c_rbnode_is_red(s)) {
                        /*
                         * Case 2:
                         * We have a red node as sibling. Rotate it onto our
                         * side so we can later on turn it black. This way, we
                         * gain the additional black node in our path.
                         */
                        t = c_rbnode_pop_root(p);
                        g = c_rbnode_parent(p);
                        x = s->left;
                        c_rbtree_store(&p->right, x);
                        c_rbtree_store(&s->left, p);
                        c_rbnode_swap_child(p, s);
                        c_rbnode_set_parent_and_flags(x, p, c_rbnode_flags(x) & ~C_RBNODE_RED);
                        c_rbnode_set_parent_and_flags(s, g, c_rbnode_flags(s) & ~C_RBNODE_RED);
                        c_rbnode_set_parent_and_flags(p, s, c_rbnode_flags(p) | C_RBNODE_RED);
                        c_rbnode_push_root(s, t);
                        s = x;
                }

                x = s->right;
                if (!x || c_rbnode_is_black(x)) {
                        y = s->left;
                        if (!y || c_rbnode_is_black(y)) {
                                /*
                                 * Case 3+4:
                                 * Our sibling is black and has only black
                                 * children. Flip it red and turn parent black.
                                 * This way we gained a black node in our path.
                                 * Note that the parent must be red, otherwise
                                 * it must have been handled by our caller.
                                 */
                                c_assert(c_rbnode_is_red(p));
                                c_rbnode_set_parent_and_flags(s, p, c_rbnode_flags(s) | C_RBNODE_RED);
                                c_rbnode_set_parent_and_flags(p, c_rbnode_parent(p), c_rbnode_flags(p) & ~C_RBNODE_RED);
                                return;
                        }

                        /*
                         * Case 5:
                         * Left child of our sibling is red, right one is black.
                         * Rotate on parent so the right child of our sibling is
                         * now red, and we can fall through to case 6.
                         */
                        x = y->right;
                        c_rbtree_store(&s->left, y->right);
                        c_rbtree_store(&y->right, s);
                        c_rbtree_store(&p->right, y);
                        if (x)
                                c_rbnode_set_parent_and_flags(x, s, c_rbnode_flags(x) & ~C_RBNODE_RED);
                        x = s;
                        s = y;
                }

                /*
                 * Case 6:
                 * The right child of our sibling is red. Rotate left and flip
                 * colors, which gains us an additional black node in our path,
                 * that was previously on our sibling.
                 */
                t = c_rbnode_pop_root(p);
                g = c_rbnode_parent(p);
                y = s->left;
                c_rbtree_store(&p->right, y);
                c_rbtree_store(&s->left, p);
                c_rbnode_swap_child(p, s);
                c_rbnode_set_parent_and_flags(x, s, c_rbnode_flags(x) & ~C_RBNODE_RED);
                if (y)
                        c_rbnode_set_parent_and_flags(y, p, c_rbnode_flags(y));
                c_rbnode_set_parent_and_flags(s, g, c_rbnode_flags(p));
                c_rbnode_set_parent_and_flags(p, s, c_rbnode_flags(p) & ~C_RBNODE_RED);
                c_rbnode_push_root(s, t);
        } else /* if (previous == p->right) */ { /* same as above, but mirrored */
                s = p->left;
                if (c_rbnode_is_red(s)) {
                        t = c_rbnode_pop_root(p);
                        g = c_rbnode_parent(p);
                        x = s->right;
                        c_rbtree_store(&p->left, x);
                        c_rbtree_store(&s->right, p);
                        c_rbnode_swap_child(p, s);
                        c_rbnode_set_parent_and_flags(x, p, c_rbnode_flags(x) & ~C_RBNODE_RED);
                        c_rbnode_set_parent_and_flags(s, g, c_rbnode_flags(s) & ~C_RBNODE_RED);
                        c_rbnode_set_parent_and_flags(p, s, c_rbnode_flags(p) | C_RBNODE_RED);
                        c_rbnode_push_root(s, t);
                        s = x;
                }

                x = s->left;
                if (!x || c_rbnode_is_black(x)) {
                        y = s->right;
                        if (!y || c_rbnode_is_black(y)) {
                                c_assert(c_rbnode_is_red(p));
                                c_rbnode_set_parent_and_flags(s, p, c_rbnode_flags(s) | C_RBNODE_RED);
                                c_rbnode_set_parent_and_flags(p, c_rbnode_parent(p), c_rbnode_flags(p) & ~C_RBNODE_RED);
                                return;
                        }

                        x = y->left;
                        c_rbtree_store(&s->right, y->left);
                        c_rbtree_store(&y->left, s);
                        c_rbtree_store(&p->left, y);
                        if (x)
                                c_rbnode_set_parent_and_flags(x, s, c_rbnode_flags(x) & ~C_RBNODE_RED);
                        x = s;
                        s = y;
                }

                t = c_rbnode_pop_root(p);
                g = c_rbnode_parent(p);
                y = s->right;
                c_rbtree_store(&p->left, y);
                c_rbtree_store(&s->right, p);
                c_rbnode_swap_child(p, s);
                c_rbnode_set_parent_and_flags(x, s, c_rbnode_flags(x) & ~C_RBNODE_RED);
                if (y)
                        c_rbnode_set_parent_and_flags(y, p, c_rbnode_flags(y));
                c_rbnode_set_parent_and_flags(s, g, c_rbnode_flags(p));
                c_rbnode_set_parent_and_flags(p, s, c_rbnode_flags(p) & ~C_RBNODE_RED);
                c_rbnode_push_root(s, t);
        }
}

static inline CRBNode *c_rbnode_rebalance_path(CRBNode *p, CRBNode **previous) {
        CRBNode *s, *nl, *nr;

        while (p) {
                s = (*previous == p->left) ? p->right : p->left;
                nl = s->left;
                nr = s->right;

                /*
                 * If the sibling under @p is black and exclusively has black
                 * children itself (i.e., nephews/nieces in @nl/@nr), then we
                 * can easily re-color to fix this sub-tree, and continue one
                 * layer up. However, if that's not the case, we have tree
                 * rotations at our hands to move one of the black nodes into
                 * our path, then turning the red node black to fully restore
                 * the RB-Tree invariants again. This fixup will be done by the
                 * caller, so we just let them know where to do that.
                 */
                if (c_rbnode_is_red(s) ||
                    (nl && c_rbnode_is_red(nl)) ||
                    (nr && c_rbnode_is_red(nr)))
                        return p;

                /*
                 * Case 3+4:
                 * Sibling is black, and all nephews/nieces are black. Flip
                 * sibling red. This way the sibling lost a black node in its
                 * path, thus getting even with our path. However, paths not
                 * going through @p haven't been fixed up, hence we proceed
                 * recursively one layer up.
                 * Before we continue one layer up, there are two possible
                 * terminations: If the parent is red, we can turn it black.
                 * This terminates the rebalancing, since the entire point of
                 * rebalancing is that everything below @p has one black node
                 * less than everything else. Lastly, if there is no layer
                 * above, we hit the tree root and nothing is left to be done.
                 */
                c_rbnode_set_parent_and_flags(s, p, c_rbnode_flags(s) | C_RBNODE_RED);
                if (c_rbnode_is_red(p)) {
                        c_rbnode_set_parent_and_flags(p, c_rbnode_parent(p), c_rbnode_flags(p) & ~C_RBNODE_RED);
                        return NULL;
                }

                *previous = p;
                p = c_rbnode_parent(p);
        }

        return NULL;
}

static inline void c_rbnode_rebalance(CRBNode *n) {
        CRBNode *previous = NULL;

        /*
         * Rebalance a tree after a node was removed. This function must be
         * called on the parent of the leaf that was removed. It will first
         * perform a recursive re-coloring on the parents of @n, until it
         * either hits the tree-root, or a condition where a tree-rotation is
         * needed to restore the RB-Tree invariants.
         */

        n = c_rbnode_rebalance_path(n, &previous);
        if (n)
                c_rbnode_rebalance_terminal(n, previous);
}

/**
 * c_rbnode_unlink_stale() - remove node from tree
 * @n:          node to remove
 *
 * This removes the given node from its tree. Once unlinked, the tree is
 * rebalanced.
 *
 * This does *NOT* reset @n to being unlinked. If you need this, use
 * c_rbtree_unlink().
 */
_c_public_ void c_rbnode_unlink_stale(CRBNode *n) {
        CRBTree *t;

        c_assert(n);
        c_assert(c_rbnode_is_linked(n));

        /*
         * There are three distinct cases during node removal of a tree:
         *  * The node has no children, in which case it can simply be removed.
         *  * The node has exactly one child, in which case the child displaces
         *    its parent.
         *  * The node has two children, in which case there is guaranteed to
         *    be a successor to the node (successor being the node ordered
         *    directly after it). This successor is the leftmost descendant of
         *    the node's right child, so it cannot have a left child of its own.
         *    Therefore, we can simply swap the node with its successor (including
         *    color) and remove the node from its new place, which will be one of
         *    the first two cases.
         *
         * Whenever the node we removed was black, we have to rebalance the
         * tree. Note that this affects the actual node we _remove_, not @n (in
         * case we swap it).
         */

        if (!n->left && !n->right) {
                /*
                 * Case 1.0
                 * The node has no children, it is a leaf-node and we
                 * can simply unlink it. If it was also black, we have
                 * to rebalance.
                 */
                t = c_rbnode_pop_root(n);
                c_rbnode_swap_child(n, NULL);
                c_rbnode_push_root(NULL, t);

                if (c_rbnode_is_black(n))
                        c_rbnode_rebalance(c_rbnode_parent(n));
        } else if (!n->left && n->right) {
                /*
                 * Case 1.1:
                 * The node has exactly one child, and it is on the
                 * right. The child *must* be red (otherwise, the right
                 * path has more black nodes than the non-existing left
                 * path), and the node to be removed must hence be
                 * black. We simply replace the node with its child,
                 * turning the red child black, and thus no rebalancing
                 * is required.
                 */
                t = c_rbnode_pop_root(n);
                c_rbnode_swap_child(n, n->right);
                c_rbnode_set_parent_and_flags(n->right, c_rbnode_parent(n), c_rbnode_flags(n->right) & ~C_RBNODE_RED);
                c_rbnode_push_root(n->right, t);
        } else if (n->left && !n->right) {
                /*
                 * Case 1.2:
                 * The node has exactly one child, and it is on the left. Treat
                 * it as mirrored case of Case 1.1 (i.e., replace the node by
                 * its child).
                 */
                t = c_rbnode_pop_root(n);
                c_rbnode_swap_child(n, n->left);
                c_rbnode_set_parent_and_flags(n->left, c_rbnode_parent(n), c_rbnode_flags(n->left) & ~C_RBNODE_RED);
                c_rbnode_push_root(n->left, t);
        } else /* if (n->left && n->right) */ {
                CRBNode *s, *p, *c, *next = NULL;

                /* Cache possible tree-root during tree-rotations. */
                t = c_rbnode_pop_root(n);

                /*
                 * Case 1.3:
                 * We are dealing with a full interior node with a child on
                 * both sides. We want to find its successor and swap it,
                 * then remove the node similar to Case 1. For performance
                 * reasons we don't perform the full swap, but skip links
                 * that are about to be removed, anyway.
                 *
                 * First locate the successor, remember its child and the
                 * parent the original node should have been linked on,
                 * before being removed. Then link up both the successor's
                 * new children and old child.
                 *
                 *      s: successor
                 *      p: parent
                 *      c: right (and only potential) child of successor
                 *      next: next node to rebalance on
                 */
                s = n->right;
                if (!s->left) {
                        /*
                         * The immediate right child is the successor,
                         * the successor's right child remains linked
                         * as before.
                         */
                        p = s;
                        c = s->right;
                } else {
                        s = c_rbnode_leftmost(s);
                        p = c_rbnode_parent(s);
                        c = s->right;

                        /*
                         * The new parent pointer of the successor's
                         * child is set below.
                         */
                        c_rbtree_store(&p->left, c);

                        c_rbtree_store(&s->right, n->right);
                        c_rbnode_set_parent_and_flags(n->right, s, c_rbnode_flags(n->right));
                }

                /*
                 * In both the above cases, the successor's left child
                 * needs to be replaced with the left child of the node
                 * that is being removed.
                 */
                c_rbtree_store(&s->left, n->left);
                c_rbnode_set_parent_and_flags(n->left, s, c_rbnode_flags(n->left));

                /*
                 * As in cases 1.1 and 1.0 above, if successor was a
                 * black leaf, we need to rebalance the tree, otherwise
                 * it must have a red child, so simply recolor that black
                 * and continue. Note that @next must be stored here, as
                 * the original color of the successor is forgotten below.
                 */
                if (c)
                        c_rbnode_set_parent_and_flags(c, p, c_rbnode_flags(c) & ~C_RBNODE_RED);
                else
                        next = c_rbnode_is_black(s) ? p : NULL;

                /*
                 * Update the successor, to inherit the parent and color
                 * from the node being removed.
                 */
                if (c_rbnode_is_red(n))
                        c_rbnode_set_parent_and_flags(s, c_rbnode_parent(n), c_rbnode_flags(s) | C_RBNODE_RED);
                else
                        c_rbnode_set_parent_and_flags(s, c_rbnode_parent(n), c_rbnode_flags(s) & ~C_RBNODE_RED);

                /*
                 * Update the parent of the node being removed. Note that this
                 * needs to happen after the parent of the successor is set
                 * above, as that call would clear the root pointer, if set.
                 */
                c_rbnode_swap_child(n, s);

                /* Possibly restore saved tree-root. */
                c_rbnode_push_root(s, t);

                if (next)
                        c_rbnode_rebalance(next);
        }
}
