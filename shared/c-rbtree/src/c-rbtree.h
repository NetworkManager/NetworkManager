#pragma once

/**
 * Standalone Red-Black-Tree Implementation in Standard ISO-C11
 *
 * This library provides an RB-Tree API, that is fully implemented in ISO-C11
 * and has no external dependencies. Furthermore, tree traversal, memory
 * allocations, and key comparisons are completely controlled by the API user.
 * The implementation only provides the RB-Tree specific rebalancing and
 * coloring.
 *
 * A tree is represented by the "CRBTree" structure. It contains a *single*
 * field, which is a pointer to the root node. If NULL, the tree is empty. If
 * non-NULL, there is at least a single element in the tree.
 *
 * Each node of the tree is represented by the "CRBNode" structure. It has
 * three fields. The @left and @right members can be accessed by the API user
 * directly to traverse the tree. The third member is a combination of the
 * parent pointer and a set of flags.
 * API users are required to embed the CRBNode object into their own objects
 * and then use offsetof() (i.e., container_of() and friends) to turn CRBNode
 * pointers into pointers to their own structure.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>

typedef struct CRBNode CRBNode;
typedef struct CRBTree CRBTree;

/* implementation detail */
#define C_RBNODE_RED                    (0x1UL)
#define C_RBNODE_ROOT                   (0x2UL)
#define C_RBNODE_UNUSED3                (0x4UL)
#define C_RBNODE_FLAG_MASK              (0x7UL)

/**
 * struct CRBNode - Node of a Red-Black Tree
 * @__parent_and_flags:         internal state
 * @left:                       left child, or NULL
 * @right:                      right child, or NULL
 *
 * Each node in an RB-Tree must embed a CRBNode object. This object contains
 * pointers to its left and right child, which can be freely accessed by the
 * API user at any time. They are NULL, if the node does not have a left/right
 * child.
 *
 * The @__parent_and_flags field must never be accessed directly. It encodes
 * the pointer to the parent node, and the color of the node. Use the accessor
 * functions instead.
 *
 * There is no reason to initialize a CRBNode object before linking it.
 * However, if you need a boolean state that tells you whether the node is
 * linked or not, you should initialize the node via c_rbnode_init() or
 * C_RBNODE_INIT.
 */
struct CRBNode {
        alignas(8) unsigned long __parent_and_flags;
        CRBNode *left;
        CRBNode *right;
};

#define C_RBNODE_INIT(_var) { .__parent_and_flags = (unsigned long)&(_var) }

CRBNode *c_rbnode_leftmost(CRBNode *n);
CRBNode *c_rbnode_rightmost(CRBNode *n);
CRBNode *c_rbnode_leftdeepest(CRBNode *n);
CRBNode *c_rbnode_rightdeepest(CRBNode *n);
CRBNode *c_rbnode_next(CRBNode *n);
CRBNode *c_rbnode_prev(CRBNode *n);
CRBNode *c_rbnode_next_postorder(CRBNode *n);
CRBNode *c_rbnode_prev_postorder(CRBNode *n);

void c_rbnode_link(CRBNode *p, CRBNode **l, CRBNode *n);
void c_rbnode_unlink_stale(CRBNode *n);

/**
 * struct CRBTree - Red-Black Tree
 * @root:       pointer to the root node, or NULL
 *
 * Each Red-Black Tree is rooted in an CRBTree object. This object contains a
 * pointer to the root node of the tree. The API user is free to access the
 * @root member at any time, and use it to traverse the tree.
 *
 * To initialize an RB-Tree, set it to NULL / all zero.
 */
struct CRBTree {
        alignas(8) CRBNode *root;
};

#define C_RBTREE_INIT {}

CRBNode *c_rbtree_first(CRBTree *t);
CRBNode *c_rbtree_last(CRBTree *t);
CRBNode *c_rbtree_first_postorder(CRBTree *t);
CRBNode *c_rbtree_last_postorder(CRBTree *t);

void c_rbtree_move(CRBTree *to, CRBTree *from);
void c_rbtree_add(CRBTree *t, CRBNode *p, CRBNode **l, CRBNode *n);

/**
 * c_rbnode_init() - mark a node as unlinked
 * @n:          node to operate on
 *
 * This marks the node @n as unlinked. The node will be set to a valid state
 * that can never happen if the node is linked in a tree. Furthermore, this
 * state is fully known to the implementation, and as such handled gracefully
 * in all cases.
 *
 * You are *NOT* required to call this on your node. c_rbtree_add() can handle
 * uninitialized nodes just fine. However, calling this allows to use
 * c_rbnode_is_linked() to check for the state of a node. Furthermore,
 * iterators and accessors can be called on initialized (yet unlinked) nodes.
 *
 * Use the C_RBNODE_INIT macro if you want to initialize static variables.
 */
static inline void c_rbnode_init(CRBNode *n) {
        *n = (CRBNode)C_RBNODE_INIT(*n);
}

/**
 * c_rbnode_entry() - get parent container of tree node
 * @_what:              tree node, or NULL
 * @_t:                 type of parent container
 * @_m:                 member name of tree node in @_t
 *
 * If the tree node @_what is embedded into a surrounding structure, this will
 * turn the tree node pointer @_what into a pointer to the parent container
 * (using offsetof(3), or sometimes called container_of(3)).
 *
 * If @_what is NULL, this will also return NULL.
 *
 * Return: Pointer to parent container, or NULL.
 */
#define c_rbnode_entry(_what, _t, _m) \
        ((_t *)(void *)(((unsigned long)(void *)(_what) ?: \
                         offsetof(_t, _m)) - offsetof(_t, _m)))

/**
 * c_rbnode_parent() - return parent pointer
 * @n           node to access
 *
 * This returns a pointer to the parent of the given node @n. If @n does not
 * have a parent, NULL is returned. If @n is not linked, @n itself is returned.
 *
 * You should not call this on unlinked or uninitialized nodes! If you do, you
 * better know its semantics.
 *
 * Return: Pointer to parent.
 */
static inline CRBNode *c_rbnode_parent(CRBNode *n) {
        return (n->__parent_and_flags & C_RBNODE_ROOT) ?
                        NULL :
                        (void *)(n->__parent_and_flags & ~C_RBNODE_FLAG_MASK);
}

/**
 * c_rbnode_is_linked() - check whether a node is linked
 * @n:          node to check, or NULL
 *
 * This checks whether the passed node is linked. If you pass NULL, or if the
 * node is not linked into a tree, this will return false. Otherwise, this
 * returns true.
 *
 * Note that you must have either linked the node or initialized it, before
 * calling this function. Never call this function on uninitialized nodes.
 * Furthermore, removing a node via c_rbnode_unlink_stale() does *NOT* mark the
 * node as unlinked. You have to call c_rbnode_init() yourself after removal, or
 * use the c_rbnode_unlink() helper.
 *
 * Return: true if the node is linked, false if not.
 */
static inline _Bool c_rbnode_is_linked(CRBNode *n) {
        return n && c_rbnode_parent(n) != n;
}

/**
 * c_rbnode_unlink() - safely remove node from tree and reinitialize it
 * @n:          node to remove, or NULL
 *
 * This is almost the same as c_rbnode_unlink_stale(), but extends it slightly, to be
 * more convenient to use in many cases:
 *  - if @n is unlinked or NULL, this is a no-op
 *  - @n is reinitialized after being removed
 */
static inline void c_rbnode_unlink(CRBNode *n) {
        if (c_rbnode_is_linked(n)) {
                c_rbnode_unlink_stale(n);
                c_rbnode_init(n);
        }
}

/**
 * c_rbtree_init() - initialize a new RB-Tree
 * @t:          tree to operate on
 *
 * This initializes a new, empty RB-Tree. An RB-Tree must be initialized before
 * any other functions are called on it. Alternatively, you can zero its memory
 * or assign C_RBTREE_INIT.
 */
static inline void c_rbtree_init(CRBTree *t) {
        *t = (CRBTree)C_RBTREE_INIT;
}

/**
 * c_rbtree_is_empty() - check whether an RB-tree is empty
 * @t:          tree to operate on
 *
 * This checks whether the passed RB-Tree is empty.
 *
 * Return: True if tree is empty, false otherwise.
 */
static inline _Bool c_rbtree_is_empty(CRBTree *t) {
        return !t->root;
}

/**
 * CRBCompareFunc - compare a node to a key
 * @t:          tree where the node is linked to
 * @k:          key to compare
 * @n:          node to compare
 *
 * If you use the tree-traversal helpers (which are optional), you need to
 * provide this callback so they can compare nodes in a tree to the key you
 * look for.
 *
 * The tree @t is provided as optional context to this callback. The key you
 * look for is provided as @k, the current node that should be compared to is
 * provided as @n. This function should work like strcmp(), that is, return <0
 * if @key orders before @n, 0 if both compare equal, and >0 if it orders after
 * @n.
 */
typedef int (*CRBCompareFunc) (CRBTree *t, void *k, CRBNode *n);

/**
 * c_rbtree_find_node() - find node
 * @t:          tree to search through
 * @f:          comparison function
 * @k:          key to search for
 *
 * This searches through @t for a node that compares equal to @k. The function
 * @f must be provided by the caller, which is used to compare nodes to @k. See
 * the documentation of CRBCompareFunc for details.
 *
 * If there are multiple entries that compare equal to @k, this will return a
 * pseudo-randomly picked node. If you need stable lookup functions for trees
 * where duplicate entries are allowed, you better code your own lookup.
 *
 * Return: Pointer to matching node, or NULL.
 */
static inline CRBNode *c_rbtree_find_node(CRBTree *t, CRBCompareFunc f, const void *k) {
        CRBNode *i;

        assert(t);
        assert(f);

        i = t->root;
        while (i) {
                int v = f(t, (void *)k, i);
                if (v < 0)
                        i = i->left;
                else if (v > 0)
                        i = i->right;
                else
                        return i;
        }

        return NULL;
}

/**
 * c_rbtree_find_entry() - find entry
 * @_t:         tree to search through
 * @_f:         comparison function
 * @_k:         key to search for
 * @_s:         type of the structure that embeds the nodes
 * @_m:         name of the node-member in type @_t
 *
 * This is very similar to c_rbtree_find_node(), but instead of returning a
 * pointer to the CRBNode, it returns a pointer to the surrounding object. This
 * object must embed the CRBNode object. The type of the surrounding object
 * must be given as @_s, and the name of the embedded CRBNode member as @_m.
 *
 * See c_rbtree_find_node() and c_rbnode_entry() for more details.
 *
 * Return: Pointer to found entry, NULL if not found.
 */
#define c_rbtree_find_entry(_t, _f, _k, _s, _m) \
        c_rbnode_entry(c_rbtree_find_node((_t), (_f), (_k)), _s, _m)

/**
 * c_rbtree_find_slot() - find slot to insert new node
 * @t:          tree to search through
 * @f:          comparison function
 * @k:          key to search for
 * @p:          output storage for parent pointer
 *
 * This searches through @t just like c_rbtree_find_node() does. However,
 * instead of returning a pointer to a node that compares equal to @k, this
 * searches for a slot to insert a node with key @k. A pointer to the slot is
 * returned, and a pointer to the parent of the slot is stored in @p. Both
 * can be passed directly to c_rbtree_add(), together with your node to insert.
 *
 * If there already is a node in the tree, that compares equal to @k, this will
 * return NULL and store the conflicting node in @p. In all other cases,
 * this will return a pointer (non-NULL) to the empty slot to insert the node
 * at. @p will point to the parent node of that slot.
 *
 * If you want trees that allow duplicate nodes, you better code your own
 * insertion function.
 *
 * Return: Pointer to slot to insert node, or NULL on conflicts.
 */
static inline CRBNode **c_rbtree_find_slot(CRBTree *t, CRBCompareFunc f, const void *k, CRBNode **p) {
        CRBNode **i;

        assert(t);
        assert(f);
        assert(p);

        i = &t->root;
        *p = NULL;
        while (*i) {
                int v = f(t, (void *)k, *i);
                *p = *i;
                if (v < 0)
                        i = &(*i)->left;
                else if (v > 0)
                        i = &(*i)->right;
                else
                        return NULL;
        }

        return i;
}

/**
 * c_rbtree_for_each*() - iterators
 *
 * The c_rbtree_for_each*() macros provide simple for-loop wrappers to iterate
 * an RB-Tree. They come in a set of flavours:
 *
 *   - "entry": This combines c_rbnode_entry() with the loop iterator, so the
 *              iterator always has the type of the surrounding object, rather
 *              than CRBNode.
 *
 *   - "safe": The loop iterator always keeps track of the next element to
 *             visit. This means, you can safely modify the current element,
 *             while retaining loop-integrity.
 *             You still must not touch any other entry of the tree. Otherwise,
 *             the loop-iterator will be corrupted. Also remember to only
 *             modify the tree in a way compatible with your iterator-order.
 *             That is, if you use in-order iteration (default), you can unlink
 *             your current object, including re-balancing the tree. However,
 *             if you use post-order, you must not trigger a tree rebalance
 *             operation, since it is not an invariant of post-order iteration.
 *
 *   - "postorder": Rather than the default in-order iteration, this iterates
 *                  the tree in post-order.
 *
 *   - "unlink": This unlinks the current element from the tree before the loop
 *               code is run. Note that the tree is not rebalanced. That is,
 *               you must never break out of the loop. If you do so, the tree
 *               is corrupted.
 */

#define c_rbtree_for_each(_iter, _tree)                                                                 \
        for (_iter = c_rbtree_first(_tree);                                                             \
             _iter;                                                                                     \
             _iter = c_rbnode_next(_iter))

#define c_rbtree_for_each_entry(_iter, _tree, _m)                                                       \
        for (_iter = c_rbnode_entry(c_rbtree_first(_tree), __typeof__(*_iter), _m);                     \
             _iter;                                                                                     \
             _iter = c_rbnode_entry(c_rbnode_next(&_iter->_m), __typeof__(*_iter), _m))

#define c_rbtree_for_each_safe(_iter, _safe, _tree)                                                     \
        for (_iter = c_rbtree_first(_tree), _safe = c_rbnode_next(_iter);                               \
             _iter;                                                                                     \
             _iter = _safe, _safe = c_rbnode_next(_safe))

#define c_rbtree_for_each_entry_safe(_iter, _safe, _tree, _m)                                           \
        for (_iter = c_rbnode_entry(c_rbtree_first(_tree), __typeof__(*_iter), _m),                     \
             _safe = _iter ? c_rbnode_entry(c_rbnode_next(&_iter->_m), __typeof__(*_iter), _m) : NULL;  \
             _iter;                                                                                     \
             _iter = _safe,                                                                             \
             _safe = _safe ? c_rbnode_entry(c_rbnode_next(&_safe->_m), __typeof__(*_iter), _m) : NULL)

#define c_rbtree_for_each_postorder(_iter, _tree)                                                       \
        for (_iter = c_rbtree_first_postorder(_tree);                                                   \
             _iter;                                                                                     \
             _iter = c_rbnode_next_postorder(_iter))                                                    \

#define c_rbtree_for_each_entry_postorder(_iter, _tree, _m)                                             \
        for (_iter = c_rbnode_entry(c_rbtree_first_postorder(_tree), __typeof__(*_iter), _m);           \
             _iter;                                                                                     \
             _iter = c_rbnode_entry(c_rbnode_next_postorder(&_iter->_m), __typeof__(*_iter), _m))

#define c_rbtree_for_each_safe_postorder(_iter, _safe, _tree)                                           \
        for (_iter = c_rbtree_first_postorder(_tree), _safe = c_rbnode_next_postorder(_iter);           \
             _iter;                                                                                     \
             _iter = _safe, _safe = c_rbnode_next_postorder(_safe))

#define c_rbtree_for_each_entry_safe_postorder(_iter, _safe, _tree, _m)                                                 \
        for (_iter = c_rbnode_entry(c_rbtree_first_postorder(_tree), __typeof__(*_iter), _m),                           \
             _safe = _iter ? c_rbnode_entry(c_rbnode_next_postorder(&_iter->_m), __typeof__(*_iter), _m) : NULL;        \
             _iter;                                                                                                     \
             _iter = _safe,                                                                                             \
             _safe = _safe ? c_rbnode_entry(c_rbnode_next_postorder(&_safe->_m), __typeof__(*_iter), _m) : NULL)

#define c_rbtree_for_each_safe_postorder_unlink(_iter, _safe, _tree)                                    \
        for (_iter = c_rbtree_first_postorder(_tree), _safe = c_rbnode_next_postorder(_iter);           \
             _iter ? ((*_iter = (CRBNode)C_RBNODE_INIT(*_iter)), 1) : (((_tree)->root = NULL), 0);      \
             _iter = _safe, _safe = c_rbnode_next_postorder(_safe))                                     \

#define c_rbtree_for_each_entry_safe_postorder_unlink(_iter, _safe, _tree, _m)                                          \
        for (_iter = c_rbnode_entry(c_rbtree_first_postorder(_tree), __typeof__(*_iter), _m),                           \
             _safe = _iter ? c_rbnode_entry(c_rbnode_next_postorder(&_iter->_m), __typeof__(*_iter), _m) : NULL;        \
             _iter ? ((_iter->_m = (CRBNode)C_RBNODE_INIT(_iter->_m)), 1) : (((_tree)->root = NULL), 0);                \
             _iter = _safe,                                                                                             \
             _safe = _safe ? c_rbnode_entry(c_rbnode_next_postorder(&_safe->_m), __typeof__(*_iter), _m) : NULL)

#ifdef __cplusplus
}
#endif
