#pragma once

/*
 * Private definitions
 * This file contains private definitions for the RB-Tree implementation, but
 * which are used by our test-suite.
 */

#include <stddef.h>
#include "c-rbtree.h"

/*
 * Macros
 */

#define _public_ __attribute__((__visibility__("default")))

/*
 * Nodes
 */

static inline void *c_rbnode_raw(CRBNode *n) {
        return (void *)(n->__parent_and_flags & ~C_RBNODE_FLAG_MASK);
}

static inline unsigned long c_rbnode_flags(CRBNode *n) {
        return n->__parent_and_flags & C_RBNODE_FLAG_MASK;
}

static inline _Bool c_rbnode_is_red(CRBNode *n) {
        return c_rbnode_flags(n) & C_RBNODE_RED;
}

static inline _Bool c_rbnode_is_black(CRBNode *n) {
        return !(c_rbnode_flags(n) & C_RBNODE_RED);
}

static inline _Bool c_rbnode_is_root(CRBNode *n) {
        return c_rbnode_flags(n) & C_RBNODE_ROOT;
}
