/*
 * Tests for Public API
 * This test, unlikely the others, is linked against the real, distributed,
 * shared library. Its sole purpose is to test for symbol availability.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c-list.h"

typedef struct {
        int id;
        CList link;
} Node;

static void test_api(void) {
        CList *list_iter, *list_safe, list = C_LIST_INIT(list);
        Node *node_iter, *node_safe, node = { .id = 0, .link = C_LIST_INIT(node.link) };

        assert(!c_list_entry(NULL, Node, link));
        assert(c_list_entry(&node.link, Node, link) == &node);
        assert(!c_list_is_linked(&node.link));
        assert(c_list_is_empty(&list));
        assert(c_list_length(&list) == 0);
        assert(c_list_contains(&list, &list));
        assert(!c_list_contains(&list, &node.link));
        c_list_flush(&list);

        /* basic link / unlink calls */

        c_list_link_before(&list, &node.link);
        assert(c_list_is_linked(&node.link));
        assert(!c_list_is_empty(&list));
        assert(c_list_length(&list) == 1);
        assert(c_list_contains(&list, &list));
        assert(c_list_contains(&list, &node.link));

        c_list_unlink_stale(&node.link);
        assert(c_list_is_linked(&node.link));
        assert(c_list_is_empty(&list));
        assert(c_list_length(&list) == 0);

        c_list_link_after(&list, &node.link);
        assert(c_list_is_linked(&node.link));
        assert(!c_list_is_empty(&list));

        c_list_unlink(&node.link);
        assert(!c_list_is_linked(&node.link));
        assert(c_list_is_empty(&list));

        /* link / unlink aliases */

        c_list_link_front(&list, &node.link);
        assert(c_list_is_linked(&node.link));

        c_list_unlink(&node.link);
        assert(!c_list_is_linked(&node.link));

        c_list_link_tail(&list, &node.link);
        assert(c_list_is_linked(&node.link));

        c_list_unlink(&node.link);
        assert(!c_list_is_linked(&node.link));

        /* swap / splice list operators */

        c_list_swap(&list, &list);
        assert(c_list_is_empty(&list));

        c_list_splice(&list, &list);
        assert(c_list_is_empty(&list));

        /* loop macros */

        c_list_for_each(list_iter, &list)
                assert(list_iter != &list);
        c_list_for_each_entry(node_iter, &list, link)
                assert(&node_iter->link != &list);
        c_list_for_each_safe(list_iter, list_safe, &list)
                assert(list_iter != &list);
        c_list_for_each_entry_safe(node_iter, node_safe, &list, link)
                assert(&node_iter->link != &list);
        c_list_for_each_continue(list_iter, &list)
                assert(list_iter != &list);
        c_list_for_each_entry_continue(node_iter, &list, link)
                assert(&node_iter->link != &list);
        c_list_for_each_safe_continue(list_iter, list_safe, &list)
                assert(list_iter != &list);
        c_list_for_each_entry_safe_continue(node_iter, node_safe, &list, link)
                assert(&node_iter->link != &list);
        c_list_for_each_safe_unlink(list_iter, list_safe, &list)
                assert(list_iter != &list);
        c_list_for_each_entry_safe_unlink(node_iter, node_safe, &list, link)
                assert(&node_iter->link != &list);

        /* list accessors */

        assert(!c_list_first(&list));
        assert(!c_list_last(&list));
        assert(!c_list_first_entry(&list, Node, link));
        assert(!c_list_last_entry(&list, Node, link));
}

int main(int argc, char **argv) {
        test_api();
        return 0;
}
