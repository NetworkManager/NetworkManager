/*
 * Tests for basic functionality
 * This contains basic, deterministic tests for list behavior, API
 * functionality, and usage.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c-list.h"

static void test_iterators(void) {
        CList *iter, *safe, a, b, list = C_LIST_INIT(list);
        unsigned int i;

        assert(!c_list_first(&list));
        assert(!c_list_last(&list));

        /* link @a and verify iterators see just it */

        c_list_link_tail(&list, &a);
        assert(c_list_is_linked(&a));
        assert(c_list_first(&list) == &a);
        assert(c_list_last(&list) == &a);

        i = 0;
        c_list_for_each(iter, &list) {
                assert(iter == &a);
                ++i;
        }
        assert(i == 1);

        i = 0;
        iter = NULL;
        c_list_for_each_continue(iter, &list) {
                assert(iter == &a);
                ++i;
        }
        assert(i == 1);

        i = 0;
        iter = &a;
        c_list_for_each_continue(iter, &list)
                ++i;
        assert(i == 0);

        /* link @b as well and verify iterators again */

        c_list_link_tail(&list, &b);
        assert(c_list_is_linked(&a));
        assert(c_list_is_linked(&b));

        i = 0;
        c_list_for_each(iter, &list) {
                assert((i == 0 && iter == &a) ||
                       (i == 1 && iter == &b));
                ++i;
        }
        assert(i == 2);

        i = 0;
        iter = NULL;
        c_list_for_each_continue(iter, &list) {
                assert((i == 0 && iter == &a) ||
                       (i == 1 && iter == &b));
                ++i;
        }
        assert(i == 2);

        i = 0;
        iter = &a;
        c_list_for_each_continue(iter, &list) {
                assert(iter == &b);
                ++i;
        }
        assert(i == 1);

        i = 0;
        iter = &b;
        c_list_for_each_continue(iter, &list)
                ++i;
        assert(i == 0);

        /* verify safe-iterator while removing elements */

        i = 0;
        c_list_for_each_safe(iter, safe, &list) {
                assert(iter == &a || iter == &b);
                c_list_unlink_stale(iter);
                ++i;
        }
        assert(i == 2);

        assert(c_list_is_empty(&list));

        /* link both and verify *_unlink() iterators */

        c_list_link_tail(&list, &a);
        c_list_link_tail(&list, &b);

        i = 0;
        c_list_for_each_safe_unlink(iter, safe, &list) {
                assert(iter == &a || iter == &b);
                assert(!c_list_is_linked(iter));
                ++i;
        }
        assert(i == 2);

        assert(c_list_is_empty(&list));
}

static void test_swap(void) {
        CList list1 = (CList)C_LIST_INIT(list1);
        CList list2 = (CList)C_LIST_INIT(list2);
        CList list;

        c_list_swap(&list1, &list2);

        assert(list1.prev == list1.next && list1.prev == &list1);
        assert(list2.prev == list2.next && list2.prev == &list2);

        c_list_link_tail(&list1, &list);

        assert(c_list_first(&list1) == &list);
        assert(c_list_last(&list1) == &list);
        assert(list.next = &list1);
        assert(list.prev = &list1);

        c_list_swap(&list1, &list2);

        assert(c_list_first(&list2) == &list);
        assert(c_list_last(&list2) == &list);
        assert(list.next = &list2);
        assert(list.prev = &list2);

        assert(list1.prev == list1.next && list1.prev == &list1);
}

static void test_splice(void) {
        CList target = (CList)C_LIST_INIT(target);
        CList source = (CList)C_LIST_INIT(source);
        CList e1, e2;

        c_list_link_tail(&source, &e1);

        c_list_splice(&target, &source);
        assert(c_list_first(&target) == &e1);
        assert(c_list_last(&target) == &e1);

        source = (CList)C_LIST_INIT(source);

        c_list_link_tail(&source, &e2);

        c_list_splice(&target, &source);
        assert(c_list_first(&target) == &e1);
        assert(c_list_last(&target) == &e2);
}

static void test_flush(void) {
        CList e1 = C_LIST_INIT(e1), e2 = C_LIST_INIT(e2);

        {
                __attribute__((__cleanup__(c_list_flush))) CList list1 = C_LIST_INIT(list1);
                __attribute__((__cleanup__(c_list_flush))) CList list2 = C_LIST_INIT(list2);

                c_list_link_tail(&list2, &e1);
                c_list_link_tail(&list2, &e2);

                assert(c_list_is_linked(&e1));
                assert(c_list_is_linked(&e2));
        }

        assert(!c_list_is_linked(&e1));
        assert(!c_list_is_linked(&e2));
}

int main(int argc, char **argv) {
        test_iterators();
        test_swap();
        test_splice();
        test_flush();
        return 0;
}
