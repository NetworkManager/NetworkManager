#pragma once

/*
 * Network Namespaces
 *
 * The netns utility provides an object-based API to network namespaces. It is
 * meant for testing purposes only.
 */

#include <c-stdaux.h>
#include <stdlib.h>

void netns_new(int *netnsp);
void netns_new_dup(int *newnsp, int netns);
int netns_close(int netns);

void netns_get(int *netnsp);
void netns_set(int netns);
void netns_set_anonymous(void);

void netns_pin(int netns, const char *name);
void netns_unpin(const char *name);

static inline void netns_closep(int *netns) {
        if (*netns >= 0)
                netns_close(*netns);
}
