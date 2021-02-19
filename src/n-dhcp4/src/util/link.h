#pragma once

/*
 * Link Management
 *
 * This utility provides easy access to network links. It is meant for testing
 * purposes only and relies on call-outs to ip(1). A proper implementation
 * should rather use netlink directly to interact with the kernel.
 *
 * Furthermore, for simplification this is limited to ethernet links.
 */

#include <c-stdaux.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>

typedef struct Link Link;

struct Link {
        int netns;
        int ifindex;
        struct ether_addr mac;
};

#define LINK_NULL(_x) {                                                         \
                .netns = -1,                                                    \
        }

void link_deinit(Link *link);

void link_new_veth(Link *veth_parentp, Link *veth_childp, int netns_parent, int netns_child);
void link_new_bridge(Link *bridgep, int netns);

void link_add_ip4(Link *link, const struct in_addr *addr, unsigned int prefix);
void link_del_ip4(Link *link, const struct in_addr *addr, unsigned int prefix);
void link_set_master(Link *link, int if_master);
void link_socket(Link *link, int *socketp, int family, int type);
