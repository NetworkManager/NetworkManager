/*
 * Link Management
 *
 * This is for our test-infrastructure only! It is not meant to be used outside
 * of unit-tests.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <c-stdaux.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "link.h"
#include "netns.h"
#include "socket.h"

/**
 * link_deinit() - deinitialize link
 * @link:               link to operate on
 *
 * This deinitializes a link and clears it. Once this call returns the link is
 * cleared to LINK_NULL().
 *
 * It is safe to call this on LINK_NULL(), in which case it is a no-op. It is
 * thus also safe to call this multiple times on the same link.
 */
void link_deinit(Link *link) {
        netns_close(link->netns);
        *link = (Link)LINK_NULL(*link);
}

static void link_query(int netns, const char *name, int *ifindexp, struct ether_addr *macp) {
        int oldns;

        netns_get(&oldns);
        {
                struct ifreq ifr = {};
                size_t n_name;
                int r, s;

                netns_set(netns);

                n_name = strlen(name);
                c_assert(n_name <= IF_NAMESIZE);

                if (ifindexp) {
                        *ifindexp = if_nametoindex(name);
                        c_assert(*ifindexp > 0);
                }

                if (macp) {
                        s = socket(AF_INET, SOCK_DGRAM, 0);
                        c_assert(s >= 0);

                        strncpy(ifr.ifr_name, name, n_name);
                        r = ioctl(s, SIOCGIFHWADDR, &ifr);
                        c_assert(r >= 0);

                        memcpy(macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

                        close(s);
                }
        }
        netns_set(oldns);
}

static void link_move(const char *ifname, int netns) {
        char *p;
        int r;

        r = asprintf(&p, "ip link set %s up netns ns-test", ifname);
        c_assert(r > 0);

        netns_pin(netns, "ns-test");
        r = system(p);
        c_assert(r == 0);
        netns_unpin("ns-test");

        free(p);
}

/**
 * link_new_veth() - create new veth pair
 * @veth_parentp:               output argument for new veth parent
 * @veth_childp:                output argument for new veth child
 * @netns_parent:               target namespace for the parent
 * @netns_child:                target namespace for the child
 *
 * This creates a new veth pair in the specified namespaces.
 */
void link_new_veth(Link *veth_parentp, Link *veth_childp, int netns_parent, int netns_child) {
        int oldns;

        netns_get(&oldns);
        {
                int r;

                /*
                 * Temporarily enter a new network namespace to make sure the
                 * interface names are fresh.
                 */
                netns_set_anonymous();

                r = system("ip link add veth-parent type veth peer name veth-child");
                c_assert(r == 0);
                r = system("ip link set veth-parent up addrgenmode none");
                c_assert(r == 0);
                r = system("ip link set veth-child up addrgenmode none");
                c_assert(r == 0);

                link_move("veth-parent", netns_parent);
                link_move("veth-child", netns_child);
        }
        netns_set(oldns);

        netns_new_dup(&veth_parentp->netns, netns_parent);
        netns_new_dup(&veth_childp->netns, netns_child);
        link_query(netns_parent, "veth-parent", &veth_parentp->ifindex, &veth_parentp->mac);
        link_query(netns_child, "veth-child", &veth_childp->ifindex, &veth_childp->mac);

        /*
         * XXX: After moving a link both its name and ifindex might have
         *      changed. Hence, link_query() might check the wrong interface.
         *      One way to fix this would be to rename the interfaces after
         *      they have been moved and queried based on their final ifindex.
         *      This way, we reserve the internal names for the constructor,
         *      and guarantee the final names will never conflict (disallowing
         *      parallel calls to this function).
         */
}

/**
 * link_new_bridge() - create new bridge
 * @bridgep:                    output argument for the new bridge
 * @netns:                      target network namespace
 *
 * This creates a new bridge interface in the specified target network
 * namespace.
 */
void link_new_bridge(Link *bridgep, int netns) {
        int oldns;

        netns_get(&oldns);
        {
                int r;

                netns_set(netns);

                r = system("ip link add test-bridge type bridge");
                c_assert(r == 0);
                r = system("ip link set test-bridge up addrgenmode none");
                c_assert(r == 0);
        }
        netns_set(oldns);

        netns_new_dup(&bridgep->netns, netns);
        link_query(netns, "test-bridge", &bridgep->ifindex, &bridgep->mac);
}

/**
 * link_add_ip4() - add IPv4 address to the specified link
 * @link:                       link to operate on
 * @addr:                       address to add
 * @prefix:                     address prefix length
 *
 * This adds the specified IPv4 address to the given link.
 */
void link_add_ip4(Link *link, const struct in_addr *addr, unsigned int prefix) {
        int oldns;

        netns_get(&oldns);
        {
                char *p, ifname[IF_NAMESIZE + 1] = {};
                int r;

                netns_set(link->netns);

                p = if_indextoname(link->ifindex, ifname);
                c_assert(p);
                r = asprintf(&p, "ip addr add %s/%u dev %s", inet_ntoa(*addr), prefix, ifname);
                c_assert(r >= 0);
                r = system(p);
                c_assert(r == 0);
                free(p);
        }
        netns_set(oldns);
}

/**
 * link_del_ip4() - delete IPv4 address from the specified link
 * @link:                       link to operate on
 * @addr:                       address to delete
 * @prefix:                     address prefix length
 *
 * This deletes the specified IPv4 address from the given link.
 */
void link_del_ip4(Link *link, const struct in_addr *addr, unsigned int prefix) {
        int oldns;

        netns_get(&oldns);
        {
                char *p, ifname[IF_NAMESIZE + 1] = {};
                int r;

                netns_set(link->netns);

                p = if_indextoname(link->ifindex, ifname);
                c_assert(p);
                r = asprintf(&p, "ip addr del %s/%u dev %s", inet_ntoa(*addr), prefix, ifname);
                c_assert(r >= 0);
                r = system(p);
                c_assert(r == 0);
                free(p);
        }
        netns_set(oldns);
}

/**
 * link_set_master() - change the bridge master of an interface
 * @link:                       link to operate on
 * @if_master:                  bridge to set as master
 *
 * This sets @if_master as the new master bridge of @link. The specified bridge
 * must be in the same network namespace as @link.
 */
void link_set_master(Link *link, int if_master) {
        int oldns;

        netns_get(&oldns);
        {
                char *p, ifname_master[IF_NAMESIZE + 1] = {}, ifname[IF_NAMESIZE + 1] = {};
                int r;

                netns_set(link->netns);

                p = if_indextoname(link->ifindex, ifname);
                c_assert(p);
                p = if_indextoname(if_master, ifname_master);
                c_assert(p);
                r = asprintf(&p, "ip link set %s master %s", ifname, ifname_master);
                c_assert(r > 0);
                r = system(p);
                c_assert(r == 0);
                free(p);
        }
        netns_set(oldns);
}

/**
 * link_socket() - create socket for link
 * @link:               link to operate on
 * @socketp:            output argument for new socket
 * @family:             socket family to create socket in
 * @type:               socket type to create socket as
 *
 * This creates a socket of the protocol family @family via socket(2), but
 * makes sure to create it in the network-namespace where @link resides.
 * Furthermore, the socket is bound to the link specified in @link.
 *
 * The new socket is returned in @socketp.
 */
void link_socket(Link *link, int *socketp, int family, int type) {
        int oldns;

        netns_get(&oldns);
        {
                int r, fd;

                netns_set(link->netns);

                fd = socket(family, type, 0);
                c_assert(fd >= 0);

                r = socket_bind_if(fd, link->ifindex);
                c_assert(!r);

                *socketp = fd;
        }
        netns_set(oldns);
}
