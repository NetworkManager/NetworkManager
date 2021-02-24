/*
 * Tests for DHCP4 Socket Helpers
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4-private.h"
#include "test.h"
#include "util/link.h"
#include "util/netns.h"
#include "util/packet.h"

static void test_poll(int sk) {
        int r;

        r = poll(&(struct pollfd){ .fd = sk, .events = POLLIN }, 1, -1);
        c_assert(r == 1);
}

static void test_client_packet_socket_new(Link *link, int *skp) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(link->netns);

        r = n_dhcp4_c_socket_packet_new(skp, link->ifindex);
        c_assert(r >= 0);

        netns_set(oldns);
}

static void test_client_udp_socket_new(Link *link,
                                       int *skp,
                                       const struct in_addr *addr_client,
                                       const struct in_addr *addr_server) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(link->netns);

        r = n_dhcp4_c_socket_udp_new(skp, link->ifindex, addr_client, addr_server);
        c_assert(r >= 0);

        netns_set(oldns);
}

static void test_server_packet_socket_new(Link *link, int *skp) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(link->netns);

        r = n_dhcp4_s_socket_packet_new(skp);
        c_assert(r >= 0);

        netns_set(oldns);
}

static void test_server_udp_socket_new(Link *link, int *skp) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(link->netns);

        r = n_dhcp4_s_socket_udp_new(skp, link->ifindex);
        c_assert(r >= 0);

        netns_set(oldns);
}

static void test_client_server_packet(Link *link_server, Link *link_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        _c_cleanup_(c_closep) int sk_server = -1, sk_client = -1;
        uint8_t buf[UINT16_MAX];
        struct sockaddr_in dest = {};
        int r;

        test_server_udp_socket_new(link_server, &sk_server);
        test_client_packet_socket_new(link_client, &sk_client);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        c_assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREQUEST;

        r = n_dhcp4_c_socket_packet_send(sk_client,
                                         link_client->ifindex,
                                         (const unsigned char[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                                         ETH_ALEN,
                                         outgoing);
        c_assert(!r);

        test_poll(sk_server);

        r = n_dhcp4_s_socket_udp_recv(sk_server, buf, sizeof(buf), &incoming, &dest);
        c_assert(!r);
        c_assert(incoming);
        c_assert(dest.sin_family == AF_INET);
        c_assert(dest.sin_port == htons(N_DHCP4_NETWORK_SERVER_PORT));
        c_assert(dest.sin_addr.s_addr == INADDR_BROADCAST);
}

static void test_client_server_udp(Link *link_server, Link *link_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        _c_cleanup_(c_closep) int sk_server = -1, sk_client = -1;
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        uint8_t buf[UINT16_MAX];
        struct sockaddr_in dest = {};
        int r;

        /* setup */

        link_add_ip4(link_server, &addr_server, 8);
        link_add_ip4(link_client, &addr_client, 8);

        /* test communication */

        test_server_udp_socket_new(link_server, &sk_server);
        test_client_udp_socket_new(link_client, &sk_client, &addr_client, &addr_server);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        c_assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREQUEST;

        r = n_dhcp4_c_socket_udp_send(sk_client, outgoing);
        c_assert(!r);

        test_poll(sk_server);

        r = n_dhcp4_s_socket_udp_recv(sk_server, buf, sizeof(buf), &incoming, &dest);
        c_assert(!r);
        c_assert(incoming);
        c_assert(dest.sin_family == AF_INET);
        c_assert(dest.sin_port == htons(N_DHCP4_NETWORK_SERVER_PORT));
        c_assert(dest.sin_addr.s_addr == addr_server.s_addr);

        /* teardown */

        link_del_ip4(link_client, &addr_client, 8);
        link_del_ip4(link_server, &addr_server, 8);
}

static void test_server_client_packet(Link *link_server, Link *link_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming1 = NULL, *incoming2 = NULL;
        _c_cleanup_(c_closep) int sk_server = -1, sk_client = -1;
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        uint8_t buf[UINT16_MAX];
        int r;

        /* setup */

        link_add_ip4(link_server, &addr_server, 8);

        /* test communication */

        test_server_packet_socket_new(link_server, &sk_server);
        test_client_packet_socket_new(link_client, &sk_client);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        c_assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREPLY;

        r = n_dhcp4_s_socket_packet_send(sk_server,
                                         link_server->ifindex,
                                         &addr_server,
                                         link_client->mac.ether_addr_octet,
                                         ETH_ALEN,
                                         &addr_client,
                                         outgoing);
        c_assert(!r);
        r = n_dhcp4_s_socket_packet_send(sk_server,
                                         link_server->ifindex,
                                         &addr_server,
                                         (const unsigned char[]){
                                                0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                                         },
                                         ETH_ALEN,
                                         &addr_client,
                                         outgoing);
        c_assert(!r);

        test_poll(sk_client);

        r = n_dhcp4_c_socket_packet_recv(sk_client, buf, sizeof(buf), &incoming1);
        c_assert(!r);
        c_assert(incoming1);

        test_poll(sk_client);

        r = n_dhcp4_c_socket_packet_recv(sk_client, buf, sizeof(buf), &incoming2);
        c_assert(!r);
        c_assert(incoming2);

        /* teardown */

        link_del_ip4(link_server, &addr_server, 8);
}

static void test_server_client_udp(Link *link_server, Link *link_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        _c_cleanup_(c_closep) int sk_server = -1, sk_client = -1;
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        uint8_t buf[UINT16_MAX];
        int r;

        /* setup */

        link_add_ip4(link_server, &addr_server, 8);
        link_add_ip4(link_client, &addr_client, 8);

        /* test communication */

        test_server_udp_socket_new(link_server, &sk_server);
        test_client_udp_socket_new(link_client, &sk_client, &addr_client, &addr_server);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        c_assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREPLY;

        r = n_dhcp4_s_socket_udp_send(sk_server,
                                      &addr_server,
                                      &addr_client,
                                      outgoing);
        c_assert(!r);

        test_poll(sk_client);

        r = n_dhcp4_c_socket_udp_recv(sk_client, buf, sizeof(buf), &incoming);
        c_assert(!r);
        c_assert(incoming);

        /* teardown */

        link_del_ip4(link_client, &addr_client, 8);
        link_del_ip4(link_server, &addr_server, 8);
}

static void test_sockets(void) {
        _c_cleanup_(netns_closep) int ns_server = -1, ns_client = -1;
        _c_cleanup_(link_deinit) Link link_server = LINK_NULL(link_server);
        _c_cleanup_(link_deinit) Link link_client = LINK_NULL(link_client);

        /* setup */

        netns_new(&ns_server);
        netns_new(&ns_client);
        link_new_veth(&link_server, &link_client, ns_server, ns_client);

        /* communication tests */

        test_client_server_packet(&link_server, &link_client);
        test_client_server_udp(&link_server, &link_client);
        test_server_client_packet(&link_server, &link_client);
        test_server_client_udp(&link_server, &link_client);
}

static void test_multiple_servers(void) {
        _c_cleanup_(netns_closep) int netns = -1;
        _c_cleanup_(link_deinit) Link link_server = LINK_NULL(link_server);
        _c_cleanup_(link_deinit) Link link_client = LINK_NULL(link_client);
        int r, oldns;

        /* setup */

        netns_new(&netns);
        link_new_veth(&link_server, &link_client, netns, netns);

        /* test multiple server UDP sockets on the same machine */

        netns_get(&oldns);
        netns_set(netns);
        {
                _c_cleanup_(c_closep) int sk1 = -1, sk2 = -1;

                /*
                 * DHCP servers have to bind to a fixed port, so you cannot run
                 * two servers on the same interface. It must be possible to
                 * run them on separate interfaces, though.
                 */

                r = n_dhcp4_s_socket_udp_new(&sk1, link_server.ifindex);
                c_assert(r >= 0);

                r = n_dhcp4_s_socket_udp_new(&sk2, link_server.ifindex);
                c_assert(r == -EADDRINUSE);

                r = n_dhcp4_s_socket_udp_new(&sk2, link_client.ifindex);
                c_assert(r >= 0);
        }
        netns_set(oldns);
}

int main(int argc, char **argv) {
        test_setup();

        test_sockets();
        test_multiple_servers();

        return 0;
}
