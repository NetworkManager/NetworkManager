/*
 * Tests for DHCP4 Client Connections
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "n-dhcp4-private.h"
#include "test.h"
#include "util/link.h"
#include "util/netns.h"
#include "util/packet.h"

static void test_poll_client(int efd, unsigned int u32) {
        struct epoll_event event = {};
        int r;

        r = epoll_wait(efd, &event, 1, -1);
        c_assert(r == 1);
        c_assert(event.events == EPOLLIN);
        c_assert(event.data.u32 == u32);
}

static void test_poll_server(int fd) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int r;

        r = poll(&pfd, 1, -1);
        c_assert(r == 1);
        c_assert(pfd.revents == POLLIN);
}

static void test_s_connection_init(int netns, NDhcp4SConnection *connection, int ifindex) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_s_connection_init(connection, ifindex);
        c_assert(!r);

        netns_set(oldns);
}

static void test_c_connection_listen(int netns, NDhcp4CConnection *connection) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_c_connection_listen(connection);
        c_assert(!r);

        netns_set(oldns);
}

static void test_c_connection_connect(int netns,
                                      NDhcp4CConnection *connection,
                                      const struct in_addr *client,
                                      const struct in_addr *server) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_c_connection_connect(connection, client, server);
        c_assert(!r);

        netns_set(oldns);
}

static void test_server_receive(NDhcp4SConnection *connection, uint8_t expected_type, NDhcp4Incoming **messagep) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t received_type;
        int r, fd;

        n_dhcp4_s_connection_get_fd(connection, &fd);
        test_poll_server(fd);

        r = n_dhcp4_s_connection_dispatch_io(connection, &message);
        c_assert(!r);
        c_assert(message);

        r = n_dhcp4_incoming_query_message_type(message, &received_type);
        c_assert(!r);
        c_assert(received_type == expected_type);

        if (messagep) {
                *messagep = message;
                message = NULL;
        }
}

static void test_client_receive(NDhcp4CConnection *connection, uint8_t expected_type, NDhcp4Incoming **messagep) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t received_type;
        int r;

        test_poll_client(connection->fd_epoll, N_DHCP4_CLIENT_EPOLL_IO);

        r = n_dhcp4_c_connection_dispatch_io(connection, &message);
        c_assert(!r);
        c_assert(message);

        r = n_dhcp4_incoming_query_message_type(message, &received_type);
        c_assert(!r);
        c_assert(received_type == expected_type);

        if (messagep) {
                *messagep = message;
                message = NULL;
        }
}

static void test_discover(NDhcp4SConnection *connection_server,
                          NDhcp4CConnection *connection_client,
                          const struct in_addr *addr_server,
                          const struct in_addr *addr_client,
                          NDhcp4Incoming **offerp) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply_out = NULL;
        int r;

        r = n_dhcp4_c_connection_discover_new(connection_client, &request_out);
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_DISCOVER, &request_in);

        r = n_dhcp4_s_connection_offer_new(connection_server, &reply_out, request_in, addr_server, addr_client, 60);
        c_assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply_out);
        c_assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_OFFER, offerp);
}

static void test_select(NDhcp4SConnection *connection_server,
                        NDhcp4CConnection *connection_client,
                        NDhcp4Incoming *offer,
                        const struct in_addr *addr_server,
                        const struct in_addr *addr_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_select_new(connection_client, &request_out, offer);
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        c_assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        c_assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, NULL);
}

static void test_reboot(NDhcp4SConnection *connection_server,
                        NDhcp4CConnection *connection_client,
                        const struct in_addr *addr_server,
                        const struct in_addr *addr_client,
                        NDhcp4Incoming **ackp) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_reboot_new(connection_client, &request_out, addr_server);
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        c_assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        c_assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, ackp);
}

static void test_decline(NDhcp4SConnection *connection_server,
                         NDhcp4CConnection *connection_client,
                         NDhcp4Incoming *ack) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        int r;

        r = n_dhcp4_c_connection_decline_new(connection_client, &request_out, ack, "No thanks.");
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_DECLINE, NULL);
}


static void test_renew(NDhcp4SConnection *connection_server,
                       NDhcp4CConnection *connection_client,
                       const struct in_addr *addr_server,
                       const struct in_addr *addr_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_renew_new(connection_client, &request_out);
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        c_assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        c_assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, NULL);
}

static void test_rebind(NDhcp4SConnection *connection_server,
                        NDhcp4CConnection *connection_client,
                        const struct in_addr *addr_server,
                        const struct in_addr *addr_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_rebind_new(connection_client, &request_out);
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        c_assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        c_assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, NULL);
}

static void test_release(NDhcp4SConnection *connection_server,
                         NDhcp4CConnection *connection_client,
                         const struct in_addr *addr_server,
                         const struct in_addr *addr_client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        int r;

        r = n_dhcp4_c_connection_release_new(connection_client, &request_out, "Shutting down!");
        c_assert(!r);

        r = n_dhcp4_c_connection_start_request(connection_client, request_out, 0);
        c_assert(!r);
        request_out = NULL;

        test_server_receive(connection_server, N_DHCP4_MESSAGE_RELEASE, NULL);
}

static void test_connection(void) {
        const struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        const struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        _c_cleanup_(netns_closep) int ns_server = -1, ns_client = -1;
        _c_cleanup_(link_deinit) Link link_server = LINK_NULL(link_server);
        _c_cleanup_(link_deinit) Link link_client = LINK_NULL(link_client);
        _c_cleanup_(c_closep) int efd_client = -1;
        int r;

        /* setup */

        netns_new(&ns_server);
        netns_new(&ns_client);

        link_new_veth(&link_server, &link_client, ns_server, ns_client);
        link_add_ip4(&link_server, &addr_server, 8);

        efd_client = epoll_create1(EPOLL_CLOEXEC);
        c_assert(efd_client >= 0);

        /* test connections */
        {
                _c_cleanup_(n_dhcp4_client_config_freep) NDhcp4ClientConfig *client_config = NULL;
                _c_cleanup_(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *probe_config = NULL;
                NDhcp4SConnection connection_server = N_DHCP4_S_CONNECTION_NULL(connection_server);
                NDhcp4SConnectionIp connection_server_ip = N_DHCP4_S_CONNECTION_IP_NULL(connection_server_ip);
                NDhcp4CConnection connection_client = N_DHCP4_C_CONNECTION_NULL(connection_client);
                _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *offer = NULL;
                _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *ack = NULL;

                test_s_connection_init(ns_server, &connection_server, link_server.ifindex);
                n_dhcp4_s_connection_ip_init(&connection_server_ip, addr_server);
                n_dhcp4_s_connection_ip_link(&connection_server_ip, &connection_server);

                r = n_dhcp4_client_config_new(&client_config);
                c_assert(!r);

                n_dhcp4_client_config_set_ifindex(client_config, link_client.ifindex);
                n_dhcp4_client_config_set_transport(client_config, N_DHCP4_TRANSPORT_ETHERNET);
                n_dhcp4_client_config_set_request_broadcast(client_config, false);
                n_dhcp4_client_config_set_mac(client_config, link_client.mac.ether_addr_octet, ETH_ALEN);
                n_dhcp4_client_config_set_broadcast_mac(client_config,
                                                        (const uint8_t[]){
                                                                0xff, 0xff, 0xff,
                                                                0xff, 0xff, 0xff,
                                                        },
                                                        ETH_ALEN);
                r = n_dhcp4_client_config_set_client_id(client_config,
                                                        (void *)"client-id",
                                                        strlen("client-id"));
                c_assert(!r);

                r = n_dhcp4_client_probe_config_new(&probe_config);
                c_assert(!r);

                r = n_dhcp4_c_connection_init(&connection_client,
                                              client_config,
                                              probe_config,
                                              efd_client);
                c_assert(!r);
                test_c_connection_listen(ns_client, &connection_client);

                test_discover(&connection_server, &connection_client, &addr_server, &addr_client, &offer);
                test_select(&connection_server, &connection_client, offer, &addr_server, &addr_client);
                test_reboot(&connection_server, &connection_client, &addr_server, &addr_client, &ack);
                test_decline(&connection_server, &connection_client, ack);

                link_add_ip4(&link_client, &addr_client, 8);
                test_c_connection_connect(ns_client, &connection_client, &addr_client, &addr_server);

                test_renew(&connection_server, &connection_client, &addr_server, &addr_client);
                test_rebind(&connection_server, &connection_client, &addr_server, &addr_client);
                test_release(&connection_server, &connection_client, &addr_server, &addr_client);

                n_dhcp4_c_connection_deinit(&connection_client);
                n_dhcp4_s_connection_ip_unlink(&connection_server_ip);
                n_dhcp4_s_connection_ip_deinit(&connection_server_ip);
                n_dhcp4_s_connection_deinit(&connection_server);
        }

        /* teardown */

        link_del_ip4(&link_client, &addr_client, 8);
        link_del_ip4(&link_server, &addr_server, 8);
}

int main(int argc, char **argv) {
        test_setup();

        test_connection();

        return 0;
}
