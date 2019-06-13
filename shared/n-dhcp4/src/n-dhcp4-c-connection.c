/*
 * DHCPv4 Client Connection
 *
 * XXX
 */

#include <assert.h>
#include <c-stdaux.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h> /* needed by linux/netdevice.h */
#include <linux/netdevice.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "n-dhcp4-private.h"
#include "util/packet.h"

/**
 * n_dhcp4_c_connection_init() - initialize client connection
 * @connection:                 connection to operate on
 * @client_config:              client configuration to use
 * @probe_config:               client probe configuration to use
 * @fd_epoll:                   epoll context to attach to, or -1
 *
 * This initializes a new client connection using the configuration given in
 * @client_config and @probe_config.
 *
 * The client-configuration given as @client_config must survive the lifetime
 * of @connection. It is pinned in the connection and used all over the place.
 * The caller must guarantee that the configuration is not deallocated in the
 * meantime. Same is true for @probe_config.
 *
 * The new connection automatically attaches to the epoll context given as
 * @fd_epoll. The epoll FD is retained in the connection and the caller must
 * guarantee that it lives as long as the connection.
 * The caller is explicitly allowed to pass -1 as @fd_epoll, in which case the
 * connection will initialize correctly, but will not be in a usable state.
 * That is, any call to n_dhcp4_c_connection_listen() will fail, since it will
 * be unable to attach to the epoll context. Such a connection can be used to
 * get a detached object that behaves sound, but provides no runtime.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_c_connection_init(NDhcp4CConnection *connection,
                              NDhcp4ClientConfig *client_config,
                              NDhcp4ClientProbeConfig *probe_config,
                              int fd_epoll) {
        *connection = (NDhcp4CConnection)N_DHCP4_C_CONNECTION_NULL(*connection);
        connection->client_config = client_config;
        connection->probe_config = probe_config;
        connection->fd_epoll = fd_epoll;

        /*
         * We explicitly allow initializing connections with an invalid
         * epoll-fd. The resulting connection immediately transitions into the
         * CLOSED state. This allows the caller to create dummy connections
         * useful to provide asynchronous constructor-feedback in the API.
         *
         * The effect of this is as if you immediately call
         * n_dhcp4_c_connection_close() on the new connection. However, by
         * directly passing -1 in the constructor, you are guaranteed not even
         * the constructor can ever mess with your epoll-set.
         */
        if (connection->fd_epoll < 0)
                connection->state = N_DHCP4_C_CONNECTION_STATE_CLOSED;

        return 0;
}

/**
 * n_dhcp4_c_connection_deinit() - deinitialize client connection
 * @connection:                 connection to operate on
 *
 * This deinitializes a connection that was previously initialized via
 * n_dhcp4_c_connection_init(). It will tear down all allocated state and
 * release it.
 *
 * Once this function returns, @connection is re-initialized to
 * N_DHCP4_C_CONNECTION_NULL. If this function is called on a deinitialized
 * connection, it is a no-op.
 */
void n_dhcp4_c_connection_deinit(NDhcp4CConnection *connection) {
        n_dhcp4_c_connection_close(connection);
        n_dhcp4_outgoing_free(connection->request);
        *connection = (NDhcp4CConnection)N_DHCP4_C_CONNECTION_NULL(*connection);
}

static void n_dhcp4_c_connection_outgoing_set_secs(NDhcp4Outgoing *message) {
        uint32_t secs;

        /*
         * This function sets the `secs` field for outgoing messages. It
         * expects the base-time and start-time to be already set by the
         * caller.
         * For a given outgoing message, its `secs` field describes the time
         * (in seconds) between the start of the transaction this message is
         * part of and the start of the operational process (also called the
         * base time here).
         *
         * The operational process in the DHCP sense describes the entire
         * process of requesting a lease and acquiring it. That is, it starts
         * with the caller's intent to request a lease, and it ends when we
         * got granted a lease. The act of refreshing a lease is, in itself, a
         * new operational process. The base-time describes the start-time
         * recorded when such a process as initiated.
         *
         * A transaction in the DHCP sense describes a request+reply
         * combination, in most cases. That is, the time a request is sent is
         * the start-time of a transaction. In the ideal case, the start-time
         * of the first transaction in an operational process matches the
         * base-time. However, transactions are often delayed with a randomized
         * offset to reduce traffic during network bursts.
         * In some cases, however, transactions are composed out of multiple
         * requests+reply combinations. This includes, for instance, the SELECT
         * message following an OFFER. The specification clearly says that
         * those must be considered a single transaction and thus share the
         * transaction start-time.
         *
         * The `secs` field, thus, describes how long a client has been busy
         * requesting a lease. DHCP servers and proxies do use it to prioritize
         * clients.
         *
         * Note: Some DHCP relays reject a `secs` value of 0 (which might look
         *       like it is uninitialized). Hence, we always clamp the value to
         *       the range `[1, INF[`.
         */

        secs = message->userdata.base_time - message->userdata.start_time;
        secs /= 1000ULL * 1000ULL * 1000ULL; /* nsecs to secs */
        secs = secs ?: 1; /* clamp to `[1, INF[` */

        n_dhcp4_outgoing_set_secs(message, secs);
}

int n_dhcp4_c_connection_listen(NDhcp4CConnection *connection) {
        _c_cleanup_(c_closep) int fd_packet = -1;
        int r;

        c_assert(connection->state == N_DHCP4_C_CONNECTION_STATE_INIT);

        r = n_dhcp4_c_socket_packet_new(&fd_packet, connection->client_config->ifindex);
        if (r)
                return r;

        r = epoll_ctl(connection->fd_epoll,
                      EPOLL_CTL_ADD,
                      fd_packet,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data = { .u32 = N_DHCP4_CLIENT_EPOLL_IO },
                      });
        if (r < 0)
                return -errno;

        connection->state = N_DHCP4_C_CONNECTION_STATE_PACKET;
        connection->fd_packet = fd_packet;
        fd_packet = -1;
        return 0;
}

int n_dhcp4_c_connection_connect(NDhcp4CConnection *connection,
                                 const struct in_addr *client,
                                 const struct in_addr *server) {
        int r, fd_udp;

        c_assert(connection->state == N_DHCP4_C_CONNECTION_STATE_PACKET);

        r = n_dhcp4_c_socket_udp_new(&fd_udp,
                                     connection->client_config->ifindex,
                                     client,
                                     server);
        if (r)
                return r;

        r = epoll_ctl(connection->fd_epoll,
                      EPOLL_CTL_ADD,
                      fd_udp,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data = { .u32 = N_DHCP4_CLIENT_EPOLL_IO },
                      });
        if (r < 0) {
                r = -errno;
                goto exit_fd;
        }

        r = packet_shutdown(connection->fd_packet);
        if (r < 0)
                goto exit_epoll;

        connection->state = N_DHCP4_C_CONNECTION_STATE_DRAINING;
        connection->fd_udp = fd_udp;
        connection->client_ip = client->s_addr;
        connection->server_ip = server->s_addr;
        fd_udp = -1;
        return 0;

exit_epoll:
        epoll_ctl(connection->fd_epoll, EPOLL_CTL_DEL, fd_udp, NULL);
exit_fd:
        close(fd_udp);
        return r;
}

void n_dhcp4_c_connection_close(NDhcp4CConnection *connection) {
        if (connection->fd_udp >= 0) {
                epoll_ctl(connection->fd_epoll, EPOLL_CTL_DEL, connection->fd_udp, NULL);
                connection->fd_udp = c_close(connection->fd_udp);
        }

        if (connection->fd_packet >= 0) {
                epoll_ctl(connection->fd_epoll, EPOLL_CTL_DEL, connection->fd_packet, NULL);
                connection->fd_packet = c_close(connection->fd_packet);
        }

        connection->fd_epoll = -1;
        connection->state = N_DHCP4_C_CONNECTION_STATE_CLOSED;
}

static int n_dhcp4_c_connection_verify_incoming(NDhcp4CConnection *connection,
                                                NDhcp4Incoming *message,
                                                uint8_t *typep) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(message);
        uint8_t type;
        uint32_t request_xid;
        uint8_t *id;
        size_t n_id;
        int r;

        r = n_dhcp4_incoming_query_message_type(message, &type);
        if (r) {
                if (r == N_DHCP4_E_UNSET)
                        return N_DHCP4_E_MALFORMED;
                else
                        return r;
        }

        switch (type) {
        case N_DHCP4_MESSAGE_OFFER:
        case N_DHCP4_MESSAGE_ACK:
        case N_DHCP4_MESSAGE_NAK:
                /*
                 * Only accept replies if there is a pending request, and it
                 * has a matching transaction id.
                 */
                if (!connection->request)
                        return N_DHCP4_E_UNEXPECTED;

                n_dhcp4_outgoing_get_xid(connection->request, &request_xid);
                if (header->xid != request_xid)
                        return N_DHCP4_E_UNEXPECTED;

                break;
        case N_DHCP4_MESSAGE_FORCERENEW:
                /*
                 * Force renew messages are triggered by a server, and do not
                 * match a pending request.
                 */
                break;
        default:
                return N_DHCP4_E_UNEXPECTED;
        }

        /*
         * In case our transport makes use of the 'chaddr' field, make sure it
         * matches exactly our address.
         */
        switch (connection->client_config->transport) {
        case N_DHCP4_TRANSPORT_ETHERNET:
                c_assert(connection->client_config->n_mac == ETH_ALEN);

                if (header->hlen != ETH_ALEN)
                        return N_DHCP4_E_UNEXPECTED;
                if (memcmp(header->chaddr, connection->client_config->mac, ETH_ALEN) != 0)
                        return N_DHCP4_E_UNEXPECTED;

                break;
        case N_DHCP4_TRANSPORT_INFINIBAND:
                if (header->hlen != 0)
                        return N_DHCP4_E_UNEXPECTED;

                break;
        }

        /*
         * If a server passes us back a client ID, it must be the one we
         * provided. We ignore any packets that have mismatching client-ids.
         */
        id = NULL;
        n_id = 0;
        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_CLIENT_IDENTIFIER, &id, &n_id);
        if (r) {
                if (r != N_DHCP4_E_UNSET)
                        return r;
        } else {
                if (n_id != connection->client_config->n_client_id)
                        return N_DHCP4_E_UNEXPECTED;
                if (memcmp(id, connection->client_config->client_id, n_id) != 0)
                        return N_DHCP4_E_UNEXPECTED;
        }

        *typep = type;
        return 0;
}

void n_dhcp4_c_connection_get_timeout(NDhcp4CConnection *connection,
                                      uint64_t *timeoutp) {
        uint64_t timeout;
        size_t n_send;

        if (!connection->request) {
                *timeoutp = 0;
                return;
        }

        switch (connection->request->userdata.type) {
        case N_DHCP4_C_MESSAGE_DISCOVER:
        case N_DHCP4_C_MESSAGE_SELECT:
        case N_DHCP4_C_MESSAGE_REBOOT:
        case N_DHCP4_C_MESSAGE_INFORM:
                /*
                 * Resend with an exponential backoff and a one second random
                 * slack, from a minimum of two seconds to a maximum of sixty
                 * four.
                 *
                 * Note that the RFC says to start at four rather than two
                 * seconds, and use [-1,1] slack, rather than [0,1].
                 */
                n_send = connection->request->userdata.n_send;
                if (n_send >= 6)
                        n_send = 6;

                timeout = connection->request->userdata.send_time + ((1ULL << n_send) * 1000000000ULL) + connection->request->userdata.send_jitter;

                break;
        case N_DHCP4_C_MESSAGE_REBIND:
        case N_DHCP4_C_MESSAGE_RENEW:
                /*
                 * Resend every sixty seconds with a one second random slack.
                 *
                 * Note that the RFC says to do this at most once, but we do
                 * it until we are cancelled.
                 */
                timeout = connection->request->userdata.send_time + (60ULL * 1000000000ULL) + connection->request->userdata.send_jitter;

                break;
        case N_DHCP4_C_MESSAGE_DECLINE:
        case N_DHCP4_C_MESSAGE_RELEASE:
                /* XXX make sure these message types are never pinned? */
                timeout = 0;
                break;
        default:
                c_assert(0);
        }

        *timeoutp = timeout;
}

static int n_dhcp4_c_connection_packet_broadcast(NDhcp4CConnection *connection,
                                                 NDhcp4Outgoing *message) {
        int r;

        c_assert(connection->state == N_DHCP4_C_CONNECTION_STATE_PACKET);

        r = n_dhcp4_c_socket_packet_send(connection->fd_packet,
                                         connection->client_config->ifindex,
                                         connection->client_config->broadcast_mac,
                                         connection->client_config->n_broadcast_mac,
                                         message);
        if (r)
                return r;

        return 0;
}

static int n_dhcp4_c_connection_udp_broadcast(NDhcp4CConnection *connection,
                                              NDhcp4Outgoing *message) {
        int r;

        c_assert(connection->state == N_DHCP4_C_CONNECTION_STATE_DRAINING ||
               connection->state == N_DHCP4_C_CONNECTION_STATE_UDP);

        r = n_dhcp4_c_socket_udp_broadcast(connection->fd_udp, message);
        if (r)
                return r;

        return 0;
}

static int n_dhcp4_c_connection_udp_send(NDhcp4CConnection *connection,
                                         NDhcp4Outgoing *message) {
        int r;

        c_assert(connection->state == N_DHCP4_C_CONNECTION_STATE_DRAINING ||
               connection->state == N_DHCP4_C_CONNECTION_STATE_UDP);

        r = n_dhcp4_c_socket_udp_send(connection->fd_udp, message);
        if (r)
                return r;

        return 0;
}

static void n_dhcp4_c_connection_init_header(NDhcp4CConnection *connection,
                                             NDhcp4Header *header) {
        bool broadcast = connection->client_config->request_broadcast;

        header->op = N_DHCP4_OP_BOOTREQUEST;

        switch (connection->client_config->transport) {
        case N_DHCP4_TRANSPORT_ETHERNET:
                c_assert(connection->client_config->n_mac == ETH_ALEN);

                header->htype = ARPHRD_ETHER;
                header->hlen = ETH_ALEN;
                memcpy(header->chaddr, connection->client_config->mac, ETH_ALEN);
                break;
        case N_DHCP4_TRANSPORT_INFINIBAND:
                header->htype = ARPHRD_INFINIBAND;
                header->hlen = 0;

                /* infiniband mandates to request broadcasts */
                broadcast = true;
                break;
        default:
                abort();
                break;
        }

        if (connection->client_ip != INADDR_ANY) {
                header->ciaddr = connection->client_ip;
        } else {
                /*
                 * When the IP stack has not been configured, we may
                 * not be able to receive unicast packets, depending
                 * on the hardware. If that is the case we must request
                 * replies from the server to be broadcast.
                 *
                 * Once the IP stack has been configured, receiving
                 * unicast packets is never a problem, so the broadcast
                 * flag should not be set.
                 */
                if (broadcast)
                        header->flags |= N_DHCP4_MESSAGE_FLAG_BROADCAST;
        }
}

static int n_dhcp4_c_connection_new_message(NDhcp4CConnection *connection,
                                            NDhcp4Outgoing **messagep,
                                            uint8_t type) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        NDhcp4Header *header;
        uint8_t message_type;
        bool via_packet_socket = false;
        int r;

        switch (type) {
        case N_DHCP4_C_MESSAGE_DISCOVER:
                message_type = N_DHCP4_MESSAGE_DISCOVER;
                via_packet_socket = true;
                break;
        case N_DHCP4_C_MESSAGE_INFORM:
                message_type = N_DHCP4_MESSAGE_INFORM;
                break;
        case N_DHCP4_C_MESSAGE_SELECT:
                message_type = N_DHCP4_MESSAGE_REQUEST;
                via_packet_socket = true;
                break;
        case N_DHCP4_C_MESSAGE_RENEW:
                message_type = N_DHCP4_MESSAGE_REQUEST;
                break;
        case N_DHCP4_C_MESSAGE_REBIND:
                message_type = N_DHCP4_MESSAGE_REQUEST;
                break;
        case N_DHCP4_C_MESSAGE_REBOOT:
                message_type = N_DHCP4_MESSAGE_REQUEST;
                via_packet_socket = true;
                break;
        case N_DHCP4_C_MESSAGE_RELEASE:
                message_type = N_DHCP4_MESSAGE_RELEASE;
                break;
        case N_DHCP4_C_MESSAGE_DECLINE:
                message_type = N_DHCP4_MESSAGE_DECLINE;
                via_packet_socket = true;
                break;
        default:
                abort();
                return -ENOTRECOVERABLE;
        }

        /*
         * We explicitly pass 0 as maximum message size, which makes
         * NDhcp4Outgoing use the mandated default value from the spec (see its
         * implementation). While the transport and like layers might support
         * bigger MTUs (and we very likely know about them through
         * n_dhcp4_client_update_mtu()), we cannot assume the target DHCP
         * server supports parsing packets bigger than the minimum (and it is
         * allowed to refuse bigger IP packets, even if the network supports
         * transmission of them).
         *
         * We could theoretically increase this for packets other than the
         * initial discovery. However, clients are unlikely to ever send large
         * packets, so we just keep the same default for all outgoing packets.
         */
        r = n_dhcp4_outgoing_new(&message, 0, N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME);
        if (r)
                return r;

        header = n_dhcp4_outgoing_get_header(message);
        n_dhcp4_c_connection_init_header(connection, header);

        message->userdata.type = type;

        /*
         * Note that some implementations expect the MESSAGE_TYPE option to be
         * the first option, and possibly even hard-code access to it. Hence,
         * we really should make sure to pass it first as well.
         */
        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MESSAGE_TYPE, &message_type, sizeof(message_type));
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message,
                                    N_DHCP4_OPTION_CLIENT_IDENTIFIER,
                                    connection->client_config->client_id,
                                    connection->client_config->n_client_id);
        if (r)
                return r;

        switch (message_type) {
        case N_DHCP4_MESSAGE_DISCOVER:
        case N_DHCP4_MESSAGE_REQUEST:
        case N_DHCP4_MESSAGE_INFORM: {
                uint16_t mtu;

                if (connection->probe_config->n_request_parameters > 0) {
                        r = n_dhcp4_outgoing_append(message,
                                                    N_DHCP4_OPTION_PARAMETER_REQUEST_LIST,
                                                    connection->probe_config->request_parameters,
                                                    connection->probe_config->n_request_parameters);
                        if (r)
                                return r;
                }

                if (via_packet_socket) {
                        /*
                         * In case of packet sockets, we do not support
                         * fragmentation. Hence, our maximum message size
                         * equals the transport MTU. In case no mtu is given,
                         * we use the minimum size mandated by the IP spec. If
                         * we omit the field, some implementations will
                         * interpret this to mean any packet size is supported,
                         * which we rather not want as default behavior (we can
                         * always support suppressing this field, if that is
                         * what the caller wants).
                         */
                        mtu = htons(connection->mtu ?: N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE);
                        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE, &mtu, sizeof(mtu));
                        if (r)
                                return r;
                } else {
                        /*
                         * Once we use UDP sockets, we support fragmentation
                         * through the kernel IP stack. This means, the biggest
                         * message we can receive is the maximum UDP size plus
                         * the possible IP header. This would sum up to
                         * 2^16-1 + 20 (or even 2^16-1 + 60 if pedantic) and
                         * thus exceed the option field. Hence, we simply set
                         * the option to the maximum possible value.
                         */
                        mtu = htons(UINT16_MAX);
                        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE, &mtu, sizeof(mtu));
                        if (r)
                                return r;
                }

                break;
        }
        default:
                break;
        }

        *messagep = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.1
 *
 *      The client broadcasts a DHCPDISCOVER message on its local physical
 *      subnet.  The DHCPDISCOVER message MAY include options that suggest
 *      values for the network address and lease duration.  BOOTP relay
 *      agents may pass the message on to DHCP servers not on the same
 *      physical subnet.
 *
 *      RFC2131 3.5
 *
 *      [...] in its initial DHCPDISCOVER or DHCPREQUEST message, a client
 *      may provide the server with a list of specific parameters the
 *      client is interested in.  If the client includes a list of
 *      parameters in a DHCPDISCOVER message, it MUST include that list in
 *      any subsequent DHCPREQUEST messages.
 *
 *      [...]
 *
 *      In addition, the client may suggest values for the network address
 *      and lease time in the DHCPDISCOVER message.  The client may include
 *      the 'requested IP address' option to suggest that a particular IP
 *      address be assigned, and may include the 'IP address lease time'
 *      option to suggest the lease time it would like.  Other options
 *      representing "hints" at configuration parameters are allowed in a
 *      DHCPDISCOVER or DHCPREQUEST message.
 *
 *      RFC2131 4.4.1
 *
 *      The client generates and records a random transaction identifier and
 *      inserts that identifier into the 'xid' field.  The client records its
 *      own local time for later use in computing the lease expiration.  The
 *      client then broadcasts the DHCPDISCOVER on the local hardware
 *      broadcast address to the 0xffffffff IP broadcast address and 'DHCP
 *      server' UDP port.
 *
 *      If the 'xid' of an arriving DHCPOFFER message does not match the
 *      'xid' of the most recent DHCPDISCOVER message, the DHCPOFFER message
 *      must be silently discarded.  Any arriving DHCPACK messages must be
 *      silently discarded.
 */
int n_dhcp4_c_connection_discover_new(NDhcp4CConnection *connection,
                                      NDhcp4Outgoing **requestp) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_DISCOVER);
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *
 *      RFC2131 4.1.1
 *
 *      The DHCPREQUEST message contains the same 'xid' as the DHCPOFFER
 *      message.
 *
 *      RFC2131 4.3.2
 *
 *      Client inserts the address of the selected server in 'server
 *      identifier', 'ciaddr' MUST be zero, 'requested IP address' MUST be
 *      filled in with the yiaddr value from the chosen DHCPOFFER.
 */
int n_dhcp4_c_connection_select_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp,
                                    NDhcp4Incoming *offer) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        struct in_addr client;
        struct in_addr server;
        uint32_t xid;
        int r;

        n_dhcp4_incoming_get_yiaddr(offer, &client);

        r = n_dhcp4_incoming_query_server_identifier(offer, &server);
        if (r)
                return r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_SELECT);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, &client, sizeof(client));
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &server, sizeof(server));
        if (r)
                return r;

        /*
         * SELECT continues the transaction started by DISCOVER, and as such
         * keeps the same start time. We also have to preserve the base time
         * of the selected lease as well as the transaction ID.
         */
        message->userdata.start_time = offer->userdata.start_time;
        message->userdata.base_time = offer->userdata.base_time;
        n_dhcp4_incoming_get_xid(offer, &xid);
        n_dhcp4_outgoing_set_xid(message, xid);

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 4.3.2
 *
 *      'server identifier' MUST NOT be filled in, 'requested IP address'
 *      option MUST be filled in with client's notion of its previously
 *      assigned address. 'ciaddr' MUST be zero. The client is seeking to
 *      verify a previously allocated, cached configuration. Server SHOULD
 *      send a DHCPNAK message to the client if the 'requested IP address'
 *      is incorrect, or is on the wrong network.
 */
int n_dhcp4_c_connection_reboot_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp,
                                    const struct in_addr *client) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_REBOOT);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, client, sizeof(*client));
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 4.3.2
 *
 *      'server identifier' MUST NOT be filled in, 'requested IP address'
 *      option MUST NOT be filled in, 'ciaddr' MUST be filled in with
 *      client's IP address. In this situation, the client is completely
 *      configured, and is trying to extend its lease. This message will
 *      be unicast, so no relay agents will be involved in its
 *      transmission.  Because 'giaddr' is therefore not filled in, the
 *      DHCP server will trust the value in 'ciaddr', and use it when
 *      replying to the client.
 *
 *      A client MAY choose to renew or extend its lease prior to T1.  The
 *      server may choose not to extend the lease (as a policy decision by
 *      the network administrator), but should return a DHCPACK message
 *      regardless.
 *
 *      RFC2131 4.4.5
 *
 *      At time T1 the client moves to RENEWING state and sends (via unicast)
 *      a DHCPREQUEST message to the server to extend its lease.  The client
 *      sets the 'ciaddr' field in the DHCPREQUEST to its current network
 *      address. The client records the local time at which the DHCPREQUEST
 *      message is sent for computation of the lease expiration time.  The
 *      client MUST NOT include a 'server identifier' in the DHCPREQUEST
 *      message.
 */
int n_dhcp4_c_connection_renew_new(NDhcp4CConnection *connection,
                                   NDhcp4Outgoing **requestp) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_RENEW);
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 4.3.2
 *
 *      'server identifier' MUST NOT be filled in, 'requested IP address'
 *      option MUST NOT be filled in, 'ciaddr' MUST be filled in with
 *      client's IP address. In this situation, the client is completely
 *      configured, and is trying to extend its lease. This message MUST
 *      be broadcast to the 0xffffffff IP broadcast address.  The DHCP
 *      server SHOULD check 'ciaddr' for correctness before replying to
 *      the DHCPREQUEST.
 *
 *      RFC2131 4.4.5
 *
 *      If no DHCPACK arrives before time T2, the client moves to REBINDING
 *      state and sends (via broadcast) a DHCPREQUEST message to extend its
 *      lease.  The client sets the 'ciaddr' field in the DHCPREQUEST to its
 *      current network address.  The client MUST NOT include a 'server
 *      identifier' in the DHCPREQUEST message.
 */
int n_dhcp4_c_connection_rebind_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_REBIND);
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.2
 *
 *      If the client detects that the IP address in the DHCPACK message
 *      is already in use, the client MUST send a DHCPDECLINE message to the
 *      server and restarts the configuration process by requesting a
 *      new network address.
 *
 *      RFC2131 4.4.4
 *
 *      Because the client is declining the use of the IP address supplied by
 *      the server, the client broadcasts DHCPDECLINE messages.
 */
int n_dhcp4_c_connection_decline_new(NDhcp4CConnection *connection,
                                     NDhcp4Outgoing **requestp,
                                     NDhcp4Incoming *ack,
                                     const char *error) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        struct in_addr client;
        struct in_addr server;
        int r;

        n_dhcp4_incoming_get_yiaddr(ack, &client);

        r = n_dhcp4_incoming_query_server_identifier(ack, &server);
        if (r)
                return r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_DECLINE);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, &client, sizeof(client));
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &server, sizeof(server));
        if (r)
                return r;

        if (error) {
                r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_ERROR_MESSAGE, error, strlen(error) + 1);
                if (r)
                        return r;
        }

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.4
 *
 *      If a client has obtained a network address through some other means
 *      (e.g., manual configuration), it may use a DHCPINFORM request message
 *      to obtain other local configuration parameters.
 *
 *      RFC2131 4.4
 *
 *      The DHCPINFORM message is not shown in figure 5.  A client simply
 *      sends the DHCPINFORM and waits for DHCPACK messages.  Once the client
 *      has selected its parameters, it has completed the configuration
 *      process.
 *
 *      RFC2131 4.4.3
 *
 *      The client sends a DHCPINFORM message. The client may request
 *      specific configuration parameters by including the 'parameter request
 *      list' option. The client generates and records a random transaction
 *      identifier and inserts that identifier into the 'xid' field. The
 *      client places its own network address in the 'ciaddr' field. The
 *      client SHOULD NOT request lease time parameters.
 *
 *      The client then unicasts the DHCPINFORM to the DHCP server if it
 *      knows the server's address, otherwise it broadcasts the message to
 *      the limited (all 1s) broadcast address.  DHCPINFORM messages MUST be
 *      directed to the 'DHCP server' UDP port.
 */
int n_dhcp4_c_connection_inform_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_INFORM);
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.1
 *
 *      The client may choose to relinquish its lease on a network address
 *      by sending a DHCPRELEASE message to the server.  The client
 *      identifies the lease to be released with its 'client identifier',
 *      or 'chaddr' and network address in the DHCPRELEASE message. If the
 *      client used a 'client identifier' when it obtained the lease, it
 *      MUST use the same 'client identifier' in the DHCPRELEASE message.
 *
 *      RFC2131 3.2
 *
 *      The client may choose to relinquish its lease on a network
 *      address by sending a DHCPRELEASE message to the server.  The
 *      client identifies the lease to be released with its
 *      'client identifier', or 'chaddr' and network address in the
 *      DHCPRELEASE message.
 *
 *      Note that in this case, where the client retains its network
 *      address locally, the client will not normally relinquish its
 *      lease during a graceful shutdown.  Only in the case where the
 *      client explicitly needs to relinquish its lease, e.g., the client
 *      is about to be moved to a different subnet, will the client send
 *      a DHCPRELEASE message.
 *
 *      RFC2131 4.4.4
 *
 *      The client unicasts DHCPRELEASE messages to the server.
 *
 *      RFC2131 4.4.6
 *
 *      If the client no longer requires use of its assigned network address
 *      (e.g., the client is gracefully shut down), the client sends a
 *      DHCPRELEASE message to the server.  Note that the correct operation
 *      of DHCP does not depend on the transmission of DHCPRELEASE messages.
 */
int n_dhcp4_c_connection_release_new(NDhcp4CConnection *connection,
                                     NDhcp4Outgoing **requestp,
                                     const char *error) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_RELEASE);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &connection->server_ip, sizeof(connection->server_ip));
        if (r)
                return r;

        if (error) {
                r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_ERROR_MESSAGE, error, strlen(error) + 1);
                if (r)
                        return r;
        }

        *requestp = message;
        message = NULL;
        return 0;
}

static int n_dhcp4_c_connection_send_request(NDhcp4CConnection *connection,
                                             NDhcp4Outgoing *request,
                                             uint64_t timestamp) {
        int r;

        /*
         * Increment the base time and reset the xid field,
         * where applicable. We never alter the header on
         * resends of SELECT, as it must always match the
         * OFFER message they are in reply to.
         */
        switch (request->userdata.type) {
        case N_DHCP4_C_MESSAGE_DISCOVER:
        case N_DHCP4_C_MESSAGE_INFORM:
        case N_DHCP4_C_MESSAGE_REBOOT:
        case N_DHCP4_C_MESSAGE_REBIND:
        case N_DHCP4_C_MESSAGE_RENEW:
                request->userdata.base_time = timestamp;
                n_dhcp4_outgoing_set_xid(request, n_dhcp4_client_probe_config_get_random(connection->probe_config));

                break;
        case N_DHCP4_C_MESSAGE_SELECT:
        case N_DHCP4_C_MESSAGE_DECLINE:
        case N_DHCP4_C_MESSAGE_RELEASE:
                break;
        default:
                c_assert(0);
        }

        request->userdata.send_time = timestamp;
        request->userdata.send_jitter = (n_dhcp4_client_probe_config_get_random(connection->probe_config) % 1000000000ULL);
        n_dhcp4_c_connection_outgoing_set_secs(request);

        switch (request->userdata.type) {
        case N_DHCP4_C_MESSAGE_DISCOVER:
        case N_DHCP4_C_MESSAGE_SELECT:
        case N_DHCP4_C_MESSAGE_REBOOT:
        case N_DHCP4_C_MESSAGE_DECLINE:
                r = n_dhcp4_c_connection_packet_broadcast(connection, request);
                if (r)
                        return r;
                break;
        case N_DHCP4_C_MESSAGE_INFORM:
        case N_DHCP4_C_MESSAGE_REBIND:
                r = n_dhcp4_c_connection_udp_broadcast(connection, request);
                if (r)
                        return r;

                break;
        case N_DHCP4_C_MESSAGE_RENEW:
        case N_DHCP4_C_MESSAGE_RELEASE:
                r = n_dhcp4_c_connection_udp_send(connection, request);
                if (r)
                        return r;

                break;
        default:
                c_assert(0);
        }

        ++request->userdata.n_send;
        return 0;
}

int n_dhcp4_c_connection_start_request(NDhcp4CConnection *connection,
                                       NDhcp4Outgoing *request,
                                       uint64_t timestamp) {
        int r;

        /*
         * This function starts a request, but in the case of SELECT it
         * continues a previous transaction, so we do not want to reset
         * the start time. Only set the start time if it was not already
         * set.
         */
        if (request->userdata.start_time == 0)
                request->userdata.start_time = timestamp;

        n_dhcp4_outgoing_free(connection->request);
        connection->request = request;

        r = n_dhcp4_c_connection_send_request(connection, request, timestamp);
        if (r)
                return r;

        return 0;
}

int n_dhcp4_c_connection_dispatch_timer(NDhcp4CConnection *connection,
                                        uint64_t timestamp) {
        uint64_t timeout;
        int r;

        if (!connection->request)
                return 0;

        n_dhcp4_c_connection_get_timeout(connection, &timeout);

        if (timeout > timestamp)
                return 0;

        r = n_dhcp4_c_connection_send_request(connection, connection->request, timestamp);
        if (r)
                return r;

        return 0;
}

int n_dhcp4_c_connection_dispatch_io(NDhcp4CConnection *connection,
                                     NDhcp4Incoming **messagep) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t type;
        int r;

        switch (connection->state) {
        case N_DHCP4_C_CONNECTION_STATE_PACKET:
                r = n_dhcp4_c_socket_packet_recv(connection->fd_packet,
                                                 connection->scratch_buffer,
                                                 sizeof(connection->scratch_buffer),
                                                 &message);
                if (r)
                        return r;

                break;
        case N_DHCP4_C_CONNECTION_STATE_DRAINING:
                r = n_dhcp4_c_socket_packet_recv(connection->fd_packet,
                                                 connection->scratch_buffer,
                                                 sizeof(connection->scratch_buffer),
                                                 &message);
                if (!r)
                        break;
                else if (r != N_DHCP4_E_AGAIN)
                        return r;

                /*
                 * The UDP socket is open and the packet socket has been shut down
                 * and drained, clean up the packet socket and fall through to
                 * dispatching the UDP socket.
                 */
                r = epoll_ctl(connection->fd_epoll, EPOLL_CTL_DEL, connection->fd_packet, NULL);
                c_assert(!r);
                connection->fd_packet = c_close(connection->fd_packet);
                connection->state = N_DHCP4_C_CONNECTION_STATE_UDP;

                /* fall-through */
        case N_DHCP4_C_CONNECTION_STATE_UDP:
                r = n_dhcp4_c_socket_udp_recv(connection->fd_udp,
                                              connection->scratch_buffer,
                                              sizeof(connection->scratch_buffer),
                                              &message);
                if (r)
                        return r;

                break;
        default:
                abort();
                return -ENOTRECOVERABLE;
        }

        r = n_dhcp4_c_connection_verify_incoming(connection, message, &type);
        if (r)
                return r;

        switch (type) {
        case N_DHCP4_MESSAGE_OFFER:
        case N_DHCP4_MESSAGE_ACK:
        case N_DHCP4_MESSAGE_NAK:
                /*
                 * Remember the start time of the transaction, and the base
                 * time of any relative timestamps from the pending request.
                 * Thes same times applies to the response, and sholud be
                 * copied over.
                 */
                message->userdata.start_time = connection->request->userdata.start_time;
                message->userdata.base_time = connection->request->userdata.base_time;

                if (type != N_DHCP4_MESSAGE_OFFER) {
                        /*
                         * We only allow one reply to ACK or NAK, but for OFFER we must
                         * accept several, so we do not free the pinned request.
                         */
                        connection->request = n_dhcp4_outgoing_free(connection->request);
                }

                break;
        default:
                break;
        }

        *messagep = message;
        message = NULL;
        return 0;
}
