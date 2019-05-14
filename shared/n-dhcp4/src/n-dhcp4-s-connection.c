/*
 * DHCPv4 Server Connection
 *
 * XXX
 */

#include <assert.h>
#include <c-stdaux.h>
#include <errno.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "n-dhcp4-private.h"
#include "util/packet.h"

int n_dhcp4_s_connection_init(NDhcp4SConnection *connection, int ifindex) {
        int r;

        *connection = (NDhcp4SConnection)N_DHCP4_S_CONNECTION_NULL(*connection);

        r = n_dhcp4_s_socket_packet_new(&connection->fd_packet);
        if (r)
                return r;

        r = n_dhcp4_s_socket_udp_new(&connection->fd_udp, ifindex);
        if (r)
                return r;

        connection->ifindex = ifindex;

        return 0;
}

void n_dhcp4_s_connection_deinit(NDhcp4SConnection *connection) {
        c_assert(!connection->ip);

        if (connection->fd_udp >= 0) {
                close(connection->fd_udp);
        }

        if (connection->fd_packet >= 0) {
                close(connection->fd_packet);
        }

        *connection = (NDhcp4SConnection)N_DHCP4_S_CONNECTION_NULL(*connection);
}

void n_dhcp4_s_connection_get_fd(NDhcp4SConnection *connection, int *fdp) {
        *fdp = connection->fd_udp;
}

static bool n_dhcp4_s_connection_owns_ip(NDhcp4SConnection *connection, struct in_addr addr) {
        if (!connection->ip)
                return false;
        return (connection->ip->ip.s_addr == addr.s_addr);
}

static int n_dhcp4_s_connection_verify_incoming(NDhcp4SConnection *connection,
                                                NDhcp4Incoming *message,
                                                bool broadcast) {
        uint8_t type;
        int r;

        r = n_dhcp4_incoming_query_message_type(message, &type);
        if (r) {
                if (r == N_DHCP4_E_UNSET)
                        return N_DHCP4_E_MALFORMED;
                else
                        return r;
        }

        switch (type) {
        case N_DHCP4_MESSAGE_DISCOVER:
                message->userdata.type = N_DHCP4_C_MESSAGE_DISCOVER;
                break;
        case N_DHCP4_MESSAGE_REQUEST: {
                struct in_addr server_identifier = {};
                struct in_addr requested_ip = {};

                r = n_dhcp4_incoming_query_server_identifier(message, &server_identifier);
                if (r) {
                        if (r == N_DHCP4_E_UNSET) {
                                r = n_dhcp4_incoming_query_requested_ip(message, &requested_ip);
                                if (r) {
                                        if (r == N_DHCP4_E_UNSET) {
                                                if (broadcast) {
                                                        message->userdata.type = N_DHCP4_C_MESSAGE_REBIND;
                                                } else {
                                                        message->userdata.type = N_DHCP4_C_MESSAGE_RENEW;
                                                }
                                        } else {
                                                return r;
                                        }
                                } else {
                                        message->userdata.type = N_DHCP4_C_MESSAGE_REBOOT;
                                }
                        } else {
                                return r;
                        }
                } else {
                        if (n_dhcp4_s_connection_owns_ip(connection, server_identifier)) {
                                message->userdata.type = N_DHCP4_C_MESSAGE_SELECT;
                        } else {
                                message->userdata.type = N_DHCP4_C_MESSAGE_IGNORE;
                        }
                }
        }
                break;
        case N_DHCP4_MESSAGE_DECLINE:
                message->userdata.type = N_DHCP4_C_MESSAGE_DECLINE;
                break;
        case N_DHCP4_MESSAGE_RELEASE:
                message->userdata.type = N_DHCP4_C_MESSAGE_RELEASE;
                break;
        default:
                return N_DHCP4_E_UNEXPECTED;
        }

        return 0;
}

int n_dhcp4_s_connection_dispatch_io(NDhcp4SConnection *connection, NDhcp4Incoming **messagep) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        struct sockaddr_in dest = {};
        int r;

        r = n_dhcp4_s_socket_udp_recv(connection->fd_udp,
                                          connection->buf,
                                          sizeof(connection->buf),
                                          &message,
                                          &dest);
        if (r)
                return r;

        r = n_dhcp4_s_connection_verify_incoming(connection,
                                                 message,
                                                 dest.sin_addr.s_addr == INADDR_BROADCAST);
        if (r) {
                if (r == N_DHCP4_E_MALFORMED || r == N_DHCP4_E_UNEXPECTED) {
                        *messagep = NULL;
                        return 0;
                }

                return -ENOTRECOVERABLE;
        }

        *messagep = message;
        message = NULL;
        return 0;
}

/*
 * If the 'giaddr' field in a DHCP message from a client is non-zero,
 * the server sends any return messages to the 'DHCP server' port on the
 * BOOTP relay agent whose address appears in 'giaddr'. If the 'giaddr'
 * field is zero and the 'ciaddr' field is nonzero, then the server
 * unicasts DHCPOFFER and DHCPACK messages to the address in 'ciaddr'.
 * If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
 * set, then the server broadcasts DHCPOFFER and DHCPACK messages to
 * 0xffffffff. If the broadcast bit is not set and 'giaddr' is zero and
 * 'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
 * messages to the client's hardware address and 'yiaddr' address.  In
 * all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
 * messages to 0xffffffff.
 */
int n_dhcp4_s_connection_send_reply(NDhcp4SConnection *connection,
                                    const struct in_addr *server_addr,
                                    NDhcp4Outgoing *message) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);
        int r;

        if (header->giaddr) {
                const struct in_addr giaddr = { header->giaddr };

                r = n_dhcp4_s_socket_udp_send(connection->fd_udp,
                                              server_addr,
                                              &giaddr,
                                              message);
                if (r)
                        return r;
        } else if (header->ciaddr) {
                const struct in_addr ciaddr = { header->ciaddr };

                r = n_dhcp4_s_socket_udp_send(connection->fd_udp,
                                              server_addr,
                                              &ciaddr,
                                              message);
                if (r)
                        return r;
        } else if (header->flags & htons(N_DHCP4_MESSAGE_FLAG_BROADCAST)) {
                r = n_dhcp4_s_socket_udp_broadcast(connection->fd_udp,
                                                   server_addr,
                                                   message);
                if (r)
                        return r;
        } else {
                r = n_dhcp4_s_socket_packet_send(connection->fd_packet,
                                                 connection->ifindex,
                                                 server_addr,
                                                 header->chaddr,
                                                 header->hlen,
                                                 &(struct in_addr){header->yiaddr},
                                                 message);
                if (r)
                        return r;
        }

        return 0;
}

static void n_dhcp4_s_connection_init_reply_header(NDhcp4SConnection *connection,
                                                   NDhcp4Header *request,
                                                   NDhcp4Header *reply) {
        reply->op = N_DHCP4_OP_BOOTREPLY;

        reply->htype = request->htype;
        reply->hlen = request->hlen;
        reply->flags = request->flags;
        reply->xid = request->xid;
        reply->ciaddr = request->ciaddr;
        reply->giaddr = request->giaddr;
        memcpy(reply->chaddr, request->chaddr, request->hlen);
}

static int n_dhcp4_s_connection_outgoing_set_yiaddr(NDhcp4Outgoing *message,
                                                     uint32_t yiaddr,
                                                     uint32_t lifetime) {
        uint32_t t1 = lifetime / 2;
        uint32_t t2 = ((uint64_t)lifetime * 7) / 8;
        struct in_addr addr = { .s_addr = yiaddr };
        int r;

        r = n_dhcp4_outgoing_append_lifetime(message, lifetime);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append_t1(message, t1);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append_t2(message, t2);
        if (r)
                return r;

        n_dhcp4_outgoing_set_yiaddr(message, addr);

        return 0;
}

static int n_dhcp4_s_connection_new_reply(NDhcp4SConnection *connection,
                                          NDhcp4Outgoing **messagep,
                                          NDhcp4Incoming *request,
                                          uint8_t type,
                                          const struct in_addr *server_address) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        uint16_t max_message_size;
        uint8_t *client_identifier;
        size_t n_client_identifier;
        int r;

        r = n_dhcp4_incoming_query_max_message_size(request, &max_message_size);
        if (r)
                return r;

        r = n_dhcp4_outgoing_new(&message,
                                 max_message_size,
                                 N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME);
        if (r)
                return r;

        n_dhcp4_s_connection_init_reply_header(connection,
                                               n_dhcp4_incoming_get_header(request),
                                               n_dhcp4_outgoing_get_header(message));

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MESSAGE_TYPE, &type, sizeof(type));
        if (r)
                return r;

        r = n_dhcp4_outgoing_append_server_identifier(message, *server_address);
        if (r)
                return r;

        r = n_dhcp4_incoming_query(request,
                                   N_DHCP4_OPTION_CLIENT_IDENTIFIER,
                                   &client_identifier,
                                   &n_client_identifier);
        if (!r) {
                r = n_dhcp4_outgoing_append(message,
                                            N_DHCP4_OPTION_CLIENT_IDENTIFIER,
                                            client_identifier,
                                            n_client_identifier);
                if (r)
                        return r;
        } else if (r != N_DHCP4_E_UNSET) {
                return r;
        }

        *messagep = message;
        message = NULL;
        return 0;
}

int n_dhcp4_s_connection_offer_new(NDhcp4SConnection *connection,
                                   NDhcp4Outgoing **replyp,
                                   NDhcp4Incoming *request,
                                   const struct in_addr *server_address,
                                   const struct in_addr *client_address,
                                   uint32_t lifetime) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_s_connection_new_reply(connection,
                                           &reply,
                                           request,
                                           N_DHCP4_MESSAGE_OFFER,
                                           server_address);
        if (r)
                return r;

        r = n_dhcp4_s_connection_outgoing_set_yiaddr(reply,
                                                     client_address->s_addr,
                                                     lifetime);
        if (r)
                return r;

        *replyp = reply;
        reply = NULL;
        return 0;
}

int n_dhcp4_s_connection_ack_new(NDhcp4SConnection *connection,
                                 NDhcp4Outgoing **replyp,
                                 NDhcp4Incoming *request,
                                 const struct in_addr *server_address,
                                 const struct in_addr *client_address,
                                 uint32_t lifetime) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_s_connection_new_reply(connection,
                                           &reply,
                                           request,
                                           N_DHCP4_MESSAGE_ACK,
                                           server_address);
        if (r)
                return r;

        r = n_dhcp4_s_connection_outgoing_set_yiaddr(reply,
                                                     client_address->s_addr,
                                                     lifetime);
        if (r)
                return r;

        *replyp = reply;
        reply = NULL;
        return 0;
}

int n_dhcp4_s_connection_nak_new(NDhcp4SConnection *connection,
                                 NDhcp4Outgoing **replyp,
                                 NDhcp4Incoming *request,
                                 const struct in_addr *server_address) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_s_connection_new_reply(connection,
                                           &reply,
                                           request,
                                           N_DHCP4_MESSAGE_NAK,
                                           server_address);
        if (r)
                return r;

        /*
         * The RFC is a bit unclear on how NAK should be sent, on the
         * one hand it says that they should be unconditinoally broadcast
         * (unless going through a relay agent), on the other, when they
         * do go through a relay agent, they will not be. We treat them
         * as any other reply and only broadcast when the broadcast bit
         * is set.
         */

        *replyp = reply;
        reply = NULL;
        return 0;
}

void n_dhcp4_s_connection_ip_init(NDhcp4SConnectionIp *ip, struct in_addr addr) {
        *ip = (NDhcp4SConnectionIp)N_DHCP4_S_CONNECTION_IP_NULL(*ip);
        ip->ip = addr;
}

void n_dhcp4_s_connection_ip_deinit(NDhcp4SConnectionIp *ip) {
        c_assert(!ip->connection);
        *ip = (NDhcp4SConnectionIp)N_DHCP4_S_CONNECTION_IP_NULL(*ip);
}

void n_dhcp4_s_connection_ip_link(NDhcp4SConnectionIp *ip, NDhcp4SConnection *connection) {
        c_assert(!connection->ip);
        c_assert(!ip->connection);

        connection->ip = ip;
        ip->connection = connection;
}

void n_dhcp4_s_connection_ip_unlink(NDhcp4SConnectionIp *ip) {
        ip->connection->ip = NULL;
        ip->connection = NULL;
}
