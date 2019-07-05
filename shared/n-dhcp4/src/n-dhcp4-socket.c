/*
 * DHCP specific low-level socket helpers
 */

#include <c-stdaux.h>
#include <errno.h>
#include <linux/filter.h>
#include <sys/socket.h> /* needed by linux/if.h */
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "n-dhcp4-private.h"
#include "util/packet.h"
#include "util/socket.h"

/**
 * n_dhcp4_c_socket_packet_new() - create a new DHCP4 client packet socket
 * @sockfdp:            return argumnet for the new socket
 * @ifindex:            interface index to bind to
 *
 * Create a new AF_PACKET/SOCK_DGRAM socket usable to listen to and send DHCP client
 * packets before an IP address has been configured.
 *
 * Only unfragmented DHCP packets from a server to a client destined for the given
 * ifindex is returned.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_c_socket_packet_new(int *sockfdp, int ifindex) {
        _c_cleanup_(c_closep) int sockfd = -1;
        struct sock_filter filter[] = {
                /*
                 * IP
                 *
                 * Check
                 *  - UDP
                 *  - Unfragmented
                 *  - Large enough to fit the DHCP header
                 *
                 *  Leave X the size of the IP header, for future indirect reads.
                 */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, protocol)),                           /* A <- IP protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),                                         /* IP protocol == UDP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, frag_off)),                           /* A <- Flags */
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, ntohs(IP_MF | IP_OFFMASK)),                                 /* A <- A & (IP_MF | IP_OFFMASK) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                                   /* fragmented packet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                                         /* X <- IP header length */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                                          /* A <- packet length */
                BPF_STMT(BPF_ALU + BPF_SUB + BPF_X, 0),                                                         /* A -= X */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct udphdr) + sizeof(NDhcp4Message), 1, 0),       /* packet >= DHCPPacket ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                /*
                 * UDP
                 *
                 * Check
                 *  - DHCP client port
                 *
                 * Leave X the size of IP and UDP headers, for future indirect reads.
                 */
                BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct udphdr, dest)),                              /* A <- UDP destination port */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_NETWORK_CLIENT_PORT, 1, 0),                         /* UDP destination port == DHCP client port ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_K, sizeof(struct udphdr)),                                        /* A <- size of UDP header */
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),                                                         /* A += X */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */

                /*
                 * DHCP
                 *
                 * Check
                 *  - BOOTREPLY (from server to client)
                 *  - DHCP magic cookie
                 */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(NDhcp4Header, op)),                                 /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREPLY, 1, 0),                                /* op == BOOTREPLY ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_IND, offsetof(NDhcp4Message, magic)),                             /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                               /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
        };
        int r, on = 1;

        sockfd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        /* We need the flag that tells us if the checksum is correct. */
        r = setsockopt(sockfd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        if (r < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

/**
 * n_dhcp4_c_socket_udp_new() - create a new DHCP4 client UDP socket
 * @sockfdp:            return argumnet for the new socket
 * @ifindex:            interface index to bind to
 * @client_addr:        client address to bind to
 * @server_addr:        server address to connect to
 *
 * Create a new AF_INET/SOCK_DGRAM socket usable to listen to and send DHCP client
 * packets.
 *
 * The client address given in @addr must be configured on the interface @ifindex
 * before the socket is created.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_c_socket_udp_new(int *sockfdp,
                             int ifindex,
                             const struct in_addr *client_addr,
                             const struct in_addr *server_addr) {
        _c_cleanup_(c_closep) int sockfd = -1;
        struct sock_filter filter[] = {
                /*
                 * IP/UDP
                 *
                 * Set X to the size of IP and UDP headers, for future indirect reads.
                 */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                                         /* X <- IP header length */
                BPF_STMT(BPF_LD + BPF_W + BPF_K, sizeof(struct udphdr)),                                        /* A <- size of UDP header */
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),                                                         /* A += X */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */

                /*
                 * DHCP
                 *
                 * Check
                 *  - BOOTREPLY (from server to client)
                 *  - DHCP magic cookie
                 */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(NDhcp4Header, op)),                                 /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREPLY, 1, 0),                                /* op == BOOTREPLY ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_IND, offsetof(NDhcp4Message, magic)),                             /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                               /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        struct sockaddr_in saddr = {
                .sin_family = AF_INET,
                .sin_addr = *client_addr,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
        };
        struct sockaddr_in daddr = {
                .sin_family = AF_INET,
                .sin_addr = *server_addr,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
        };
        int r, tos = IPTOS_CLASS_CS6, on = 1;

        sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = socket_bind_if(sockfd, ifindex);
        if (r)
                return r;

        r = setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (r < 0)
                return -errno;

        r = bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr));
        if (r < 0)
                return -errno;

        r = connect(sockfd, (struct sockaddr*)&daddr, sizeof(daddr));
        if (r < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

/**
 * n_dhcp4_s_socket_packet_new() - create a new DHCP4 server packet socket
 * @sockfdp:            return argumnet for the new socket
 *
 * Create a new AF_PACKET/SOCK_DGRAM socket usable to send DHCP packets to clients
 * before they have an IP address configured, on the given interface.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_s_socket_packet_new(int *sockfdp) {
        _c_cleanup_(c_closep) int sockfd = -1;

        sockfd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

/**
 * n_dhcp4_s_socket_udp_new() - create a new DHCP4 server UDP socket
 * @sockfdp:            return argumnet for the new socket
 * @ifindex:            intercafe index to bind to
 *
 * Create a new AF_INET/SOCK_DGRAM socket usable to listen to DHCP server packets,
 * on the given interface.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_s_socket_udp_new(int *sockfdp, int ifindex) {
        _c_cleanup_(c_closep) int sockfd = -1;
        struct sock_filter filter[] = {
                /*
                 * IP/UDP
                 *
                 * Set X to the size of IP and UDP headers, for future indirect reads.
                 */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                                         /* X <- IP header length */
                BPF_STMT(BPF_LD + BPF_W + BPF_K, sizeof(struct udphdr)),                                        /* A <- size of UDP header */
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),                                                         /* A += X */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */

                /*
                 * DHCP
                 *
                 * Check
                 *  - BOOTREQUEST (from client to server)
                 *  - DHCP magic cookie
                 */

                BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(NDhcp4Header, op)),                                 /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREQUEST, 1, 0),                              /* op == BOOTREQUEST ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_IND, offsetof(NDhcp4Message, magic)),                             /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                               /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_addr = { INADDR_ANY },
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
        };
        int r, tos = IPTOS_CLASS_CS6, on = 1;

        sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = socket_bind_if(sockfd, ifindex);
        if (r)
                return r;

        r = setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        if (r < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

static int n_dhcp4_socket_packet_send(int sockfd,
                                      int ifindex,
                                      const struct sockaddr_in *src_paddr,
                                      const unsigned char *dest_haddr,
                                      unsigned char halen,
                                      const struct sockaddr_in *dest_paddr,
                                      NDhcp4Outgoing *message) {
        struct packet_sockaddr_ll haddr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = halen,
        };
        const void *buf;
        size_t n_buf, len;
        int r;

        c_assert(halen <= sizeof(haddr.sll_addr));

        memcpy(haddr.sll_addr, dest_haddr, halen);

        n_buf = n_dhcp4_outgoing_get_raw(message, &buf);

        r = packet_sendto_udp(sockfd, buf, n_buf, &len, src_paddr, &haddr, dest_paddr);
        if (r < 0) {
                if (r == -EAGAIN || r == -ENOBUFS)
                        return N_DHCP4_E_DROPPED;
                else if (r == -ENETDOWN || r == -ENXIO)
                        return N_DHCP4_E_DOWN;
                else
                        return r;
        } else if (len != n_buf) {
                return N_DHCP4_E_DROPPED;
        }

        return 0;
}

/**
 * n_dhcp4_c_socket_packet_send() - XXX
 */
int n_dhcp4_c_socket_packet_send(int sockfd,
                                 int ifindex,
                                 const unsigned char *dest_haddr,
                                 unsigned char halen,
                                 NDhcp4Outgoing *message) {
        struct sockaddr_in src_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
                .sin_addr = { INADDR_ANY },
        };
        struct sockaddr_in dest_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
                .sin_addr = { INADDR_BROADCAST }
        };

        return n_dhcp4_socket_packet_send(sockfd,
                                          ifindex,
                                          &src_paddr,
                                          dest_haddr,
                                          halen,
                                          &dest_paddr,
                                          message);
}

/**
 * n_dhcp4_c_socket_udp_send() - XXX
 */
int n_dhcp4_c_socket_udp_send(int sockfd,
                              NDhcp4Outgoing *message) {
        const void *buf;
        size_t n_buf;
        ssize_t len;

        n_buf = n_dhcp4_outgoing_get_raw(message, &buf);

        len = send(sockfd, buf, n_buf, 0);
        if (len < 0) {
                if (errno == EAGAIN || errno == ENOBUFS)
                        return N_DHCP4_E_DROPPED;
                else if (errno == ENETDOWN || errno == ENXIO)
                        return N_DHCP4_E_DOWN;
                else
                        return -errno;
        } else if ((size_t)len != n_buf)
                return N_DHCP4_E_DROPPED;

        return 0;
}

/**
 * n_dhcp4_c_socket_udp_broadcast() - XXX
 */
int n_dhcp4_c_socket_udp_broadcast(int sockfd, NDhcp4Outgoing *message) {
        struct sockaddr_in sockaddr_dest = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
                .sin_addr = { INADDR_BROADCAST },
        };
        const void *buf;
        size_t n_buf;
        ssize_t len;

        n_buf = n_dhcp4_outgoing_get_raw(message, &buf);

        len = sendto(sockfd,
                     buf,
                     n_buf,
                     0,
                     (struct sockaddr*)&sockaddr_dest,
                     sizeof(sockaddr_dest));
        if (len < 0) {
                if (errno == EAGAIN || errno == ENOBUFS)
                        return N_DHCP4_E_DROPPED;
                else if (errno == ENETDOWN || errno == ENXIO)
                        return N_DHCP4_E_DOWN;
                else
                        return -errno;
        } else if ((size_t)len != n_buf)
                return N_DHCP4_E_DROPPED;

        return 0;
}

/**
 * n_dhcp4_s_socket_packet_send() - XXX
 */
int n_dhcp4_s_socket_packet_send(int sockfd,
                                 int ifindex,
                                 const struct in_addr *src_inaddr,
                                 const unsigned char *dest_haddr,
                                 unsigned char halen,
                                 const struct in_addr *dest_inaddr,
                                 NDhcp4Outgoing *message) {
        struct sockaddr_in src_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
                .sin_addr = *src_inaddr,
        };
        struct sockaddr_in dest_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
                .sin_addr = *dest_inaddr,
        };

        return n_dhcp4_socket_packet_send(sockfd,
                                          ifindex,
                                          &src_paddr,
                                          dest_haddr,
                                          halen,
                                          &dest_paddr,
                                          message);
}

/**
 * n_dhcp4_s_socket_udp_send() - XXX
 */
int n_dhcp4_s_socket_udp_send(int sockfd,
                              const struct in_addr *inaddr_src,
                              const struct in_addr *inaddr_dest,
                              NDhcp4Outgoing *message) {
        struct sockaddr_in sockaddr_dest = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
                .sin_addr = *inaddr_dest,
        };
        struct iovec iov = {};
        union {
               struct cmsghdr align; /* ensure correct stack alignment */
               char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        } control = {};
        struct in_pktinfo pktinfo = {
                .ipi_spec_dst = *inaddr_src,
        };
        struct msghdr msg = {
                .msg_name = (void*)&sockaddr_dest,
                .msg_namelen = sizeof(sockaddr_dest),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control.buf,
                .msg_controllen = sizeof(control.buf),
        };
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        ssize_t len;

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));

        iov.iov_len = n_dhcp4_outgoing_get_raw(message, (const void **)&iov.iov_base);

        len = sendmsg(sockfd, &msg, 0);
        if (len < 0) {
                if (errno == EAGAIN || errno == ENOBUFS)
                        return N_DHCP4_E_DROPPED;
                else if (errno == ENETDOWN || errno == ENXIO)
                        return N_DHCP4_E_DOWN;
                else
                        return -errno;
        } else if ((size_t)len != iov.iov_len)
                return N_DHCP4_E_DROPPED;

        return 0;
}

int n_dhcp4_s_socket_udp_broadcast(int sockfd,
                                   const struct in_addr *inaddr_src,
                                   NDhcp4Outgoing *message) {
        return n_dhcp4_s_socket_udp_send(sockfd,
                                         inaddr_src,
                                         &(const struct in_addr){INADDR_BROADCAST},
                                         message);
}

int n_dhcp4_c_socket_packet_recv(int sockfd,
                                 uint8_t *buf,
                                 size_t n_buf,
                                 NDhcp4Incoming **messagep) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        size_t len;
        int r;

        r = packet_recv_udp(sockfd, buf, n_buf, &len);
        if (r < 0) {
                if (r == -ENETDOWN)
                        return N_DHCP4_E_DOWN;
                else if (r == -EAGAIN)
                        return N_DHCP4_E_AGAIN;
                else
                        return -errno;
        } else if (len == 0) {
                return N_DHCP4_E_MALFORMED;
        }

        r = n_dhcp4_incoming_new(&message, buf, len);
        if (r)
                return r;

        *messagep = message;
        message = NULL;
        return 0;
}

static int n_dhcp4_socket_udp_recv(int sockfd,
                                   uint8_t *buf,
                                   size_t n_buf,
                                   NDhcp4Incoming **messagep,
                                   struct in_pktinfo *pktinfo) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        struct iovec iov = {
                .iov_base = buf,
                .iov_len = n_buf,
        };
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct in_pktinfo))];
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        ssize_t len;
        int r;

        len = recvmsg(sockfd, &msg, MSG_TRUNC);
        if (len < 0) {
                if (errno == ENETDOWN)
                        return N_DHCP4_E_DOWN;
                else if (errno == EAGAIN)
                        return N_DHCP4_E_AGAIN;
                else
                        return -errno;
        } else if (len == 0 || (size_t)len > n_buf) {
                return N_DHCP4_E_MALFORMED;
        }

        r = n_dhcp4_incoming_new(&message, buf, len);
        if (r)
                return r;

        if (pktinfo) {
                struct cmsghdr *cmsg;

                cmsg = CMSG_FIRSTHDR(&msg);
                c_assert(cmsg);
                c_assert(cmsg->cmsg_level == IPPROTO_IP);
                c_assert(cmsg->cmsg_type == IP_PKTINFO);
                c_assert(cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)));

                memcpy(pktinfo, (void*)CMSG_DATA(cmsg), sizeof(struct in_pktinfo));
        }

        *messagep = message;
        message = NULL;
        return 0;
}

int n_dhcp4_c_socket_udp_recv(int sockfd,
                              uint8_t *buf,
                              size_t n_buf,
                              NDhcp4Incoming **messagep) {
        return n_dhcp4_socket_udp_recv(sockfd, buf, n_buf, messagep, NULL);
}

int n_dhcp4_s_socket_udp_recv(int sockfd,
                              uint8_t *buf,
                              size_t n_buf,
                              NDhcp4Incoming **messagep,
                              struct sockaddr_in *dest) {
        struct in_pktinfo pktinfo = {};
        int r;

        r = n_dhcp4_socket_udp_recv(sockfd, buf, n_buf, messagep, &pktinfo);
        if (r)
                return r;

        if (dest) {
                dest->sin_family = AF_INET;
                dest->sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT);
                dest->sin_addr.s_addr = pktinfo.ipi_addr.s_addr;
        }

        return 0;
}
