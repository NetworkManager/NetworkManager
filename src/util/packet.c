/*
 * Packet Sockets
 */

#include <assert.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "packet.h"

/**
 * packet_internet_checksum() - compute the internet checksum
 * @data:               the data to checksum
 * @size:               the length of @data in bytes
 *
 * Computes the internet checksum for a given blob according to RFC1071.
 *
 * The internet checksum is the one's complement of the one's complement sum of
 * the 16-bit words of the data, padded with zero-bytes if the data does not
 * end on a 16-bit boundary.
 *
 * Return: Checksum is returned.
 */
uint16_t packet_internet_checksum(const uint8_t *data, size_t size) {
        uint64_t acc = 0;
        uint32_t local;

        while (size >= sizeof(local)) {
                memcpy(&local, data, sizeof(local));
                acc += local;

                data += sizeof(local);
                size -= sizeof(local);
        }

        if (size) {
                local = 0;
                memcpy(&local, data, size);
                acc += local;
        }

        while (acc >> 16)
                acc = (acc & 0xffff) + (acc >> 16);

        return ~acc;
}

/**
 * packet_internet_checksum_udp() - compute the internet checkum for UDP packets
 * @src_addr:           source IP address
 * @dst_addr:           destination IP address
 * @src_port:           source port
 * @dst_port:           destination port
 * @data:               payload
 * @size:               length of payload in bytes
 * @checksum:           current checksum, or 0
 *
 * Computes the internet checksum for a UDP packet, given the relevant IP and
 * UDP header fields.
 *
 * Note that since a UDP packet contains the checksum itself, the resulting
 * checksum will always be 0 (this fact is used to verify that a UDP packet is
 * valid).
 * Inversely, when calculating the checksum for outgoing packets, you have to
 * specify 0 as @checksum, and this function will return the checksum for the
 * caller to use for the packet. In this case, though, the caller must check
 * whether the returned checksum might coincidentally be 0, in which case it
 * must be flipped to -1 (0xffff), since 0 is not allowed as checksum in UDP
 * packets, and -1 is arithmetically equivalent in the checksum calculation.
 *
 * Return: Checksum is returned.
 */
uint16_t packet_internet_checksum_udp(const struct in_addr *src_addr,
                                      const struct in_addr *dst_addr,
                                      uint16_t src_port,
                                      uint16_t dst_port,
                                      const uint8_t *data,
                                      size_t size,
                                      uint16_t checksum) {
        struct {
                uint32_t src;
                uint32_t dst;
                uint8_t _zeros;
                uint8_t protocol;
                uint16_t length;
                struct udphdr udp;
        } _c_packed_ udp_phdr = {
                .src = src_addr->s_addr,
                .dst = dst_addr->s_addr,
                .protocol = IPPROTO_UDP,
                .length = htons(sizeof(struct udphdr) + size),
                .udp = {
                        .source = htons(src_port),
                        .dest = htons(dst_port),
                        .len = htons(sizeof(struct udphdr) + size),
                        .check = checksum,
                },
        };
        const uint8_t *iter;
        uint64_t acc = 0;
        uint32_t local;

        _Static_assert(!(sizeof(udp_phdr) % sizeof(local)),
                       "UDP header structure size is not a multiple of 4");

        for (iter = (const uint8_t *)&udp_phdr;
             iter < (const uint8_t *)(&udp_phdr + 1);
             iter += sizeof(local)) {
                memcpy(&local, iter, sizeof(local));
                acc += local;
        }

        while (size >= sizeof(local)) {
                memcpy(&local, data, sizeof(local));
                acc += local;

                data += sizeof(local);
                size -= sizeof(local);
        }

        if (size) {
                local = 0;
                memcpy(&local, data, size);
                acc += local;
        }

        while (acc >> 16)
                acc = (acc & 0xffff) + (acc >> 16);

        return ~acc;
}

/**
 * packet_sendto_udp() - send UDP packet on AF_PACKET socket
 * @sockfd:             AF_PACKET/SOCK_DGRAM socket
 * @buf:                payload
 * @n_buf:              length of payload in bytes
 * @n_transmittedp:     output argument for number of transmitted bytes
 * @src_paddr:          source protocol address, see ip(7)
 * @dest_haddr:         destination hardware address, see packet(7)
 * @dest_paddr:         destination protocol address, see ip(7)
 *
 * Sends an UDP packet on a AF_PACKET socket directly to a hardware
 * address. The difference between this and sendto() on an AF_INET
 * socket is that no routing is performed, so the packet is delivered
 * even if the destination IP is not yet configured on the destination
 * host.
 *
 * Return: 0 on success, negative error code on failure.
 */
int packet_sendto_udp(int sockfd,
                      const void *buf,
                      size_t n_buf,
                      size_t *n_transmittedp,
                      const struct sockaddr_in *src_paddr,
                      const struct packet_sockaddr_ll *dest_haddr,
                      const struct sockaddr_in *dest_paddr) {
        struct iphdr ip_hdr = {
                .version = IPVERSION,
                .ihl = sizeof(ip_hdr) / 4, /* Length of header in multiples of four bytes */
                .tos = IPTOS_CLASS_CS6, /* Class Selector for network control */
                .tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + n_buf),
                .frag_off = htons(IP_DF), /* Do not fragment */
                .ttl = IPDEFTTL,
                .protocol = IPPROTO_UDP,
                .saddr = src_paddr->sin_addr.s_addr,
                .daddr = dest_paddr->sin_addr.s_addr,
        };
        struct udphdr udp_hdr = {
                .source = src_paddr->sin_port,
                .dest = dest_paddr->sin_port,
                .len = htons(sizeof(udp_hdr) + n_buf),
        };
        struct iovec iov[3] = {
                {
                        .iov_base = &ip_hdr,
                        .iov_len = sizeof(ip_hdr),
                },
                {
                        .iov_base = &udp_hdr,
                        .iov_len = sizeof(udp_hdr),
                },
                {
                        .iov_base = (void *)buf,
                        .iov_len = n_buf,
                },
        };
        struct msghdr msg = {
                .msg_name = (void*)dest_haddr,
                .msg_namelen = sizeof(*dest_haddr),
                .msg_iov = iov,
                .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
        };
        ssize_t pktlen;

        ip_hdr.check = packet_internet_checksum((void*)&ip_hdr, sizeof(ip_hdr));
        udp_hdr.check = packet_internet_checksum_udp(&src_paddr->sin_addr,
                                                     &dest_paddr->sin_addr,
                                                     ntohs(src_paddr->sin_port),
                                                     ntohs(dest_paddr->sin_port),
                                                     buf,
                                                     n_buf,
                                                     0);

        /*
         * 0x0000 and 0xffff are equivalent for computing the UDP checksum,
         * but 0x0000 is reserved in UDP headers, to mean that the checksum is
         * not set and should be ignored by the receiver. Hence, flip it to
         * 0xffff in that case.
         */
        udp_hdr.check = udp_hdr.check ?: 0xffff;

        pktlen = sendmsg(sockfd, &msg, 0);
        if (pktlen < 0)
                return -errno;

        /*
         * Kernel never truncates. Worst case, we get -EMSGSIZE. Kernel *might*
         * prepend VNET headers, in which case a bigger length than sent is
         * returned.
         * Lets assert on this, and then return to the caller the proportion of
         * its own buffer that we sent (which is always exactly the requested
         * size).
         */
        c_assert((size_t)pktlen >= sizeof(ip_hdr) + sizeof(udp_hdr) + n_buf);
        *n_transmittedp = n_buf;
        return 0;
}

/**
 * packet_recvfrom_upd() - receive UDP packet from AF_PACKET socket
 * @sockfd:             AF_PACKET/SOCK_DGRAM socket
 * @buf:                buffor for payload
 * @n_buf:              max length of payload in bytes
 * @n_transmittedp:     output argument for number transmitted bytes
 * @src:                return argumnet for source address, or NULL, see ip(7)
 *
 * Receives an UDP packet on a AF_PACKET socket. The difference between
 * this and recvfrom() on an AF_INET socket is that the packet will be
 * received even if the destination IP address has not been configured
 * on the interface.
 *
 * Return: 0 on success, negative error code on failure.
 */
int packet_recvfrom_udp(int sockfd,
                        void *buf,
                        size_t n_buf,
                        size_t *n_transmittedp,
                        struct sockaddr_in *src) {
        union {
                struct iphdr hdr;
                /*
                 * Maximum IP-header length is 15 * 4, since it is specified in
                 * the `ihl` field, which is four bits and interpreted as
                 * factor of 4. So maximum `ihl` value is `(2^4 - 1) * 4`.
                 */
                uint8_t data[15 * 4];
        } ip_hdr;
        struct udphdr udp_hdr;
        struct iovec iov[3] = {
                {
                        .iov_base = &ip_hdr,
                },
                {
                        .iov_base = &udp_hdr,
                        .iov_len = sizeof(udp_hdr),
                },
                {
                        .iov_base = buf,
                        .iov_len = n_buf,
                },
        };
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
        struct msghdr msg = {
                .msg_iov = iov,
                .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        struct cmsghdr *cmsg;
        bool checksum = true;
        ssize_t pktlen;
        size_t hdrlen;

        /* Peek packet to obtain the real IP header length */
        pktlen = recv(sockfd, &ip_hdr.hdr, sizeof(ip_hdr.hdr), MSG_PEEK);
        if (pktlen < 0)
                return -errno;

        if ((size_t)pktlen < sizeof(ip_hdr.hdr)) {
                /*
                 * Received packet is smaller than the minimal IP header length,
                 * discard it.
                 */
                recv(sockfd, NULL, 0, 0);
                *n_transmittedp = 0;
                return 0;
        }

        if (ip_hdr.hdr.version != IPVERSION) {
                /*
                 * This is not an IPv4 packet, discard it.
                 */
                recv(sockfd, NULL, 0, 0);
                *n_transmittedp = 0;
                return 0;
        }

        hdrlen = ip_hdr.hdr.ihl * 4;
        if (hdrlen < sizeof(ip_hdr.hdr)) {
                /*
                 * The length given in the header is smaller than the minimum
                 * header length, discard the packet.
                 */
                recv(sockfd, NULL, 0, 0);
                *n_transmittedp = 0;
                return 0;
        }

        /*
         * Now that we know the ip-header length, we can prepare the iovec to
         * read the entire packet into the correct buffers.
         */
        iov[0].iov_len = hdrlen;
        pktlen = recvmsg(sockfd, &msg, 0);
        if (pktlen < 0)
                return -errno;

        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg) {
                if (cmsg->cmsg_level == SOL_PACKET &&
                    cmsg->cmsg_type == PACKET_AUXDATA &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct tpacket_auxdata))) {
                        struct tpacket_auxdata *aux = (void *)CMSG_DATA(cmsg);
                        checksum = !(aux->tp_status & TP_STATUS_CSUMNOTREADY);
                }
        }

        if (ntohs(ip_hdr.hdr.tot_len) > pktlen) {
                /*
                 * The IP-packet is bigger than the chunk returned by the
                 * kernel. So either the packet is corrupt, or our caller
                 * provided too small a buffer. In both cases, we simply drop
                 * the packet.
                 */
                *n_transmittedp = 0;
                return 0;
        }

        /* Truncate trailing garbage. */
        pktlen = ntohs(ip_hdr.hdr.tot_len);

        if ((size_t)pktlen < hdrlen + sizeof(udp_hdr)) {
                /*
                 * The packet is too small to even contain an entire UDP
                 * header, so discard it entirely.
                 */
                *n_transmittedp = 0;
                return 0;
        } else if ((size_t)pktlen < hdrlen + ntohs(udp_hdr.len)) {
                /*
                 * The UDP header specified a longer length than the returned
                 * packet, so discard it entirely.
                 */
                *n_transmittedp = 0;
                return 0;
        }

        /*
         * Make @pktlen the length of the packet payload, without IP/UDP
         * headers, since that is what the caller is interested in.
         */
        pktlen = ntohs(udp_hdr.len) - sizeof(struct udphdr);

        /* IP */

        if (ip_hdr.hdr.protocol != IPPROTO_UDP) {
                *n_transmittedp = 0;
                return 0; /* not a UDP packet, discard it */
        } else if (ip_hdr.hdr.frag_off & htons(IP_MF | IP_OFFMASK)) {
                *n_transmittedp = 0;
                return 0; /* fragmented packet, discard it */
        } else if (checksum && packet_internet_checksum(ip_hdr.data, hdrlen)) {
                *n_transmittedp = 0;
                return 0; /* invalid checksum, discard it */
        }

        /* UDP */

        if (checksum && udp_hdr.check) {
                /*
                 * Computing the checksum of a packet that has the checksum set
                 * must yield 0. If it does not yield 0, the packet is invalid,
                 * in which case we discard it.
                 */
               if (packet_internet_checksum_udp(&(struct in_addr){ ip_hdr.hdr.saddr },
                                                &(struct in_addr){ ip_hdr.hdr.daddr },
                                                ntohs(udp_hdr.source),
                                                ntohs(udp_hdr.dest),
                                                buf,
                                                pktlen,
                                                udp_hdr.check)) {
                        *n_transmittedp = 0;
                        return 0;
               }
        }

        if (src) {
                src->sin_family = AF_INET;
                src->sin_addr.s_addr = ip_hdr.hdr.saddr;
                src->sin_port = udp_hdr.source;
        }

        /* Return length of UDP payload (i.e., data written to @buf). */
        *n_transmittedp = pktlen;
        return 0;
}

/**
 * packet_shutdown() - shutdown socket for future receive operations
 * @sockfd:     socket
 *
 * Partially emulates `shutdown(sockfd, SHUT_RD)`, in the sense that no
 * further packets may be queued on the socket. All packets that are
 * already queued will still be delivered, but once -EAGAIN is returned
 * we are guaranteed never to be able to read more packets in the future.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int packet_shutdown(int sockfd) {
        struct sock_filter filter[] = {
                BPF_STMT(BPF_RET + BPF_K, 0), /* discard all packets */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        int r;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        return 0;
}
