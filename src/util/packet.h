#pragma once

/*
 * Packet Sockets
 */

#include <c-stdaux.h>
#include <inttypes.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * `struct sockaddr_ll` is too small to fit the Infiniband hardware address.
 * Introduce `struct packet_sockaddr_ll` which is the same as the original,
 * except the `sl_addr` field is extended to fit all the supported hardware
 * addresses.
 */
struct packet_sockaddr_ll {
        unsigned short  sll_family;
        __be16          sll_protocol;
        int             sll_ifindex;
        unsigned short  sll_hatype;
        unsigned char   sll_pkttype;
        unsigned char   sll_halen;
        unsigned char   sll_addr[32]; /* MAX_ADDR_LEN */
};

uint16_t packet_internet_checksum(const uint8_t *data, size_t len);
uint16_t packet_internet_checksum_udp(const struct in_addr *src_addr,
                                      const struct in_addr *dst_addr,
                                      uint16_t src_port,
                                      uint16_t dst_port,
                                      const uint8_t *data,
                                      size_t size,
                                      uint16_t checksum);

int packet_sendto_udp(int sockfd,
                      const void *buf,
                      size_t n_buf,
                      size_t *n_transmittedp,
                      const struct sockaddr_in *src_paddr,
                      const struct packet_sockaddr_ll *dest_haddr,
                      const struct sockaddr_in *dest_paddr);
int packet_recvfrom_udp(int sockfd,
                        void *buf,
                        size_t n_buf,
                        size_t *n_transmittedp,
                        struct sockaddr_in *src);

int packet_shutdown(int sockfd);

/* inline helpers */

static inline int packet_recv_udp(int sockfd,
                                  void *buf,
                                  size_t n_buf,
                                  size_t *n_transmittedp) {
        return packet_recvfrom_udp(sockfd, buf, n_buf, n_transmittedp, NULL);
}
