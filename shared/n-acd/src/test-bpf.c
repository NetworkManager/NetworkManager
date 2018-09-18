/*
 * eBPF socket filter tests
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "n-acd.h"
#include "n-acd-private.h"
#include "test.h"

#define ETHER_ARP_PACKET_INIT(_op, _mac, _sip, _tip) {                  \
                .ea_hdr = {                                             \
                        .ar_hrd = htobe16(ARPHRD_ETHER),                \
                        .ar_pro = htobe16(ETHERTYPE_IP),                \
                        .ar_hln = 6,                                    \
                        .ar_pln = 4,                                    \
                        .ar_op = htobe16(_op),                          \
                },                                                      \
                .arp_sha[0] = (_mac)->ether_addr_octet[0],              \
                .arp_sha[1] = (_mac)->ether_addr_octet[1],              \
                .arp_sha[2] = (_mac)->ether_addr_octet[2],              \
                .arp_sha[3] = (_mac)->ether_addr_octet[3],              \
                .arp_sha[4] = (_mac)->ether_addr_octet[4],              \
                .arp_sha[5] = (_mac)->ether_addr_octet[5],              \
                .arp_spa[0] = (be32toh((_sip)->s_addr) >> 24) & 0xff,   \
                .arp_spa[1] = (be32toh((_sip)->s_addr) >> 16) & 0xff,   \
                .arp_spa[2] = (be32toh((_sip)->s_addr) >> 8) & 0xff,    \
                .arp_spa[3] =  be32toh((_sip)->s_addr) & 0xff,          \
                .arp_tpa[0] = (be32toh((_tip)->s_addr) >> 24) & 0xff,   \
                .arp_tpa[1] = (be32toh((_tip)->s_addr) >> 16) & 0xff,   \
                .arp_tpa[2] = (be32toh((_tip)->s_addr) >> 8) & 0xff,    \
                .arp_tpa[3] =  be32toh((_tip)->s_addr) & 0xff,          \
        }

static void test_map(void) {
        int r, mapfd = -1;
        struct in_addr addr = { 1 };

        r = n_acd_bpf_map_create(&mapfd, 8);
        assert(r >= 0);
        assert(mapfd >= 0);

        r = n_acd_bpf_map_remove(mapfd, &addr);
        assert(r == -ENOENT);

        r = n_acd_bpf_map_add(mapfd, &addr);
        assert(r >= 0);

        r = n_acd_bpf_map_add(mapfd, &addr);
        assert(r == -EEXIST);

        r = n_acd_bpf_map_remove(mapfd, &addr);
        assert(r >= 0);

        r = n_acd_bpf_map_remove(mapfd, &addr);
        assert(r == -ENOENT);

        close(mapfd);
}

static void verify_success(struct ether_arp *packet, int out_fd, int in_fd) {
        uint8_t buf[sizeof(struct ether_arp)];
        int r;

        r = send(out_fd, packet, sizeof(struct ether_arp), 0);
        assert(r == sizeof(struct ether_arp));

        r = recv(in_fd, buf, sizeof(buf), 0);
        assert(r == sizeof(struct ether_arp));
}

static void verify_failure(struct ether_arp *packet, int out_fd, int in_fd) {
        uint8_t buf[sizeof(struct ether_arp)];
        int r;

        r = send(out_fd, packet, sizeof(struct ether_arp), 0);
        assert(r == sizeof(struct ether_arp));

        r = recv(in_fd, buf, sizeof(buf), 0);
        assert(r < 0);
        assert(errno == EAGAIN);
}

static void test_filter(void) {
        uint8_t buf[sizeof(struct ether_arp) + 1];
        struct ether_addr mac1 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } };
        struct ether_addr mac2 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x07 } };
        struct in_addr ip0 = { 0 };
        struct in_addr ip1 = { 1 };
        struct in_addr ip2 = { 2 };
        struct ether_arp *packet = (struct ether_arp *)buf;
        int r, mapfd = -1, progfd = -1, pair[2];

        r = n_acd_bpf_map_create(&mapfd, 1);
        assert(r >= 0);

        r = n_acd_bpf_compile(&progfd, mapfd, &mac1);
        assert(r >= 0);
        assert(progfd >= 0);

        r = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair);
        assert(r >= 0);

        r = setsockopt(pair[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd,
                       sizeof(progfd));
        assert(r >= 0);

        r = n_acd_bpf_map_add(mapfd, &ip1);
        assert(r >= 0);

        /* valid */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        verify_success(packet, pair[0], pair[1]);

        /* valid: reply instead of request */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REPLY, &mac2, &ip1, &ip2);
        verify_success(packet, pair[0], pair[1]);

        /* valid: to us instead of from us */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip0, &ip1);
        verify_success(packet, pair[0], pair[1]);

        /* invalid header type */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        packet->arp_hrd += 1;
        verify_failure(packet, pair[0], pair[1]);

        /* invalid protocol */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        packet->arp_pro += 1;
        verify_failure(packet, pair[0], pair[1]);

        /* invalid hw addr length */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        packet->arp_hln += 1;
        verify_failure(packet, pair[0], pair[1]);

        /* invalid protocol addr length */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        packet->arp_pln += 1;
        verify_failure(packet, pair[0], pair[1]);

        /* invalid operation */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_NAK, &mac2, &ip1, &ip2);
        packet->arp_hln += 1;
        verify_failure(packet, pair[0], pair[1]);

        /* own mac */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac1, &ip1, &ip2);
        verify_failure(packet, pair[0], pair[1]);

        /* not to, nor from us, with source */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip2, &ip2);
        verify_failure(packet, pair[0], pair[1]);

        /* not to, nor from us, without source */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip0, &ip2);
        verify_failure(packet, pair[0], pair[1]);

        /* to us instead of from us, but reply */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REPLY, &mac2, &ip0, &ip1);
        verify_failure(packet, pair[0], pair[1]);

        /* long */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        r = send(pair[0], buf, sizeof(struct ether_arp) + 1, 0);
        assert(r == sizeof(struct ether_arp) + 1);

        r = recv(pair[1], buf, sizeof(buf), 0);
        assert(r == sizeof(struct ether_arp));

        /* short */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        r = send(pair[0], buf, sizeof(struct ether_arp) - 1, 0);
        assert(r == sizeof(struct ether_arp) - 1);

        r = recv(pair[1], buf, sizeof(buf), 0);
        assert(r < 0);
        assert(errno == EAGAIN);

        /*
         * Send one packet before and one packet after modifying the map,
         * verify that the modification applies at the time of send(), not recv().
         */
        *packet = (struct ether_arp)ETHER_ARP_PACKET_INIT(ARPOP_REQUEST, &mac2, &ip1, &ip2);
        r = send(pair[0], buf, sizeof(struct ether_arp), 0);
        assert(r == sizeof(struct ether_arp));

        r = n_acd_bpf_map_remove(mapfd, &ip1);
        assert(r >= 0);

        r = send(pair[0], buf, sizeof(struct ether_arp), 0);
        assert(r == sizeof(struct ether_arp));

        r = recv(pair[1], buf, sizeof(buf), 0);
        assert(r == sizeof(struct ether_arp));

        r = recv(pair[1], buf, sizeof(buf), 0);
        assert(r < 0);
        assert(errno == EAGAIN);

        close(pair[0]);
        close(pair[1]);
        close(progfd);
        close(mapfd);
}

int main(int argc, char **argv) {
        int r;

        r = test_setup();
        if (r)
                return r;

        test_map();
        test_filter();

        return 0;
}
