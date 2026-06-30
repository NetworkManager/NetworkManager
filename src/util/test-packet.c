/*
 * Packet Socket Tests
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <errno.h>
#include <net/if_arp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4-private.h"
#include "link.h"
#include "netns.h"
#include "packet.h"
#include "test.h"

typedef struct Blob {
        uint16_t checksum;
        uint8_t data[128];
} Blob;

static void test_checksum_one(Blob *blob, size_t size) {
        uint16_t checksum;

        /*
         * The only important property of the internet-checksum is that if the
         * target blob is amended with its own checksum, the checksum
         * calculation will become 0. So here we simply calculate the checksum
         * with a dummy 0 in place, then put the checksum in and verify that
         * the resulting checksum becomes 0.
         */

        blob->checksum = 0;
        blob->checksum = packet_internet_checksum((uint8_t*)blob, size);

        checksum = packet_internet_checksum((uint8_t*)blob, size);
        c_assert(!checksum);
}

static void test_checksum_udp_one(Blob *blob, size_t size) {
        uint16_t checksum;

        /*
         * Like test_checksum_one(), here we calculate the target checksum,
         * then place it in the source blob and calculate the checksum again.
         * We expect it to be 0 in the end (i.e., pass the checksum test).
         *
         * Unlike the generic version, we must pass dummy UDP data into the
         * helpers and also avoid a 0 checksum in the original source.
         */

        checksum = packet_internet_checksum_udp(&(struct in_addr){ htonl((10 << 24) | 2)},
                                                &(struct in_addr){ htonl((10 << 24) | 1)},
                                                67,
                                                68,
                                                blob->data,
                                                sizeof(blob->data),
                                                0);
        checksum = checksum ?: 0xffff;
        checksum = packet_internet_checksum_udp(&(struct in_addr){ htonl((10 << 24) | 2)},
                                                &(struct in_addr){ htonl((10 << 24) | 1)},
                                                67,
                                                68,
                                                blob->data,
                                                sizeof(blob->data),
                                                checksum);
        c_assert(!checksum);
}

/*
 * This generates some pseudo-random bytes and verifies that
 * packet_internet_checksum{,_udp}() correctly calculates the checksum on this
 * random-data.
 */
static void test_checksum(void) {
        Blob blob = {};

        /* fill @blob.data with some pseudo-random bytes */
        for (size_t i = 0; i < sizeof(blob.data); ++i)
                blob.data[i] = i ^ (i >> 8) ^ (i >> 16) ^ (i >> 24);

        /* take chunks of @blob.data and verify their checksum */
        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                for (uint32_t i = 0; i <= 0xffff; ++i) {
                        blob.data[0] = i & 0xff;
                        blob.data[1] = i >> 8;
                        test_checksum_one(&blob, sizeof(blob) - j);
                        test_checksum_udp_one(&blob, sizeof(blob) - j);
                }
        }
}

static void test_new_packet_socket(Link *link, int *skp) {
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = link->ifindex,
        };
        int r, on = 1;

        link_socket(link, skp, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);

        r = setsockopt(*skp, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        c_assert(r >= 0);

        r = bind(*skp, (struct sockaddr*)&addr, sizeof(addr));
        c_assert(r >= 0);
}

static void test_packet_unicast(int ifindex, int sk, void *buf, size_t n_buf,
                                const struct sockaddr_in *paddr_src,
                                const struct sockaddr_in *paddr_dst,
                                const struct ether_addr *haddr_dst) {
        struct packet_sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        size_t len;
        int r;

        memcpy(addr.sll_addr, haddr_dst, ETH_ALEN);

        r = packet_sendto_udp(sk, buf, n_buf, &len, paddr_src, &addr, paddr_dst, N_DHCP4_DSCP_DEFAULT);
        c_assert(!r);
        c_assert(len == n_buf);
}

static void test_packet_broadcast(int ifindex, int sk, void *buf, size_t n_buf,
                                  const struct sockaddr_in *paddr_src,
                                  const struct sockaddr_in *paddr_dst) {
        struct packet_sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        size_t len;
        int r;

        memcpy(addr.sll_addr, (unsigned char[]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, ETH_ALEN);

        r = packet_sendto_udp(sk, buf, n_buf, &len, paddr_src, &addr, paddr_dst, N_DHCP4_DSCP_DEFAULT);
        c_assert(!r);
        c_assert(len == n_buf);
}

static void test_packet_packet(Link *link_src,
                               Link *link_dst,
                               const struct sockaddr_in *paddr_src,
                               const struct sockaddr_in *paddr_dst) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        size_t len;
        int r;

        link_socket(link_src, &sk_src, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst);

        test_packet_unicast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst, &link_dst->mac);
        test_packet_broadcast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst);

        r = packet_recv_udp(sk_dst, buf, sizeof(buf), &len);
        c_assert(!r);
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        r = packet_recv_udp(sk_dst, buf, sizeof(buf), &len);
        c_assert(!r);
        c_assert(len == (ssize_t)sizeof(buf) - 1);
}

static void test_packet_udp(Link *link_src,
                            Link *link_dst,
                            const struct sockaddr_in *paddr_src,
                            const struct sockaddr_in *paddr_dst) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t len;
        int r;

        link_socket(link_src, &sk_src, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_socket(link_dst, &sk_dst, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        r = bind(sk_dst, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(r >= 0);

        test_packet_unicast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst, &link_dst->mac);
        test_packet_broadcast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
}

static void test_udp_packet(Link *link_src,
                            Link *link_dst,
                            const struct sockaddr_in *paddr_src,
                            const struct sockaddr_in *paddr_dst) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t slen;
        size_t len;
        int r;

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        slen = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                      (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(slen == (ssize_t)sizeof(buf) - 1);

        r = packet_recv_udp(sk_dst, buf, sizeof(buf), &len);
        c_assert(!r);
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

static void test_udp_udp(Link *link_src,
                         Link *link_dst,
                         const struct sockaddr_in *paddr_src,
                         const struct sockaddr_in *paddr_dst) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t len;
        int r;

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_socket(link_dst, &sk_dst, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        r = bind(sk_dst, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(r >= 0);

        len = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

static void test_shutdown(Link *link_src,
                          Link *link_dst,
                          const struct sockaddr_in *paddr_src,
                          const struct sockaddr_in *paddr_dst) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst1 = -1, sk_dst2 = -1;
        uint8_t buf[1024];
        ssize_t slen;
        size_t len;
        int r;

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst1);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        /* 1 - send only to the packet socket */
        slen = sendto(sk_src, buf, sizeof(buf), 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(slen == (ssize_t)sizeof(buf));

        /* create a UDP socket */
        link_socket(link_dst, &sk_dst2, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);

        r = bind(sk_dst2, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(r >= 0);

        /* 2 - send to both sockets */
        slen = sendto(sk_src, buf, sizeof(buf), 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(slen == (ssize_t)sizeof(buf));

        /* shut down the packet socket */
        r = packet_shutdown(sk_dst1);
        c_assert(r >= 0);

        /* 3 - send only to the UDP socket */
        slen = sendto(sk_src, buf, sizeof(buf), 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(slen == (ssize_t)sizeof(buf));

        /* receive 1 and 2 on the packet socket */
        r = packet_recv_udp(sk_dst1, buf, sizeof(buf), &len);
        c_assert(!r);
        c_assert(len == (ssize_t)sizeof(buf));
        r = packet_recv_udp(sk_dst1, buf, sizeof(buf), &len);
        c_assert(!r);
        c_assert(len == (ssize_t)sizeof(buf));

        /* make sure there is nothing more pending on the packet socket */
        slen = recv(sk_dst1, buf, sizeof(buf), MSG_DONTWAIT);
        c_assert(slen < 0);
        c_assert(errno == EAGAIN);

        /* receive 2 and 3 on the UDP socket */
        slen = recv(sk_dst2, buf, sizeof(buf), 0);
        c_assert(slen == (ssize_t)sizeof(buf));
        slen = recv(sk_dst2, buf, sizeof(buf), 0);
        c_assert(slen == (ssize_t)sizeof(buf));

        /* make sure there is nothing more pending on the UDP socket */
        slen = recv(sk_dst1, buf, sizeof(buf), MSG_DONTWAIT);
        c_assert(slen < 0);
        c_assert(errno == EAGAIN);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

/*
 * @udp_len:     value to write into the UDP length field
 * @payload_len: bytes of UDP payload actually sent
 * @udp_check:   UDP checksum field (non-zero exercises the checksum gate)
 * @expect_drop: whether packet_recvfrom_udp() must discard the packet
 */
struct udp_len_case {
        uint16_t udp_len;
        size_t   payload_len;
        uint16_t udp_check;
        bool     expect_drop;
};

static void test_udp_packet_len_one(Link *link_src,
                                    Link *link_dst,
                                    const struct sockaddr_in *paddr_src,
                                    const struct sockaddr_in *paddr_dst,
                                    const struct udp_len_case *tc) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst = -1;
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = link_src->ifindex,
                .sll_halen = ETH_ALEN,
        };
        struct {
                struct iphdr ip;
                struct udphdr udp;
                uint8_t payload[8];
        } _c_packed_ frame = {};
        size_t frame_len = sizeof(frame.ip) + sizeof(frame.udp) + tc->payload_len;
        uint16_t accept_sentinel = 0xffff;
        struct sockaddr_in src = { .sin_port = accept_sentinel };
        uint8_t buf[1024];
        size_t len;
        ssize_t slen;
        int r;

        c_assert(tc->payload_len <= sizeof(frame.payload));

        link_socket(link_src, &sk_src, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst);

        memcpy(addr.sll_addr, &link_dst->mac, ETH_ALEN);

        frame.ip.version  = IPVERSION;
        frame.ip.ihl      = 5;
        frame.ip.tot_len  = htons(frame_len);
        frame.ip.ttl      = 64;
        frame.ip.protocol = IPPROTO_UDP;
        frame.ip.saddr    = paddr_src->sin_addr.s_addr;
        frame.ip.daddr    = paddr_dst->sin_addr.s_addr;
        frame.ip.check    = packet_internet_checksum((uint8_t *)&frame.ip,
                                                     sizeof(frame.ip));

        frame.udp.source  = paddr_src->sin_port;
        frame.udp.dest    = paddr_dst->sin_port;
        frame.udp.len     = htons(tc->udp_len);
        frame.udp.check   = tc->udp_check;

        slen = sendto(sk_src, &frame, frame_len, 0,
                      (struct sockaddr *)&addr, sizeof(addr));
        c_assert(slen == (ssize_t)frame_len);

        /*
         * packet_recvfrom_udp() fills @src only when it accepts the packet.
         * A zero-payload accept and a drop both report a zero length, so the
         * sentinel sin_port is what tells them apart: it survives a drop and
         * is overwritten with the source port on accept.
         */
        r = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), &len, &src);
        c_assert(!r);
        if (tc->expect_drop) {
                c_assert(len == 0);
                c_assert(src.sin_port == accept_sentinel);
        } else {
                c_assert(len == tc->payload_len);
                c_assert(src.sin_port == frame.udp.source);
        }
}

/*
 * Regression test: a UDP packet whose udp.len is shorter than the 8-byte
 * UDP header underflows the payload-length computation in
 * packet_recvfrom_udp() and triggers an out-of-bounds read. Sampled lengths
 * from the underflowing range (0, 1, and the top value 7) must be discarded
 * whether or not the packet carries a UDP checksum, while the zero-payload
 * udp.len == sizeof(struct udphdr) boundary and a header+payload packet must
 * still be accepted.
 */
static void test_udp_packet_short_len(Link *link_src,
                                      Link *link_dst,
                                      const struct sockaddr_in *paddr_src,
                                      const struct sockaddr_in *paddr_dst) {
        static const struct udp_len_case cases[] = {
                /* malformed, with a UDP checksum: an unguarded parser reaches the read */
                { .udp_len = 0,                         .udp_check = 1, .expect_drop = true },
                { .udp_len = 1,                         .udp_check = 1, .expect_drop = true },
                { .udp_len = sizeof(struct udphdr) - 1, .udp_check = 1, .expect_drop = true },
                /* malformed, without a UDP checksum: the checksum gate is skipped */
                { .udp_len = 0,                         .udp_check = 0, .expect_drop = true },
                { .udp_len = 1,                         .udp_check = 0, .expect_drop = true },
                { .udp_len = sizeof(struct udphdr) - 1, .udp_check = 0, .expect_drop = true },
                /* valid: the zero-payload boundary pins the check to '<' */
                { .udp_len = sizeof(struct udphdr),     .expect_drop = false },
                /* valid: header plus payload */
                { .udp_len = sizeof(struct udphdr) + 4, .payload_len = 4, .expect_drop = false },
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
                test_udp_packet_len_one(link_src, link_dst, paddr_src, paddr_dst, &cases[i]);
}

static void test_ip_hdr(Link *link_src,
                        Link *link_dst,
                        const struct sockaddr_in *paddr_src,
                        const struct sockaddr_in *paddr_dst) {
        _c_cleanup_(c_closep) int sk_src = -1, sk_dst = -1;
        uint8_t ipopts[5] = { 1, 1, 1, 1, 1 };
        uint8_t buf[1024];
        ssize_t slen;
        size_t len;
        int r;

        /*
         * This test sends a packet from a UDP socket to a packet socket, but
         * appends 5-bytes of IPOPT_NOOP ip-options. With this we verify our
         * packet socket correctly skips additional ip-options and does not
         * interpret the ip-header as a fixed size header.
         */

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        r = setsockopt(sk_src, IPPROTO_IP, IP_OPTIONS, ipopts, sizeof(ipopts));
        c_assert(r >= 0);

        slen = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                      (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        c_assert(slen == (ssize_t)sizeof(buf) - 1);

        r = packet_recv_udp(sk_dst, buf, sizeof(buf), &len);
        c_assert(!r);
        c_assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

/*
 * This test verifies that we can send packets from/to packet/udp sockets. It
 * tests all combinations: packet->packet, packet->udp, udp->packet, udp->udp
 *
 * Furthermore, this test checks for some of the behavioural properties of our
 * packet socket helpers.
 */
static void test_packet(void) {
        _c_cleanup_(netns_closep) int ns_src = -1, ns_dst = -1;
        _c_cleanup_(link_deinit) Link link_src = LINK_NULL(link_src);
        _c_cleanup_(link_deinit) Link link_dst = LINK_NULL(link_dst);
        struct sockaddr_in paddr_src = {
                .sin_family = AF_INET,
                .sin_addr = (struct in_addr){ htonl(10<<24 | 1) },
                .sin_port = htons(10),
        };
        struct sockaddr_in paddr_dst = {
                .sin_family = AF_INET,
                .sin_addr = (struct in_addr){ htonl(10<<24 | 2) },
                .sin_port = htons(11),
        };

        /* setup */

        netns_new(&ns_src);
        netns_new(&ns_dst);
        link_new_veth(&link_src, &link_dst, ns_src, ns_dst);

        /* communication tests */

        test_packet_packet(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_packet_udp(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_udp_packet(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_udp_packet_short_len(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_udp_udp(&link_src, &link_dst, &paddr_src, &paddr_dst);

        /* behavior tests */

        test_shutdown(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_ip_hdr(&link_src, &link_dst, &paddr_src, &paddr_dst);
}

int main(int argc, char **argv) {
        test_setup();

        test_checksum();
        test_packet();

        return 0;
}
