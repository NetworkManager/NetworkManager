/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include "nm-sd-adapt-core.h"

#include <arpa/inet.h>
#include <linux/filter.h>
#include <netinet/if_ether.h>

#include "arp-util.h"
#include "fd-util.h"
#include "unaligned.h"
#include "util.h"

int arp_network_bind_raw_socket(int ifindex, be32_t address, const struct ether_addr *eth_mac) {
        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                         /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct ether_arp), 1, 0),           /* packet >= arp packet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_hrd)), /* A <- header */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),                       /* header == ethernet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_pro)), /* A <- protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),                       /* protocol == IP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_hln)), /* A <- hardware address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct ether_addr), 1, 0),          /* length == sizeof(ether_addr)? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_pln)), /* A <- protocol address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct in_addr), 1, 0),             /* length == sizeof(in_addr) ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_op)),  /* A <- operation */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 2, 0),                      /* protocol == request ? */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 0),                        /* protocol == reply ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                /* Sender Hardware Address must be different from our own */
                BPF_STMT(BPF_LD + BPF_IMM, unaligned_read_be32(&eth_mac->ether_addr_octet[0])),/* A <- 4 bytes of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                               /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_sha)),       /* A <- 4 bytes of SHA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                        /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 6),                                  /* A == 0 ? */
                BPF_STMT(BPF_LD + BPF_IMM, unaligned_read_be16(&eth_mac->ether_addr_octet[4])),/* A <- remainder of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                               /* X <- A */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, arp_sha) + 4),   /* A <- remainder of SHA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                        /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                  /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                /* Sender Protocol Address or Target Protocol Address must be equal to the one we care about */
                BPF_STMT(BPF_LD + BPF_IMM, htobe32(address)),                                  /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                               /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_spa)),       /* A <- SPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                        /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                  /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                              /* return all */
                BPF_STMT(BPF_LD + BPF_IMM, htobe32(address)),                                  /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                               /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_tpa)),       /* A <- TPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                        /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                  /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                              /* return all */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
        };
        struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = (struct sock_filter*) filter
        };
        union sockaddr_union link = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_ARP),
                .ll.sll_ifindex = ifindex,
                .ll.sll_halen = ETH_ALEN,
                .ll.sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(ifindex > 0);

        s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = bind(s, &link.sa, sizeof(link.ll));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

static int arp_send_packet(int fd, int ifindex,
                           be32_t pa, const struct ether_addr *ha,
                           bool announce) {
        union sockaddr_union link = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_ARP),
                .ll.sll_ifindex = ifindex,
                .ll.sll_halen = ETH_ALEN,
                .ll.sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        struct ether_arp arp = {
                .ea_hdr.ar_hrd = htobe16(ARPHRD_ETHER), /* HTYPE */
                .ea_hdr.ar_pro = htobe16(ETHERTYPE_IP), /* PTYPE */
                .ea_hdr.ar_hln = ETH_ALEN, /* HLEN */
                .ea_hdr.ar_pln = sizeof(be32_t), /* PLEN */
                .ea_hdr.ar_op = htobe16(ARPOP_REQUEST), /* REQUEST */
        };
        int r;

        assert(fd >= 0);
        assert(pa != 0);
        assert(ha);

        memcpy(&arp.arp_sha, ha, ETH_ALEN);
        memcpy(&arp.arp_tpa, &pa, sizeof(pa));

        if (announce)
                memcpy(&arp.arp_spa, &pa, sizeof(pa));

        r = sendto(fd, &arp, sizeof(struct ether_arp), 0, &link.sa, sizeof(link.ll));
        if (r < 0)
                return -errno;

        return 0;
}

int arp_send_probe(int fd, int ifindex,
                    be32_t pa, const struct ether_addr *ha) {
        return arp_send_packet(fd, ifindex, pa, ha, false);
}

int arp_send_announcement(int fd, int ifindex,
                          be32_t pa, const struct ether_addr *ha) {
        return arp_send_packet(fd, ifindex, pa, ha, true);
}
