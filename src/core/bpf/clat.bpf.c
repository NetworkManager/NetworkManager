/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Toke Høiland-Jørgensen <toke@toke.dk> */
/* Copyright 2025 Mary Strodl <mstrodl@csh.rit.edu> */

/**
 * This is an implementation of a CLAT in eBPF. BPF is a different environment
 * than the rest of NetworkManager, and we don't have access to most of the
 * C standard library, so some things might look a little different from what
 * you're used to.
 *
 * Check out src/core/bpf/meson.build to see how this gets built.
 **/

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include "clat.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct clat_v4_config_key);
    __type(value, struct clat_v4_config_value);
    __uint(max_entries, 16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} v4_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct clat_v6_config_key);
    __type(value, struct clat_v6_config_value);
    __uint(max_entries, 16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} v6_config_map SEC(".maps");

#ifdef DEBUG
#define DBG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = "clat: " fmt;                             \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
#define DBG(fmt, ...)
#endif

/* Macros to read the sk_buff data* pointers, preventing the compiler
 * from generating a 32-bit register spill. */
#define SKB_ACCESS_MEMBER_32(_skb, member)                                  \
    ({                                                                      \
        void *ptr;                                                          \
                                                                            \
        asm volatile("%0 = *(u32 *)(%1 + %2)"                               \
                     : "=r"(ptr)                                            \
                     : "r"(_skb), "i"(offsetof(struct __sk_buff, member))); \
                                                                            \
        ptr;                                                                \
    })

#define SKB_DATA(_skb)     SKB_ACCESS_MEMBER_32(_skb, data)
#define SKB_DATA_END(_skb) SKB_ACCESS_MEMBER_32(_skb, data_end)

struct icmpv6_pseudo {
    struct in6_addr saddr;
    struct in6_addr daddr;
    __u32           len;
    __u8            padding[3];
    __u8            nh;
} __attribute__((packed));

static __always_inline void
update_l4_checksum(struct __sk_buff *skb,
                   struct ipv6hdr   *ip6h,
                   struct iphdr     *iph,
                   int               ip_type,
                   bool              v4to6)
{
    void *data  = SKB_DATA(skb);
    int   flags = BPF_F_PSEUDO_HDR;
    __u16 offset;
    __u32 csum;

    if (v4to6) {
        csum   = bpf_csum_diff((__be32 *) &iph->saddr,
                             2 * sizeof(__u32),
                             (__be32 *) &ip6h->saddr,
                             2 * sizeof(struct in6_addr),
                             0);
        offset = (void *) (iph + 1) - data;
    } else {
        csum   = bpf_csum_diff((__be32 *) &ip6h->saddr,
                             2 * sizeof(struct in6_addr),
                             (__be32 *) &iph->saddr,
                             2 * sizeof(__u32),
                             0);
        offset = (void *) (ip6h + 1) - data;
    }

    switch (ip_type) {
    case IPPROTO_TCP:
        offset += offsetof(struct tcphdr, check);
        break;
    case IPPROTO_UDP:
        offset += offsetof(struct udphdr, check);
        flags |= BPF_F_MARK_MANGLED_0;
        break;
    default:
        return;
    }

    bpf_l4_csum_replace(skb, offset, 0, csum, flags);
}

static __always_inline void
update_icmp_checksum(struct __sk_buff *skb,
                     struct ipv6hdr   *ip6h,
                     void             *icmp_before,
                     void             *icmp_after,
                     bool              add)
{
    void                *data = SKB_DATA(skb);
    struct icmpv6_pseudo ph   = {.nh    = IPPROTO_ICMPV6,
                                 .saddr = ip6h->saddr,
                                 .daddr = ip6h->daddr,
                                 .len   = ip6h->payload_len};
    __u16                h_before, h_after, offset;
    __u32                csum, u_before, u_after;

    /* Do checksum update in two passes: first compute the incremental
     * checksum update of the ICMPv6 pseudo header, update the checksum
     * using bpf_l4_csum_replace(), and then do a separate update for the
     * ICMP type and code (which is two consecutive bytes, so cast them to
     * u16). The bpf_csum_diff() helper can be used to compute the
     * incremental update of the full block, whereas the
     * bpf_l4_csum_replace() helper can do the two-byte diff and update by
     * itself.
     */
    csum = bpf_csum_diff((__be32 *) &ph,
                         add ? 0 : sizeof(ph),
                         (__be32 *) &ph,
                         add ? sizeof(ph) : 0,
                         0);

    offset = ((void *) icmp_after - data) + 2;
    /* first two bytes of ICMP header, type and code */
    h_before = *(__u16 *) icmp_before;
    h_after  = *(__u16 *) icmp_after;

    /* last four bytes of ICMP header, the data union */
    u_before = *(__u32 *) (icmp_before + 4);
    u_after  = *(__u32 *) (icmp_after + 4);

    bpf_l4_csum_replace(skb, offset, 0, csum, BPF_F_PSEUDO_HDR);
    bpf_l4_csum_replace(skb, offset, h_before, h_after, 2);

    if (u_before != u_after)
        bpf_l4_csum_replace(skb, offset, u_before, u_after, 4);
}

static int
rewrite_icmp(struct iphdr *iph, struct ipv6hdr *ip6h, struct __sk_buff *skb)
{
    void           *data_end = SKB_DATA_END(skb);
    struct icmphdr  old_icmp, *icmp = (void *) (iph + 1);
    struct icmp6hdr icmp6, *new_icmp6;
    __u32           mtu;

    if ((void *) (icmp + 1) > data_end)
        return -1;

    old_icmp  = *icmp;
    new_icmp6 = (void *) icmp;
    icmp6     = *new_icmp6;

    /* These translations are defined in RFC6145 section 4.2 */
    switch (icmp->type) {
    case ICMP_ECHO:
        icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;
        break;
    case ICMP_ECHOREPLY:
        icmp6.icmp6_type = ICMPV6_ECHO_REPLY;
        break;
    case ICMP_DEST_UNREACH:
        icmp6.icmp6_type = ICMPV6_DEST_UNREACH;
        switch (icmp->code) {
        case ICMP_NET_UNREACH:
        case ICMP_HOST_UNREACH:
        case ICMP_SR_FAILED:
        case ICMP_NET_UNKNOWN:
        case ICMP_HOST_UNKNOWN:
        case ICMP_HOST_ISOLATED:
        case ICMP_NET_UNR_TOS:
        case ICMP_HOST_UNR_TOS:
            icmp6.icmp6_code = ICMPV6_NOROUTE;
            break;
        case ICMP_PROT_UNREACH:
            icmp6.icmp6_type    = ICMPV6_PARAMPROB;
            icmp6.icmp6_code    = ICMPV6_UNK_NEXTHDR;
            icmp6.icmp6_pointer = bpf_htonl(offsetof(struct ipv6hdr, nexthdr));
        case ICMP_PORT_UNREACH:
            icmp6.icmp6_code = ICMPV6_PORT_UNREACH;
            break;
        case ICMP_FRAG_NEEDED:
            icmp6.icmp6_type = ICMPV6_PKT_TOOBIG;
            icmp6.icmp6_code = 0;
            mtu              = bpf_ntohs(icmp->un.frag.mtu) + 20;
            /* RFC6145 section 6, "second approach" - should not be
             * necessary, but might as well do this
             */
            if (mtu < 1280)
                mtu = 1280;
            icmp6.icmp6_mtu = bpf_htonl(mtu);
        case ICMP_NET_ANO:
        case ICMP_HOST_ANO:
        case ICMP_PKT_FILTERED:
        case ICMP_PREC_CUTOFF:
            icmp6.icmp6_code = ICMPV6_ADM_PROHIBITED;
        default:
            return -1;
        }
        break;
    case ICMP_PARAMETERPROB:
        if (icmp->code == 1)
            return -1;
        icmp6.icmp6_type = ICMPV6_PARAMPROB;
        icmp6.icmp6_code = ICMPV6_HDR_FIELD;
        /* The pointer field not defined in the Linux header. This
         * translation is from Figure 3 of RFC6145.
         */
        switch (icmp->un.reserved[0]) {
        case 0: /* version/IHL */
            icmp6.icmp6_pointer = 0;
            break;
        case 1: /* Type of Service */
            icmp6.icmp6_pointer = bpf_htonl(1);
            break;
        case 2: /* Total length */
        case 3:
            icmp6.icmp6_pointer = bpf_htonl(4);
            break;
        case 8: /* Time to Live */
            icmp6.icmp6_pointer = bpf_htonl(7);
            break;
        case 9: /* Protocol */
            icmp6.icmp6_pointer = bpf_htonl(6);
            break;
        case 12: /* Source address */
        case 13:
        case 14:
        case 15:
            icmp6.icmp6_pointer = bpf_htonl(8);
            break;
        case 16: /* Destination address */
        case 17:
        case 18:
        case 19:
            icmp6.icmp6_pointer = bpf_htonl(24);
            break;
        default:
            return -1;
        }
    default:
        return -1;
    }

    *new_icmp6 = icmp6;
    update_icmp_checksum(skb, ip6h, &old_icmp, new_icmp6, true);

    /* FIXME: also need to rewrite IP header embedded in ICMP error */

    return 0;
}

/* ipv4 traffic in from application on this device, needs to be translated to v6 and sent to PLAT */
static __attribute__((always_inline)) inline int
clat_handle_v4(struct __sk_buff *skb, struct hdr_cursor *nh)
{
    int   ret      = TC_ACT_OK;
    void *data_end = SKB_DATA_END(skb);
    void *data     = SKB_DATA(skb);
    int   ip_type, iphdr_len, ip_offset;

    struct in6_addr *dst_v6;
    struct ipv6hdr  *ip6h;
    struct ipv6hdr   dst_hdr = {
          .version = 6,
    };
    struct iphdr  *iph;
    struct ethhdr *eth;
    struct in_addr src_v4;

    struct clat_v4_config_value *v4_config;
    struct clat_v4_config_key    v4_config_key;

    ip_offset = (nh->pos - data) & 0x1fff;

    ip_type = parse_iphdr(nh, data_end, &iph);
    if (ip_type < 0)
        goto out;

    src_v4.s_addr          = iph->saddr;
    v4_config_key.ifindex  = skb->ifindex;
    v4_config_key.local_v4 = src_v4;

    v4_config = bpf_map_lookup_elem(&v4_config_map, &v4_config_key);
    if (!v4_config) {
        DBG("-> v4: config for src_v4=%pI4 not found!\n", &v4_config_key.local_v4);
        goto out;
    }

    /* At this point we know the destination IP is within the configured
     * subnet, so if we can't rewrite the packet it should be dropped (so as
     * not to leak traffic in that subnet).
     */
    ret = TC_ACT_SHOT;

    /* we don't bother dealing with IP options or fragmented packets. The
     * latter are identified by the 'frag_off' field having a value (either
     * the MF bit, or the fragmet offset, or both). However, this field also
     * contains the "don't fragment" (DF) bit, which we ignore, so mask that
     * out. The DF is the second-most-significant bit (as bit 0 is
     * reserved).
     */
    iphdr_len = iph->ihl * 4;
    if (iphdr_len != sizeof(struct iphdr) || (iph->frag_off & ~bpf_htons(1 << 14))) {
        DBG("v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\n",
            &iph->daddr,
            &iph->saddr);
        goto out;
    }

    dst_v6               = &v4_config->pref64;
    dst_v6->s6_addr32[3] = iph->daddr;

    DBG("v4: Found mapping for dst %pI4 to %pI6c\n", &iph->daddr, dst_v6);

    /* src v4 as last octet of clat address */
    dst_hdr.saddr     = v4_config->local_v6;
    dst_hdr.daddr     = *dst_v6;
    dst_hdr.nexthdr   = iph->protocol;
    dst_hdr.hop_limit = iph->ttl;
    /* weird definition in ipv6hdr */
    dst_hdr.priority    = (iph->tos & 0x70) >> 4;
    dst_hdr.flow_lbl[0] = iph->tos << 4;
    dst_hdr.payload_len = bpf_htons(bpf_ntohs(iph->tot_len) - iphdr_len);

    switch (dst_hdr.nexthdr) {
    case IPPROTO_ICMP:
        if (rewrite_icmp(iph, &dst_hdr, skb))
            goto out;
        dst_hdr.nexthdr = IPPROTO_ICMPV6;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        update_l4_checksum(skb, &dst_hdr, iph, dst_hdr.nexthdr, true);
        break;
    default:
        break;
    }

    if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0))
        goto out;

    data     = SKB_DATA(skb);
    data_end = SKB_DATA_END(skb);

    eth  = data;
    ip6h = data + ip_offset;
    if ((void *) (eth + 1) > data_end || (void *) (ip6h + 1) > data_end)
        goto out;

    eth->h_proto = bpf_htons(ETH_P_IPV6);
    *ip6h        = dst_hdr;

    ret = bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
out:
    return ret;
}

static __always_inline __u16
csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __attribute__((always_inline)) inline int clat_translate_v6(struct __sk_buff  *skb,
                                                                   struct hdr_cursor *nh,
                                                                   void              *data_end,
                                                                   struct iphdr      *dst_hdr_out,
                                                                   bool               depth);

static __attribute__((always_inline)) inline int
rewrite_icmpv6(struct ipv6hdr    *ip6h,
               struct __sk_buff  *skb,
               struct icmphdr   **new_icmp_out,
               struct hdr_cursor *nh)
{
    void           *data_end = SKB_DATA_END(skb);
    struct icmp6hdr old_icmp6, *icmp6 = (void *) (ip6h + 1);
    struct icmphdr  icmp, *new_icmp;
    __u32           mtu, ptr;
    struct iphdr    dst_hdr;
    void           *inner_packet;

    if ((void *) (icmp6 + 1) > data_end)
        return -1;

    old_icmp6 = *icmp6;
    new_icmp  = (void *) icmp6;
    icmp      = *new_icmp;

    /* These translations are defined in RFC6145 section 5.2 */
    switch (icmp6->icmp6_type) {
    case ICMPV6_ECHO_REQUEST:
        icmp.type = ICMP_ECHO;
        break;
    case ICMPV6_ECHO_REPLY:
        icmp.type = ICMP_ECHOREPLY;
        break;
    case ICMPV6_DEST_UNREACH:
        icmp.type = ICMP_DEST_UNREACH;
        switch (icmp6->icmp6_code) {
        case ICMPV6_NOROUTE:
        case ICMPV6_NOT_NEIGHBOUR:
        case ICMPV6_ADDR_UNREACH:
            icmp.code = ICMP_HOST_UNREACH;
            break;
        case ICMPV6_ADM_PROHIBITED:
            icmp.code = ICMP_HOST_ANO;
            break;
        case ICMPV6_PORT_UNREACH:
            icmp.code = ICMP_PORT_UNREACH;
            break;
        default:
            return -1;
        }
        break;
    case ICMPV6_PKT_TOOBIG:
        icmp.type = ICMP_DEST_UNREACH;
        icmp.code = ICMP_FRAG_NEEDED;

        mtu = bpf_htonl(icmp6->icmp6_mtu) - 20;
        if (mtu > 0xffff)
            return -1;
        icmp.un.frag.mtu = bpf_htons(mtu);
        break;
    case ICMPV6_TIME_EXCEED:
        icmp.type = ICMP_TIME_EXCEEDED;
        break;
    case ICMPV6_PARAMPROB:
        switch (icmp6->icmp6_code) {
        case 0:
            icmp.type = ICMP_PARAMETERPROB;
            icmp.code = 0;
            break;
        case 1:
            icmp.type = ICMP_DEST_UNREACH;
            icmp.code = ICMP_PROT_UNREACH;
            ptr       = bpf_ntohl(icmp6->icmp6_pointer);
            /* Figure 6 in RFC6145 - using if statements b/c of
             * range at the bottom
             */
            if (ptr == 0 || ptr == 1)
                icmp.un.reserved[0] = ptr;
            else if (ptr == 4 || ptr == 5)
                icmp.un.reserved[0] = 2;
            else if (ptr == 6)
                icmp.un.reserved[0] = 9;
            else if (ptr == 7)
                icmp.un.reserved[0] = 8;
            else if (ptr >= 8 && ptr <= 23)
                icmp.un.reserved[0] = 12;
            else if (ptr >= 24 && ptr <= 39)
                icmp.un.reserved[0] = 16;
            else
                return -1;
            break;
        default:
            return -1;
        }
        break;
    default:
        return -1;
    }

    *new_icmp = icmp;
out:
    *new_icmp_out = new_icmp;
    return 0;
}

static __attribute__((always_inline)) inline int
clat_translate_v6(struct __sk_buff  *skb,
                  struct hdr_cursor *nh,
                  void              *data_end,
                  struct iphdr      *dst_hdr_out,
                  bool               depth)
{
    struct in6_addr subnet_v6 = {};
    struct in_addr  src_v4;
    int             ip_type;
    struct ipv6hdr *ip6h;
    int             ret = TC_ACT_OK;
    struct icmphdr *new_icmp;
    struct icmp6hdr old_icmp6;
    struct iphdr    dst_hdr_icmp;
    int             type;

    struct clat_v6_config_value *v6_config;
    struct clat_v6_config_key    v6_config_key;

    struct iphdr dst_hdr = {
        .version  = 4,
        .ihl      = 5,
        .frag_off = bpf_htons(1 << 14), /* set Don't Fragment bit */
    };

    ip_type = parse_ip6hdr(nh, data_end, &ip6h);
    if (ip_type < 0)
        goto out;

    src_v4.s_addr = ip6h->saddr.s6_addr32[3];

    v6_config_key.local_v6 = ip6h->daddr;
    v6_config_key.pref64   = ip6h->saddr;
    /* v6 pxlen is always 96 */
    v6_config_key.pref64.s6_addr32[3] = 0;
    v6_config_key.ifindex             = skb->ifindex;

    v6_config = bpf_map_lookup_elem(&v6_config_map, &v6_config_key);
    if (!v6_config) {
        DBG("<- v6: config for pref64=%pI6c, local_v6=%pI6c not found!\n",
            &v6_config_key.pref64,
            &v6_config_key.local_v6);
        goto out;
    }

    /* At this point we know the destination IP is within the configured
     * subnet, so if we can't rewrite the packet it should be dropped (so as
     * not to leak traffic in that subnet).
     */
    ret = TC_ACT_SHOT;

    /* drop packets with IP options - parser skips options */
    if (ip_type != ip6h->nexthdr) {
        DBG("v6: dropping packet with IP options from %pI6c\n", &ip6h->saddr);
        goto out;
    }

    dst_hdr.daddr    = v6_config->local_v4.s_addr;
    dst_hdr.saddr    = src_v4.s_addr;
    dst_hdr.protocol = ip6h->nexthdr;
    dst_hdr.ttl      = ip6h->hop_limit;
    dst_hdr.tos      = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4);
    dst_hdr.tot_len  = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));

    switch (dst_hdr.protocol) {
    case IPPROTO_ICMPV6:

        new_icmp  = (void *) (ip6h + 1);
        old_icmp6 = *((struct icmp6hdr *) (void *) new_icmp);
        if (rewrite_icmpv6(ip6h, skb, &new_icmp, nh))
            goto out;

        /* FIXME: also need to rewrite IP header embedded in ICMP error */
        if (depth)
            goto icmp_out;
        if (!new_icmp)
            goto icmp_out;
        if ((void *) (new_icmp + 1) > data_end)
            goto icmp_out;

        /* int type = (*new_icmp).type; */
        /* switch (type) { */
        /* case ICMP_TIME_EXCEEDED: */
        /* case ICMP_DEST_UNREACH: */

        /*     nh->pos = new_icmp + 1; */
        /*     if (clat_translate_v6(skb, nh, data_end, &dst_hdr_icmp, 1)) { */
        /*         DBG("Bad embedded v6?"); */
        /*         goto out; */
        /*     } */
        /*     if (((__u8 *)(new_icmp + 1)) + sizeof(dst_hdr_icmp) >= data_end) { */
        /*         DBG("ICMP header is out of bounds"); */
        /*         goto out; */
        /*     } */
        /*     memcpy(new_icmp + 1, &dst_hdr_icmp, sizeof(dst_hdr_icmp));  // dst_hdr.ihl * 4 */

        /*     /\* Scoot the payload up against the v4 header *\/ */
        /*     /\* (Note: We can't use a normal memmove here because clang only supports */
        /*        constexpr lengths!) *\/ */

        /*     clat_memmove(((__u8 *)(new_icmp + 1)) + sizeof(dst_hdr), */
        /*                  ((__u8 *)(new_icmp + 1)) + sizeof(struct ipv6hdr), */
        /*                  skb, */
        /*                  dst_hdr.tot_len - (dst_hdr.ihl * 4)); */
        /*     /\* TODO: Translate ICMP Extension length *\/ */
        /*     break; */
        /* } */

        update_icmp_checksum(skb, ip6h, &old_icmp6, new_icmp, false);

icmp_out:
        dst_hdr.protocol = IPPROTO_ICMP;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        update_l4_checksum(skb, ip6h, &dst_hdr, dst_hdr.protocol, false);
        break;
    default:
        break;
    }

    dst_hdr.check = csum_fold_helper(
        bpf_csum_diff((__be32 *) &dst_hdr, 0, (__be32 *) &dst_hdr, sizeof(dst_hdr), 0));

    *dst_hdr_out = dst_hdr;

out:
    return ret;
}

/* ipv6 traffic from the PLAT, to be translated into ipv4 and sent to an application */
static __attribute__((always_inline)) inline int
clat_handle_v6(struct __sk_buff *skb, struct hdr_cursor *nh)
{
    int   ret      = TC_ACT_OK;
    void *data_end = SKB_DATA_END(skb);
    void *data     = SKB_DATA(skb);

    struct ethhdr *eth;
    struct iphdr  *iph;
    struct iphdr   dst_hdr;

    int ip_offset = (nh->pos - data) & 0x1fff;

    ret = clat_translate_v6(skb, nh, data_end, &dst_hdr, 0);
    if (ret != TC_ACT_SHOT) {
        goto out;
    }

    if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
        goto out;

    data     = SKB_DATA(skb);
    data_end = SKB_DATA_END(skb);

    eth = data;
    iph = data + ip_offset;
    if ((void *) (eth + 1) > data_end || (void *) (iph + 1) > data_end)
        goto out;

    eth->h_proto = bpf_htons(ETH_P_IP);
    *iph         = dst_hdr;

    ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS);
out:
    return ret;
}

static __attribute__((always_inline)) inline int
clat_handler(struct __sk_buff *skb, bool egress)
{
    void             *data_end = SKB_DATA_END(skb);
    void             *data     = SKB_DATA(skb);
    struct hdr_cursor nh       = {.pos = data};
    struct ethhdr    *eth;
    int               eth_type;

    /* Parse Ethernet and IP/IPv6 headers */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP) && egress)
        return clat_handle_v4(skb, &nh);
    else if (eth_type == bpf_htons(ETH_P_IPV6) && !egress)
        return clat_handle_v6(skb, &nh);

    return TC_ACT_OK;
}
SEC("tcx/egress")
int
clat_egress(struct __sk_buff *skb)
{
    return clat_handler(skb, true);
}

SEC("tcx/ingress")
int
clat_ingress(struct __sk_buff *skb)
{
    return clat_handler(skb, false);
}
