/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Toke Høiland-Jørgensen <toke@toke.dk> */
/* Copyright 2025 Mary Strodl <mstrodl@csh.rit.edu> */
/* Copyright 2025 Beniamino Galvani <bgalvani@redhat.com> */

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
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "clat.h"

char _license[] SEC("license") = "GPL";

struct clat_config config;

#ifdef DEBUG
/* Note: when enabling debugging, you also need to add CAP_PERFMON
 * to the CapabilityBoundingSet of the NM systemd unit. The messages
 * will be printed to /sys/kernel/debug/tracing/trace_pipe */
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

struct ip6_frag {
    __u8  nexthdr;
    __u8  reserved;
    __u16 offset;
    __u32 identification;
} __attribute__((packed));

/* This function must be declared as inline because the BPF calling
 * convention only supports up to 5 function arguments. */
static __always_inline void
update_l4_checksum(struct __sk_buff *skb,
                   struct ipv6hdr   *ip6h,
                   struct iphdr     *iph,
                   bool              v4to6,
                   bool              is_inner,
                   bool              is_v6_fragment,
                   __u32            *csum_diff)
{
    int   flags = BPF_F_PSEUDO_HDR;
    __u16 offset;
    __u32 csum;
    int   ip_type;

    if (v4to6) {
        void *from_ptr = &iph->saddr;
        void *to_ptr   = &ip6h->saddr;

        csum   = bpf_csum_diff(from_ptr, 2 * sizeof(__u32), to_ptr, 2 * sizeof(struct in6_addr), 0);
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
        ip_type = ip6h->nexthdr;
    } else {
        void *from_ptr = &ip6h->saddr;
        void *to_ptr   = &iph->saddr;

        csum   = bpf_csum_diff(from_ptr, 2 * sizeof(struct in6_addr), to_ptr, 2 * sizeof(__u32), 0);
        offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        ip_type = iph->protocol;

        if (is_inner) {
            offset = offset + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr);
        }
    }

    if (is_v6_fragment) {
        offset += sizeof(struct ip6_frag);
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

    if (csum_diff) {
        *csum_diff = bpf_csum_diff((__be32 *) &csum, sizeof(csum), 0, 0, *csum_diff);
    }
}

static __always_inline void
update_icmp_checksum(struct __sk_buff     *skb,
                     const struct ipv6hdr *ip6h,
                     void                 *icmp_before,
                     void                 *icmp_after,
                     bool                  v4to6,
                     bool                  is_inner,
                     __u32                 seed)
{
    struct icmpv6_pseudo ph = {.nh = IPPROTO_ICMPV6, .len = ip6h->payload_len};
    __u16                h_before;
    __u16                h_after;
    __u16                offset;
    __u32                csum;
    __u32                u_before;
    __u32                u_after;

    __builtin_memcpy(&ph.saddr, &ip6h->saddr, sizeof(struct in6_addr));
    __builtin_memcpy(&ph.daddr, &ip6h->daddr, sizeof(struct in6_addr));

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
                         v4to6 ? 0 : sizeof(ph),
                         (__be32 *) &ph,
                         v4to6 ? sizeof(ph) : 0,
                         seed);

    if (v4to6) {
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2;
    } else {
        offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + 2;
        if (is_inner)
            offset += sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr);
    }

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
rewrite_icmp(struct __sk_buff *skb, const struct ipv6hdr *ip6h)
{
    void            *data_end = SKB_DATA_END(skb);
    void            *data     = SKB_DATA(skb);
    struct icmphdr   icmp_buf;  /* copy of the old ICMPv4 header */
    struct icmp6hdr  icmp6_buf; /* buffer for the new ICMPv6 header */
    struct icmphdr  *icmp;
    struct icmp6hdr *icmp6;
    __u32            mtu;

    icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((icmp + 1) > data_end)
        return -1;

    icmp_buf  = *icmp;
    icmp6     = (void *) icmp;
    icmp6_buf = *icmp6;

    /* These translations are defined in RFC6145 section 4.2 */
    switch (icmp->type) {
    case ICMP_ECHO:
        icmp6_buf.icmp6_type = ICMPV6_ECHO_REQUEST;
        break;
    case ICMP_ECHOREPLY:
        icmp6_buf.icmp6_type = ICMPV6_ECHO_REPLY;
        break;
    case ICMP_DEST_UNREACH:
        icmp6_buf.icmp6_type = ICMPV6_DEST_UNREACH;
        switch (icmp->code) {
        case ICMP_NET_UNREACH:
        case ICMP_HOST_UNREACH:
        case ICMP_SR_FAILED:
        case ICMP_NET_UNKNOWN:
        case ICMP_HOST_UNKNOWN:
        case ICMP_HOST_ISOLATED:
        case ICMP_NET_UNR_TOS:
        case ICMP_HOST_UNR_TOS:
            icmp6_buf.icmp6_code = ICMPV6_NOROUTE;
            break;
        case ICMP_PROT_UNREACH:
            icmp6_buf.icmp6_type    = ICMPV6_PARAMPROB;
            icmp6_buf.icmp6_code    = ICMPV6_UNK_NEXTHDR;
            icmp6_buf.icmp6_pointer = bpf_htonl(offsetof(struct ipv6hdr, nexthdr));
            break;
        case ICMP_PORT_UNREACH:
            icmp6_buf.icmp6_code = ICMPV6_PORT_UNREACH;
            break;
        case ICMP_FRAG_NEEDED:
            icmp6_buf.icmp6_type = ICMPV6_PKT_TOOBIG;
            icmp6_buf.icmp6_code = 0;
            mtu                  = bpf_ntohs(icmp->un.frag.mtu) + 20;
            /* RFC6145 section 6, "second approach" - should not be
             * necessary, but might as well do this
             */
            if (mtu < 1280)
                mtu = 1280;
            icmp6_buf.icmp6_mtu = bpf_htonl(mtu);
            break;
        case ICMP_NET_ANO:
        case ICMP_HOST_ANO:
        case ICMP_PKT_FILTERED:
        case ICMP_PREC_CUTOFF:
            icmp6_buf.icmp6_code = ICMPV6_ADM_PROHIBITED;
            break;
        default:
            return -1;
        }
        break;
    case ICMP_PARAMETERPROB:
        if (icmp->code == 1)
            return -1;
        icmp6_buf.icmp6_type = ICMPV6_PARAMPROB;
        icmp6_buf.icmp6_code = ICMPV6_HDR_FIELD;
        /* The pointer field not defined in the Linux header. This
         * translation is from Figure 3 of RFC6145.
         */
        switch (icmp->un.reserved[0]) {
        case 0: /* version/IHL */
            icmp6_buf.icmp6_pointer = 0;
            break;
        case 1: /* Type of Service */
            icmp6_buf.icmp6_pointer = bpf_htonl(1);
            break;
        case 2: /* Total length */
        case 3:
            icmp6_buf.icmp6_pointer = bpf_htonl(4);
            break;
        case 8: /* Time to Live */
            icmp6_buf.icmp6_pointer = bpf_htonl(7);
            break;
        case 9: /* Protocol */
            icmp6_buf.icmp6_pointer = bpf_htonl(6);
            break;
        case 12: /* Source address */
        case 13:
        case 14:
        case 15:
            icmp6_buf.icmp6_pointer = bpf_htonl(8);
            break;
        case 16: /* Destination address */
        case 17:
        case 18:
        case 19:
            icmp6_buf.icmp6_pointer = bpf_htonl(24);
            break;
        default:
            return -1;
        }
        break;
    default:
        return -1;
    }

    *icmp6 = icmp6_buf;
    update_icmp_checksum(skb, ip6h, &icmp_buf, icmp6, true, false, 0);

    /* FIXME: also need to rewrite IP header embedded in ICMP error */

    return 0;
}

/*
  * Convert an IPv4 address to the corresponding "IPv4-Embedded IPv6 Address"
  * according to RFC 6052 2.2.
  *
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |32|     prefix    |v4(32)         | u | suffix                    |
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |40|     prefix        |v4(24)     | u |(8)| suffix                |
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |48|     prefix            |v4(16) | u | (16)  | suffix            |
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |56|     prefix                |(8)| u |  v4(24)   | suffix        |
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |64|     prefix                    | u |   v4(32)      | suffix    |
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *  |96|     prefix                                    |    v4(32)     |
  *  +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  *
  */
static __always_inline bool
v4addr_to_v6(__be32 addr4, struct in6_addr *addr6, const struct in6_addr *pref64, int pref64_len)
{
    union {
        __be32 a32;
        __u8   a8[4];
    } u;

    u.a32 = addr4;

    addr6->s6_addr32[0] = 0;
    addr6->s6_addr32[1] = 0;
    addr6->s6_addr32[2] = 0;
    addr6->s6_addr32[3] = 0;

    switch (pref64_len) {
    case 96:
        addr6->s6_addr32[0] = pref64->s6_addr32[0];
        addr6->s6_addr32[1] = pref64->s6_addr32[1];
        addr6->s6_addr32[2] = pref64->s6_addr32[2];
        addr6->s6_addr32[3] = addr4;
        break;
    case 64:
        addr6->s6_addr32[0] = pref64->s6_addr32[0];
        addr6->s6_addr32[1] = pref64->s6_addr32[1];
        addr6->s6_addr[9]   = u.a8[0];
        addr6->s6_addr[10]  = u.a8[1];
        addr6->s6_addr[11]  = u.a8[2];
        addr6->s6_addr[12]  = u.a8[3];
        break;
    case 56:
        addr6->s6_addr32[0] = pref64->s6_addr32[0];
        addr6->s6_addr32[1] = pref64->s6_addr32[1];
        addr6->s6_addr[7]   = u.a8[0];
        addr6->s6_addr[9]   = u.a8[1];
        addr6->s6_addr[10]  = u.a8[2];
        addr6->s6_addr[11]  = u.a8[3];
        break;
    case 48:
        addr6->s6_addr32[0] = pref64->s6_addr32[0];
        addr6->s6_addr16[2] = pref64->s6_addr16[2];
        addr6->s6_addr[6]   = u.a8[0];
        addr6->s6_addr[7]   = u.a8[1];
        addr6->s6_addr[9]   = u.a8[2];
        addr6->s6_addr[10]  = u.a8[3];
        break;
    case 40:
        addr6->s6_addr32[0] = pref64->s6_addr32[0];
        addr6->s6_addr[4]   = pref64->s6_addr[4];
        addr6->s6_addr[5]   = u.a8[0];
        addr6->s6_addr[6]   = u.a8[1];
        addr6->s6_addr[7]   = u.a8[2];
        addr6->s6_addr[9]   = u.a8[3];
        break;
    case 32:
        addr6->s6_addr32[0] = pref64->s6_addr32[0];
        addr6->s6_addr32[1] = addr4;
        break;
    default:
        return false;
    }
    return true;
}

/*
  * Extract the IPv4 address @addr4 and the NAT64 prefix @pref64 from an IPv6 address,
  * given the known prefix length @pref64_len. See the table above.
  */
static __always_inline bool
v6addr_to_v4(const struct in6_addr *addr6, int pref64_len, __be32 *addr4, struct in6_addr *pref64)
{
    union {
        __be32 a32;
        __u8   a8[4];
    } u;

    pref64->s6_addr32[0] = 0;
    pref64->s6_addr32[1] = 0;
    pref64->s6_addr32[2] = 0;
    pref64->s6_addr32[3] = 0;

    switch (pref64_len) {
    case 96:
        u.a32 = addr6->s6_addr32[3];

        pref64->s6_addr32[0] = addr6->s6_addr32[0];
        pref64->s6_addr32[1] = addr6->s6_addr32[1];
        pref64->s6_addr32[2] = addr6->s6_addr32[2];
        break;
    case 64:
        u.a8[0] = addr6->s6_addr[9];
        u.a8[1] = addr6->s6_addr[10];
        u.a8[2] = addr6->s6_addr[11];
        u.a8[3] = addr6->s6_addr[12];

        pref64->s6_addr32[0] = addr6->s6_addr32[0];
        pref64->s6_addr32[1] = addr6->s6_addr32[1];
        break;
    case 56:
        u.a8[0] = addr6->s6_addr[7];
        u.a8[1] = addr6->s6_addr[9];
        u.a8[2] = addr6->s6_addr[10];
        u.a8[3] = addr6->s6_addr[11];

        pref64->s6_addr32[0] = addr6->s6_addr32[0];
        pref64->s6_addr32[1] = addr6->s6_addr32[1];
        pref64->s6_addr[7]   = 0;
        break;
    case 48:
        u.a8[0] = addr6->s6_addr[6];
        u.a8[1] = addr6->s6_addr[7];
        u.a8[2] = addr6->s6_addr[9];
        u.a8[3] = addr6->s6_addr[10];

        pref64->s6_addr32[0] = addr6->s6_addr32[0];
        pref64->s6_addr32[1] = addr6->s6_addr32[1];
        pref64->s6_addr16[3] = 0;
        break;
    case 40:
        u.a8[0] = addr6->s6_addr[5];
        u.a8[1] = addr6->s6_addr[6];
        u.a8[2] = addr6->s6_addr[7];
        u.a8[3] = addr6->s6_addr[9];

        pref64->s6_addr32[0] = addr6->s6_addr32[0];
        pref64->s6_addr32[1] = addr6->s6_addr32[1];
        pref64->s6_addr16[3] = 0;
        pref64->s6_addr[5]   = 0;

        break;
    case 32:
        u.a32 = addr6->s6_addr32[1];

        pref64->s6_addr32[0] = addr6->s6_addr32[0];
        break;
    default:
        return false;
    }

    *addr4 = u.a32;
    return true;
}

/* ipv4 traffic in from application on this device, needs to be translated to v6 and sent to PLAT */
static int
clat_handle_v4(struct __sk_buff *skb)
{
    int             ret      = TC_ACT_OK;
    void           *data_end = SKB_DATA_END(skb);
    void           *data     = SKB_DATA(skb);
    struct ipv6hdr *ip6h;
    struct ipv6hdr  dst_hdr = {
         .version = 6,
    };
    struct iphdr  *iph;
    struct ethhdr *eth;

    iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
        goto out;

    if (iph->saddr != config.local_v4.s_addr)
        goto out;

    /* At this point we know the packet needs translation. If we can't
     * rewrite it, it should be dropped.
     */
    ret = TC_ACT_SHOT;

    /* we don't bother dealing with IP options or fragmented packets. The
     * latter are identified by the 'frag_off' field having a value (either
     * the MF bit, or the fragment offset, or both). However, this field also
     * contains the "don't fragment" (DF) bit, which we ignore, so mask that
     * out. The DF is the second-most-significant bit (as bit 0 is
     * reserved).
     */

    if (iph->ihl != 5 || (iph->frag_off & ~bpf_htons(1 << 14))) {
        DBG("v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\n",
            &iph->saddr,
            &iph->daddr);
        goto out;
    }

    if (!v4addr_to_v6(iph->daddr, &dst_hdr.daddr, &config.pref64, config.pref64_len))
        goto out;

    dst_hdr.saddr     = config.local_v6;
    dst_hdr.nexthdr   = iph->protocol;
    dst_hdr.hop_limit = iph->ttl;
    /* weird definition in ipv6hdr */
    dst_hdr.priority    = (iph->tos & 0x70) >> 4;
    dst_hdr.flow_lbl[0] = iph->tos << 4;
    dst_hdr.payload_len = bpf_htons(bpf_ntohs(iph->tot_len) - sizeof(struct iphdr));

    DBG("v4: outgoing pkt to dst %pI4 (%pI6c)\n", &iph->daddr, &dst_hdr.daddr);

    switch (dst_hdr.nexthdr) {
    case IPPROTO_ICMP:
        if (rewrite_icmp(skb, &dst_hdr))
            goto out;
        dst_hdr.nexthdr = IPPROTO_ICMPV6;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        update_l4_checksum(skb, &dst_hdr, iph, true, false, false, NULL);
        break;
    default:
        break;
    }

    if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0))
        goto out;

    data     = SKB_DATA(skb);
    data_end = SKB_DATA_END(skb);

    eth = data;
    if (eth + 1 > data_end)
        goto out;

    ip6h = (void *) (eth + 1);
    if (ip6h + 1 > data_end)
        goto out;

    eth->h_proto = bpf_htons(ETH_P_IPV6);
    *ip6h        = dst_hdr;

    ret = bpf_redirect(skb->ifindex, 0);
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

static __always_inline bool
v6addr_equal(const struct in6_addr *a, const struct in6_addr *b)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (a->s6_addr32[i] != b->s6_addr32[i])
            return false;
    }
    return true;
}

static __always_inline void
translate_ipv6_header(const struct ipv6hdr *ip6, struct iphdr *ip, __be32 saddr, __be32 daddr)
{
    *ip = (struct iphdr) {
        .version  = 4,
        .ihl      = 5,
        .tos      = ip6->priority << 4 | (ip6->flow_lbl[0] >> 4),
        .frag_off = bpf_htons(1 << 14),
        .ttl      = ip6->hop_limit,
        .protocol = ip6->nexthdr == IPPROTO_ICMPV6 ? IPPROTO_ICMP : ip6->nexthdr,
        .saddr    = saddr,
        .daddr    = daddr,
        .tot_len  = bpf_htons(bpf_ntohs(ip6->payload_len) + sizeof(struct iphdr)),
    };

    ip->check =
        csum_fold_helper(bpf_csum_diff((__be32 *) ip, 0, (__be32 *) ip, sizeof(struct iphdr), 0));
}

static __always_inline int
translate_icmpv6_header(const struct icmp6hdr *icmp6, struct icmphdr *icmp)
{
    /* These translations are defined in RFC6145 section 5.2 */
    switch (icmp6->icmp6_type) {
    case ICMPV6_ECHO_REQUEST:
        icmp->type = ICMP_ECHO;
        break;
    case ICMPV6_ECHO_REPLY:
        icmp->type = ICMP_ECHOREPLY;
        break;
    case ICMPV6_DEST_UNREACH:
        icmp->type = ICMP_DEST_UNREACH;
        switch (icmp6->icmp6_code) {
        case ICMPV6_NOROUTE:
        case ICMPV6_NOT_NEIGHBOUR:
        case ICMPV6_ADDR_UNREACH:
            icmp->code = ICMP_HOST_UNREACH;
            break;
        case ICMPV6_ADM_PROHIBITED:
            icmp->code = ICMP_HOST_ANO;
            break;
        case ICMPV6_PORT_UNREACH:
            icmp->code = ICMP_PORT_UNREACH;
            break;
        default:
            return -1;
        }
        break;
    case ICMPV6_PKT_TOOBIG:
    {
        __u32 mtu;

        icmp->type = ICMP_DEST_UNREACH;
        icmp->code = ICMP_FRAG_NEEDED;

        mtu = bpf_ntohl(icmp6->icmp6_mtu) - 20;
        if (mtu > 0xffff)
            return -1;
        icmp->un.frag.mtu = bpf_htons(mtu);
        break;
    }
    case ICMPV6_TIME_EXCEED:
        icmp->type = ICMP_TIME_EXCEEDED;
        break;
    case ICMPV6_PARAMPROB:
        switch (icmp6->icmp6_code) {
        case 0:
        {
            __u32 ptr;

            icmp->type = ICMP_PARAMETERPROB;
            icmp->code = 0;

            ptr = bpf_ntohl(icmp6->icmp6_pointer);
            /* Figure 6 in RFC6145 - using if statements b/c of
             * range at the bottom
             */
            if (ptr == 0 || ptr == 1)
                icmp->un.reserved[0] = ptr;
            else if (ptr == 4 || ptr == 5)
                icmp->un.reserved[0] = 2;
            else if (ptr == 6)
                icmp->un.reserved[0] = 9;
            else if (ptr == 7)
                icmp->un.reserved[0] = 8;
            else if (ptr >= 8 && ptr <= 23)
                icmp->un.reserved[0] = 12;
            else if (ptr >= 24 && ptr <= 39)
                icmp->un.reserved[0] = 16;
            else
                return -1;
            break;
        }
        case 1:
            icmp->type = ICMP_DEST_UNREACH;
            icmp->code = ICMP_PROT_UNREACH;
            break;
        default:
            return -1;
        }
        break;
    default:
        return -1;
    }

    return 0;
}

static int
rewrite_icmpv6_inner(struct __sk_buff *skb, __u32 *csum_diff)
{
    void            *data_end = SKB_DATA_END(skb);
    void            *data     = SKB_DATA(skb);
    struct icmphdr  *icmp;
    struct icmp6hdr *icmp6;
    struct icmphdr   icmp_buf;  /* buffer for the new ICMPv4 header */
    struct icmp6hdr  icmp6_buf; /* copy of the old ICMPv6 header */

    /*
     * icmp6:                                                    v
     * -------------------------------------------------------------------------
     * | Ethernet | IPv6             | ICMPv6 | IPv6             | ICMPv6 | ...
     * -------------------------------------------------------------------------
     */

    icmp6 = data + sizeof(struct ethhdr) + 2 * sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr);
    if (icmp6 + 1 > data_end)
        return -1;

    icmp6_buf = *icmp6;
    icmp      = (void *) icmp6;
    icmp_buf  = *icmp;

    if (translate_icmpv6_header(icmp6, &icmp_buf))
        return -1;

    *icmp = icmp_buf;
    update_icmp_checksum(skb,
                         (struct ipv6hdr *) (data + sizeof(struct ethhdr)),
                         &icmp6_buf,
                         icmp,
                         false,
                         true,
                         0);

    if (csum_diff) {
        data_end = SKB_DATA_END(skb);
        data     = SKB_DATA(skb);

        icmp = data + sizeof(struct ethhdr) + 2 * sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr);
        if (icmp + 1 > data_end)
            return -1;

        /* Compute the checksum difference between the old ICMPv6 header and the new ICMPv4 one */
        *csum_diff = bpf_csum_diff((__be32 *) &icmp6_buf,
                                   sizeof(struct icmp6hdr),
                                   (__be32 *) &icmp6_buf,
                                   0,
                                   *csum_diff);
        *csum_diff =
            bpf_csum_diff((__be32 *) icmp, 0, (__be32 *) icmp, sizeof(struct icmphdr), *csum_diff);
    }
    return 0;
}

static int
rewrite_ipv6_inner(struct __sk_buff *skb, struct iphdr *dst_hdr, __u32 *csum_diff)
{
    void           *data_end = SKB_DATA_END(skb);
    void           *data     = SKB_DATA(skb);
    struct ipv6hdr *ip6h;
    __be32          addr4;
    struct in6_addr subnet_v6;

    /*
     * ip6h:                                  v
     * ----------------------------------------------------------------
     * | Ethernet | IPv6             | ICMPv6 | IPv6             | ...
     * ----------------------------------------------------------------
     */

    ip6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr);
    if (ip6h + 1 > data_end)
        return -1;

    if (!v6addr_equal(&ip6h->saddr, &config.local_v6))
        return -1;
    if (!v6addr_to_v4(&ip6h->daddr, config.pref64_len, &addr4, &subnet_v6))
        return -1;
    if (!v6addr_equal(&subnet_v6, &config.pref64))
        return -1;

    translate_ipv6_header(ip6h, dst_hdr, config.local_v4.s_addr, addr4);

    if (csum_diff) {
        /* Checksum difference between the old IPv6 header and the new IPv4 one */
        *csum_diff =
            bpf_csum_diff((__be32 *) ip6h, sizeof(struct ipv6hdr), (__be32 *) ip6h, 0, *csum_diff);

        *csum_diff = bpf_csum_diff((__be32 *) dst_hdr,
                                   0,
                                   (__be32 *) dst_hdr,
                                   sizeof(struct iphdr),
                                   *csum_diff);
    }

    switch (dst_hdr->protocol) {
    case IPPROTO_ICMP:
        if (rewrite_icmpv6_inner(skb, csum_diff))
            return -1;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        update_l4_checksum(skb, ip6h, dst_hdr, false, true, false, csum_diff);
        break;
    default:
        break;
    }

    return 0;
}

static int
rewrite_icmpv6(struct __sk_buff *skb, int *out_length_diff)
{
    void            *data_end = SKB_DATA_END(skb);
    void            *data     = SKB_DATA(skb);
    struct iphdr    *ip;
    struct icmp6hdr *icmp6;
    struct icmphdr  *icmp;
    struct icmphdr   icmp_buf;  /* buffer for the new ICMPv4 header */
    struct icmp6hdr  icmp6_buf; /* copy of the old ICMPv6 header */
    struct iphdr     ip_in_buf; /* buffer for the new inner IPv4 header */
    __u32            csum_diff = 0;

    /*
     * icmp6:                        v
     * ---------------------------------------------
     * | Ethernet | IPv6             | ICMPv6 | ...
     * ---------------------------------------------
     */

    icmp6 = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if (icmp6 + 1 > data_end)
        return -1;

    icmp6_buf = *icmp6;
    icmp      = (void *) icmp6;
    icmp_buf  = *icmp;

    if (translate_icmpv6_header(icmp6, &icmp_buf))
        return -1;

    if (icmp6->icmp6_type >= 128) {
        /* ICMPv6 non-error message: only translate the header */
        *icmp = icmp_buf;
        update_icmp_checksum(skb,
                             (struct ipv6hdr *) (data + sizeof(struct ethhdr)),
                             &icmp6_buf,
                             icmp,
                             false,
                             false,
                             0);
        return 0;
    }

    /* ICMPv6 error messages: we need to rewrite the headers in the inner packet.
     * Track in csum_diff the incremental changes to the checksum for the ICMPv4
     * header. */

    if (rewrite_ipv6_inner(skb, &ip_in_buf, &csum_diff))
        return -1;

    /* The inner IP header shrinks from 40 (IPv6) to 20 (IPv4) bytes; we need to move
     * the L4 header and payload. BPF programs don't have an easy way to move a variable
     * amount of packet data; use bpf_skb_adjust_room() which can add or remove data
     * inside a packet. It doesn't support arbitrary offsets, but we can use BPF_ADJ_ROOM_NET
     * to remove the bytes just after the L3 header, and rewrite the ICMP and the inner
     * IP headers.
     */
    if (bpf_skb_adjust_room(skb,
                            (int) sizeof(struct iphdr) - (int) sizeof(struct ipv6hdr),
                            BPF_ADJ_ROOM_NET,
                            0))
        return -1;

    *out_length_diff = (int) sizeof(struct iphdr) - (int) sizeof(struct ipv6hdr);

    data_end = SKB_DATA_END(skb);
    data     = SKB_DATA(skb);

    /* Rewrite the ICMPv6 header with the translated ICMPv4 one */
    icmp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if (icmp + 1 > data_end)
        return -1;

    *icmp = icmp_buf;

    /* Rewrite the inner IPv6 header with the translated IPv4 one */
    ip = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmphdr);
    if (ip + 1 > data_end)
        return -1;

    *ip = ip_in_buf;

    /* Update the ICMPv4 checksum according to all the changes in headers */
    update_icmp_checksum(skb,
                         (struct ipv6hdr *) (data + sizeof(struct ethhdr)),
                         &icmp6_buf,
                         icmp,
                         false,
                         false,
                         csum_diff);

    return 0;
}

/* ipv6 traffic from the PLAT, to be translated into ipv4 and sent to an application */
static int
clat_handle_v6(struct __sk_buff *skb)
{
    int             ret      = TC_ACT_OK;
    void           *data_end = SKB_DATA_END(skb);
    void           *data     = SKB_DATA(skb);
    struct ethhdr  *eth;
    struct ipv6hdr *ip6h;
    struct iphdr   *iph;
    struct iphdr    dst_hdr;
    struct in6_addr subnet_v6;
    __be32          addr4;
    int             length_diff = 0;
    bool            fragmented  = false;

    /*
     * ip6h:      v
     * ------------------------------------
     * | Ethernet | IPv6             | ...
     * ------------------------------------
     */

    ip6h = data + sizeof(struct ethhdr);
    if (ip6h + 1 > data_end)
        goto out;

    if (!v6addr_equal(&ip6h->daddr, &config.local_v6))
        goto out;
    if (!v6addr_to_v4(&ip6h->saddr, config.pref64_len, &addr4, &subnet_v6))
        goto out;
    if (!v6addr_equal(&subnet_v6, &config.pref64)) {
        struct icmp6hdr *icmp6;

        /* Follow draft-ietf-v6ops-icmpext-xlat-v6only-source-01:
         *
         * "Whenever a translator translates an ICMPv6 Destination Unreachable,
         *  ICMPv6 Time Exceeded or ICMPv6 Packet Too Big ([RFC4443]) to the
         *  corresponding ICMPv4 ([RFC0792]) message, and the IPv6 source
         *  address in the outermost IPv6 header is untranslatable, the
         *  translator SHOULD use the dummy IPv4 address (192.0.0.8) as the IPv4
         *  source address for the translated packet."
         */
        if (ip6h->nexthdr != IPPROTO_ICMPV6)
            goto out;

        icmp6 = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (icmp6 + 1 > data_end)
            goto out;

        if (icmp6->icmp6_type != ICMPV6_DEST_UNREACH && icmp6->icmp6_type != ICMPV6_TIME_EXCEED
            && icmp6->icmp6_type != ICMPV6_PKT_TOOBIG)
            goto out;

        DBG("v6: icmpv6 type %u from native address %pI6c, translating src to dummy ipv4\n",
            icmp6->icmp6_type,
            &ip6h->saddr);

        addr4 = __cpu_to_be32(INADDR_DUMMY);
    }

    /* At this point we know the packet needs translation. If we can't
     * rewrite it, it should be dropped.
     */
    ret = TC_ACT_SHOT;

    if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP
        || ip6h->nexthdr == IPPROTO_ICMPV6) {
        translate_ipv6_header(ip6h, &dst_hdr, addr4, config.local_v4.s_addr);
        DBG("v6: incoming pkt from src %pI6c (%pI4)\n", &ip6h->saddr, &addr4);
    } else if (ip6h->nexthdr == IPPROTO_FRAGMENT) {
        struct ip6_frag *frag = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        int              tot_len;
        __u16            offset;

        if (frag + 1 > data_end)
            goto out;

        /* Translate into an IPv4 fragmented packet, RFC 6145 5.1.1 */

        tot_len = bpf_ntohs(ip6h->payload_len) + sizeof(struct iphdr) - sizeof(struct ip6_frag);

        offset = bpf_ntohs(frag->offset);
        offset = ((offset & 1) << 13) | /* More Fragments flag */
                 (offset >> 3);         /* Offset in 8-octet units */

        dst_hdr = (struct iphdr) {
            .version  = 4,
            .ihl      = 5,
            .id       = bpf_htons(bpf_ntohl(frag->identification) & 0xffff),
            .tos      = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4),
            .frag_off = bpf_htons(offset),
            .ttl      = ip6h->hop_limit,
            .protocol = frag->nexthdr == IPPROTO_ICMPV6 ? IPPROTO_ICMP : frag->nexthdr,
            .saddr    = addr4,
            .daddr    = config.local_v4.s_addr,
            .tot_len  = bpf_htons(tot_len),
        };

        dst_hdr.check = csum_fold_helper(
            bpf_csum_diff((__be32 *) &dst_hdr, 0, (__be32 *) &dst_hdr, sizeof(struct iphdr), 0));

        fragmented = true;

        DBG("v6: incoming fragmented pkt from src %pI6c (%pI4), id 0x%x\n",
            &ip6h->saddr,
            &addr4,
            bpf_ntohs(dst_hdr.id));
    } else {
        DBG("v6: pkt src/dst %pI6c/%pI6c has nexthdr %u, dropping\n", &ip6h->saddr, &ip6h->daddr);
        goto out;
    }

    switch (dst_hdr.protocol) {
    case IPPROTO_ICMP:
        /* We can't update the checksum of ICMP fragmented packets: ICMPv4 doesn't use
         * a pseudo header, while the ICMPv6 pseudo-header includes the total payload
         * length, which is not known when parsing the first fragment. This makes it
         * impossible for a stateless translator to compute the checksum delta. TCP and
         * UDP don't have this problem because both the v4 and v6 pseudo-headers include
         * the total length. */
        if (fragmented)
            goto out;

        if (rewrite_icmpv6(skb, &length_diff))
            goto out;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        /* Update the L4 headers only for non-fragmented packets or for the first
         * fragment, which contains the L4 header. */
        if (!fragmented || (bpf_ntohs(dst_hdr.frag_off) & 0x1FFF) == 0) {
            update_l4_checksum(skb, ip6h, &dst_hdr, false, false, fragmented, NULL);
        }
        break;
    default:
        break;
    }

    /* rewrite_icmpv6() can change the payload length when it rewrites the content of
     * an ICMPv6 error packet. Update the length and the checksum. */
    if (length_diff != 0) {
        data     = SKB_DATA(skb);
        data_end = SKB_DATA_END(skb);

        ip6h = data + sizeof(struct ethhdr);
        if (ip6h + 1 > data_end)
            goto out;

        dst_hdr.tot_len =
            bpf_htons(bpf_ntohs(ip6h->payload_len) + length_diff + sizeof(struct iphdr));

        dst_hdr.check = 0;
        dst_hdr.check = csum_fold_helper(
            bpf_csum_diff((__be32 *) &dst_hdr, 0, (__be32 *) &dst_hdr, sizeof(struct iphdr), 0));
    }

    if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
        goto out;

    if (fragmented) {
        /* Remove the IPv6 fragment header */
        if (bpf_skb_adjust_room(skb, -(__s32) sizeof(struct ip6_frag), BPF_ADJ_ROOM_NET, 0))
            goto out;
    }

    data     = SKB_DATA(skb);
    data_end = SKB_DATA_END(skb);

    eth = data;
    if (eth + 1 > data_end)
        goto out;

    iph = (void *) (eth + 1);
    if (iph + 1 > data_end)
        goto out;

    eth->h_proto = bpf_htons(ETH_P_IP);
    *iph         = dst_hdr;

    ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS);
out:
    return ret;
}

static int
clat_handler(struct __sk_buff *skb, bool egress)
{
    void          *data     = SKB_DATA(skb);
    void          *data_end = SKB_DATA_END(skb);
    struct ethhdr *eth;

    eth = data;
    if (eth + 1 > data_end)
        return TC_ACT_OK;

    /* Don't explicitly handle Ethernet types 8021Q and 8021AD
     * because we don't expect to receive VLAN-tagged packets
     * on the interface. */

    if (eth->h_proto == bpf_htons(ETH_P_IP) && egress)
        return clat_handle_v4(skb);
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6) && !egress)
        return clat_handle_v6(skb);

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
