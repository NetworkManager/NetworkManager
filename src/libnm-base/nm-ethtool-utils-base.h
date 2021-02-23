/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_ETHTOOL_UTILS_H__
#define __NM_ETHTOOL_UTILS_H__

G_BEGIN_DECLS

/*****************************************************************************/

#define NM_ETHTOOL_OPTNAME_FEATURE_ESP_HW_OFFLOAD             "feature-esp-hw-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_ESP_TX_CSUM_HW_OFFLOAD     "feature-esp-tx-csum-hw-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_FCOE_MTU                   "feature-fcoe-mtu"
#define NM_ETHTOOL_OPTNAME_FEATURE_GRO                        "feature-gro"
#define NM_ETHTOOL_OPTNAME_FEATURE_GSO                        "feature-gso"
#define NM_ETHTOOL_OPTNAME_FEATURE_HIGHDMA                    "feature-highdma"
#define NM_ETHTOOL_OPTNAME_FEATURE_HW_TC_OFFLOAD              "feature-hw-tc-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_L2_FWD_OFFLOAD             "feature-l2-fwd-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_LOOPBACK                   "feature-loopback"
#define NM_ETHTOOL_OPTNAME_FEATURE_LRO                        "feature-lro"
#define NM_ETHTOOL_OPTNAME_FEATURE_MACSEC_HW_OFFLOAD          "feature-macsec-hw-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_NTUPLE                     "feature-ntuple"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX                         "feature-rx"
#define NM_ETHTOOL_OPTNAME_FEATURE_RXHASH                     "feature-rxhash"
#define NM_ETHTOOL_OPTNAME_FEATURE_RXVLAN                     "feature-rxvlan"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_ALL                     "feature-rx-all"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_FCS                     "feature-rx-fcs"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_GRO_HW                  "feature-rx-gro-hw"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_GRO_LIST                "feature-rx-gro-list"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_UDP_GRO_FORWARDING      "feature-rx-udp-gro-forwarding"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD "feature-rx-udp_tunnel-port-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_VLAN_FILTER             "feature-rx-vlan-filter"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_VLAN_STAG_FILTER        "feature-rx-vlan-stag-filter"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_VLAN_STAG_HW_PARSE      "feature-rx-vlan-stag-hw-parse"
#define NM_ETHTOOL_OPTNAME_FEATURE_SG                         "feature-sg"
#define NM_ETHTOOL_OPTNAME_FEATURE_TLS_HW_RECORD              "feature-tls-hw-record"
#define NM_ETHTOOL_OPTNAME_FEATURE_TLS_HW_RX_OFFLOAD          "feature-tls-hw-rx-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_TLS_HW_TX_OFFLOAD          "feature-tls-hw-tx-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_TSO                        "feature-tso"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX                         "feature-tx"
#define NM_ETHTOOL_OPTNAME_FEATURE_TXVLAN                     "feature-txvlan"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_FCOE_CRC       "feature-tx-checksum-fcoe-crc"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_IPV4           "feature-tx-checksum-ipv4"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_IPV6           "feature-tx-checksum-ipv6"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_IP_GENERIC     "feature-tx-checksum-ip-generic"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_SCTP           "feature-tx-checksum-sctp"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_ESP_SEGMENTATION        "feature-tx-esp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_FCOE_SEGMENTATION       "feature-tx-fcoe-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GRE_CSUM_SEGMENTATION   "feature-tx-gre-csum-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GRE_SEGMENTATION        "feature-tx-gre-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GSO_LIST                "feature-tx-gso-list"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GSO_PARTIAL             "feature-tx-gso-partial"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GSO_ROBUST              "feature-tx-gso-robust"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_IPXIP4_SEGMENTATION     "feature-tx-ipxip4-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_IPXIP6_SEGMENTATION     "feature-tx-ipxip6-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_NOCACHE_COPY            "feature-tx-nocache-copy"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_SCATTER_GATHER          "feature-tx-scatter-gather"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_SCATTER_GATHER_FRAGLIST "feature-tx-scatter-gather-fraglist"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_SCTP_SEGMENTATION       "feature-tx-sctp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP6_SEGMENTATION       "feature-tx-tcp6-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_ECN_SEGMENTATION    "feature-tx-tcp-ecn-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_MANGLEID_SEGMENTATION \
    "feature-tx-tcp-mangleid-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_SEGMENTATION "feature-tx-tcp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TUNNEL_REMCSUM_SEGMENTATION \
    "feature-tx-tunnel-remcsum-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_UDP_SEGMENTATION "feature-tx-udp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION \
    "feature-tx-udp_tnl-csum-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_UDP_TNL_SEGMENTATION "feature-tx-udp_tnl-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_VLAN_STAG_HW_INSERT  "feature-tx-vlan-stag-hw-insert"

#define NM_ETHTOOL_OPTNAME_COALESCE_ADAPTIVE_RX       "coalesce-adaptive-rx"
#define NM_ETHTOOL_OPTNAME_COALESCE_ADAPTIVE_TX       "coalesce-adaptive-tx"
#define NM_ETHTOOL_OPTNAME_COALESCE_PKT_RATE_HIGH     "coalesce-pkt-rate-high"
#define NM_ETHTOOL_OPTNAME_COALESCE_PKT_RATE_LOW      "coalesce-pkt-rate-low"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES         "coalesce-rx-frames"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES_HIGH    "coalesce-rx-frames-high"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES_IRQ     "coalesce-rx-frames-irq"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES_LOW     "coalesce-rx-frames-low"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_USECS          "coalesce-rx-usecs"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_USECS_HIGH     "coalesce-rx-usecs-high"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_USECS_IRQ      "coalesce-rx-usecs-irq"
#define NM_ETHTOOL_OPTNAME_COALESCE_RX_USECS_LOW      "coalesce-rx-usecs-low"
#define NM_ETHTOOL_OPTNAME_COALESCE_SAMPLE_INTERVAL   "coalesce-sample-interval"
#define NM_ETHTOOL_OPTNAME_COALESCE_STATS_BLOCK_USECS "coalesce-stats-block-usecs"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES         "coalesce-tx-frames"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES_HIGH    "coalesce-tx-frames-high"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES_IRQ     "coalesce-tx-frames-irq"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES_LOW     "coalesce-tx-frames-low"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_USECS          "coalesce-tx-usecs"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_USECS_HIGH     "coalesce-tx-usecs-high"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_USECS_IRQ      "coalesce-tx-usecs-irq"
#define NM_ETHTOOL_OPTNAME_COALESCE_TX_USECS_LOW      "coalesce-tx-usecs-low"

#define NM_ETHTOOL_OPTNAME_RING_RX       "ring-rx"
#define NM_ETHTOOL_OPTNAME_RING_RX_JUMBO "ring-rx-jumbo"
#define NM_ETHTOOL_OPTNAME_RING_RX_MINI  "ring-rx-mini"
#define NM_ETHTOOL_OPTNAME_RING_TX       "ring-tx"

/*****************************************************************************/

G_END_DECLS

#endif /* __NM_ETHTOOL_UTILS_H__ */
