/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_SETTING_ETHTOOL_H__
#define __NM_SETTING_ETHTOOL_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

/*****************************************************************************/

#define NM_ETHTOOL_OPTNAME_FEATURE_ESP_HW_OFFLOAD               "feature-esp-hw-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_ESP_TX_CSUM_HW_OFFLOAD       "feature-esp-tx-csum-hw-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_FCOE_MTU                     "feature-fcoe-mtu"
#define NM_ETHTOOL_OPTNAME_FEATURE_GRO                          "feature-gro"
#define NM_ETHTOOL_OPTNAME_FEATURE_GSO                          "feature-gso"
#define NM_ETHTOOL_OPTNAME_FEATURE_HIGHDMA                      "feature-highdma"
#define NM_ETHTOOL_OPTNAME_FEATURE_HW_TC_OFFLOAD                "feature-hw-tc-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_L2_FWD_OFFLOAD               "feature-l2-fwd-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_LOOPBACK                     "feature-loopback"
#define NM_ETHTOOL_OPTNAME_FEATURE_LRO                          "feature-lro"
#define NM_ETHTOOL_OPTNAME_FEATURE_NTUPLE                       "feature-ntuple"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX                           "feature-rx"
#define NM_ETHTOOL_OPTNAME_FEATURE_RXHASH                       "feature-rxhash"
#define NM_ETHTOOL_OPTNAME_FEATURE_RXVLAN                       "feature-rxvlan"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_ALL                       "feature-rx-all"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_FCS                       "feature-rx-fcs"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_GRO_HW                    "feature-rx-gro-hw"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD   "feature-rx-udp_tunnel-port-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_VLAN_FILTER               "feature-rx-vlan-filter"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_VLAN_STAG_FILTER          "feature-rx-vlan-stag-filter"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX_VLAN_STAG_HW_PARSE        "feature-rx-vlan-stag-hw-parse"
#define NM_ETHTOOL_OPTNAME_FEATURE_SG                           "feature-sg"
#define NM_ETHTOOL_OPTNAME_FEATURE_TLS_HW_RECORD                "feature-tls-hw-record"
#define NM_ETHTOOL_OPTNAME_FEATURE_TLS_HW_TX_OFFLOAD            "feature-tls-hw-tx-offload"
#define NM_ETHTOOL_OPTNAME_FEATURE_TSO                          "feature-tso"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX                           "feature-tx"
#define NM_ETHTOOL_OPTNAME_FEATURE_TXVLAN                       "feature-txvlan"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_FCOE_CRC         "feature-tx-checksum-fcoe-crc"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_IPV4             "feature-tx-checksum-ipv4"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_IPV6             "feature-tx-checksum-ipv6"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_IP_GENERIC       "feature-tx-checksum-ip-generic"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_CHECKSUM_SCTP             "feature-tx-checksum-sctp"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_ESP_SEGMENTATION          "feature-tx-esp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_FCOE_SEGMENTATION         "feature-tx-fcoe-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GRE_CSUM_SEGMENTATION     "feature-tx-gre-csum-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GRE_SEGMENTATION          "feature-tx-gre-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GSO_PARTIAL               "feature-tx-gso-partial"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_GSO_ROBUST                "feature-tx-gso-robust"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_IPXIP4_SEGMENTATION       "feature-tx-ipxip4-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_IPXIP6_SEGMENTATION       "feature-tx-ipxip6-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_NOCACHE_COPY              "feature-tx-nocache-copy"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_SCATTER_GATHER            "feature-tx-scatter-gather"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_SCATTER_GATHER_FRAGLIST   "feature-tx-scatter-gather-fraglist"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_SCTP_SEGMENTATION         "feature-tx-sctp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP6_SEGMENTATION         "feature-tx-tcp6-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_ECN_SEGMENTATION      "feature-tx-tcp-ecn-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_MANGLEID_SEGMENTATION "feature-tx-tcp-mangleid-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_SEGMENTATION          "feature-tx-tcp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_UDP_SEGMENTATION          "feature-tx-udp-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION "feature-tx-udp_tnl-csum-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_UDP_TNL_SEGMENTATION      "feature-tx-udp_tnl-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_VLAN_STAG_HW_INSERT       "feature-tx-vlan-stag-hw-insert"

NM_AVAILABLE_IN_1_20
gboolean nm_ethtool_optname_is_feature (const char *optname);

/*****************************************************************************/

#define NM_TYPE_SETTING_ETHTOOL            (nm_setting_ethtool_get_type ())
#define NM_SETTING_ETHTOOL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtool))
#define NM_SETTING_ETHTOOL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtoolClass))
#define NM_IS_SETTING_ETHTOOL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_ETHTOOL))
#define NM_IS_SETTING_ETHTOOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_ETHTOOL))
#define NM_SETTING_ETHTOOL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtoolClass))

#define NM_SETTING_ETHTOOL_SETTING_NAME "ethtool"

/*****************************************************************************/

typedef struct _NMSettingEthtoolClass NMSettingEthtoolClass;

NM_AVAILABLE_IN_1_14
GType nm_setting_ethtool_get_type (void);

NM_AVAILABLE_IN_1_14
NMSetting        *nm_setting_ethtool_new (void);

/*****************************************************************************/

NM_AVAILABLE_IN_1_14
NMTernary         nm_setting_ethtool_get_feature (NMSettingEthtool *setting,
                                                  const char *optname);
NM_AVAILABLE_IN_1_14
void              nm_setting_ethtool_set_feature (NMSettingEthtool *setting,
                                                  const char *optname,
                                                  NMTernary value);
NM_AVAILABLE_IN_1_14
void              nm_setting_ethtool_clear_features (NMSettingEthtool *setting);

NM_AVAILABLE_IN_1_20
const char **     nm_setting_ethtool_get_optnames (NMSettingEthtool *setting,
                                                   guint *out_length);

G_END_DECLS

#endif /* __NM_SETTING_ETHTOOL_H__ */
