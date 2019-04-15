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
 */

#ifndef __NM_LIBNM_SHARED_UTILS_H__
#define __NM_LIBNM_SHARED_UTILS_H__

/****************************************************************************/

#include "nm-setting-bridge.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip-config.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-sriov.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wireguard.h"

/****************************************************************************/

#define nm_auto_unref_ip_address nm_auto (_nm_ip_address_unref)
NM_AUTO_DEFINE_FCN0 (NMIPAddress *, _nm_ip_address_unref, nm_ip_address_unref)

#define nm_auto_unref_ip_route nm_auto (_nm_auto_unref_ip_route)
NM_AUTO_DEFINE_FCN0 (NMIPRoute *, _nm_auto_unref_ip_route, nm_ip_route_unref)

#define nm_auto_unref_ip_routing_rule nm_auto(_nm_auto_unref_ip_routing_rule)
NM_AUTO_DEFINE_FCN0 (NMIPRoutingRule *, _nm_auto_unref_ip_routing_rule, nm_ip_routing_rule_unref)

#define nm_auto_unref_sriov_vf nm_auto (_nm_auto_unref_sriov_vf)
NM_AUTO_DEFINE_FCN0 (NMSriovVF *, _nm_auto_unref_sriov_vf, nm_sriov_vf_unref)

#define nm_auto_unref_tc_qdisc nm_auto (_nm_auto_unref_tc_qdisc)
NM_AUTO_DEFINE_FCN0 (NMTCQdisc *, _nm_auto_unref_tc_qdisc, nm_tc_qdisc_unref)

#define nm_auto_unref_tc_tfilter nm_auto (_nm_auto_unref_tc_tfilter)
NM_AUTO_DEFINE_FCN0 (NMTCTfilter *, _nm_auto_unref_tc_tfilter, nm_tc_tfilter_unref)

#define nm_auto_unref_bridge_vlan nm_auto (_nm_auto_unref_bridge_vlan)
NM_AUTO_DEFINE_FCN0 (NMBridgeVlan *, _nm_auto_unref_bridge_vlan, nm_bridge_vlan_unref)

#define nm_auto_unref_team_link_watcher nm_auto (_nm_auto_unref_team_link_watcher)
NM_AUTO_DEFINE_FCN0 (NMTeamLinkWatcher *, _nm_auto_unref_team_link_watcher, nm_team_link_watcher_unref)

#define nm_auto_unref_wgpeer nm_auto (_nm_auto_unref_wgpeer)
NM_AUTO_DEFINE_FCN0 (NMWireGuardPeer *, _nm_auto_unref_wgpeer, nm_wireguard_peer_unref)

/****************************************************************************/

static inline guint32
nm_utils_vlan_priority_map_get_max_prio (NMVlanPriorityMap map, gboolean from)
{
	if (map == NM_VLAN_INGRESS_MAP) {
		return   from
		       ? 7u /* MAX_8021P_PRIO */
		       : (guint32) G_MAXUINT32 /* MAX_SKB_PRIO */;
	}
	nm_assert (map == NM_VLAN_EGRESS_MAP);
	return   from
	       ? (guint32) G_MAXUINT32 /* MAX_SKB_PRIO */
	       : 7u /* MAX_8021P_PRIO */;
}

gboolean nm_utils_vlan_priority_map_parse_str (NMVlanPriorityMap map_type,
                                               const char *str,
                                               gboolean allow_wildcard_to,
                                               guint32 *out_from,
                                               guint32 *out_to,
                                               gboolean *out_has_wildcard_to);

/*****************************************************************************/

static inline int
nm_setting_ip_config_get_addr_family (NMSettingIPConfig *s_ip)
{
	if (NM_IS_SETTING_IP4_CONFIG (s_ip))
		return AF_INET;
	if (NM_IS_SETTING_IP6_CONFIG (s_ip))
		return AF_INET6;
	g_return_val_if_reached (AF_UNSPEC);
}

/*****************************************************************************/

/* The maximum MTU for infiniband.
 *
 * This is both in transport-mode "datagram" and "connected"
 * and they both have the same maximum define.
 *
 * Note that in the past, MTU in "datagram" mode was restricted
 * to 2044 bytes. That is no longer the case and we accept large
 * MTUs.
 *
 * This define is the maxiumum for the MTU in a connection profile (the
 * setting). Whether large MTUs can be configured later (at activation time)
 * depends on other factors. */
#define NM_INFINIBAND_MAX_MTU ((guint) 65520)

#endif /* __NM_LIBNM_SHARED_UTILS_H__ */
