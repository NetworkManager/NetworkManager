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
 * Copyright 2014 - 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_H__
#define __NETWORKMANAGER_H__

#define __NETWORKMANAGER_H_INSIDE__

#include "nm-access-point.h"
#include "nm-active-connection.h"
#include "nm-client.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"
#include "nm-dbus-interface.h"
#include "nm-device-6lowpan.h"
#include "nm-device-adsl.h"
#include "nm-device-bond.h"
#include "nm-device-bridge.h"
#include "nm-device-bt.h"
#include "nm-device-dummy.h"
#include "nm-device-ethernet.h"
#include "nm-device-generic.h"
#include "nm-device-infiniband.h"
#include "nm-device-ip-tunnel.h"
#include "nm-device-macsec.h"
#include "nm-device-macvlan.h"
#include "nm-device-modem.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-ovs-bridge.h"
#include "nm-device-ovs-interface.h"
#include "nm-device-ovs-port.h"
#include "nm-device-ppp.h"
#include "nm-device-team.h"
#include "nm-device-tun.h"
#include "nm-device-vlan.h"
#include "nm-device-vxlan.h"
#include "nm-device-wifi-p2p.h"
#include "nm-device-wifi.h"
#include "nm-device-wimax.h"
#include "nm-device-wireguard.h"
#include "nm-device-wpan.h"
#include "nm-device.h"
#include "nm-dhcp-config.h"
#include "nm-enum-types.h"
#include "nm-ip-config.h"
#include "nm-object.h"
#include "nm-remote-connection.h"
#include "nm-setting-6lowpan.h"
#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-dcb.h"
#include "nm-setting-dummy.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-ip-config.h"
#include "nm-setting-ip-tunnel.h"
#include "nm-setting-macsec.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-match.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-dpdk.h"
#include "nm-setting-ovs-patch.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-wifi-p2p.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-proxy.h"
#include "nm-setting-serial.h"
#include "nm-setting-sriov.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-tun.h"
#include "nm-setting-user.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-vxlan.h"
#include "nm-setting-wimax.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireguard.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wpan.h"
#include "nm-setting.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"
#include "nm-version.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-vpn-editor.h"
#include "nm-vpn-editor-plugin.h"
#include "nm-vpn-plugin-info.h"
#include "nm-vpn-service-plugin.h"
#include "nm-wifi-p2p-peer.h"
#include "nm-wimax-nsp.h"

#include "nm-autoptr.h"

#undef __NETWORKMANAGER_H_INSIDE__

#endif /* __NETWORKMANAGER_H__ */
