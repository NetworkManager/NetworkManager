/* nmcli - command-line tool to control NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 - 2012 Red Hat, Inc.
 */

#ifndef NMC_SETTINGS_H
#define NMC_SETTINGS_H

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-adsl.h>
#include <nm-setting-8021x.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-serial.h>
#include <nm-setting-ppp.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wimax.h>
#include <nm-setting-infiniband.h>
#include <nm-setting-bond.h>
#include <nm-setting-bridge.h>
#include <nm-setting-bridge-port.h>
#include <nm-setting-vlan.h>

#include "nmcli.h"
#include "utils.h"


gboolean setting_details (NMSetting *ssetting, NmCli *nmc);
gboolean setting_connection_details (NMSettingConnection *s_con, NmCli *nmc);
gboolean setting_wired_details (NMSettingWired *s_wired, NmCli *nmc);
gboolean setting_802_1X_details (NMSetting8021x *s_8021X, NmCli *nmc);
gboolean setting_wireless_details (NMSettingWireless *s_wireless, NmCli *nmc);
gboolean setting_wireless_security_details (NMSettingWirelessSecurity *s_wsec, NmCli *nmc);
gboolean setting_ip4_config_details (NMSettingIP4Config *s_ip4, NmCli *nmc);
gboolean setting_ip6_config_details (NMSettingIP6Config *s_ip6, NmCli *nmc);
gboolean setting_serial_details (NMSettingSerial *s_serial, NmCli *nmc);
gboolean setting_ppp_details (NMSettingPPP *s_ppp, NmCli *nmc);
gboolean setting_pppoe_details (NMSettingPPPOE *s_pppoe, NmCli *nmc);
gboolean setting_gsm_details (NMSettingGsm *s_gsm, NmCli *nmc);
gboolean setting_cdma_details (NMSettingCdma *s_cdma, NmCli *nmc);
gboolean setting_bluetooth_details (NMSettingBluetooth *s_bluetooth, NmCli *nmc);
gboolean setting_olpc_mesh_details (NMSettingOlpcMesh *s_olpc_mesh, NmCli *nmc);
gboolean setting_vpn_details (NMSettingVPN *s_vpn, NmCli *nmc);
gboolean setting_wimax_details (NMSettingWimax *s_wimax, NmCli *nmc);
gboolean setting_infiniband_details (NMSettingInfiniband *s_infiniband, NmCli *nmc);
gboolean setting_bond_details (NMSettingBond *s_bond, NmCli *nmc);
gboolean setting_vlan_details (NMSettingVlan *s_vlan, NmCli *nmc);
gboolean setting_adsl_details (NMSettingAdsl *s_adsl, NmCli *nmc);
gboolean setting_bridge_details (NMSettingBridge *s_bridge, NmCli *nmc);
gboolean setting_bridge_port_details (NMSettingBridgePort *s_bridge_port, NmCli *nmc);

#endif /* NMC_SETTINGS_H */
