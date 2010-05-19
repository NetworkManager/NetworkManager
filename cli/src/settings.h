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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#ifndef NMC_SETTINGS_H
#define NMC_SETTINGS_H

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
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

#include "nmcli.h"
#include "utils.h"


gboolean setting_connection_details (NMSetting *setting, NmCli *nmc);
gboolean setting_wired_details (NMSetting *setting, NmCli *nmc);
gboolean setting_802_1X_details (NMSetting *setting, NmCli *nmc);
gboolean setting_wireless_details (NMSetting *setting, NmCli *nmc);
gboolean setting_wireless_security_details (NMSetting *setting, NmCli *nmc);
gboolean setting_ip4_config_details (NMSetting *setting, NmCli *nmc);
gboolean setting_ip6_config_details (NMSetting *setting, NmCli *nmc);
gboolean setting_serial_details (NMSetting *setting, NmCli *nmc);
gboolean setting_ppp_details (NMSetting *setting, NmCli *nmc);
gboolean setting_pppoe_details (NMSetting *setting, NmCli *nmc);
gboolean setting_gsm_details (NMSetting *setting, NmCli *nmc);
gboolean setting_cdma_details (NMSetting *setting, NmCli *nmc);
gboolean setting_bluetooth_details (NMSetting *setting, NmCli *nmc);
gboolean setting_olpc_mesh_details (NMSetting *setting, NmCli *nmc);
gboolean setting_vpn_details (NMSetting *setting, NmCli *nmc);

#endif /* NMC_SETTINGS_H */
