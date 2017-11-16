/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-meta-setting.h"

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
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-ip-config.h"
#include "nm-setting-ip-tunnel.h"
#include "nm-setting-macsec.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-patch.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-proxy.h"
#include "nm-setting-serial.h"
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
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"

/*****************************************************************************/

const NMSetting8021xSchemeVtable nm_setting_8021x_scheme_vtable[] = {
	[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT] = {
		.setting_key            = NM_SETTING_802_1X_CA_CERT,
		.scheme_func            = nm_setting_802_1x_get_ca_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_ca_cert_path,
		.blob_func              = nm_setting_802_1x_get_ca_cert_blob,
		.uri_func               = nm_setting_802_1x_get_ca_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_ca_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_ca_cert_password_flags,
		.file_suffix            = "ca-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT] = {
		.setting_key            = NM_SETTING_802_1X_PHASE2_CA_CERT,
		.scheme_func            = nm_setting_802_1x_get_phase2_ca_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_phase2_ca_cert_path,
		.blob_func              = nm_setting_802_1x_get_phase2_ca_cert_blob,
		.uri_func               = nm_setting_802_1x_get_phase2_ca_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_phase2_ca_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_phase2_ca_cert_password_flags,
		.file_suffix            = "inner-ca-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT] = {
		.setting_key            = NM_SETTING_802_1X_CLIENT_CERT,
		.scheme_func            = nm_setting_802_1x_get_client_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_client_cert_path,
		.blob_func              = nm_setting_802_1x_get_client_cert_blob,
		.uri_func               = nm_setting_802_1x_get_client_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_client_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_client_cert_password_flags,
		.file_suffix            = "client-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT] = {
		.setting_key            = NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
		.scheme_func            = nm_setting_802_1x_get_phase2_client_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_phase2_client_cert_path,
		.blob_func              = nm_setting_802_1x_get_phase2_client_cert_blob,
		.uri_func               = nm_setting_802_1x_get_phase2_client_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_phase2_client_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_phase2_client_cert_password_flags,
		.file_suffix            = "inner-client-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY] = {
		.setting_key            = NM_SETTING_802_1X_PRIVATE_KEY,
		.scheme_func            = nm_setting_802_1x_get_private_key_scheme,
		.format_func            = nm_setting_802_1x_get_private_key_format,
		.path_func              = nm_setting_802_1x_get_private_key_path,
		.blob_func              = nm_setting_802_1x_get_private_key_blob,
		.uri_func               = nm_setting_802_1x_get_private_key_uri,
		.passwd_func            = nm_setting_802_1x_get_private_key_password,
		.pwflag_func            = nm_setting_802_1x_get_private_key_password_flags,
		.file_suffix            = "private-key",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY] = {
		.setting_key            = NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
		.scheme_func            = nm_setting_802_1x_get_phase2_private_key_scheme,
		.format_func            = nm_setting_802_1x_get_phase2_private_key_format,
		.path_func              = nm_setting_802_1x_get_phase2_private_key_path,
		.blob_func              = nm_setting_802_1x_get_phase2_private_key_blob,
		.uri_func               = nm_setting_802_1x_get_phase2_private_key_uri,
		.passwd_func            = nm_setting_802_1x_get_phase2_private_key_password,
		.pwflag_func            = nm_setting_802_1x_get_phase2_private_key_password_flags,
		.file_suffix            = "inner-private-key",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_UNKNOWN] = { NULL },
};

/*****************************************************************************/

const NMMetaSettingInfo nm_meta_setting_infos[] = {
	[NM_META_SETTING_TYPE_802_1X] = {
		.meta_type =                NM_META_SETTING_TYPE_802_1X,
		.setting_name =             NM_SETTING_802_1X_SETTING_NAME,
		.get_setting_gtype =        nm_setting_802_1x_get_type,
	},
	[NM_META_SETTING_TYPE_ADSL] = {
		.meta_type =                NM_META_SETTING_TYPE_ADSL,
		.setting_name =             NM_SETTING_ADSL_SETTING_NAME,
		.get_setting_gtype =        nm_setting_adsl_get_type,
	},
	[NM_META_SETTING_TYPE_BLUETOOTH] = {
		.meta_type =                NM_META_SETTING_TYPE_BLUETOOTH,
		.setting_name =             NM_SETTING_BLUETOOTH_SETTING_NAME,
		.get_setting_gtype =        nm_setting_bluetooth_get_type,
	},
	[NM_META_SETTING_TYPE_BOND] = {
		.meta_type =                NM_META_SETTING_TYPE_BOND,
		.setting_name =             NM_SETTING_BOND_SETTING_NAME,
		.get_setting_gtype =        nm_setting_bond_get_type,
	},
	[NM_META_SETTING_TYPE_BRIDGE] = {
		.meta_type =                NM_META_SETTING_TYPE_BRIDGE,
		.setting_name =             NM_SETTING_BRIDGE_SETTING_NAME,
		.get_setting_gtype =        nm_setting_bridge_get_type,
	},
	[NM_META_SETTING_TYPE_BRIDGE_PORT] = {
		.meta_type =                NM_META_SETTING_TYPE_BRIDGE_PORT,
		.setting_name =             NM_SETTING_BRIDGE_PORT_SETTING_NAME,
		.get_setting_gtype =        nm_setting_bridge_port_get_type,
	},
	[NM_META_SETTING_TYPE_CDMA] = {
		.meta_type =                NM_META_SETTING_TYPE_CDMA,
		.setting_name =             NM_SETTING_CDMA_SETTING_NAME,
		.get_setting_gtype =        nm_setting_cdma_get_type,
	},
	[NM_META_SETTING_TYPE_CONNECTION] = {
		.meta_type =                NM_META_SETTING_TYPE_CONNECTION,
		.setting_name =             NM_SETTING_CONNECTION_SETTING_NAME,
		.get_setting_gtype =        nm_setting_connection_get_type,
	},
	[NM_META_SETTING_TYPE_DCB] = {
		.meta_type =                NM_META_SETTING_TYPE_DCB,
		.setting_name =             NM_SETTING_DCB_SETTING_NAME,
		.get_setting_gtype =        nm_setting_dcb_get_type,
	},
	[NM_META_SETTING_TYPE_DUMMY] = {
		.meta_type =                NM_META_SETTING_TYPE_DUMMY,
		.setting_name =             NM_SETTING_DUMMY_SETTING_NAME,
		.get_setting_gtype =        nm_setting_dummy_get_type,
	},
	[NM_META_SETTING_TYPE_GENERIC] = {
		.meta_type =                NM_META_SETTING_TYPE_GENERIC,
		.setting_name =             NM_SETTING_GENERIC_SETTING_NAME,
		.get_setting_gtype =        nm_setting_generic_get_type,
	},
	[NM_META_SETTING_TYPE_GSM] = {
		.meta_type =                NM_META_SETTING_TYPE_GSM,
		.setting_name =             NM_SETTING_GSM_SETTING_NAME,
		.get_setting_gtype =        nm_setting_gsm_get_type,
	},
	[NM_META_SETTING_TYPE_INFINIBAND] = {
		.meta_type =                NM_META_SETTING_TYPE_INFINIBAND,
		.setting_name =             NM_SETTING_INFINIBAND_SETTING_NAME,
		.get_setting_gtype =        nm_setting_infiniband_get_type,
	},
	[NM_META_SETTING_TYPE_IP4_CONFIG] = {
		.meta_type =                NM_META_SETTING_TYPE_IP4_CONFIG,
		.setting_name =             NM_SETTING_IP4_CONFIG_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ip4_config_get_type,
	},
	[NM_META_SETTING_TYPE_IP6_CONFIG] = {
		.meta_type =                NM_META_SETTING_TYPE_IP6_CONFIG,
		.setting_name =             NM_SETTING_IP6_CONFIG_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ip6_config_get_type,
	},
	[NM_META_SETTING_TYPE_IP_TUNNEL] = {
		.meta_type =                NM_META_SETTING_TYPE_IP_TUNNEL,
		.setting_name =             NM_SETTING_IP_TUNNEL_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ip_tunnel_get_type,
	},
	[NM_META_SETTING_TYPE_MACSEC] = {
		.meta_type =                NM_META_SETTING_TYPE_MACSEC,
		.setting_name =             NM_SETTING_MACSEC_SETTING_NAME,
		.get_setting_gtype =        nm_setting_macsec_get_type,
	},
	[NM_META_SETTING_TYPE_MACVLAN] = {
		.meta_type =                NM_META_SETTING_TYPE_MACVLAN,
		.setting_name =             NM_SETTING_MACVLAN_SETTING_NAME,
		.get_setting_gtype =        nm_setting_macvlan_get_type,
	},
	[NM_META_SETTING_TYPE_OLPC_MESH] = {
		.meta_type =                NM_META_SETTING_TYPE_OLPC_MESH,
		.setting_name =             NM_SETTING_OLPC_MESH_SETTING_NAME,
		.get_setting_gtype =        nm_setting_olpc_mesh_get_type,
	},
	[NM_META_SETTING_TYPE_OVS_BRIDGE] = {
		.meta_type =                NM_META_SETTING_TYPE_OVS_BRIDGE,
		.setting_name =             NM_SETTING_OVS_BRIDGE_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ovs_bridge_get_type,
	},
	[NM_META_SETTING_TYPE_OVS_INTERFACE] = {
		.meta_type =                NM_META_SETTING_TYPE_OVS_INTERFACE,
		.setting_name =             NM_SETTING_OVS_INTERFACE_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ovs_interface_get_type,
	},
	[NM_META_SETTING_TYPE_OVS_PATCH] = {
		.meta_type =                NM_META_SETTING_TYPE_OVS_PATCH,
		.setting_name =             NM_SETTING_OVS_PATCH_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ovs_patch_get_type,
	},
	[NM_META_SETTING_TYPE_OVS_PORT] = {
		.meta_type =                NM_META_SETTING_TYPE_OVS_PORT,
		.setting_name =             NM_SETTING_OVS_PORT_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ovs_port_get_type,
	},
	[NM_META_SETTING_TYPE_PPPOE] = {
		.meta_type =                NM_META_SETTING_TYPE_PPPOE,
		.setting_name =             NM_SETTING_PPPOE_SETTING_NAME,
		.get_setting_gtype =        nm_setting_pppoe_get_type,
	},
	[NM_META_SETTING_TYPE_PPP] = {
		.meta_type =                NM_META_SETTING_TYPE_PPP,
		.setting_name =             NM_SETTING_PPP_SETTING_NAME,
		.get_setting_gtype =        nm_setting_ppp_get_type,
	},
	[NM_META_SETTING_TYPE_PROXY] = {
		.meta_type =                NM_META_SETTING_TYPE_PROXY,
		.setting_name =             NM_SETTING_PROXY_SETTING_NAME,
		.get_setting_gtype =        nm_setting_proxy_get_type,
	},
	[NM_META_SETTING_TYPE_SERIAL] = {
		.meta_type =                NM_META_SETTING_TYPE_SERIAL,
		.setting_name =             NM_SETTING_SERIAL_SETTING_NAME,
		.get_setting_gtype =        nm_setting_serial_get_type,
	},
	[NM_META_SETTING_TYPE_TC_CONFIG] = {
		.meta_type =                NM_META_SETTING_TYPE_TC_CONFIG,
		.setting_name =             NM_SETTING_TC_CONFIG_SETTING_NAME,
		.get_setting_gtype =        nm_setting_tc_config_get_type,
	},
	[NM_META_SETTING_TYPE_TEAM] = {
		.meta_type =                NM_META_SETTING_TYPE_TEAM,
		.setting_name =             NM_SETTING_TEAM_SETTING_NAME,
		.get_setting_gtype =        nm_setting_team_get_type,
	},
	[NM_META_SETTING_TYPE_TEAM_PORT] = {
		.meta_type =                NM_META_SETTING_TYPE_TEAM_PORT,
		.setting_name =             NM_SETTING_TEAM_PORT_SETTING_NAME,
		.get_setting_gtype =        nm_setting_team_port_get_type,
	},
	[NM_META_SETTING_TYPE_TUN] = {
		.meta_type =                NM_META_SETTING_TYPE_TUN,
		.setting_name =             NM_SETTING_TUN_SETTING_NAME,
		.get_setting_gtype =        nm_setting_tun_get_type,
	},
	[NM_META_SETTING_TYPE_USER] = {
		.meta_type =                NM_META_SETTING_TYPE_USER,
		.setting_name =             NM_SETTING_USER_SETTING_NAME,
		.get_setting_gtype =        nm_setting_user_get_type,
	},
	[NM_META_SETTING_TYPE_VLAN] = {
		.meta_type =                NM_META_SETTING_TYPE_VLAN,
		.setting_name =             NM_SETTING_VLAN_SETTING_NAME,
		.get_setting_gtype =        nm_setting_vlan_get_type,
	},
	[NM_META_SETTING_TYPE_VPN] = {
		.meta_type =                NM_META_SETTING_TYPE_VPN,
		.setting_name =             NM_SETTING_VPN_SETTING_NAME,
		.get_setting_gtype =        nm_setting_vpn_get_type,
	},
	[NM_META_SETTING_TYPE_VXLAN] = {
		.meta_type =                NM_META_SETTING_TYPE_VXLAN,
		.setting_name =             NM_SETTING_VXLAN_SETTING_NAME,
		.get_setting_gtype =        nm_setting_vxlan_get_type,
	},
	[NM_META_SETTING_TYPE_WIMAX] = {
		.meta_type =                NM_META_SETTING_TYPE_WIMAX,
		.setting_name =             NM_SETTING_WIMAX_SETTING_NAME,
		.get_setting_gtype =        nm_setting_wimax_get_type,
	},
	[NM_META_SETTING_TYPE_WIRED] = {
		.meta_type =                NM_META_SETTING_TYPE_WIRED,
		.setting_name =             NM_SETTING_WIRED_SETTING_NAME,
		.get_setting_gtype =        nm_setting_wired_get_type,
	},
	[NM_META_SETTING_TYPE_WIRELESS] = {
		.meta_type =                NM_META_SETTING_TYPE_WIRELESS,
		.setting_name =             NM_SETTING_WIRELESS_SETTING_NAME,
		.get_setting_gtype =        nm_setting_wireless_get_type,
	},
	[NM_META_SETTING_TYPE_WIRELESS_SECURITY] = {
		.meta_type =                NM_META_SETTING_TYPE_WIRELESS_SECURITY,
		.setting_name =             NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
		.get_setting_gtype =        nm_setting_wireless_security_get_type,
	},

	[NM_META_SETTING_TYPE_UNKNOWN] = {
		.meta_type =                NM_META_SETTING_TYPE_UNKNOWN,
	},
};

const NMMetaSettingInfo *
nm_meta_setting_infos_by_name (const char *name)
{
	int i;

	if (name) {
		for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
			if (nm_streq (nm_meta_setting_infos[i].setting_name, name))
				return &nm_meta_setting_infos[i];
		}
	}
	return NULL;
}

const NMMetaSettingInfo *
nm_meta_setting_infos_by_gtype (GType gtype)
{
	int i;

	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		if (nm_meta_setting_infos[i].get_setting_gtype () == gtype)
			return &nm_meta_setting_infos[i];
	}
	return NULL;
}

/*****************************************************************************/
