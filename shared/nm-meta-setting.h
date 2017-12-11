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

#ifndef __NM_META_SETTING_H__
#define __NM_META_SETTING_H__

#include "nm-setting-8021x.h"

/*****************************************************************************/

typedef enum {
	NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY,
	NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY,

	NM_SETTING_802_1X_SCHEME_TYPE_UNKNOWN,

	_NM_SETTING_802_1X_SCHEME_TYPE_NUM = NM_SETTING_802_1X_SCHEME_TYPE_UNKNOWN,
} NMSetting8021xSchemeType;

typedef struct {
	const char *setting_key;
	NMSetting8021xCKScheme (*scheme_func) (NMSetting8021x *setting);
	NMSetting8021xCKFormat (*format_func) (NMSetting8021x *setting);
	const char *           (*path_func)   (NMSetting8021x *setting);
	GBytes *               (*blob_func)   (NMSetting8021x *setting);
	const char *           (*uri_func)    (NMSetting8021x *setting);
	const char *           (*passwd_func) (NMSetting8021x *setting);
	NMSettingSecretFlags   (*pwflag_func) (NMSetting8021x *setting);
	const char *file_suffix;
} NMSetting8021xSchemeVtable;

extern const NMSetting8021xSchemeVtable nm_setting_8021x_scheme_vtable[_NM_SETTING_802_1X_SCHEME_TYPE_NUM + 1];

/*****************************************************************************/

typedef enum {
	NM_META_SETTING_TYPE_802_1X,
	NM_META_SETTING_TYPE_ADSL,
	NM_META_SETTING_TYPE_BLUETOOTH,
	NM_META_SETTING_TYPE_BOND,
	NM_META_SETTING_TYPE_BRIDGE,
	NM_META_SETTING_TYPE_BRIDGE_PORT,
	NM_META_SETTING_TYPE_CDMA,
	NM_META_SETTING_TYPE_CONNECTION,
	NM_META_SETTING_TYPE_DCB,
	NM_META_SETTING_TYPE_DUMMY,
	NM_META_SETTING_TYPE_GENERIC,
	NM_META_SETTING_TYPE_GSM,
	NM_META_SETTING_TYPE_INFINIBAND,
	NM_META_SETTING_TYPE_IP4_CONFIG,
	NM_META_SETTING_TYPE_IP6_CONFIG,
	NM_META_SETTING_TYPE_IP_TUNNEL,
	NM_META_SETTING_TYPE_MACSEC,
	NM_META_SETTING_TYPE_MACVLAN,
	NM_META_SETTING_TYPE_OLPC_MESH,
	NM_META_SETTING_TYPE_OVS_BRIDGE,
	NM_META_SETTING_TYPE_OVS_INTERFACE,
	NM_META_SETTING_TYPE_OVS_PATCH,
	NM_META_SETTING_TYPE_OVS_PORT,
	NM_META_SETTING_TYPE_PPP,
	NM_META_SETTING_TYPE_PPPOE,
	NM_META_SETTING_TYPE_PROXY,
	NM_META_SETTING_TYPE_SERIAL,
	NM_META_SETTING_TYPE_TC_CONFIG,
	NM_META_SETTING_TYPE_TEAM,
	NM_META_SETTING_TYPE_TEAM_PORT,
	NM_META_SETTING_TYPE_TUN,
	NM_META_SETTING_TYPE_USER,
	NM_META_SETTING_TYPE_VLAN,
	NM_META_SETTING_TYPE_VPN,
	NM_META_SETTING_TYPE_VXLAN,
	NM_META_SETTING_TYPE_WIMAX,
	NM_META_SETTING_TYPE_WIRED,
	NM_META_SETTING_TYPE_WIRELESS,
	NM_META_SETTING_TYPE_WIRELESS_SECURITY,

	NM_META_SETTING_TYPE_UNKNOWN,

	_NM_META_SETTING_TYPE_NUM = NM_META_SETTING_TYPE_UNKNOWN,
} NMMetaSettingType;

typedef struct {
	NMMetaSettingType meta_type;
	const char *setting_name;
	GType (*get_setting_gtype) (void);
} NMMetaSettingInfo;

extern const NMMetaSettingInfo nm_meta_setting_infos[_NM_META_SETTING_TYPE_NUM + 1];

const NMMetaSettingInfo *nm_meta_setting_infos_by_name (const char *name);
const NMMetaSettingInfo *nm_meta_setting_infos_by_gtype (GType gtype);

/*****************************************************************************/

#endif /* __NM_META_SETTING_H__ */
