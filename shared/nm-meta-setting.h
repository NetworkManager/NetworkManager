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
 * Copyright 2017 - 2018 Red Hat, Inc.
 */

#ifndef __NM_META_SETTING_H__
#define __NM_META_SETTING_H__

#include "nm-setting-8021x.h"

/*****************************************************************************/

/*
 * A setting's priority should roughly follow the OSI layer model, but it also
 * controls which settings get asked for secrets first.  Thus settings which
 * relate to things that must be working first, like hardware, should get a
 * higher priority than things which layer on top of the hardware.  For example,
 * the GSM/CDMA settings should provide secrets before the PPP setting does,
 * because a PIN is required to unlock the device before PPP can even start.
 * Even settings without secrets should be assigned the right priority.
 *
 * 0: reserved for invalid
 *
 * 1: reserved for the Connection setting
 *
 * 2,3: hardware-related settings like Ethernet, Wi-Fi, InfiniBand, Bridge, etc.
 * These priority 1 settings are also "base types", which means that at least
 * one of them is required for the connection to be valid, and their name is
 * valid in the 'type' property of the Connection setting.
 *
 * 4: hardware-related auxiliary settings that require a base setting to be
 * successful first, like Wi-Fi security, 802.1x, etc.
 *
 * 5: hardware-independent settings that are required before IP connectivity
 * can be established, like PPP, PPPoE, etc.
 *
 * 6: IP-level stuff
 *
 * 10: NMSettingUser
 */
typedef enum { /*< skip >*/
	NM_SETTING_PRIORITY_INVALID     = 0,
	NM_SETTING_PRIORITY_CONNECTION  = 1,
	NM_SETTING_PRIORITY_HW_BASE     = 2,
	NM_SETTING_PRIORITY_HW_NON_BASE = 3,
	NM_SETTING_PRIORITY_HW_AUX      = 4,
	NM_SETTING_PRIORITY_AUX         = 5,
	NM_SETTING_PRIORITY_IP          = 6,
	NM_SETTING_PRIORITY_USER        = 10,
} NMSettingPriority;

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
	gboolean (*set_cert_func) (NMSetting8021x *setting,
	                           const char *value,
	                           NMSetting8021xCKScheme scheme,
	                           NMSetting8021xCKFormat *out_format,
	                           GError **error);
	gboolean (*set_private_key_func) (NMSetting8021x *setting,
	                                  const char *value,
	                                  const char *password,
	                                  NMSetting8021xCKScheme scheme,
	                                  NMSetting8021xCKFormat *out_format,
	                                  GError **error);
	const char *file_suffix;
	NMSetting8021xSchemeType scheme_type;
	bool is_secret:1;
} NMSetting8021xSchemeVtable;

extern const NMSetting8021xSchemeVtable nm_setting_8021x_scheme_vtable[_NM_SETTING_802_1X_SCHEME_TYPE_NUM + 1];

/*****************************************************************************/

typedef enum {
	/* the enum (and their numeric values) are internal API. Do not assign
	 * any meaning the numeric values, because they already have one:
	 *
	 * they are sorted in a way, that corresponds to the asciibetical sort
	 * order of the corresponding setting-name. */

	NM_META_SETTING_TYPE_6LOWPAN,
	NM_META_SETTING_TYPE_OLPC_MESH,
	NM_META_SETTING_TYPE_WIRELESS,
	NM_META_SETTING_TYPE_WIRELESS_SECURITY,
	NM_META_SETTING_TYPE_802_1X,
	NM_META_SETTING_TYPE_WIRED,
	NM_META_SETTING_TYPE_ADSL,
	NM_META_SETTING_TYPE_BLUETOOTH,
	NM_META_SETTING_TYPE_BOND,
	NM_META_SETTING_TYPE_BRIDGE,
	NM_META_SETTING_TYPE_BRIDGE_PORT,
	NM_META_SETTING_TYPE_CDMA,
	NM_META_SETTING_TYPE_CONNECTION,
	NM_META_SETTING_TYPE_DCB,
	NM_META_SETTING_TYPE_DUMMY,
	NM_META_SETTING_TYPE_ETHTOOL,
	NM_META_SETTING_TYPE_GENERIC,
	NM_META_SETTING_TYPE_GSM,
	NM_META_SETTING_TYPE_INFINIBAND,
	NM_META_SETTING_TYPE_IP_TUNNEL,
	NM_META_SETTING_TYPE_IP4_CONFIG,
	NM_META_SETTING_TYPE_IP6_CONFIG,
	NM_META_SETTING_TYPE_MACSEC,
	NM_META_SETTING_TYPE_MACVLAN,
	NM_META_SETTING_TYPE_MATCH,
	NM_META_SETTING_TYPE_OVS_BRIDGE,
	NM_META_SETTING_TYPE_OVS_DPDK,
	NM_META_SETTING_TYPE_OVS_INTERFACE,
	NM_META_SETTING_TYPE_OVS_PATCH,
	NM_META_SETTING_TYPE_OVS_PORT,
	NM_META_SETTING_TYPE_PPP,
	NM_META_SETTING_TYPE_PPPOE,
	NM_META_SETTING_TYPE_PROXY,
	NM_META_SETTING_TYPE_SERIAL,
	NM_META_SETTING_TYPE_SRIOV,
	NM_META_SETTING_TYPE_TC_CONFIG,
	NM_META_SETTING_TYPE_TEAM,
	NM_META_SETTING_TYPE_TEAM_PORT,
	NM_META_SETTING_TYPE_TUN,
	NM_META_SETTING_TYPE_USER,
	NM_META_SETTING_TYPE_VLAN,
	NM_META_SETTING_TYPE_VPN,
	NM_META_SETTING_TYPE_VXLAN,
	NM_META_SETTING_TYPE_WIFI_P2P,
	NM_META_SETTING_TYPE_WIMAX,
	NM_META_SETTING_TYPE_WIREGUARD,
	NM_META_SETTING_TYPE_WPAN,

	NM_META_SETTING_TYPE_UNKNOWN,

	_NM_META_SETTING_TYPE_NUM = NM_META_SETTING_TYPE_UNKNOWN,
} NMMetaSettingType;

/* this header is statically linked with both libnm-core.la and libnmc.la.
 * Though, there is no stable API/ABI, so whenever on of these components
 * accesses NMMetaSettingInfo or NMMetaSettingType, it only has meaning
 * inside the same component.
 *
 * Note how NMSettingClass has field of type "struct _NMMetaSettingInfo".
 * It would be a serious bug, if libnmc tries to interpret this pointer
 * with the meaning of NMMetaSettingInfo. They might be different, because
 * libnm.so (libnm-core.la) might be a newer version than nmcli (libnmc.la).
 *
 * This define helps to ensure that we don't accidentally use the pointer
 * in different contexts. */
#if ((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
#define _NMMetaSettingInfoXX _NMMetaSettingInfo
#else
#define _NMMetaSettingInfoXX _NMMetaSettingInfoCli
#endif
struct _NMMetaSettingInfoXX {
	const char *setting_name;
	GType (*get_setting_gtype) (void);
	NMMetaSettingType meta_type;
	NMSettingPriority setting_priority;
};

typedef struct _NMMetaSettingInfoXX NMMetaSettingInfo;

/* note that we statically link nm-meta-setting.h both to libnm-core.la and
 * libnmc.la. That means, there are two versions of nm_meta_setting_infos
 * in nmcli. That is not easily avoidable, because at this point, we don't
 * want yet to making it public API.
 *
 * Eventually, this should become public API of libnm, and nmcli/libnmc.la
 * should use that version.
 *
 * Downsides of the current solution:
 *
 * - duplication of the array in nmcli.
 *
 * - there is no stable API/ABI. That means, when you have a NMMetaSettingInfo
 *   pointer, or a NMMetaSettingType value, the value can only be used within
 *   the current context (libnm-core.la or libnmc.la). In other words, libnmc.la
 *   (and nmcli) must never access a NMMetaSettingInfo/NMMetaSettingType value,
 *   that comes from libnm-core.la.
 */
extern const NMMetaSettingInfo nm_meta_setting_infos[_NM_META_SETTING_TYPE_NUM + 1];

const NMMetaSettingInfo *nm_meta_setting_infos_by_name (const char *name);
const NMMetaSettingInfo *nm_meta_setting_infos_by_gtype (GType gtype);

/*****************************************************************************/

#endif /* __NM_META_SETTING_H__ */
