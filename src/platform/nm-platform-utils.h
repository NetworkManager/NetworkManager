/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_PLATFORM_UTILS_H__
#define __NM_PLATFORM_UTILS_H__

#include "nm-platform.h"
#include "nm-setting-wired.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

/*****************************************************************************/

const char *nmp_utils_ethtool_get_driver (int ifindex);
gboolean nmp_utils_ethtool_supports_carrier_detect (int ifindex);
gboolean nmp_utils_ethtool_supports_vlans (int ifindex);
int nmp_utils_ethtool_get_peer_ifindex (int ifindex);
gboolean nmp_utils_ethtool_get_wake_on_lan (int ifindex);
gboolean nmp_utils_ethtool_set_wake_on_lan (int ifindex, NMSettingWiredWakeOnLan wol,
                                            const char *wol_password);

gboolean nmp_utils_ethtool_get_link_settings (int ifindex, gboolean *out_autoneg, guint32 *out_speed, NMPlatformLinkDuplexType *out_duplex);
gboolean nmp_utils_ethtool_set_link_settings (int ifindex, gboolean autoneg, guint32 speed, NMPlatformLinkDuplexType duplex);

gboolean  nmp_utils_ethtool_get_permanent_address (int ifindex,
                                                   guint8 *buf,
                                                   size_t *length);

typedef struct {
	/* We don't want to include <linux/ethtool.h> in header files,
	 * thus create a ABI compatible version of struct ethtool_drvinfo.*/
	guint32 _private_cmd;
	char    driver[32];
	char    version[32];
	char    fw_version[32];
	char    _private_bus_info[32];
	char    _private_erom_version[32];
	char    _private_reserved2[12];
	guint32 _private_n_priv_flags;
	guint32 _private_n_stats;
	guint32 _private_testinfo_len;
	guint32 _private_eedump_len;
	guint32 _private_regdump_len;
} NMPUtilsEthtoolDriverInfo;

gboolean nmp_utils_ethtool_get_driver_info (int ifindex,
                                            NMPUtilsEthtoolDriverInfo *data);

typedef struct {
	NMEthtoolID ethtool_id;

	guint8 n_kernel_names;

	/* one NMEthtoolID refers to one or more kernel_names. The reason for supporting this complexity
	 * (where one NMSettingEthtool option refers to multiple kernel features)  is to follow what
	 * ethtool does, where "tx" is an alias for multiple features. */
	const char *const*kernel_names;
} NMEthtoolFeatureInfo;

typedef struct {
	const NMEthtoolFeatureInfo *info;

	guint idx_ss_features;

	/* one NMEthtoolFeatureInfo references one or more kernel_names. This is the index
	 * of the matching info->kernel_names */
	guint8 idx_kernel_name;

	bool available:1;
	bool requested:1;
	bool active:1;
	bool never_changed:1;
} NMEthtoolFeatureState;

struct _NMEthtoolFeatureStates {
	guint n_states;

	guint n_ss_features;

	/* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */
	const NMEthtoolFeatureState *const*states_indexed[_NM_ETHTOOL_ID_FEATURE_NUM];

	/* the same content, here as a list of n_states entries. */
	const NMEthtoolFeatureState states_list[];
};

NMEthtoolFeatureStates *nmp_utils_ethtool_get_features (int ifindex);

gboolean nmp_utils_ethtool_set_features (int ifindex,
                                         const NMEthtoolFeatureStates *features,
                                         const NMTernary *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
                                         gboolean do_set /* or reset */);

/*****************************************************************************/

gboolean nmp_utils_mii_supports_carrier_detect (int ifindex);

struct udev_device;

const char *nmp_utils_udev_get_driver (struct udev_device *udevice);

NMIPConfigSource nmp_utils_ip_config_source_from_rtprot (guint8 rtprot) _nm_const;
guint8           nmp_utils_ip_config_source_coerce_to_rtprot   (NMIPConfigSource source) _nm_const;
NMIPConfigSource nmp_utils_ip_config_source_coerce_from_rtprot (NMIPConfigSource source) _nm_const;
NMIPConfigSource nmp_utils_ip_config_source_round_trip_rtprot  (NMIPConfigSource source) _nm_const;
const char *     nmp_utils_ip_config_source_to_string (NMIPConfigSource source, char *buf, gsize len);

const char *nmp_utils_if_indextoname (int ifindex, char *out_ifname/*IFNAMSIZ*/);
int nmp_utils_if_nametoindex (const char *ifname);

int nmp_utils_sysctl_open_netdir (int ifindex,
                                  const char *ifname_guess,
                                  char *out_ifname);

#endif /* __NM_PLATFORM_UTILS_H__ */
