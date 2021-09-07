/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_PLATFORM_UTILS_H__
#define __NM_PLATFORM_UTILS_H__

#include "libnm-base/nm-base.h"
#include "libnm-platform/nmp-base.h"

/*****************************************************************************/

const char *nmp_utils_ethtool_get_driver(int ifindex);
gboolean    nmp_utils_ethtool_supports_carrier_detect(int ifindex);
gboolean    nmp_utils_ethtool_supports_vlans(int ifindex);
int         nmp_utils_ethtool_get_peer_ifindex(int ifindex);
gboolean    nmp_utils_ethtool_get_wake_on_lan(int ifindex);
gboolean    nmp_utils_ethtool_set_wake_on_lan(int                      ifindex,
                                              _NMSettingWiredWakeOnLan wol,
                                              const char *             wol_password);

const char *nm_platform_link_duplex_type_to_string(NMPlatformLinkDuplexType duplex);

extern const guint8  _nmp_link_mode_all_advertised_modes_bits[79];
extern const guint32 _nmp_link_mode_all_advertised_modes[3];

gboolean nmp_utils_ethtool_get_link_settings(int                       ifindex,
                                             gboolean *                out_autoneg,
                                             guint32 *                 out_speed,
                                             NMPlatformLinkDuplexType *out_duplex);
gboolean nmp_utils_ethtool_set_link_settings(int                      ifindex,
                                             gboolean                 autoneg,
                                             guint32                  speed,
                                             NMPlatformLinkDuplexType duplex);

gboolean nmp_utils_ethtool_get_permanent_address(int ifindex, guint8 *buf, size_t *length);

gboolean nmp_utils_ethtool_get_driver_info(int ifindex, NMPUtilsEthtoolDriverInfo *data);

NMEthtoolFeatureStates *nmp_utils_ethtool_get_features(int ifindex);

gboolean nmp_utils_ethtool_set_features(
    int                           ifindex,
    const NMEthtoolFeatureStates *features,
    const NMOptionBool *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
    gboolean            do_set /* or reset */);

gboolean nmp_utils_ethtool_get_coalesce(int ifindex, NMEthtoolCoalesceState *coalesce);

gboolean nmp_utils_ethtool_set_coalesce(int ifindex, const NMEthtoolCoalesceState *coalesce);

gboolean nmp_utils_ethtool_get_ring(int ifindex, NMEthtoolRingState *ring);

gboolean nmp_utils_ethtool_set_ring(int ifindex, const NMEthtoolRingState *ring);

gboolean nmp_utils_ethtool_get_pause(int ifindex, NMEthtoolPauseState *pause);

gboolean nmp_utils_ethtool_set_pause(int ifindex, const NMEthtoolPauseState *pause);

/*****************************************************************************/

gboolean nmp_utils_mii_supports_carrier_detect(int ifindex);

struct udev_device;

const char *nmp_utils_udev_get_driver(struct udev_device *udevice);

NMIPConfigSource nmp_utils_ip_config_source_from_rtprot(guint8 rtprot) _nm_const;
guint8           nmp_utils_ip_config_source_coerce_to_rtprot(NMIPConfigSource source) _nm_const;
NMIPConfigSource nmp_utils_ip_config_source_coerce_from_rtprot(NMIPConfigSource source) _nm_const;
NMIPConfigSource nmp_utils_ip_config_source_round_trip_rtprot(NMIPConfigSource source) _nm_const;
const char *nmp_utils_ip_config_source_to_string(NMIPConfigSource source, char *buf, gsize len);

const char *nmp_utils_if_indextoname(int ifindex, char *out_ifname /*IFNAMSIZ*/);
int         nmp_utils_if_nametoindex(const char *ifname);

int nmp_utils_sysctl_open_netdir(int ifindex, const char *ifname_guess, char *out_ifname);

char *      nmp_utils_new_vlan_name(const char *parent_iface, guint32 vlan_id);
const char *nmp_utils_new_infiniband_name(char *name, const char *parent_name, int p_key);

guint32
nmp_utils_lifetime_rebase_relative_time_on_now(guint32 timestamp, guint32 duration, gint32 now);

guint32 nmp_utils_lifetime_get(guint32  timestamp,
                               guint32  lifetime,
                               guint32  preferred,
                               gint32   now,
                               guint32 *out_preferred);

int nmp_utils_modprobe(GError **error, gboolean suppress_error_logging, const char *arg1, ...)
    G_GNUC_NULL_TERMINATED;

#endif /* __NM_PLATFORM_UTILS_H__ */
