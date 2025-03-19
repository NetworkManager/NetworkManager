/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_PLATFORM_UTILS_H__
#define __NM_PLATFORM_UTILS_H__

#include "libnm-base/nm-base.h"
#include "libnm-platform/nmp-base.h"
#include "libnm-platform/nm-platform.h"

/*****************************************************************************/

const char *nm_platform_link_duplex_type_to_string(NMPlatformLinkDuplexType duplex);

extern const guint8  _nmp_link_mode_all_advertised_modes_bits[79];
extern const guint32 _nmp_link_mode_all_advertised_modes[3];

/*****************************************************************************/

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

char *nmp_utils_new_vlan_name(const char *parent_iface, guint32 vlan_id);

guint32
nmp_utils_lifetime_rebase_relative_time_on_now(guint32 timestamp, guint32 duration, gint32 now);

guint32 nmp_utils_lifetime_get(guint32  timestamp,
                               guint32  lifetime,
                               guint32  preferred,
                               gint32  *cached_now,
                               guint32 *out_preferred);

int nmp_utils_modprobe(GError **error, gboolean suppress_error_logging, const char *arg1, ...)
    G_GNUC_NULL_TERMINATED;

void nmp_utils_bridge_vlan_normalize(NMPlatformBridgeVlan *vlans, guint *num_vlans);

gboolean nmp_utils_bridge_normalized_vlans_equal(const NMPlatformBridgeVlan *vlans_a,
                                                 guint                       num_vlans_a,
                                                 const NMPlatformBridgeVlan *vlans_b,
                                                 guint                       num_vlans_b);

#endif /* __NM_PLATFORM_UTILS_H__ */
