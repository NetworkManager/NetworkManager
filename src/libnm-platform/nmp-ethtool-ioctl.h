/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef __NMP_ETHTOOL_IOCTL_H__
#define __NMP_ETHTOOL_IOCTL_H__

#include "libnm-platform/nmp-base.h"
#include "libnm-platform/nm-netlink.h"

gboolean nmp_ethtool_ioctl_supports_carrier_detect(int ifindex);

gboolean nmp_ethtool_ioctl_supports_vlans(int ifindex);

gboolean nmp_ethtool_ioctl_get_wake_on_lan(int ifindex);

gboolean nmp_ethtool_ioctl_set_wake_on_lan(int                      ifindex,
                                           _NMSettingWiredWakeOnLan wol,
                                           const char              *wol_password);

gboolean nmp_ethtool_ioctl_get_link_settings(int                       ifindex,
                                             gboolean                 *out_autoneg,
                                             guint32                  *out_speed,
                                             NMPlatformLinkDuplexType *out_duplex);
gboolean nmp_ethtool_ioctl_set_link_settings(int                      ifindex,
                                             gboolean                 autoneg,
                                             guint32                  speed,
                                             NMPlatformLinkDuplexType duplex);

gboolean nmp_ethtool_ioctl_get_permanent_address(int ifindex, guint8 *buf, size_t *length);

gboolean nmp_ethtool_ioctl_get_driver_info(int ifindex, NMPUtilsEthtoolDriverInfo *data);

NMEthtoolFeatureStates *nmp_ethtool_ioctl_get_features(int ifindex);

gboolean nmp_ethtool_ioctl_set_features(
    int                           ifindex,
    const NMEthtoolFeatureStates *features,
    const NMOptionBool *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
    gboolean            do_set /* or reset */);

gboolean nmp_ethtool_ioctl_get_coalesce(int ifindex, NMEthtoolCoalesceState *coalesce);

gboolean nmp_ethtool_ioctl_set_coalesce(int ifindex, const NMEthtoolCoalesceState *coalesce);

gboolean nmp_ethtool_ioctl_get_channels(int ifindex, NMEthtoolChannelsState *channels);

gboolean nmp_ethtool_ioctl_set_channels(int ifindex, const NMEthtoolChannelsState *channels);

gboolean nmp_ethtool_ioctl_get_fec_mode(int ifindex, uint32_t *fec_mode);

gboolean nmp_ethtool_ioctl_set_fec_mode(int ifindex, uint32_t fec_mode);

gboolean nmp_mii_ioctl_supports_carrier_detect(int ifindex);

#endif /* __NMP_ETHTOOL_IOCTL_H__ */
