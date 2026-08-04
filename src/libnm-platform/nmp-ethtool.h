/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef __NMP_ETHTOOL_H__
#define __NMP_ETHTOOL_H__

#include "libnm-platform/nmp-base.h"
#include "libnm-platform/nm-netlink.h"

gboolean nmp_ethtool_get_pause(struct nl_sock      *genl_sock,
                               guint16              family_id,
                               int                  ifindex,
                               NMEthtoolPauseState *pause);
gboolean nmp_ethtool_set_pause(struct nl_sock            *genl_sock,
                               guint16                    family_id,
                               int                        ifindex,
                               const NMEthtoolPauseState *pause);

gboolean nmp_ethtool_get_eee(struct nl_sock    *genl_sock,
                             guint16            family_id,
                             int                ifindex,
                             NMEthtoolEEEState *eee);
gboolean nmp_ethtool_set_eee(struct nl_sock          *genl_sock,
                             guint16                  family_id,
                             int                      ifindex,
                             const NMEthtoolEEEState *eee);

gboolean nmp_ethtool_get_ring(struct nl_sock     *genl_sock,
                              guint16             family_id,
                              int                 ifindex,
                              NMEthtoolRingState *ring);
gboolean nmp_ethtool_set_ring(struct nl_sock           *genl_sock,
                              guint16                   family_id,
                              int                       ifindex,
                              const NMEthtoolRingState *ring);

typedef struct {
    guint32 bits;
    guint32 len;

    /* Compact bitset in native-endian u32 words; room for newer kernel modes. */
    guint32 modes[16];
} NMPEthtoolLinkModesMask;

NMOptionBool
_nmp_ethtool_link_modes_mask_restrict(NMPEthtoolLinkModesMask *mask, guint32 speed, guint8 duplex);

gboolean _nmp_ethtool_link_mode_has_speed(guint bit);

gboolean nmp_ethtool_get_link_settings(struct nl_sock             *genl_sock,
                                       guint16                     family_id,
                                       int                         ifindex,
                                       NMEthtoolLinkSettingsState *settings);
gboolean nmp_ethtool_set_link_settings(struct nl_sock                   *genl_sock,
                                       guint16                           family_id,
                                       int                               ifindex,
                                       const NMEthtoolLinkSettingsState *settings);

#endif /* __NMP_ETHTOOL_H__ */
