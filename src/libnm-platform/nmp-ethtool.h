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

#endif /* __NMP_ETHTOOL_H__ */
