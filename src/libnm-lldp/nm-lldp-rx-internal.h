/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_LLDP_RX_INTERNAL_H__
#define __NM_LLDP_RX_INTERNAL_H__

#include "libnm-glib-aux/nm-prioq.h"
#include "libnm-log-core/nm-logging.h"

#include "nm-lldp-rx.h"

struct _NMLldpRX {
    int ref_count;

    int fd;

    NMLldpRXConfig config;

    GMainContext *main_context;

    GSource *io_event_source;
    GSource *timer_event_source;

    GHashTable *neighbor_by_id;
    NMPrioq     neighbor_by_expiry;
};

/*****************************************************************************/

#define _NMLOG2_DOMAIN LOGD_PLATFORM
#define _NMLOG2(level, lldp_rx, ...)                                             \
    G_STMT_START                                                                 \
    {                                                                            \
        const NMLogLevel _level   = (level);                                     \
        NMLldpRX        *_lldp_rx = (lldp_rx);                                   \
                                                                                 \
        if (_NMLOG2_ENABLED(_level)) {                                           \
            _nm_log(level,                                                       \
                    _NMLOG2_DOMAIN,                                              \
                    0,                                                           \
                    _lldp_rx->config.log_ifname,                                 \
                    _lldp_rx->config.log_uuid,                                   \
                    "lldp-rx[" NM_HASH_OBFUSCATE_PTR_FMT                         \
                    "%s%s]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                \
                    NM_HASH_OBFUSCATE_PTR(_lldp_rx),                             \
                    NM_PRINT_FMT_QUOTED2(_lldp_rx->config.log_ifname,            \
                                         ", ",                                   \
                                         _lldp_rx->config.log_ifname,            \
                                         "") _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        }                                                                        \
    }                                                                            \
    G_STMT_END

/*****************************************************************************/

#endif /* __NM_LLDP_RX_INTERNAL_H__ */
