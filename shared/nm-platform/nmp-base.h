/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __NMP_FWD_H__
#define __NMP_FWD_H__

#include "nm-base/nm-base.h"

/*****************************************************************************/

typedef enum {
    NM_PLATFORM_LINK_DUPLEX_UNKNOWN,
    NM_PLATFORM_LINK_DUPLEX_HALF,
    NM_PLATFORM_LINK_DUPLEX_FULL,
} NMPlatformLinkDuplexType;

/*****************************************************************************/

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

typedef struct {
    NMEthtoolID ethtool_id;

    guint8 n_kernel_names;

    /* one NMEthtoolID refers to one or more kernel_names. The reason for supporting this complexity
     * (where one NMSettingEthtool option refers to multiple kernel features)  is to follow what
     * ethtool does, where "tx" is an alias for multiple features. */
    const char *const *kernel_names;
} NMEthtoolFeatureInfo;

typedef struct {
    const NMEthtoolFeatureInfo *info;

    guint idx_ss_features;

    /* one NMEthtoolFeatureInfo references one or more kernel_names. This is the index
     * of the matching info->kernel_names */
    guint8 idx_kernel_name;

    bool available : 1;
    bool requested : 1;
    bool active : 1;
    bool never_changed : 1;
} NMEthtoolFeatureState;

typedef struct {
    guint n_states;

    guint n_ss_features;

    /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */
    const NMEthtoolFeatureState *const *states_indexed[_NM_ETHTOOL_ID_FEATURE_NUM];

    /* the same content, here as a list of n_states entries. */
    const NMEthtoolFeatureState states_list[];
} NMEthtoolFeatureStates;

/*****************************************************************************/

typedef struct {
    guint32
        s[_NM_ETHTOOL_ID_COALESCE_NUM /* indexed by (NMEthtoolID - _NM_ETHTOOL_ID_COALESCE_FIRST) */
    ];
} NMEthtoolCoalesceState;

/*****************************************************************************/

typedef struct {
    guint32 rx_pending;
    guint32 rx_mini_pending;
    guint32 rx_jumbo_pending;
    guint32 tx_pending;
} NMEthtoolRingState;

/*****************************************************************************/

typedef struct _NMPNetns NMPNetns;

#endif /* __NMP_FWD_H__ */
