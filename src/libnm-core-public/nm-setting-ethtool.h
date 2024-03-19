/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_SETTING_ETHTOOL_H__
#define __NM_SETTING_ETHTOOL_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include <linux/ethtool.h>

G_BEGIN_DECLS

/**
 * NMEthtoolFec:
 * @NM_ETHTOOL_FEC_NONE: Internal use only
 * @NM_ETHTOOL_FEC_AUTO: Select default/best FEC mode automatically
 * @NM_ETHTOOL_FEC_OFF: No FEC Mode
 * @NM_ETHTOOL_FEC_RS: Reed-Solomon FEC Mode
 * @NM_ETHTOOL_FEC_BASER: Base-R/Reed-Solomon FEC Mode
 * @NM_ETHTOOL_FEC_LLRS: Low Latency Reed Solomon FEC Mode
 *
 * #NMEthtoolFec describe ethtool Forward Error Correction(FEC) encoding modes.
 * FQDN.
 *
 * Since: 1.48
 */
typedef enum /*< flags >*/ {
    NM_ETHTOOL_FEC_NONE  = ETHTOOL_FEC_NONE,
    NM_ETHTOOL_FEC_AUTO  = ETHTOOL_FEC_AUTO,
    NM_ETHTOOL_FEC_OFF   = ETHTOOL_FEC_OFF,
    NM_ETHTOOL_FEC_RS    = ETHTOOL_FEC_RS,
    NM_ETHTOOL_FEC_BASER = ETHTOOL_FEC_BASER,
    NM_ETHTOOL_FEC_LLRS  = ETHTOOL_FEC_LLRS,
} NMEthtoolFec;

NM_AVAILABLE_IN_1_20
gboolean nm_ethtool_optname_is_feature(const char *optname);

NM_AVAILABLE_IN_1_26
gboolean nm_ethtool_optname_is_coalesce(const char *optname);

NM_AVAILABLE_IN_1_26
gboolean nm_ethtool_optname_is_ring(const char *optname);

NM_AVAILABLE_IN_1_32
gboolean nm_ethtool_optname_is_pause(const char *optname);

NM_AVAILABLE_IN_1_46
gboolean nm_ethtool_optname_is_channels(const char *optname);

NM_AVAILABLE_IN_1_46
gboolean nm_ethtool_optname_is_eee(const char *optname);

NM_AVAILABLE_IN_1_48
gboolean nm_ethtool_optname_is_fec(const char *optname);

/*****************************************************************************/

#define NM_TYPE_SETTING_ETHTOOL (nm_setting_ethtool_get_type())
#define NM_SETTING_ETHTOOL(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtool))
#define NM_SETTING_ETHTOOL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtoolClass))
#define NM_IS_SETTING_ETHTOOL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_ETHTOOL))
#define NM_IS_SETTING_ETHTOOL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_ETHTOOL))
#define NM_SETTING_ETHTOOL_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtoolClass))

#define NM_SETTING_ETHTOOL_SETTING_NAME "ethtool"

/*****************************************************************************/

typedef struct _NMSettingEthtoolClass NMSettingEthtoolClass;

NM_AVAILABLE_IN_1_14
GType nm_setting_ethtool_get_type(void);

NM_AVAILABLE_IN_1_14
NMSetting *nm_setting_ethtool_new(void);

/*****************************************************************************/

NM_AVAILABLE_IN_1_20
NM_DEPRECATED_IN_1_26
const char **nm_setting_ethtool_get_optnames(NMSettingEthtool *setting, guint *out_length);

NM_AVAILABLE_IN_1_14
NM_DEPRECATED_IN_1_26
NMTernary nm_setting_ethtool_get_feature(NMSettingEthtool *setting, const char *optname);
NM_AVAILABLE_IN_1_14
NM_DEPRECATED_IN_1_26
void
nm_setting_ethtool_set_feature(NMSettingEthtool *setting, const char *optname, NMTernary value);
NM_AVAILABLE_IN_1_14
NM_DEPRECATED_IN_1_26
void nm_setting_ethtool_clear_features(NMSettingEthtool *setting);

G_END_DECLS

#endif /* __NM_SETTING_ETHTOOL_H__ */
