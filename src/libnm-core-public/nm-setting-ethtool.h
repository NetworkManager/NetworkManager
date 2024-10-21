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

G_BEGIN_DECLS

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

NM_AVAILABLE_IN_1_46_8
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

/**
 * NMSettingEthtoolFecMode:
 * @NM_SETTING_ETHTOOL_FEC_MODE_NONE: FEC mode configuration is not supported.
 * @NM_SETTING_ETHTOOL_FEC_MODE_AUTO: Select default/best FEC mode automatically.
 * @NM_SETTING_ETHTOOL_FEC_MODE_OFF: No FEC mode.
 * @NM_SETTING_ETHTOOL_FEC_MODE_RS: Reed-Solomon FEC Mode.
 * @NM_SETTING_ETHTOOL_FEC_MODE_BASER: Base-R/Reed-Solomon FEC Mode.
 * @NM_SETTING_ETHTOOL_FEC_MODE_LLRS: Low Latency Reed Solomon FEC Mode.
 *
 * These flags modify the ethtool FEC(Forward Error Correction) mode.
 *
 * Since: 1.52, 1.46.6
 **/
typedef enum {                                             /*< flags >*/
               NM_SETTING_ETHTOOL_FEC_MODE_NONE  = 1 << 0, /*< skip >*/
               NM_SETTING_ETHTOOL_FEC_MODE_AUTO  = 1 << 1,
               NM_SETTING_ETHTOOL_FEC_MODE_OFF   = 1 << 2,
               NM_SETTING_ETHTOOL_FEC_MODE_RS    = 1 << 3,
               NM_SETTING_ETHTOOL_FEC_MODE_BASER = 1 << 4,
               NM_SETTING_ETHTOOL_FEC_MODE_LLRS  = 1 << 5,
               /* New constant should align with linux/ethtool.h ETHTOOL_FEC_XXX */
               _NM_SETTING_ETHTOOL_FEC_MODE_LAST = NM_SETTING_ETHTOOL_FEC_MODE_LLRS, /*< skip >*/
} NMSettingEthtoolFecMode;

G_END_DECLS

#endif /* __NM_SETTING_ETHTOOL_H__ */
