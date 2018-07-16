/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_SETTING_ETHTOOL_H__
#define __NM_SETTING_ETHTOOL_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

/*****************************************************************************/

#define NM_ETHTOOL_OPTNAME_FEATURE_GRO                     "feature-gro"
#define NM_ETHTOOL_OPTNAME_FEATURE_GSO                     "feature-gso"
#define NM_ETHTOOL_OPTNAME_FEATURE_LRO                     "feature-lro"
#define NM_ETHTOOL_OPTNAME_FEATURE_NTUPLE                  "feature-ntuple"
#define NM_ETHTOOL_OPTNAME_FEATURE_RX                      "feature-rx"
#define NM_ETHTOOL_OPTNAME_FEATURE_RXHASH                  "feature-rxhash"
#define NM_ETHTOOL_OPTNAME_FEATURE_RXVLAN                  "feature-rxvlan"
#define NM_ETHTOOL_OPTNAME_FEATURE_SG                      "feature-sg"
#define NM_ETHTOOL_OPTNAME_FEATURE_TSO                     "feature-tso"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX                      "feature-tx"
#define NM_ETHTOOL_OPTNAME_FEATURE_TXVLAN                  "feature-txvlan"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP6_SEGMENTATION    "feature-tx-tcp6-segmentation"
#define NM_ETHTOOL_OPTNAME_FEATURE_TX_TCP_SEGMENTATION     "feature-tx-tcp-segmentation"

gboolean nm_ethtool_optname_is_feature (const char *optname);

/*****************************************************************************/

#define NM_TYPE_SETTING_ETHTOOL            (nm_setting_ethtool_get_type ())
#define NM_SETTING_ETHTOOL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtool))
#define NM_SETTING_ETHTOOL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtoolClass))
#define NM_IS_SETTING_ETHTOOL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_ETHTOOL))
#define NM_IS_SETTING_ETHTOOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_ETHTOOL))
#define NM_SETTING_ETHTOOL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_ETHTOOL, NMSettingEthtoolClass))

#define NM_SETTING_ETHTOOL_SETTING_NAME "ethtool"

/*****************************************************************************/

typedef struct _NMSettingEthtoolClass NMSettingEthtoolClass;

NM_AVAILABLE_IN_1_14
GType nm_setting_ethtool_get_type (void);

NM_AVAILABLE_IN_1_14
NMSetting        *nm_setting_ethtool_new (void);

/*****************************************************************************/

NM_AVAILABLE_IN_1_14
NMTernary         nm_setting_ethtool_get_feature (NMSettingEthtool *setting,
                                                  const char *optname);
NM_AVAILABLE_IN_1_14
void              nm_setting_ethtool_set_feature (NMSettingEthtool *setting,
                                                  const char *optname,
                                                  NMTernary value);
NM_AVAILABLE_IN_1_14
void              nm_setting_ethtool_clear_features (NMSettingEthtool *setting);

G_END_DECLS

#endif /* __NM_SETTING_ETHTOOL_H__ */
