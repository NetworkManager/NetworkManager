/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2020 Red Hat, Inc.
 */

#ifndef __NM_SETTING_LINK_H__
#define __NM_SETTING_LINK_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_LINK (nm_setting_link_get_type())
#define NM_SETTING_LINK(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_LINK, NMSettingLink))
#define NM_SETTING_LINK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_LINK, NMSettingLinkClass))
#define NM_IS_SETTING_LINK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_LINK))
#define NM_IS_SETTING_LINK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_LINK))
#define NM_SETTING_LINK_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_LINK, NMSettingLinkClass))

#define NM_SETTING_LINK_SETTING_NAME "link"

#define NM_SETTING_LINK_TX_QUEUE_LENGTH  "tx-queue-length"
#define NM_SETTING_LINK_GSO_MAX_SIZE     "gso-max-size"
#define NM_SETTING_LINK_GSO_MAX_SEGMENTS "gso-max-segments"
#define NM_SETTING_LINK_GRO_MAX_SIZE     "gro-max-size"

typedef struct _NMSettingLinkClass NMSettingLinkClass;

NM_AVAILABLE_IN_1_44
GType nm_setting_link_get_type(void);
NM_AVAILABLE_IN_1_44
NMSetting *nm_setting_link_new(void);

NM_AVAILABLE_IN_1_44
gint64 nm_setting_link_get_tx_queue_length(NMSettingLink *setting);
NM_AVAILABLE_IN_1_44
gint64 nm_setting_link_get_gso_max_size(NMSettingLink *setting);
NM_AVAILABLE_IN_1_44
gint64 nm_setting_link_get_gso_max_segments(NMSettingLink *setting);
NM_AVAILABLE_IN_1_44
gint64 nm_setting_link_get_gro_max_size(NMSettingLink *setting);

G_END_DECLS

#endif /* __NM_SETTING_LINK_H__ */
