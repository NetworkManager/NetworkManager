/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#ifndef __NM_SETTING_WPAN_H__
#define __NM_SETTING_WPAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WPAN (nm_setting_wpan_get_type())
#define NM_SETTING_WPAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_WPAN, NMSettingWpan))
#define NM_SETTING_WPAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_WPANCONFIG, NMSettingWpanClass))
#define NM_IS_SETTING_WPAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_WPAN))
#define NM_IS_SETTING_WPAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_WPAN))
#define NM_SETTING_WPAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_WPAN, NMSettingWpanClass))

#define NM_SETTING_WPAN_SETTING_NAME  "wpan"
#define NM_SETTING_WPAN_MAC_ADDRESS   "mac-address"
#define NM_SETTING_WPAN_PAN_ID        "pan-id"
#define NM_SETTING_WPAN_SHORT_ADDRESS "short-address"
#define NM_SETTING_WPAN_PAGE          "page"
#define NM_SETTING_WPAN_CHANNEL       "channel"

#define NM_SETTING_WPAN_PAGE_DEFAULT    -1
#define NM_SETTING_WPAN_CHANNEL_DEFAULT -1

typedef struct _NMSettingWpanClass NMSettingWpanClass;

NM_AVAILABLE_IN_1_14
GType nm_setting_wpan_get_type(void);
NM_AVAILABLE_IN_1_14
NMSetting *nm_setting_wpan_new(void);

NM_AVAILABLE_IN_1_14
const char *nm_setting_wpan_get_mac_address(NMSettingWpan *setting);
NM_AVAILABLE_IN_1_14
guint16 nm_setting_wpan_get_pan_id(NMSettingWpan *setting);
NM_AVAILABLE_IN_1_14
guint16 nm_setting_wpan_get_short_address(NMSettingWpan *setting);
NM_AVAILABLE_IN_1_16
gint16 nm_setting_wpan_get_page(NMSettingWpan *setting);
NM_AVAILABLE_IN_1_16
gint16 nm_setting_wpan_get_channel(NMSettingWpan *setting);

G_END_DECLS

#endif /* __NM_SETTING_WPAN_H__ */
