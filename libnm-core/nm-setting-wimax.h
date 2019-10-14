// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef __NM_SETTING_WIMAX_H__
#define __NM_SETTING_WIMAX_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIMAX            (nm_setting_wimax_get_type ())
#define NM_SETTING_WIMAX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIMAX, NMSettingWimax))
#define NM_SETTING_WIMAX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIMAX, NMSettingWimaxClass))
#define NM_IS_SETTING_WIMAX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIMAX))
#define NM_IS_SETTING_WIMAX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIMAX))
#define NM_SETTING_WIMAX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIMAX, NMSettingWimaxClass))

#define NM_SETTING_WIMAX_SETTING_NAME "wimax"

#define NM_SETTING_WIMAX_NETWORK_NAME "network-name"
#define NM_SETTING_WIMAX_MAC_ADDRESS  "mac-address"

/**
 * NMSettingWimax:
 *
 * WiMax Settings
 */
struct _NMSettingWimax {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingWimaxClass;

NM_DEPRECATED_IN_1_2
GType nm_setting_wimax_get_type (void);

NM_DEPRECATED_IN_1_2
NMSetting        *nm_setting_wimax_new              (void);
NM_DEPRECATED_IN_1_2
const char       *nm_setting_wimax_get_network_name (NMSettingWimax *setting);
NM_DEPRECATED_IN_1_2
const char       *nm_setting_wimax_get_mac_address  (NMSettingWimax *setting);

G_END_DECLS

#endif /* __NM_SETTING_WIMAX_H__ */
