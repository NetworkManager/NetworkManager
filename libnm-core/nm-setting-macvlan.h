// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_SETTING_MACVLAN_H__
#define __NM_SETTING_MACVLAN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_MACVLAN            (nm_setting_macvlan_get_type ())
#define NM_SETTING_MACVLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_MACVLAN, NMSettingMacvlan))
#define NM_SETTING_MACVLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_MACVLANCONFIG, NMSettingMacvlanClass))
#define NM_IS_SETTING_MACVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_MACVLAN))
#define NM_IS_SETTING_MACVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_MACVLAN))
#define NM_SETTING_MACVLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_MACVLAN, NMSettingMacvlanClass))

#define NM_SETTING_MACVLAN_SETTING_NAME         "macvlan"

#define NM_SETTING_MACVLAN_PARENT               "parent"
#define NM_SETTING_MACVLAN_MODE                 "mode"
#define NM_SETTING_MACVLAN_PROMISCUOUS          "promiscuous"
#define NM_SETTING_MACVLAN_TAP                  "tap"

/**
 * NMSettingMacvlan:
 *
 * MAC VLAN Settings
 */
struct _NMSettingMacvlan {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingMacvlanClass;

/**
 * NMSettingMacvlanMode:
 * @NM_SETTING_MACVLAN_MODE_UNKNOWN: unknown/unset mode
 * @NM_SETTING_MACVLAN_MODE_VEPA: Virtual Ethernet Port Aggregator mode
 * @NM_SETTING_MACVLAN_MODE_BRIDGE: bridge mode
 * @NM_SETTING_MACVLAN_MODE_PRIVATE: private mode
 * @NM_SETTING_MACVLAN_MODE_PASSTHRU: passthru mode
 * @NM_SETTING_MACVLAN_MODE_SOURCE: source mode
 **/
typedef enum {
	NM_SETTING_MACVLAN_MODE_UNKNOWN   = 0,
	NM_SETTING_MACVLAN_MODE_VEPA      = 1,
	NM_SETTING_MACVLAN_MODE_BRIDGE    = 2,
	NM_SETTING_MACVLAN_MODE_PRIVATE   = 3,
	NM_SETTING_MACVLAN_MODE_PASSTHRU  = 4,
	NM_SETTING_MACVLAN_MODE_SOURCE    = 5,
	_NM_SETTING_MACVLAN_MODE_NUM,     /*< skip >*/
	NM_SETTING_MACVLAN_MODE_LAST      = _NM_SETTING_MACVLAN_MODE_NUM - 1, /*< skip >*/
} NMSettingMacvlanMode;

NM_AVAILABLE_IN_1_2
GType nm_setting_macvlan_get_type (void);
NM_AVAILABLE_IN_1_2
NMSetting *nm_setting_macvlan_new (void);

NM_AVAILABLE_IN_1_2
const char          *nm_setting_macvlan_get_parent (NMSettingMacvlan *setting);
NM_AVAILABLE_IN_1_2
NMSettingMacvlanMode nm_setting_macvlan_get_mode (NMSettingMacvlan *setting);
NM_AVAILABLE_IN_1_2
gboolean             nm_setting_macvlan_get_promiscuous (NMSettingMacvlan *setting);
NM_AVAILABLE_IN_1_2
gboolean             nm_setting_macvlan_get_tap (NMSettingMacvlan *setting);

G_END_DECLS

#endif /* __NM_SETTING_MACVLAN_H__ */
