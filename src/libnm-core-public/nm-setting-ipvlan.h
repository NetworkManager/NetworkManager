/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#ifndef __NM_SETTING_IPVLAN_H__
#define __NM_SETTING_IPVLAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IPVLAN (nm_setting_ipvlan_get_type())
#define NM_SETTING_IPVLAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_IPVLAN, NMSettingIpvlan))
#define NM_IS_SETTING_IPVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_IPVLAN))
#define NM_IS_SETTING_IPVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_IPVLAN))
#define NM_SETTING_IPVLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_IPVLAN, NMSettingIpvlanClass))

#define NM_SETTING_IPVLAN_SETTING_NAME "ipvlan"

#define NM_SETTING_IPVLAN_PARENT  "parent"
#define NM_SETTING_IPVLAN_MODE    "mode"
#define NM_SETTING_IPVLAN_PRIVATE "private"
#define NM_SETTING_IPVLAN_VEPA    "vepa"

typedef struct _NMSettingIpvlanClass NMSettingIpvlanClass;

/**
 * NMSettingIpvlanMode:
 * @NM_SETTING_IPVLAN_MODE_UNKNOWN: unknown/unset mode
 * @NM_SETTING_IPVLAN_MODE_L2:  L2 mode, device receives and responds to ARP.
 * @NM_SETTING_IPVLAN_MODE_L3:  L3 mode, device process only L3 traffic and above.
 * @NM_SETTING_IPVLAN_MODE_L3S: L3S mode, same way as L3 mode but egress and ingress
 * lands on netfilter chain.
 *
 * Since: 1.52
 **/
typedef enum {
    NM_SETTING_IPVLAN_MODE_UNKNOWN = 0,
    NM_SETTING_IPVLAN_MODE_L2      = 1,
    NM_SETTING_IPVLAN_MODE_L3      = 2,
    NM_SETTING_IPVLAN_MODE_L3S     = 3,
    _NM_SETTING_IPVLAN_MODE_NUM,                                   /*< skip >*/
    NM_SETTING_IPVLAN_MODE_LAST = _NM_SETTING_IPVLAN_MODE_NUM - 1, /*< skip >*/
} NMSettingIpvlanMode;

NM_AVAILABLE_IN_1_52
GType nm_setting_ipvlan_get_type(void);
NM_AVAILABLE_IN_1_52
NMSetting *nm_setting_ipvlan_new(void);

NM_AVAILABLE_IN_1_52
const char *nm_setting_ipvlan_get_parent(NMSettingIpvlan *setting);
NM_AVAILABLE_IN_1_52
NMSettingIpvlanMode nm_setting_ipvlan_get_mode(NMSettingIpvlan *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_ipvlan_get_private(NMSettingIpvlan *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_ipvlan_get_vepa(NMSettingIpvlan *setting);

G_END_DECLS

#endif /* __NM_SETTING_IPVLAN_H__ */
