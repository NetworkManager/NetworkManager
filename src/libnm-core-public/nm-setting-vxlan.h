/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_SETTING_VXLAN_H__
#define __NM_SETTING_VXLAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VXLAN (nm_setting_vxlan_get_type())
#define NM_SETTING_VXLAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_VXLAN, NMSettingVxlan))
#define NM_SETTING_VXLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_VXLANCONFIG, NMSettingVxlanClass))
#define NM_IS_SETTING_VXLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_VXLAN))
#define NM_IS_SETTING_VXLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_VXLAN))
#define NM_SETTING_VXLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_VXLAN, NMSettingVxlanClass))

#define NM_SETTING_VXLAN_SETTING_NAME "vxlan"

#define NM_SETTING_VXLAN_PARENT           "parent"
#define NM_SETTING_VXLAN_ID               "id"
#define NM_SETTING_VXLAN_LOCAL            "local"
#define NM_SETTING_VXLAN_REMOTE           "remote"
#define NM_SETTING_VXLAN_SOURCE_PORT_MIN  "source-port-min"
#define NM_SETTING_VXLAN_SOURCE_PORT_MAX  "source-port-max"
#define NM_SETTING_VXLAN_DESTINATION_PORT "destination-port"
#define NM_SETTING_VXLAN_TOS              "tos"
#define NM_SETTING_VXLAN_TTL              "ttl"
#define NM_SETTING_VXLAN_AGEING           "ageing"
#define NM_SETTING_VXLAN_LIMIT            "limit"
#define NM_SETTING_VXLAN_PROXY            "proxy"
#define NM_SETTING_VXLAN_LEARNING         "learning"
#define NM_SETTING_VXLAN_RSC              "rsc"
#define NM_SETTING_VXLAN_L2_MISS          "l2-miss"
#define NM_SETTING_VXLAN_L3_MISS          "l3-miss"

typedef struct _NMSettingVxlanClass NMSettingVxlanClass;

NM_AVAILABLE_IN_1_2
GType nm_setting_vxlan_get_type(void);
NM_AVAILABLE_IN_1_2
NMSetting *nm_setting_vxlan_new(void);
NM_AVAILABLE_IN_1_2
const char *nm_setting_vxlan_get_parent(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_id(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_vxlan_get_local(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_vxlan_get_remote(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_source_port_min(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_source_port_max(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_destination_port(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_tos(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_ttl(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_ageing(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
guint nm_setting_vxlan_get_limit(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_vxlan_get_proxy(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_vxlan_get_learning(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_vxlan_get_rsc(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_vxlan_get_l2_miss(NMSettingVxlan *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_vxlan_get_l3_miss(NMSettingVxlan *setting);

G_END_DECLS

#endif /* __NM_SETTING_VXLAN_H__ */
