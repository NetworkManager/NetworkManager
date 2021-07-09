/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_SETTING_OVS_BRIDGE_H__
#define __NM_SETTING_OVS_BRIDGE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OVS_BRIDGE (nm_setting_ovs_bridge_get_type())
#define NM_SETTING_OVS_BRIDGE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_OVS_BRIDGE, NMSettingOvsBridge))
#define NM_SETTING_OVS_BRIDGE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_OVS_BRIDGECONFIG, NMSettingOvsBridgeClass))
#define NM_IS_SETTING_OVS_BRIDGE(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_OVS_BRIDGE))
#define NM_IS_SETTING_OVS_BRIDGE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_OVS_BRIDGE))
#define NM_SETTING_OVS_BRIDGE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_OVS_BRIDGE, NMSettingOvsBridgeClass))

#define NM_SETTING_OVS_BRIDGE_SETTING_NAME "ovs-bridge"

#define NM_SETTING_OVS_BRIDGE_FAIL_MODE             "fail-mode"
#define NM_SETTING_OVS_BRIDGE_MCAST_SNOOPING_ENABLE "mcast-snooping-enable"
#define NM_SETTING_OVS_BRIDGE_RSTP_ENABLE           "rstp-enable"
#define NM_SETTING_OVS_BRIDGE_STP_ENABLE            "stp-enable"
#define NM_SETTING_OVS_BRIDGE_DATAPATH_TYPE         "datapath-type"

typedef struct _NMSettingOvsBridgeClass NMSettingOvsBridgeClass;

NM_AVAILABLE_IN_1_10
GType nm_setting_ovs_bridge_get_type(void);
NM_AVAILABLE_IN_1_10
NMSetting *nm_setting_ovs_bridge_new(void);

NM_AVAILABLE_IN_1_10
const char *nm_setting_ovs_bridge_get_fail_mode(NMSettingOvsBridge *self);
NM_AVAILABLE_IN_1_10
gboolean nm_setting_ovs_bridge_get_mcast_snooping_enable(NMSettingOvsBridge *self);
NM_AVAILABLE_IN_1_10
gboolean nm_setting_ovs_bridge_get_rstp_enable(NMSettingOvsBridge *self);
NM_AVAILABLE_IN_1_10
gboolean nm_setting_ovs_bridge_get_stp_enable(NMSettingOvsBridge *self);
NM_AVAILABLE_IN_1_20
const char *nm_setting_ovs_bridge_get_datapath_type(NMSettingOvsBridge *self);

G_END_DECLS

#endif /* __NM_SETTING_OVS_BRIDGE_H__ */
