/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NM_SETTING_BRIDGE_PORT_H__
#define __NM_SETTING_BRIDGE_PORT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-setting-bridge.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BRIDGE_PORT (nm_setting_bridge_port_get_type())
#define NM_SETTING_BRIDGE_PORT(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePort))
#define NM_SETTING_BRIDGE_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortClass))
#define NM_IS_SETTING_BRIDGE_PORT(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_BRIDGE_PORT))
#define NM_IS_SETTING_BRIDGE_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_BRIDGE_PORT))
#define NM_SETTING_BRIDGE_PORT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortClass))

#define NM_SETTING_BRIDGE_PORT_SETTING_NAME "bridge-port"

#define NM_SETTING_BRIDGE_PORT_PRIORITY               "priority"
#define NM_SETTING_BRIDGE_PORT_PATH_COST              "path-cost"
#define NM_SETTING_BRIDGE_PORT_BPDU_GUARD             "bpdu-guard"
#define NM_SETTING_BRIDGE_PORT_BROADCAST_FLOOD        "broadcast-flood"
#define NM_SETTING_BRIDGE_PORT_FAST_LEAVE             "fast-leave"
#define NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE           "hairpin-mode"
#define NM_SETTING_BRIDGE_PORT_ISOLATED               "isolated"
#define NM_SETTING_BRIDGE_PORT_LEARNING               "learning"
#define NM_SETTING_BRIDGE_PORT_LOCKED                 "locked"
#define NM_SETTING_BRIDGE_PORT_MULTICAST_FLOOD        "multicast-flood"
#define NM_SETTING_BRIDGE_PORT_MULTICAST_TO_UNICAST   "multicast-to-unicast"
#define NM_SETTING_BRIDGE_PORT_NEIGHBOR_SUPPRESS      "neighbor-suppress"
#define NM_SETTING_BRIDGE_PORT_NEIGHBOR_VLAN_SUPPRESS "neighbor-vlan-suppress"
#define NM_SETTING_BRIDGE_PORT_ROOT_BLOCK             "root-block"
#define NM_SETTING_BRIDGE_PORT_UNICAST_FLOOD          "unicast-flood"
#define NM_SETTING_BRIDGE_PORT_VLAN_TUNNEL            "vlan-tunnel"
#define NM_SETTING_BRIDGE_PORT_VLANS                  "vlans"

typedef struct _NMSettingBridgePortClass NMSettingBridgePortClass;

GType nm_setting_bridge_port_get_type(void);

NMSetting *nm_setting_bridge_port_new(void);

guint16 nm_setting_bridge_port_get_priority(NMSettingBridgePort *setting);

guint16 nm_setting_bridge_port_get_path_cost(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_bpdu_guard(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_broadcast_flood(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_fast_leave(NMSettingBridgePort *setting);

gboolean nm_setting_bridge_port_get_hairpin_mode(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_isolated(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_learning(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_locked(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_multicast_flood(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_multicast_to_unicast(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_neighbor_suppress(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_neighbor_vlan_suppress(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_root_block(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_unicast_flood(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_60
gboolean nm_setting_bridge_port_get_vlan_tunnel(NMSettingBridgePort *setting);

NM_AVAILABLE_IN_1_18
void nm_setting_bridge_port_add_vlan(NMSettingBridgePort *setting, NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
guint nm_setting_bridge_port_get_num_vlans(NMSettingBridgePort *setting);
NM_AVAILABLE_IN_1_18
NMBridgeVlan *nm_setting_bridge_port_get_vlan(NMSettingBridgePort *setting, guint idx);
NM_AVAILABLE_IN_1_18
void nm_setting_bridge_port_remove_vlan(NMSettingBridgePort *setting, guint idx);
NM_AVAILABLE_IN_1_18
gboolean nm_setting_bridge_port_remove_vlan_by_vid(NMSettingBridgePort *setting,
                                                   guint16              vid_start,
                                                   guint16              vid_end);
NM_AVAILABLE_IN_1_18
void nm_setting_bridge_port_clear_vlans(NMSettingBridgePort *setting);

G_END_DECLS

#endif /* __NM_SETTING_BRIDGE_PORT_H__ */
