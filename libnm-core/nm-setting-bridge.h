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
 * Copyright 2011 - 2015 Red Hat, Inc.
 */

#ifndef __NM_SETTING_BRIDGE_H__
#define __NM_SETTING_BRIDGE_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BRIDGE            (nm_setting_bridge_get_type ())
#define NM_SETTING_BRIDGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BRIDGE, NMSettingBridge))
#define NM_SETTING_BRIDGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BRIDGE, NMSettingBridgeClass))
#define NM_IS_SETTING_BRIDGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BRIDGE))
#define NM_IS_SETTING_BRIDGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BRIDGE))
#define NM_SETTING_BRIDGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BRIDGE, NMSettingBridgeClass))

#define NM_SETTING_BRIDGE_SETTING_NAME "bridge"

#define NM_SETTING_BRIDGE_MAC_ADDRESS    "mac-address"
#define NM_SETTING_BRIDGE_STP            "stp"
#define NM_SETTING_BRIDGE_PRIORITY       "priority"
#define NM_SETTING_BRIDGE_FORWARD_DELAY  "forward-delay"
#define NM_SETTING_BRIDGE_HELLO_TIME     "hello-time"
#define NM_SETTING_BRIDGE_MAX_AGE        "max-age"
#define NM_SETTING_BRIDGE_AGEING_TIME    "ageing-time"
#define NM_SETTING_BRIDGE_GROUP_FORWARD_MASK "group-forward-mask"
#define NM_SETTING_BRIDGE_MULTICAST_SNOOPING "multicast-snooping"
#define NM_SETTING_BRIDGE_VLAN_FILTERING     "vlan-filtering"
#define NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID  "vlan-default-pvid"
#define NM_SETTING_BRIDGE_VLANS              "vlans"

#define NM_BRIDGE_VLAN_VID_MIN            1
#define NM_BRIDGE_VLAN_VID_MAX            4094

/**
 * NMSettingBridge:
 *
 * Bridging Settings
 */
struct _NMSettingBridge {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingBridgeClass;

typedef struct _NMBridgeVlan NMBridgeVlan;

GType nm_setting_bridge_get_type (void);

NMSetting *  nm_setting_bridge_new                (void);

const char * nm_setting_bridge_get_mac_address    (NMSettingBridge *setting);

gboolean     nm_setting_bridge_get_stp            (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_priority       (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_forward_delay  (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_hello_time     (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_max_age        (NMSettingBridge *setting);

guint32      nm_setting_bridge_get_ageing_time    (NMSettingBridge *setting);
NM_AVAILABLE_IN_1_10
guint16      nm_setting_bridge_get_group_forward_mask (NMSettingBridge *setting);

gboolean     nm_setting_bridge_get_multicast_snooping (NMSettingBridge *setting);
NM_AVAILABLE_IN_1_18
gboolean     nm_setting_bridge_get_vlan_filtering (NMSettingBridge *setting);
NM_AVAILABLE_IN_1_18
guint16      nm_setting_bridge_get_vlan_default_pvid (NMSettingBridge *setting);
NM_AVAILABLE_IN_1_18
void          nm_setting_bridge_add_vlan (NMSettingBridge *setting,
                                          NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
guint         nm_setting_bridge_get_num_vlans (NMSettingBridge *setting);
NM_AVAILABLE_IN_1_18
NMBridgeVlan *nm_setting_bridge_get_vlan (NMSettingBridge *setting, guint idx);
NM_AVAILABLE_IN_1_18
void          nm_setting_bridge_remove_vlan (NMSettingBridge *setting, guint idx);
NM_AVAILABLE_IN_1_18
gboolean      nm_setting_bridge_remove_vlan_by_vid (NMSettingBridge *setting,
                                                    guint16 vid_start,
                                                    guint16 vid_end);
NM_AVAILABLE_IN_1_18
void          nm_setting_bridge_clear_vlans (NMSettingBridge *setting);

NM_AVAILABLE_IN_1_18
GType          nm_bridge_vlan_get_type (void);
NM_AVAILABLE_IN_1_18
NMBridgeVlan * nm_bridge_vlan_new (guint16 vid_start, guint16 vid_end);
NM_AVAILABLE_IN_1_18
NMBridgeVlan * nm_bridge_vlan_ref (NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
void           nm_bridge_vlan_unref (NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
NMBridgeVlan * nm_bridge_vlan_new_clone (const NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
int            nm_bridge_vlan_cmp (const NMBridgeVlan *a, const NMBridgeVlan *b);
NM_AVAILABLE_IN_1_18
void           nm_bridge_vlan_seal (NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
gboolean       nm_bridge_vlan_is_sealed (const NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
void           nm_bridge_vlan_set_untagged (NMBridgeVlan *vlan, gboolean value);
NM_AVAILABLE_IN_1_18
void           nm_bridge_vlan_set_pvid (NMBridgeVlan *vlan, gboolean value);
NM_AVAILABLE_IN_1_18
gboolean       nm_bridge_vlan_get_vid_range (const NMBridgeVlan *vlan, guint16 *vid_start, guint16 *vid_end);
NM_AVAILABLE_IN_1_18
gboolean       nm_bridge_vlan_is_untagged (const NMBridgeVlan *vlan);
NM_AVAILABLE_IN_1_18
gboolean       nm_bridge_vlan_is_pvid (const NMBridgeVlan *vlan);

NM_AVAILABLE_IN_1_18
char         * nm_bridge_vlan_to_str (const NMBridgeVlan *vlan, GError **error);
NM_AVAILABLE_IN_1_18
NMBridgeVlan * nm_bridge_vlan_from_str (const char *str, GError **error);

G_END_DECLS

#endif /* __NM_SETTING_BRIDGE_H__ */
