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
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_SETTING_OVS_PORT_H__
#define __NM_SETTING_OVS_PORT_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OVS_PORT            (nm_setting_ovs_port_get_type ())
#define NM_SETTING_OVS_PORT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_OVS_PORT, NMSettingOvsPort))
#define NM_SETTING_OVS_PORT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_OVS_PORTCONFIG, NMSettingOvsPortClass))
#define NM_IS_SETTING_OVS_PORT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_OVS_PORT))
#define NM_IS_SETTING_OVS_PORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_OVS_PORT))
#define NM_SETTING_OVS_PORT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_OVS_PORT, NMSettingOvsPortClass))

#define NM_SETTING_OVS_PORT_SETTING_NAME        "ovs-port"

#define NM_SETTING_OVS_PORT_VLAN_MODE           "vlan-mode"
#define NM_SETTING_OVS_PORT_TAG                 "tag"
#define NM_SETTING_OVS_PORT_LACP                "lacp"
#define NM_SETTING_OVS_PORT_BOND_MODE           "bond-mode"
#define NM_SETTING_OVS_PORT_BOND_UPDELAY        "bond-updelay"
#define NM_SETTING_OVS_PORT_BOND_DOWNDELAY      "bond-downdelay"

typedef struct _NMSettingOvsPortClass NMSettingOvsPortClass;

NM_AVAILABLE_IN_1_10
GType nm_setting_ovs_port_get_type (void);
NM_AVAILABLE_IN_1_10
NMSetting *nm_setting_ovs_port_new (void);

NM_AVAILABLE_IN_1_10
const char *nm_setting_ovs_port_get_vlan_mode      (NMSettingOvsPort *self);
NM_AVAILABLE_IN_1_10
guint       nm_setting_ovs_port_get_tag            (NMSettingOvsPort *self);
NM_AVAILABLE_IN_1_10
const char *nm_setting_ovs_port_get_lacp           (NMSettingOvsPort *self);
NM_AVAILABLE_IN_1_10
const char *nm_setting_ovs_port_get_bond_mode      (NMSettingOvsPort *self);
NM_AVAILABLE_IN_1_10
guint       nm_setting_ovs_port_get_bond_updelay   (NMSettingOvsPort *self);
NM_AVAILABLE_IN_1_10
guint       nm_setting_ovs_port_get_bond_downdelay (NMSettingOvsPort *self);

G_END_DECLS

#endif /* __NM_SETTING_OVS_PORT_H__ */
