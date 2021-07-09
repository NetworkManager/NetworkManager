/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_SETTING_OVS_INTERFACE_H__
#define __NM_SETTING_OVS_INTERFACE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OVS_INTERFACE (nm_setting_ovs_interface_get_type())
#define NM_SETTING_OVS_INTERFACE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_OVS_INTERFACE, NMSettingOvsInterface))
#define NM_SETTING_OVS_INTERFACE_CLASS(klass)                     \
    (G_TYPE_CHECK_CLASS_CAST((klass),                             \
                             NM_TYPE_SETTING_OVS_INTERFACECONFIG, \
                             NMSettingOvsInterfaceClass))
#define NM_IS_SETTING_OVS_INTERFACE(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_OVS_INTERFACE))
#define NM_IS_SETTING_OVS_INTERFACE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_OVS_INTERFACE))
#define NM_SETTING_OVS_INTERFACE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_OVS_INTERFACE, NMSettingOvsInterfaceClass))

#define NM_SETTING_OVS_INTERFACE_SETTING_NAME "ovs-interface"

#define NM_SETTING_OVS_INTERFACE_TYPE "type"

typedef struct _NMSettingOvsInterfaceClass NMSettingOvsInterfaceClass;

NM_AVAILABLE_IN_1_10
GType nm_setting_ovs_interface_get_type(void);
NM_AVAILABLE_IN_1_10
NMSetting *nm_setting_ovs_interface_new(void);

NM_AVAILABLE_IN_1_10
const char *nm_setting_ovs_interface_get_interface_type(NMSettingOvsInterface *self);

G_END_DECLS

#endif /* __NM_SETTING_OVS_INTERFACE_H__ */
