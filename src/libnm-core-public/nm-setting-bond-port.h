/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NM_SETTING_BOND_PORT_H__
#define __NM_SETTING_BOND_PORT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-setting-bond.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BOND_PORT (nm_setting_bond_port_get_type())
#define NM_SETTING_BOND_PORT(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_BOND_PORT, NMSettingBondPort))
#define NM_SETTING_BOND_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_BOND_PORT, NMSettingBondPortClass))
#define NM_IS_SETTING_BOND_PORT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_BOND_PORT))
#define NM_IS_SETTING_BOND_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_BOND_PORT))
#define NM_SETTING_BOND_PORT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_BOND_PORT, NMSettingBondPortClass))

#define NM_SETTING_BOND_PORT_SETTING_NAME "bond-port"

#define NM_SETTING_BOND_PORT_QUEUE_ID "queue-id"

typedef struct _NMSettingBondPortClass NMSettingBondPortClass;

NM_AVAILABLE_IN_1_34
GType nm_setting_bond_port_get_type(void);

NM_AVAILABLE_IN_1_34
NMSetting *nm_setting_bond_port_new(void);

NM_AVAILABLE_IN_1_34
guint32 nm_setting_bond_port_get_queue_id(NMSettingBondPort *setting);

G_END_DECLS

#endif /* __NM_SETTING_BOND_PORT_H__ */
