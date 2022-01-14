/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2009 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_BLUETOOTH_H__
#define __NM_SETTING_BLUETOOTH_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BLUETOOTH (nm_setting_bluetooth_get_type())
#define NM_SETTING_BLUETOOTH(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetooth))
#define NM_SETTING_BLUETOOTH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothClass))
#define NM_IS_SETTING_BLUETOOTH(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_BLUETOOTH))
#define NM_IS_SETTING_BLUETOOTH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_BLUETOOTH))
#define NM_SETTING_BLUETOOTH_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothClass))

#define NM_SETTING_BLUETOOTH_SETTING_NAME "bluetooth"

#define NM_SETTING_BLUETOOTH_BDADDR "bdaddr"
#define NM_SETTING_BLUETOOTH_TYPE   "type"

/**
 * NM_SETTING_BLUETOOTH_TYPE_DUN:
 *
 * Connection type describing a connection to devices that support the Bluetooth
 * DUN profile.
 */
#define NM_SETTING_BLUETOOTH_TYPE_DUN "dun"

/**
 * NM_SETTING_BLUETOOTH_TYPE_PANU:
 *
 * Connection type describing PANU connection to a Bluetooth NAP (Network
 * Access Point).
 */
#define NM_SETTING_BLUETOOTH_TYPE_PANU "panu"

/**
 * NM_SETTING_BLUETOOTH_TYPE_NAP:
 *
 * Connection type describing a Bluetooth NAP (Network Access Point),
 * which accepts PANU clients.
 */
#define NM_SETTING_BLUETOOTH_TYPE_NAP "nap"

typedef struct _NMSettingBluetoothClass NMSettingBluetoothClass;

GType nm_setting_bluetooth_get_type(void);

NMSetting  *nm_setting_bluetooth_new(void);
const char *nm_setting_bluetooth_get_bdaddr(NMSettingBluetooth *setting);
const char *nm_setting_bluetooth_get_connection_type(NMSettingBluetooth *setting);

G_END_DECLS

#endif /* __NM_SETTING_BLUETOOTH_H__ */
