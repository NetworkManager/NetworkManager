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
 * Copyright 2007 - 2009 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_BLUETOOTH_H__
#define __NM_SETTING_BLUETOOTH_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BLUETOOTH            (nm_setting_bluetooth_get_type ())
#define NM_SETTING_BLUETOOTH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetooth))
#define NM_SETTING_BLUETOOTH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothClass))
#define NM_IS_SETTING_BLUETOOTH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BLUETOOTH))
#define NM_IS_SETTING_BLUETOOTH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BLUETOOTH))
#define NM_SETTING_BLUETOOTH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothClass))

#define NM_SETTING_BLUETOOTH_SETTING_NAME "bluetooth"

#define NM_SETTING_BLUETOOTH_BDADDR    "bdaddr"
#define NM_SETTING_BLUETOOTH_TYPE      "type"

/**
 * NM_SETTING_BLUETOOTH_TYPE_DUN:
 *
 * Connection type describing a connection to devices that support the Bluetooth
 * DUN profile.
 */
#define NM_SETTING_BLUETOOTH_TYPE_DUN  "dun"

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

/**
 * NMSettingBluetooth:
 *
 * Bluetooth Settings
 */
struct _NMSettingBluetooth {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingBluetoothClass;

GType nm_setting_bluetooth_get_type (void);

NMSetting *       nm_setting_bluetooth_new                 (void);
const char *      nm_setting_bluetooth_get_bdaddr          (NMSettingBluetooth *setting);
const char *      nm_setting_bluetooth_get_connection_type (NMSettingBluetooth *setting);

G_END_DECLS

#endif /* __NM_SETTING_BLUETOOTH_H__ */
