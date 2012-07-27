/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Bastien Nocera <hadess@hadess.net>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_BLUETOOTH_H
#define NM_SETTING_BLUETOOTH_H

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BLUETOOTH            (nm_setting_bluetooth_get_type ())
#define NM_SETTING_BLUETOOTH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetooth))
#define NM_SETTING_BLUETOOTH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothClass))
#define NM_IS_SETTING_BLUETOOTH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BLUETOOTH))
#define NM_IS_SETTING_BLUETOOTH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BLUETOOTH))
#define NM_SETTING_BLUETOOTH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothClass))

#define NM_SETTING_BLUETOOTH_SETTING_NAME "bluetooth"

/**
 * NMSettingBluetoothError:
 * @NM_SETTING_BLUETOOTH_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 * @NM_SETTING_BLUETOOTH_ERROR_TYPE_SETTING_NOT_FOUND: the connection
 * did not contain a required type setting, ie for DUN connections the connection
 * must also contain an #NMSettingGsm or #NMSettingCdma as appropriate
 */
typedef enum {
	NM_SETTING_BLUETOOTH_ERROR_UNKNOWN = 0,            /*< nick=UnknownError >*/
	NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY,       /*< nick=InvalidProperty >*/
	NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY,       /*< nick=MissingProperty >*/
	NM_SETTING_BLUETOOTH_ERROR_TYPE_SETTING_NOT_FOUND, /*< nick=TypeSettingNotFound >*/
} NMSettingBluetoothError;

#define NM_SETTING_BLUETOOTH_ERROR nm_setting_bluetooth_error_quark ()
GQuark nm_setting_bluetooth_error_quark (void);

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
 * Connection type describing a connection to devices that support the Bluetooth
 * NAP (Network Access Point) protocol, which accepts connections via PANU.
 */
#define NM_SETTING_BLUETOOTH_TYPE_PANU "panu"

typedef struct {
	NMSetting parent;
} NMSettingBluetooth;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingBluetoothClass;

GType nm_setting_bluetooth_get_type (void);

NMSetting *       nm_setting_bluetooth_new                 (void);
const GByteArray *nm_setting_bluetooth_get_bdaddr          (NMSettingBluetooth *setting);
const char *      nm_setting_bluetooth_get_connection_type (NMSettingBluetooth *setting);

G_END_DECLS

#endif /* NM_SETTING_BLUETOOTH_H */
