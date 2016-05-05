/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2007 - 2008 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_SERIAL_H__
#define __NM_SETTING_SERIAL_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_SERIAL            (nm_setting_serial_get_type ())
#define NM_SETTING_SERIAL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_SERIAL, NMSettingSerial))
#define NM_SETTING_SERIAL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_SERIAL, NMSettingSerialClass))
#define NM_IS_SETTING_SERIAL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_SERIAL))
#define NM_IS_SETTING_SERIAL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_SERIAL))
#define NM_SETTING_SERIAL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_SERIAL, NMSettingSerialClass))

#define NM_SETTING_SERIAL_SETTING_NAME "serial"

/**
 * NMSettingSerialParity:
 * @NM_SETTING_SERIAL_PARITY_NONE: No parity bits (default)
 * @NM_SETTING_SERIAL_PARITY_EVEN: Even parity
 * @NM_SETTING_SERIAL_PARITY_ODD: Odd parity
 *
 * The parity setting of a serial port.
 */
typedef enum {
	NM_SETTING_SERIAL_PARITY_NONE = 0,
	NM_SETTING_SERIAL_PARITY_EVEN,
	NM_SETTING_SERIAL_PARITY_ODD
} NMSettingSerialParity;

#define NM_SETTING_SERIAL_BAUD "baud"
#define NM_SETTING_SERIAL_BITS "bits"
#define NM_SETTING_SERIAL_PARITY "parity"
#define NM_SETTING_SERIAL_STOPBITS "stopbits"
#define NM_SETTING_SERIAL_SEND_DELAY "send-delay"

/**
 * NMSettingSerial:
 */
struct _NMSettingSerial {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingSerialClass;

GType nm_setting_serial_get_type (void);

NMSetting             *nm_setting_serial_new            (void);
guint                  nm_setting_serial_get_baud       (NMSettingSerial *setting);
guint                  nm_setting_serial_get_bits       (NMSettingSerial *setting);
NMSettingSerialParity  nm_setting_serial_get_parity     (NMSettingSerial *setting);
guint                  nm_setting_serial_get_stopbits   (NMSettingSerial *setting);
guint64                nm_setting_serial_get_send_delay (NMSettingSerial *setting);

G_END_DECLS

#endif /* __NM_SETTING_SERIAL_H__ */
