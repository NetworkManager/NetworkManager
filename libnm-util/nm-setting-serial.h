/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_SERIAL_H
#define NM_SETTING_SERIAL_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_SERIAL            (nm_setting_serial_get_type ())
#define NM_SETTING_SERIAL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_SERIAL, NMSettingSerial))
#define NM_SETTING_SERIAL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_SERIAL, NMSettingSerialClass))
#define NM_IS_SETTING_SERIAL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_SERIAL))
#define NM_IS_SETTING_SERIAL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_SERIAL))
#define NM_SETTING_SERIAL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_SERIAL, NMSettingSerialClass))

#define NM_SETTING_SERIAL_SETTING_NAME "serial"

typedef enum
{
	NM_SETTING_SERIAL_ERROR_UNKNOWN = 0,
	NM_SETTING_SERIAL_ERROR_INVALID_PROPERTY,
	NM_SETTING_SERIAL_ERROR_MISSING_PROPERTY,
	NM_SETTING_SERIAL_ERROR_MISSING_PPP_SETTING
} NMSettingSerialError;

#define NM_TYPE_SETTING_SERIAL_ERROR (nm_setting_serial_error_get_type ()) 
GType nm_setting_serial_error_get_type (void);

#define NM_SETTING_SERIAL_ERROR nm_setting_serial_error_quark ()
GQuark nm_setting_serial_error_quark (void);

#define NM_SETTING_SERIAL_BAUD "baud"
#define NM_SETTING_SERIAL_BITS "bits"
#define NM_SETTING_SERIAL_PARITY "parity"
#define NM_SETTING_SERIAL_STOPBITS "stopbits"
#define NM_SETTING_SERIAL_SEND_DELAY "send-delay"

typedef struct {
	NMSetting parent;
} NMSettingSerial;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingSerialClass;

GType nm_setting_serial_get_type (void);

NMSetting *nm_setting_serial_new            (void);
guint      nm_setting_serial_get_baud       (NMSettingSerial *setting);
guint      nm_setting_serial_get_bits       (NMSettingSerial *setting);
char       nm_setting_serial_get_parity     (NMSettingSerial *setting);
guint      nm_setting_serial_get_stopbits   (NMSettingSerial *setting);
guint64    nm_setting_serial_get_send_delay (NMSettingSerial *setting);

G_END_DECLS

#endif /* NM_SETTING_SERIAL_H */
