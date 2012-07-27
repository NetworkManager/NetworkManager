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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_CDMA_H
#define NM_SETTING_CDMA_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CDMA            (nm_setting_cdma_get_type ())
#define NM_SETTING_CDMA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_CDMA, NMSettingCdma))
#define NM_SETTING_CDMA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))
#define NM_IS_SETTING_CDMA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_CDMA))
#define NM_IS_SETTING_CDMA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_CDMA))
#define NM_SETTING_CDMA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))

#define NM_SETTING_CDMA_SETTING_NAME "cdma"

/**
 * NMSettingCdmaError:
 * @NM_SETTING_CDMA_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_CDMA_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_CDMA_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 * @NM_SETTING_CDMA_ERROR_MISSING_SERIAL_SETTING: the required #NMSettingSerial
 * is missing in the connection
 */
typedef enum {
	NM_SETTING_CDMA_ERROR_UNKNOWN = 0,           /*< nick=UnknownError >*/
	NM_SETTING_CDMA_ERROR_INVALID_PROPERTY,      /*< nick=InvalidProperty >*/
	NM_SETTING_CDMA_ERROR_MISSING_PROPERTY,      /*< nick=MissingProperty >*/
	NM_SETTING_CDMA_ERROR_MISSING_SERIAL_SETTING /*< nick=MissingSerialSetting >*/
} NMSettingCdmaError;

#define NM_SETTING_CDMA_ERROR nm_setting_cdma_error_quark ()
GQuark nm_setting_cdma_error_quark (void);

#define NM_SETTING_CDMA_NUMBER         "number"
#define NM_SETTING_CDMA_USERNAME       "username"
#define NM_SETTING_CDMA_PASSWORD       "password"
#define NM_SETTING_CDMA_PASSWORD_FLAGS "password-flags"

typedef struct {
	NMSetting parent;
} NMSettingCdma;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingCdmaClass;

GType nm_setting_cdma_get_type (void);

NMSetting  *nm_setting_cdma_new          (void);
const char *nm_setting_cdma_get_number   (NMSettingCdma *setting);
const char *nm_setting_cdma_get_username (NMSettingCdma *setting);
const char *nm_setting_cdma_get_password (NMSettingCdma *setting);
NMSettingSecretFlags nm_setting_cdma_get_password_flags (NMSettingCdma *setting);

G_END_DECLS

#endif /* NM_SETTING_CDMA_H */
