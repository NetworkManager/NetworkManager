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

#ifndef NM_SETTING_GSM_H
#define NM_SETTING_GSM_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GSM            (nm_setting_gsm_get_type ())
#define NM_SETTING_GSM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_GSM, NMSettingGsm))
#define NM_SETTING_GSM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_GSM, NMSettingGsmClass))
#define NM_IS_SETTING_GSM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_GSM))
#define NM_IS_SETTING_GSM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_GSM))
#define NM_SETTING_GSM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_GSM, NMSettingGsmClass))

#define NM_SETTING_GSM_SETTING_NAME "gsm"

typedef enum
{
	NM_SETTING_GSM_ERROR_UNKNOWN = 0,
	NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
	NM_SETTING_GSM_ERROR_MISSING_PROPERTY,
	NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING
} NMSettingGsmError;

#define NM_TYPE_SETTING_GSM_ERROR (nm_setting_gsm_error_get_type ()) 
GType nm_setting_gsm_error_get_type (void);

#define NM_SETTING_GSM_ERROR nm_setting_gsm_error_quark ()
GQuark nm_setting_gsm_error_quark (void);

#define NM_SETTING_GSM_NUMBER       "number"
#define NM_SETTING_GSM_USERNAME     "username"
#define NM_SETTING_GSM_PASSWORD     "password"
#define NM_SETTING_GSM_APN          "apn"
#define NM_SETTING_GSM_NETWORK_ID   "network-id"
#define NM_SETTING_GSM_NETWORK_TYPE "network-type"
#define NM_SETTING_GSM_BAND         "band"
#define NM_SETTING_GSM_PIN          "pin"
#define NM_SETTING_GSM_PUK          "puk"

enum {
	NM_GSM_NETWORK_ANY = -1,
	NM_GSM_NETWORK_UMTS_HSPA = 0,
	NM_GSM_NETWORK_GPRS_EDGE = 1,
	NM_GSM_NETWORK_PREFER_UMTS_HSPA = 2,
	NM_GSM_NETWORK_PREFER_GPRS_EDGE = 3
};

typedef struct {
	NMSetting parent;
} NMSettingGsm;

typedef struct {
	NMSettingClass parent;
} NMSettingGsmClass;

GType nm_setting_gsm_get_type (void);

NMSetting *nm_setting_gsm_new               (void);
const char *nm_setting_gsm_get_number       (NMSettingGsm *setting);
const char *nm_setting_gsm_get_username     (NMSettingGsm *setting);
const char *nm_setting_gsm_get_password     (NMSettingGsm *setting);
const char *nm_setting_gsm_get_apn          (NMSettingGsm *setting);
const char *nm_setting_gsm_get_network_id   (NMSettingGsm *setting);
int         nm_setting_gsm_get_network_type (NMSettingGsm *setting);
int         nm_setting_gsm_get_band         (NMSettingGsm *setting);
const char *nm_setting_gsm_get_pin          (NMSettingGsm *setting);
const char *nm_setting_gsm_get_puk          (NMSettingGsm *setting);

G_END_DECLS

#endif /* NM_SETTING_GSM_H */
