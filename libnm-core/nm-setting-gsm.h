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
 * Copyright 2007 - 2011 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_GSM_H
#define NM_SETTING_GSM_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GSM            (nm_setting_gsm_get_type ())
#define NM_SETTING_GSM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_GSM, NMSettingGsm))
#define NM_SETTING_GSM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_GSM, NMSettingGsmClass))
#define NM_IS_SETTING_GSM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_GSM))
#define NM_IS_SETTING_GSM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_GSM))
#define NM_SETTING_GSM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_GSM, NMSettingGsmClass))

#define NM_SETTING_GSM_SETTING_NAME "gsm"

/**
 * NMSettingGsmError:
 * @NM_SETTING_GSM_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_GSM_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_GSM_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 * @NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING: the required #NMSettingSerial
 * is missing in the connection
 */
typedef enum {
	NM_SETTING_GSM_ERROR_UNKNOWN = 0,           /*< nick=UnknownError >*/
	NM_SETTING_GSM_ERROR_INVALID_PROPERTY,      /*< nick=InvalidProperty >*/
	NM_SETTING_GSM_ERROR_MISSING_PROPERTY,      /*< nick=MissingProperty >*/
	NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING /*< nick=MissingSerialSetting >*/
} NMSettingGsmError;

#define NM_SETTING_GSM_ERROR nm_setting_gsm_error_quark ()
GQuark nm_setting_gsm_error_quark (void);

#define NM_SETTING_GSM_NUMBER         "number"
#define NM_SETTING_GSM_USERNAME       "username"
#define NM_SETTING_GSM_PASSWORD       "password"
#define NM_SETTING_GSM_PASSWORD_FLAGS "password-flags"
#define NM_SETTING_GSM_APN            "apn"
#define NM_SETTING_GSM_NETWORK_ID     "network-id"
#define NM_SETTING_GSM_PIN            "pin"
#define NM_SETTING_GSM_PIN_FLAGS      "pin-flags"
#define NM_SETTING_GSM_HOME_ONLY      "home-only"

/* Deprecated */
#define NM_SETTING_GSM_ALLOWED_BANDS  "allowed-bands"
#define NM_SETTING_GSM_NETWORK_TYPE   "network-type"

/**
 * NMSettingGsmNetworkType:
 * @NM_SETTING_GSM_NETWORK_TYPE_ANY: any access technology may be used
 * @NM_SETTING_GSM_NETWORK_TYPE_UMTS_HSPA: only 3G-type (UMTS and HSPA)
 * technologies may be used
 * @NM_SETTING_GSM_NETWORK_TYPE_GPRS_EDGE: only 2G-type (GPRS and EDGE)
 * technologies may be used
 * @NM_SETTING_GSM_NETWORK_TYPE_PREFER_UMTS_HSPA: 3G-type technologies are
 * preferred but 2G-type technologies may be used as a fallback
 * @NM_SETTING_GSM_NETWORK_TYPE_PREFER_GPRS_EDGE: 2G-type technologies are
 * preferred but 3G-type technologies may be used as a fallback
 * @NM_SETTING_GSM_NETWORK_TYPE_PREFER_4G: 4G/LTE-type technologies are
 * preferred but 3G/2/-type technologies may be used as a fallback
 * @NM_SETTING_GSM_NETWORK_TYPE_4G: only 4G/LTE type
 * technologies may be used
 *
 * #NMSettingGsmNetworkType values indicate the allowed access technologies
 * the device may use when connecting to this network.
 *
 * Deprecated: 0.9.10: No longer used.
 */
typedef enum {
	NM_SETTING_GSM_NETWORK_TYPE_ANY = -1,
	NM_SETTING_GSM_NETWORK_TYPE_UMTS_HSPA = 0,
	NM_SETTING_GSM_NETWORK_TYPE_GPRS_EDGE = 1,
	NM_SETTING_GSM_NETWORK_TYPE_PREFER_UMTS_HSPA = 2,
	NM_SETTING_GSM_NETWORK_TYPE_PREFER_GPRS_EDGE = 3,
	NM_SETTING_GSM_NETWORK_TYPE_PREFER_4G = 4,
	NM_SETTING_GSM_NETWORK_TYPE_4G = 5
} NMSettingGsmNetworkType;

/**
 * NMSettingGsmNetworkBand:
 * @NM_SETTING_GSM_BAND_UNKNOWN: unknown or no band specified
 * @NM_SETTING_GSM_BAND_ANY: any band is allowed
 * @NM_SETTING_GSM_BAND_EGSM: 900 MHz original GSM band
 * @NM_SETTING_GSM_BAND_DCS: 1800 MHz DCS band
 * @NM_SETTING_GSM_BAND_PCS: US 1900 MHz PCS band
 * @NM_SETTING_GSM_BAND_G850: US 850 MHz Cellular band
 * @NM_SETTING_GSM_BAND_U2100: WCDMA 3GPP UMTS 2100 MHz (Class I)
 * @NM_SETTING_GSM_BAND_U1800: WCDMA 3GPP UMTS 1800 MHz (Class III)
 * @NM_SETTING_GSM_BAND_U17IV: WCDMA 3GPP AWS 1700/2100 MHz (Class IV)
 * @NM_SETTING_GSM_BAND_U800: WCDMA 3GPP UMTS 800 MHz (Class VI)
 * @NM_SETTING_GSM_BAND_U850: WCDMA 3GPP UMTS 850 MHz (Class V)
 * @NM_SETTING_GSM_BAND_U900: WCDMA 3GPP UMTS 900 MHz (Class VIII)
 * @NM_SETTING_GSM_BAND_U17IX: WCDMA 3GPP UMTS 1700 MHz (Class IX)
 * @NM_SETTING_GSM_BAND_U1900: WCDMA 3GPP UMTS 1900 MHz (Class II)
 * @NM_SETTING_GSM_BAND_U2600: WCDMA 3GPP UMTS 2600 MHz (Class VII, internal)
 *
 * #NMSettingGsmNetworkBand values indicate the allowed frequency bands
 * the device may use when connecting to this network.
 *
 * Deprecated: 0.9.10: No longer used.
 */
typedef enum {
	NM_SETTING_GSM_BAND_UNKNOWN      = 0x00000000,
	NM_SETTING_GSM_BAND_ANY          = 0x00000001,
	NM_SETTING_GSM_BAND_EGSM         = 0x00000002, /*  900 MHz */
	NM_SETTING_GSM_BAND_DCS          = 0x00000004, /* 1800 MHz */
	NM_SETTING_GSM_BAND_PCS          = 0x00000008, /* 1900 MHz */
	NM_SETTING_GSM_BAND_G850         = 0x00000010, /*  850 MHz */
	NM_SETTING_GSM_BAND_U2100        = 0x00000020, /* WCDMA 3GPP UMTS 2100 MHz     (Class I) */
	NM_SETTING_GSM_BAND_U1800        = 0x00000040, /* WCDMA 3GPP UMTS 1800 MHz     (Class III) */
	NM_SETTING_GSM_BAND_U17IV        = 0x00000080, /* WCDMA 3GPP AWS 1700/2100 MHz (Class IV) */
	NM_SETTING_GSM_BAND_U800         = 0x00000100, /* WCDMA 3GPP UMTS 800 MHz      (Class VI) */
	NM_SETTING_GSM_BAND_U850         = 0x00000200, /* WCDMA 3GPP UMTS 850 MHz      (Class V) */
	NM_SETTING_GSM_BAND_U900         = 0x00000400, /* WCDMA 3GPP UMTS 900 MHz      (Class VIII) */
	NM_SETTING_GSM_BAND_U17IX        = 0x00000800, /* WCDMA 3GPP UMTS 1700 MHz     (Class IX) */
	NM_SETTING_GSM_BAND_U1900        = 0x00001000, /* WCDMA 3GPP UMTS 1900 MHz     (Class II) */
	NM_SETTING_GSM_BAND_U2600        = 0x00002000, /* WCDMA 3GPP UMTS 2600 MHz     (Class VII, internal) */
} NMSettingGsmNetworkBand;

/**
 * NM_SETTING_GSM_BANDS_MAX:
 *
 * #NM_SETTING_GSM_BANDS_MAX macro indicate the maximal value that can be used
 * as the allowed frequency bands (#NMSettingGsm:allowed-bands property).
 *
 * Deprecated: 0.9.10: No longer used.
 */
#define NM_SETTING_GSM_BANDS_MAX (  NM_SETTING_GSM_BAND_UNKNOWN \
                                  | NM_SETTING_GSM_BAND_ANY \
                                  | NM_SETTING_GSM_BAND_EGSM \
                                  | NM_SETTING_GSM_BAND_DCS \
                                  | NM_SETTING_GSM_BAND_PCS \
                                  | NM_SETTING_GSM_BAND_G850 \
                                  | NM_SETTING_GSM_BAND_U2100 \
                                  | NM_SETTING_GSM_BAND_U1800 \
                                  | NM_SETTING_GSM_BAND_U17IV \
                                  | NM_SETTING_GSM_BAND_U800 \
                                  | NM_SETTING_GSM_BAND_U850 \
                                  | NM_SETTING_GSM_BAND_U900 \
                                  | NM_SETTING_GSM_BAND_U17IX \
                                  | NM_SETTING_GSM_BAND_U1900 \
                                  | NM_SETTING_GSM_BAND_U2600)

typedef struct {
	NMSetting parent;
} NMSettingGsm;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingGsmClass;

GType nm_setting_gsm_get_type (void);

NMSetting *nm_setting_gsm_new                (void);
const char *nm_setting_gsm_get_number        (NMSettingGsm *setting);
const char *nm_setting_gsm_get_username      (NMSettingGsm *setting);
const char *nm_setting_gsm_get_password      (NMSettingGsm *setting);
const char *nm_setting_gsm_get_apn           (NMSettingGsm *setting);
const char *nm_setting_gsm_get_network_id    (NMSettingGsm *setting);
const char *nm_setting_gsm_get_pin           (NMSettingGsm *setting);
gboolean    nm_setting_gsm_get_home_only     (NMSettingGsm *setting);

NMSettingSecretFlags nm_setting_gsm_get_pin_flags      (NMSettingGsm *setting);
NMSettingSecretFlags nm_setting_gsm_get_password_flags (NMSettingGsm *setting);

/* Deprecated */
NM_DEPRECATED_IN_0_9_10
int     nm_setting_gsm_get_network_type  (NMSettingGsm *setting);
NM_DEPRECATED_IN_0_9_10
guint32 nm_setting_gsm_get_allowed_bands (NMSettingGsm *setting);

G_END_DECLS

#endif /* NM_SETTING_GSM_H */
