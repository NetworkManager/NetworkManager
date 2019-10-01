// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_TYPES_H__
#define __NETWORKMANAGER_SUPPLICANT_TYPES_H__

#define WPAS_DBUS_SERVICE       "fi.w1.wpa_supplicant1"
#define WPAS_DBUS_PATH          "/fi/w1/wpa_supplicant1"
#define WPAS_DBUS_INTERFACE     "fi.w1.wpa_supplicant1"

typedef struct _NMSupplicantManager NMSupplicantManager;
typedef struct _NMSupplicantInterface NMSupplicantInterface;
typedef struct _NMSupplicantConfig NMSupplicantConfig;

typedef enum {
	NM_SUPPLICANT_FEATURE_UNKNOWN = 0,  /* Can't detect whether supported or not */
	NM_SUPPLICANT_FEATURE_NO = 1,       /* Feature definitely not supported */
	NM_SUPPLICANT_FEATURE_YES = 2,      /* Feature definitely supported */
} NMSupplicantFeature;

/**
 * NMSupplicantError:
 * @NM_SUPPLICANT_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SUPPLICANT_ERROR_CONFIG: a failure constructing the
 *   wpa-supplicant configuration.
 */
typedef enum {
	NM_SUPPLICANT_ERROR_UNKNOWN = 0,                    /*< nick=Unknown >*/
	NM_SUPPLICANT_ERROR_CONFIG = 1,                     /*< nick=Config >*/
} NMSupplicantError;

typedef enum {
	NM_SUPPLICANT_DRIVER_WIRELESS,
	NM_SUPPLICANT_DRIVER_WIRED,
	NM_SUPPLICANT_DRIVER_MACSEC,
} NMSupplicantDriver;

#define NM_SUPPLICANT_ERROR (nm_supplicant_error_quark ())
GQuark nm_supplicant_error_quark (void);

#endif  /* NM_SUPPLICANT_TYPES_H */
