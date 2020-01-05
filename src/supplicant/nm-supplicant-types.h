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

/*****************************************************************************/

typedef enum {
	NM_SUPPL_CAP_TYPE_AP = 0,
	NM_SUPPL_CAP_TYPE_FAST,
	NM_SUPPL_CAP_TYPE_PMF,
	NM_SUPPL_CAP_TYPE_FILS,
	NM_SUPPL_CAP_TYPE_P2P,
	NM_SUPPL_CAP_TYPE_MESH,
	NM_SUPPL_CAP_TYPE_WFD,
	NM_SUPPL_CAP_TYPE_FT,
	NM_SUPPL_CAP_TYPE_SHA384,
	_NM_SUPPL_CAP_TYPE_NUM,
} NMSupplCapType;

#define NM_SUPPL_CAP_MASK_NO(type)   ((NMSupplCapMask) (1llu << ((type) * 2u)))
#define NM_SUPPL_CAP_MASK_YES(type)  ((NMSupplCapMask) (2llu << ((type) * 2u)))
#define NM_SUPPL_CAP_MASK_MASK(type) ((NMSupplCapMask) (3llu << ((type) * 2u)))

typedef enum {
	NM_SUPPL_CAP_MASK_NONE = 0,
	NM_SUPPL_CAP_MASK_ALL = ((1llu << (_NM_SUPPL_CAP_TYPE_NUM * 2)) - 1),

/* usually it's bad to use macros to define enum values (because you cannot find them with ctags/cscope
 * anymore. In this case, still do it because the alternative is ugly too. */
#define _NM_SUPPL_CAP_MASK_DEFINE(type) \
	NM_SUPPL_CAP_MASK_T_##type##_NO   =   (1llu << ((NM_SUPPL_CAP_TYPE_##type) * 2u)), \
	NM_SUPPL_CAP_MASK_T_##type##_YES  =   (2llu << ((NM_SUPPL_CAP_TYPE_##type) * 2u)), \
	NM_SUPPL_CAP_MASK_T_##type##_MASK =   (3llu << ((NM_SUPPL_CAP_TYPE_##type) * 2u))
	_NM_SUPPL_CAP_MASK_DEFINE (AP),
	_NM_SUPPL_CAP_MASK_DEFINE (FAST),
	_NM_SUPPL_CAP_MASK_DEFINE (PMF),
	_NM_SUPPL_CAP_MASK_DEFINE (FILS),
	_NM_SUPPL_CAP_MASK_DEFINE (P2P),
	_NM_SUPPL_CAP_MASK_DEFINE (MESH),
	_NM_SUPPL_CAP_MASK_DEFINE (WFD),
	_NM_SUPPL_CAP_MASK_DEFINE (FT),
	_NM_SUPPL_CAP_MASK_DEFINE (SHA384),
#undef _NM_SUPPL_CAP_MASK_DEFINE
} NMSupplCapMask;

static inline NMSupplCapMask
NM_SUPPL_CAP_MASK_SET (NMSupplCapMask features, NMSupplCapType type, NMTernary value)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (type));
	nm_assert (type < _NM_SUPPL_CAP_TYPE_NUM);
	nm_assert (NM_IN_SET (value, NM_TERNARY_DEFAULT,
	                             NM_TERNARY_TRUE,
	                             NM_TERNARY_FALSE));
	nm_assert (!(features & ~NM_SUPPL_CAP_MASK_ALL));

	features &= ~NM_SUPPL_CAP_MASK_MASK (type);
	switch (value) {
	case NM_TERNARY_FALSE:
		features |= NM_SUPPL_CAP_MASK_NO (type);
		break;
	case NM_TERNARY_TRUE:
		features |= NM_SUPPL_CAP_MASK_YES (type);
		break;
	case NM_TERNARY_DEFAULT:
		break;
	}

	return features;
}

static inline NMTernary
NM_SUPPL_CAP_MASK_GET (NMSupplCapMask features, NMSupplCapType type)
{
	int f;

	nm_assert (_NM_INT_NOT_NEGATIVE (type));
	nm_assert (type < _NM_SUPPL_CAP_TYPE_NUM);
	nm_assert (!(features & ~NM_SUPPL_CAP_MASK_ALL));

	f = ((int) (features >> (2 * (int) type))) & 0x3;

	nm_assert (NM_IN_SET (f, 0, 1, 2));

	return (NMTernary) (f - 1);
}

/*****************************************************************************/

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
