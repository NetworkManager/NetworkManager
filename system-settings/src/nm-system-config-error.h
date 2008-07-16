/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SYSTEM_CONFIG_ERROR_H
#define NM_SYSTEM_CONFIG_ERROR_H

#include <glib/gtypes.h>
#include <glib-object.h>

enum {
	NM_SYSCONFIG_SETTINGS_ERROR_GENERAL = 0,
	NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
	NM_SYSCONFIG_SETTINGS_ERROR_INVALID_CONNECTION,
	NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED,
	NM_SYSCONFIG_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED,
	NM_SYSCONFIG_SETTINGS_ERROR_DELETE_NOT_SUPPORTED,
	NM_SYSCONFIG_SETTINGS_ERROR_ADD_FAILED
};

#define NM_SYSCONFIG_SETTINGS_ERROR (nm_sysconfig_settings_error_quark ())
#define NM_TYPE_SYSCONFIG_SETTINGS_ERROR (nm_sysconfig_settings_error_get_type ())

GQuark nm_sysconfig_settings_error_quark    (void);
GType  nm_sysconfig_settings_error_get_type (void);

#endif /* NM_SYSTEM_CONFIG_ERROR_H */
