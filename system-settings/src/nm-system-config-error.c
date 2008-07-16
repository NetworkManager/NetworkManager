/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "nm-system-config-error.h"

GQuark
nm_sysconfig_settings_error_quark (void)
{
	static GQuark ret = 0;

	if (ret == 0)
		ret = g_quark_from_static_string ("nm_sysconfig_settings_error");

	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_sysconfig_settings_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_GENERAL, "GeneralError"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED, "NotPrivileged"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED, "AddNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED, "UpdateNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_DELETE_NOT_SUPPORTED, "DeleteNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_ADD_FAILED, "AddFailed"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMSysconfigSettingsError", values);
	}

	return etype;
}
