/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

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
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED, "AddNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED, "UpdateNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_DELETE_NOT_SUPPORTED, "DeleteNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_ADD_FAILED, "AddFailed"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED, "SaveHostnameNotSupported"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_FAILED, "SaveHostnameFailed"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMSysconfigSettingsError", values);
	}

	return etype;
}
