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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include "nm-settings-error.h"

GQuark
nm_settings_error_quark (void)
{
	static GQuark ret = 0;

	if (ret == 0)
		ret = g_quark_from_static_string ("nm-settings-error");

	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_settings_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_SETTINGS_ERROR_GENERAL, "GeneralError"),

			/* The connection was invalid. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The connection is read-only; modifications are not allowed. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_READ_ONLY_CONNECTION, "ReadOnlyConnection"),
			/* A bug in the settings service caused the error. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_INTERNAL_ERROR, "InternalError"),
			/* Retrieval or request of secrets failed. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_SECRETS_UNAVAILABLE, "SecretsUnavailable"),
			/* The request for secrets was canceled. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_SECRETS_REQUEST_CANCELED, "SecretsRequestCanceled"),
			/* The request could not be completed because permission was denied. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The requested setting does not existing in this connection. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_INVALID_SETTING, "InvalidSetting"),
			/* The caller does not have permission to perform this operation */
			ENUM_ENTRY (NM_SETTINGS_ERROR_NOT_PRIVILEGED, "NotPrivileged"),
			/* No plugin supports adding new connections */
			ENUM_ENTRY (NM_SETTINGS_ERROR_ADD_NOT_SUPPORTED, "AddNotSupported"),
			/* The plugin providing this connection does not support updating it */
			ENUM_ENTRY (NM_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED, "UpdateNotSupported"),
			/* The plugin providing this connection does not support deleting it */
			ENUM_ENTRY (NM_SETTINGS_ERROR_DELETE_NOT_SUPPORTED, "DeleteNotSupported"),
			/* Failed to add the connection */
			ENUM_ENTRY (NM_SETTINGS_ERROR_ADD_FAILED, "AddFailed"),
			/* No plugin supports modifying the system hostname */
			ENUM_ENTRY (NM_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED, "SaveHostnameNotSupported"),
			/* Saving the system hostname failed */
			ENUM_ENTRY (NM_SETTINGS_ERROR_SAVE_HOSTNAME_FAILED, "SaveHostnameFailed"),
			/* A connection with this UUID already exists */
			ENUM_ENTRY (NM_SETTINGS_ERROR_UUID_EXISTS, "UuidExists"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMSettingsError", values);
	}

	return etype;
}
