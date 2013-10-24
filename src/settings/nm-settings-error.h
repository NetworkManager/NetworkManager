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

#ifndef NM_SETTINGS_ERROR_H
#define NM_SETTINGS_ERROR_H

#include <glib.h>
#include <glib-object.h>

typedef enum {
	NM_SETTINGS_ERROR_GENERAL = 0,                 /*< nick=GeneralError >*/
	NM_SETTINGS_ERROR_INVALID_CONNECTION,          /*< nick=InvalidConnection >*/
	NM_SETTINGS_ERROR_READ_ONLY_CONNECTION,        /*< nick=ReadOnlyConnection >*/
	NM_SETTINGS_ERROR_INTERNAL_ERROR,              /*< nick=InternalError >*/
	NM_SETTINGS_ERROR_SECRETS_UNAVAILABLE,         /*< nick=SecretsUnavailable >*/
	NM_SETTINGS_ERROR_SECRETS_REQUEST_CANCELED,    /*< nick=SecretsRequestCanceled >*/
	NM_SETTINGS_ERROR_PERMISSION_DENIED,           /*< nick=PermissionDenied >*/
	NM_SETTINGS_ERROR_INVALID_SETTING,             /*< nick=InvalidSetting >*/
	NM_SETTINGS_ERROR_ADD_NOT_SUPPORTED,           /*< nick=AddNotSupported >*/
	NM_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED,        /*< nick=UpdateNotSupported >*/
	NM_SETTINGS_ERROR_DELETE_NOT_SUPPORTED,        /*< nick=DeleteNotSupported >*/
	NM_SETTINGS_ERROR_ADD_FAILED,                  /*< nick=AddFailed >*/
	NM_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED, /*< nick=SaveHostnameNotSupported >*/
	NM_SETTINGS_ERROR_SAVE_HOSTNAME_FAILED,        /*< nick=SaveHostnameFailed >*/
	NM_SETTINGS_ERROR_HOSTNAME_INVALID,            /*< nick=HostnameInvalid >*/
	NM_SETTINGS_ERROR_UUID_EXISTS,                 /*< nick=UuidExists >*/
} NMSettingsError;

#define NM_SETTINGS_ERROR (nm_settings_error_quark ())
GQuark nm_settings_error_quark (void);

#define NM_TYPE_SETTINGS_ERROR (nm_settings_error_get_type ())
GType  nm_settings_error_get_type (void);

#endif /* NM_SETTINGS_ERROR_H */
