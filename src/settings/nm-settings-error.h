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

enum {
	NM_SETTINGS_ERROR_GENERAL = 0,
	NM_SETTINGS_ERROR_INVALID_CONNECTION,
	NM_SETTINGS_ERROR_READ_ONLY_CONNECTION,
	NM_SETTINGS_ERROR_INTERNAL_ERROR,
	NM_SETTINGS_ERROR_SECRETS_UNAVAILABLE,
	NM_SETTINGS_ERROR_SECRETS_REQUEST_CANCELED,
	NM_SETTINGS_ERROR_PERMISSION_DENIED,
	NM_SETTINGS_ERROR_INVALID_SETTING,
	NM_SETTINGS_ERROR_NOT_PRIVILEGED,
	NM_SETTINGS_ERROR_ADD_NOT_SUPPORTED,
	NM_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED,
	NM_SETTINGS_ERROR_DELETE_NOT_SUPPORTED,
	NM_SETTINGS_ERROR_ADD_FAILED,
	NM_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED,
	NM_SETTINGS_ERROR_SAVE_HOSTNAME_FAILED,
	NM_SETTINGS_ERROR_UUID_EXISTS,
};

#define NM_SETTINGS_ERROR (nm_settings_error_quark ())
GQuark nm_settings_error_quark (void);

#define NM_TYPE_SETTINGS_ERROR (nm_settings_error_get_type ())
GType  nm_settings_error_get_type (void);

#endif /* NM_SETTINGS_ERROR_H */
