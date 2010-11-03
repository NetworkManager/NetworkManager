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

#ifndef NM_SETTING_CONNECTION_H
#define NM_SETTING_CONNECTION_H

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CONNECTION            (nm_setting_connection_get_type ())
#define NM_SETTING_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_CONNECTION, NMSettingConnection))
#define NM_SETTING_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionClass))
#define NM_IS_SETTING_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_CONNECTION))
#define NM_IS_SETTING_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_CONNECTION))
#define NM_SETTING_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionClass))

#define NM_SETTING_CONNECTION_SETTING_NAME "connection"

/**
 * NMSettingConnectionError:
 * @NM_SETTING_CONNECTION_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY: the property's value is
 *   invalid
 * @NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY: a required property is not
 *   present
 * @NM_SETTING_CONNECTION_ERROR_TYPE_SETTING_NOT_FOUND: the #NMSetting object
 *   referenced by the setting name contained in the
 *   #NMSettingConnection:type property was not present in the #NMConnection
 *
 * Describes errors that may result from operations involving a
 * #NMSettingConnection.
 *
 **/
typedef enum
{
	NM_SETTING_CONNECTION_ERROR_UNKNOWN = 0,
	NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
	NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY,
	NM_SETTING_CONNECTION_ERROR_TYPE_SETTING_NOT_FOUND
} NMSettingConnectionError;

#define NM_TYPE_SETTING_CONNECTION_ERROR (nm_setting_connection_error_get_type ()) 
GType nm_setting_connection_error_get_type (void);

#define NM_SETTING_CONNECTION_ERROR nm_setting_connection_error_quark ()
GQuark nm_setting_connection_error_quark (void);

#define NM_SETTING_CONNECTION_ID          "id"
#define NM_SETTING_CONNECTION_UUID        "uuid"
#define NM_SETTING_CONNECTION_TYPE        "type"
#define NM_SETTING_CONNECTION_AUTOCONNECT "autoconnect"
#define NM_SETTING_CONNECTION_TIMESTAMP   "timestamp"
#define NM_SETTING_CONNECTION_READ_ONLY   "read-only"

/**
 * NMSettingConnection:
 *
 * The NMSettingConnection struct contains only private data.
 * It should only be accessed through the functions described below.
 */
typedef struct {
	NMSetting parent;
} NMSettingConnection;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingConnectionClass;

GType nm_setting_connection_get_type (void);

NMSetting * nm_setting_connection_new                 (void);
const char *nm_setting_connection_get_id              (NMSettingConnection *setting);
const char *nm_setting_connection_get_uuid            (NMSettingConnection *setting);
const char *nm_setting_connection_get_connection_type (NMSettingConnection *setting);
gboolean    nm_setting_connection_get_autoconnect     (NMSettingConnection *setting);
guint64     nm_setting_connection_get_timestamp       (NMSettingConnection *setting);
gboolean    nm_setting_connection_get_read_only       (NMSettingConnection *setting);

G_END_DECLS

#endif /* NM_SETTING_CONNECTION_H */
