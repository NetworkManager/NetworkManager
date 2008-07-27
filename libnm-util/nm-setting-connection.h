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
#define NM_SETTING_CONNECTION_TYPE        "type"
#define NM_SETTING_CONNECTION_AUTOCONNECT "autoconnect"
#define NM_SETTING_CONNECTION_TIMESTAMP   "timestamp"

typedef struct {
	NMSetting parent;

	char *id;
	char *type;
	gboolean autoconnect;
	guint64 timestamp;
} NMSettingConnection;

typedef struct {
	NMSettingClass parent;
} NMSettingConnectionClass;

GType nm_setting_connection_get_type (void);

NMSetting *nm_setting_connection_new (void);

G_END_DECLS

#endif /* NM_SETTING_CONNECTION_H */
