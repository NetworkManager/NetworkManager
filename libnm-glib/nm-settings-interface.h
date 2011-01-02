/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#ifndef NM_SETTINGS_INTERFACE_H
#define NM_SETTINGS_INTERFACE_H

#include <glib-object.h>

#include "NetworkManager.h"
#include "nm-settings-connection-interface.h"

G_BEGIN_DECLS

typedef enum {
	NM_SETTINGS_INTERFACE_ERROR_INVALID_CONNECTION = 0,
	NM_SETTINGS_INTERFACE_ERROR_READ_ONLY_CONNECTION,
	NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
	NM_SETTINGS_INTERFACE_ERROR_SECRETS_UNAVAILABLE,
	NM_SETTINGS_INTERFACE_ERROR_SECRETS_REQUEST_CANCELED,
	NM_SETTINGS_INTERFACE_ERROR_PERMISSION_DENIED,
	NM_SETTINGS_INTERFACE_ERROR_INVALID_SETTING,
} NMSettingsInterfaceError;

#define NM_SETTINGS_INTERFACE_ERROR (nm_settings_interface_error_quark ())
GQuark nm_settings_interface_error_quark (void);

#define NM_TYPE_SETTINGS_INTERFACE_ERROR (nm_settings_interface_error_get_type ()) 
GType nm_settings_interface_error_get_type (void);


#define NM_TYPE_SETTINGS_INTERFACE               (nm_settings_interface_get_type ())
#define NM_SETTINGS_INTERFACE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_INTERFACE, NMSettingsInterface))
#define NM_IS_SETTINGS_INTERFACE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_INTERFACE))
#define NM_SETTINGS_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SETTINGS_INTERFACE, NMSettingsInterface))

#define NM_SETTINGS_INTERFACE_NEW_CONNECTION   "new-connection"
#define NM_SETTINGS_INTERFACE_CONNECTIONS_READ "connections-read"

typedef struct _NMSettingsInterface NMSettingsInterface;

typedef void (*NMSettingsAddConnectionFunc) (NMSettingsInterface *settings,
                                             GError *error,
                                             gpointer user_data);

struct _NMSettingsInterface {
	GTypeInterface g_iface;

	/* Methods */
	/* Returns a list of objects implementing NMSettingsConnectionInterface */
	GSList * (*list_connections) (NMSettingsInterface *settings);

	NMSettingsConnectionInterface * (*get_connection_by_path) (NMSettingsInterface *settings,
	                                                           const char *path);

	gboolean (*add_connection) (NMSettingsInterface *settings,
	                            NMConnection *connection,
	                            NMSettingsAddConnectionFunc callback,
	                            gpointer user_data);

	/* Signals */
	void (*new_connection) (NMSettingsInterface *settings,
	                        NMSettingsConnectionInterface *connection);

	void (*connections_read) (NMSettingsInterface *settings);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
};

GType nm_settings_interface_get_type (void);

/* Returns a list of objects implementing NMSettingsConnectionInterface */
GSList *nm_settings_interface_list_connections (NMSettingsInterface *settings);

NMSettingsConnectionInterface *nm_settings_interface_get_connection_by_path (NMSettingsInterface *settings,
                                                                             const char *path); 

gboolean nm_settings_interface_add_connection (NMSettingsInterface *settings,
                                               NMConnection *connection,
                                               NMSettingsAddConnectionFunc callback,
                                               gpointer user_data);

G_END_DECLS

#endif /* NM_SETTINGS_INTERFACE_H */
