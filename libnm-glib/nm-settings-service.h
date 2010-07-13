/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2009 Red Hat, Inc.
 */

#ifndef NM_SETTINGS_SERVICE_H
#define NM_SETTINGS_SERVICE_H

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <nm-exported-connection.h>
#include <nm-settings-interface.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTINGS_SERVICE            (nm_settings_service_get_type ())
#define NM_SETTINGS_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_SERVICE, NMSettingsService))
#define NM_SETTINGS_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS_SERVICE, NMSettingsServiceClass))
#define NM_IS_SETTINGS_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_SERVICE))
#define NM_IS_SETTINGS_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTINGS_SERVICE))
#define NM_SETTINGS_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS_SERVICE, NMSettingsServiceClass))

#define NM_SETTINGS_SERVICE_BUS "bus"
#define NM_SETTINGS_SERVICE_SCOPE "scope"

typedef struct {
	GObject parent;
} NMSettingsService;

typedef struct {
	GObjectClass parent;

	/* Returned list must contain all NMExportedConnection objects exported
	 * by the settings service.  The list (but not the NMExportedConnection
	 * objects) will be freed by caller.
	 */
	GSList * (*list_connections) (NMSettingsService *self);

	void (*add_connection) (NMSettingsService *self,
	                        NMConnection *connection,
	                        DBusGMethodInvocation *context, /* Only present for D-Bus calls */
	                        NMSettingsAddConnectionFunc callback,
	                        gpointer user_data);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMSettingsServiceClass;

GType nm_settings_service_get_type (void);

NMExportedConnection *nm_settings_service_get_connection_by_path (NMSettingsService *self,
                                                                  const char *path);

void nm_settings_service_export (NMSettingsService *self);

void nm_settings_service_export_connection (NMSettingsService *self,
                                            NMSettingsConnectionInterface *exported);

G_END_DECLS

#endif /* NM_SETTINGS_SERVICE_H */
