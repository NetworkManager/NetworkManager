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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef NM_SYSTEM_CONFIG_INTERFACE_H
#define NM_SYSTEM_CONFIG_INTERFACE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-connection.h>
#include <nm-settings-connection-interface.h>

G_BEGIN_DECLS

#define PLUGIN_PRINT(pname, fmt, args...) \
	{ g_message ("   " pname ": " fmt, ##args); }

#define PLUGIN_WARN(pname, fmt, args...) \
	{ g_warning ("   " pname ": " fmt, ##args); }


/* Plugin's factory function that returns a GObject that implements
 * NMSystemConfigInterface.
 */
GObject * nm_system_config_factory (void);

/* NOTE:
 *   When passing NMConnection objects to NetworkManager, any properties
 * of that NMConnection's NMSetting objects that are secrets must be set as
 * GObject data items on the NMSetting object, _not_ inside the NMSetting
 * object itself.  This is to ensure that the secrets are only given to
 * NetworkManager itself and not exposed to clients like nm-applet that need
 * connection details, but not secrets.
 */

#define NM_TYPE_SYSTEM_CONFIG_INTERFACE      (nm_system_config_interface_get_type ())
#define NM_SYSTEM_CONFIG_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE, NMSystemConfigInterface))
#define NM_IS_SYSTEM_CONFIG_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE))
#define NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE, NMSystemConfigInterface))


#define NM_SYSTEM_CONFIG_INTERFACE_NAME "name"
#define NM_SYSTEM_CONFIG_INTERFACE_INFO "info"
#define NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES "capabilities"
#define NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME "hostname"

#define NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED "unmanaged-specs-changed"
#define NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED "connection-added"

typedef enum {
	NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE = 0x00000000,
	NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS = 0x00000001,
	NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME = 0x00000002,

	NM_SYSTEM_CONFIG_INTERFACE_CAP_LAST = NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME
} NMSystemConfigInterfaceCapabilities;

typedef enum {
	NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST = 0x1000,

	NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME = NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
} NMSystemConfigInterfaceProp;


typedef struct _NMSystemConfigInterface NMSystemConfigInterface;

struct _NMSystemConfigInterface {
	GTypeInterface g_iface;

	/* Called when the plugin is loaded to initialize it */
	void     (*init) (NMSystemConfigInterface *config);

	/* Returns a GSList of objects that implement NMSettingsConnectionInterface
	 * that represent connections the plugin knows about.  The returned list
	 * is freed by the system settings service.
	 */
	GSList * (*get_connections) (NMSystemConfigInterface *config);

	/*
	 * Return a string list of specifications of devices which NetworkManager
	 * should not manage.  Returned list will be freed by the system settings
	 * service, and each element must be allocated using g_malloc() or its
	 * variants (g_strdup, g_strdup_printf, etc).
	 *
	 * Each string in the list must follow the format <method>:<data>, where
	 * the method and data are one of the following:
	 *
	 * Method: mac    Data: device MAC address formatted with leading zeros and
	 *                      lowercase letters, like 00:0a:0b:0c:0d:0e
	 *
	 * Method: s390-subchannels  Data: string of 2 or 3 s390 subchannels
	 *                                 separated by commas (,) that identify the
	 *                                 device, like "0.0.09a0,0.0.09a1,0.0.09a2".
	 *                                 The string may contain only the following
	 *                                 characters: [a-fA-F0-9,.]
	 */
	GSList * (*get_unmanaged_specs) (NMSystemConfigInterface *config);

	/*
	 * Add a new connection.
	 */
	gboolean (*add_connection) (NMSystemConfigInterface *config,
	                            NMConnection *connection,
	                            GError **error);

	/* Signals */

	/* Emitted when a new connection has been found by the plugin */
	void (*connection_added)   (NMSystemConfigInterface *config,
	                            NMSettingsConnectionInterface *connection);

	/* Emitted when the list of unmanaged device specifications changes */
	void (*unmanaged_specs_changed) (NMSystemConfigInterface *config);
};

GType nm_system_config_interface_get_type (void);

void nm_system_config_interface_init (NMSystemConfigInterface *config,
                                      gpointer unused);

GSList *nm_system_config_interface_get_connections (NMSystemConfigInterface *config);

GSList *nm_system_config_interface_get_unmanaged_specs (NMSystemConfigInterface *config);

gboolean nm_system_config_interface_add_connection (NMSystemConfigInterface *config,
                                                    NMConnection *connection,
                                                    GError **error);

G_END_DECLS

#endif	/* NM_SYSTEM_CONFIG_INTERFACE_H */
