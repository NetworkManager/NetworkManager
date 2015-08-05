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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_SYSTEM_CONFIG_INTERFACE_H__
#define __NETWORKMANAGER_SYSTEM_CONFIG_INTERFACE_H__


#include <nm-connection.h>
#include "nm-default.h"

G_BEGIN_DECLS

/* Plugin's factory function that returns a GObject that implements
 * NMSystemConfigInterface.
 */
GObject * nm_system_config_factory (void);

#define NM_TYPE_SYSTEM_CONFIG_INTERFACE      (nm_system_config_interface_get_type ())
#define NM_SYSTEM_CONFIG_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE, NMSystemConfigInterface))
#define NM_IS_SYSTEM_CONFIG_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE))
#define NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE, NMSystemConfigInterface))


#define NM_SYSTEM_CONFIG_INTERFACE_NAME "name"
#define NM_SYSTEM_CONFIG_INTERFACE_INFO "info"
#define NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES "capabilities"

#define NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED "unmanaged-specs-changed"
#define NM_SYSTEM_CONFIG_INTERFACE_UNRECOGNIZED_SPECS_CHANGED "unrecognized-specs-changed"
#define NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED "connection-added"

typedef enum {
	NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE = 0x00000000,
	NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS = 0x00000001,

	/* When adding more capabilities, be sure to update the "Capabilities"
	 * property max value in nm-system-config-interface.c.
	 */
} NMSystemConfigInterfaceCapabilities;

typedef enum {
	NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST = 0x1000,

	NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME = NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
} NMSystemConfigInterfaceProp;


typedef struct _NMSystemConfigInterface NMSystemConfigInterface;

struct _NMSystemConfigInterface {
	GTypeInterface g_iface;

	/* Called when the plugin is loaded to initialize it */
	void     (*init) (NMSystemConfigInterface *config);

	/* Returns a GSList of NMSettingsConnection objects that represent
	 * connections the plugin knows about.  The returned list is freed by the
	 * system settings service.
	 */
	GSList * (*get_connections) (NMSystemConfigInterface *config);

	/* Requests that the plugin load/reload a single connection, if it
	 * recognizes the filename. Returns success or failure.
	 */
	gboolean (*load_connection) (NMSystemConfigInterface *config,
	                             const char *filename);

	/* Requests that the plugin reload all connection files from disk,
	 * and emit signals reflecting new, changed, and removed connections.
	 */
	void (*reload_connections) (NMSystemConfigInterface *config);

	/*
	 * Return a string list of specifications of devices which NetworkManager
	 * should not manage.  Returned list will be freed by the system settings
	 * service, and each element must be allocated using g_malloc() or its
	 * variants (g_strdup, g_strdup_printf, etc).
	 *
	 * Each string in the list must be in one of the formats recognized by
	 * nm_device_spec_match_list().
	 */
	GSList * (*get_unmanaged_specs) (NMSystemConfigInterface *config);

	/*
	 * Return a string list of specifications of devices for which at least
	 * one non-NetworkManager-based configuration is defined. Returned list
	 * will be freed by the system settings service, and each element must be
	 * allocated using g_malloc() or its variants (g_strdup, g_strdup_printf,
	 * etc).
	 *
	 * Each string in the list must be in one of the formats recognized by
	 * nm_device_spec_match_list().
	 */
	GSList * (*get_unrecognized_specs) (NMSystemConfigInterface *config);

	/*
	 * Initialize the plugin-specific connection and return a new
	 * NMSettingsConnection subclass that contains the same settings as the
	 * original connection.  The connection should only be saved to backing
	 * storage if @save_to_disk is TRUE.  The returned object is owned by the
	 * plugin and must be referenced by the owner if necessary.
	 */
	NMSettingsConnection * (*add_connection) (NMSystemConfigInterface *config,
	                                          NMConnection *connection,
	                                          gboolean save_to_disk,
	                                          GError **error);

	/* Signals */

	/* Emitted when a new connection has been found by the plugin */
	void (*connection_added)   (NMSystemConfigInterface *config,
	                            NMSettingsConnection *connection);

	/* Emitted when the list of unmanaged device specifications changes */
	void (*unmanaged_specs_changed) (NMSystemConfigInterface *config);

	/* Emitted when the list of devices with unrecognized connections changes */
	void (*unrecognized_specs_changed) (NMSystemConfigInterface *config);
};

GType nm_system_config_interface_get_type (void);

void nm_system_config_interface_init (NMSystemConfigInterface *config,
                                      gpointer unused);

GSList *nm_system_config_interface_get_connections (NMSystemConfigInterface *config);

gboolean nm_system_config_interface_load_connection (NMSystemConfigInterface *config,
                                                     const char *filename);
void nm_system_config_interface_reload_connections (NMSystemConfigInterface *config);

GSList *nm_system_config_interface_get_unmanaged_specs (NMSystemConfigInterface *config);
GSList *nm_system_config_interface_get_unrecognized_specs (NMSystemConfigInterface *config);

NMSettingsConnection *nm_system_config_interface_add_connection (NMSystemConfigInterface *config,
                                                                 NMConnection *connection,
                                                                 gboolean save_to_disk,
                                                                 GError **error);

G_END_DECLS

#endif	/* NM_SYSTEM_CONFIG_INTERFACE_H */
