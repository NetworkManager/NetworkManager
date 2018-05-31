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

#ifndef __NETWORKMANAGER_SETTINGS_PLUGIN_H__
#define __NETWORKMANAGER_SETTINGS_PLUGIN_H__

#include "nm-connection.h"

/* Plugin's factory function that returns a GObject that implements
 * NMSettingsPlugin.
 */
GObject * nm_settings_plugin_factory (void);

#define NM_TYPE_SETTINGS_PLUGIN               (nm_settings_plugin_get_type ())
#define NM_SETTINGS_PLUGIN(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_PLUGIN, NMSettingsPlugin))
#define NM_IS_SETTINGS_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_PLUGIN))
#define NM_SETTINGS_PLUGIN_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SETTINGS_PLUGIN, NMSettingsPluginInterface))

#define NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED "unmanaged-specs-changed"
#define NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED "unrecognized-specs-changed"
#define NM_SETTINGS_PLUGIN_CONNECTION_ADDED "connection-added"

typedef struct _NMSettingsPlugin NMSettingsPlugin;

typedef struct {
	GTypeInterface g_iface;

	/* Called when the plugin is loaded to initialize it */
	void     (*init) (NMSettingsPlugin *config);

	/* Returns a GSList of NMSettingsConnection objects that represent
	 * connections the plugin knows about.  The returned list is freed by the
	 * system settings service.
	 */
	GSList * (*get_connections) (NMSettingsPlugin *config);

	/* Requests that the plugin load/reload a single connection, if it
	 * recognizes the filename. Returns success or failure.
	 */
	gboolean (*load_connection) (NMSettingsPlugin *config,
	                             const char *filename);

	/* Requests that the plugin reload all connection files from disk,
	 * and emit signals reflecting new, changed, and removed connections.
	 */
	void (*reload_connections) (NMSettingsPlugin *config);

	/*
	 * Return a string list of specifications of devices which NetworkManager
	 * should not manage.  Returned list will be freed by the system settings
	 * service, and each element must be allocated using g_malloc() or its
	 * variants (g_strdup, g_strdup_printf, etc).
	 *
	 * Each string in the list must be in one of the formats recognized by
	 * nm_device_spec_match_list().
	 */
	GSList * (*get_unmanaged_specs) (NMSettingsPlugin *config);

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
	GSList * (*get_unrecognized_specs) (NMSettingsPlugin *config);

	/*
	 * Initialize the plugin-specific connection and return a new
	 * NMSettingsConnection subclass that contains the same settings as the
	 * original connection.  The connection should only be saved to backing
	 * storage if @save_to_disk is TRUE.  The returned object is owned by the
	 * plugin and must be referenced by the owner if necessary.
	 */
	NMSettingsConnection * (*add_connection) (NMSettingsPlugin *config,
	                                          NMConnection *connection,
	                                          gboolean save_to_disk,
	                                          GError **error);

	/* Signals */

	/* Emitted when a new connection has been found by the plugin */
	void (*connection_added)   (NMSettingsPlugin *config,
	                            NMSettingsConnection *connection);

	/* Emitted when the list of unmanaged device specifications changes */
	void (*unmanaged_specs_changed) (NMSettingsPlugin *config);

	/* Emitted when the list of devices with unrecognized connections changes */
	void (*unrecognized_specs_changed) (NMSettingsPlugin *config);
} NMSettingsPluginInterface;

GType nm_settings_plugin_get_type (void);

void nm_settings_plugin_init (NMSettingsPlugin *config);

GSList *nm_settings_plugin_get_connections (NMSettingsPlugin *config);

gboolean nm_settings_plugin_load_connection (NMSettingsPlugin *config,
                                             const char *filename);
void nm_settings_plugin_reload_connections (NMSettingsPlugin *config);

GSList *nm_settings_plugin_get_unmanaged_specs (NMSettingsPlugin *config);
GSList *nm_settings_plugin_get_unrecognized_specs (NMSettingsPlugin *config);

NMSettingsConnection *nm_settings_plugin_add_connection (NMSettingsPlugin *config,
                                                         NMConnection *connection,
                                                         gboolean save_to_disk,
                                                         GError **error);

#endif /* __NETWORKMANAGER_SETTINGS_PLUGIN_H__ */
