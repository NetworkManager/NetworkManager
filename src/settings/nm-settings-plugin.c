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
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-settings-plugin.h"

#include "nm-settings-connection.h"

/*****************************************************************************/

enum {
	CONNECTION_ADDED,
	UNMANAGED_SPECS_CHANGED,
	UNRECOGNIZED_SPECS_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (NMSettingsPlugin, nm_settings_plugin, G_TYPE_OBJECT)

/*****************************************************************************/

void
nm_settings_plugin_initialize (NMSettingsPlugin *self)
{
	g_return_if_fail (NM_IS_SETTINGS_PLUGIN (self));

	if (NM_SETTINGS_PLUGIN_GET_CLASS (self)->initialize)
		NM_SETTINGS_PLUGIN_GET_CLASS (self)->initialize (self);
}

GSList *
nm_settings_plugin_get_connections (NMSettingsPlugin *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_PLUGIN (self), NULL);

	if (NM_SETTINGS_PLUGIN_GET_CLASS (self)->get_connections)
		return NM_SETTINGS_PLUGIN_GET_CLASS (self)->get_connections (self);
	return NULL;
}

gboolean
nm_settings_plugin_load_connection (NMSettingsPlugin *self,
                                    const char *filename)
{
	g_return_val_if_fail (NM_IS_SETTINGS_PLUGIN (self), FALSE);

	if (NM_SETTINGS_PLUGIN_GET_CLASS (self)->load_connection)
		return NM_SETTINGS_PLUGIN_GET_CLASS (self)->load_connection (self, filename);
	return FALSE;
}

void
nm_settings_plugin_reload_connections (NMSettingsPlugin *self)
{
	g_return_if_fail (NM_IS_SETTINGS_PLUGIN (self));

	if (NM_SETTINGS_PLUGIN_GET_CLASS (self)->reload_connections)
		NM_SETTINGS_PLUGIN_GET_CLASS (self)->reload_connections (self);
}

GSList *
nm_settings_plugin_get_unmanaged_specs (NMSettingsPlugin *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_PLUGIN (self), NULL);

	if (NM_SETTINGS_PLUGIN_GET_CLASS (self)->get_unmanaged_specs)
		return NM_SETTINGS_PLUGIN_GET_CLASS (self)->get_unmanaged_specs (self);
	return NULL;
}

GSList *
nm_settings_plugin_get_unrecognized_specs (NMSettingsPlugin *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_PLUGIN (self), NULL);

	if (NM_SETTINGS_PLUGIN_GET_CLASS (self)->get_unrecognized_specs)
		return NM_SETTINGS_PLUGIN_GET_CLASS (self)->get_unrecognized_specs (self);
	return NULL;
}

/**
 * nm_settings_plugin_add_connection:
 * @self: the #NMSettingsPlugin
 * @connection: the source connection to create a plugin-specific
 * #NMSettingsConnection from
 * @save_to_disk: %TRUE to save the connection to disk immediately, %FALSE to
 * not save to disk
 * @error: on return, a location to store any errors that may occur
 *
 * Creates a new #NMSettingsConnection for the given source @connection.  If the
 * plugin cannot handle the given connection type, it should return %NULL and
 * set @error.  The plugin owns the returned object and the caller must reference
 * the object if it wishes to continue using it.
 *
 * Returns: the new #NMSettingsConnection or %NULL
 */
NMSettingsConnection *
nm_settings_plugin_add_connection (NMSettingsPlugin *self,
                                   NMConnection *connection,
                                   gboolean save_to_disk,
                                   GError **error)
{
	NMSettingsPluginClass *klass;

	g_return_val_if_fail (NM_IS_SETTINGS_PLUGIN (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	klass = NM_SETTINGS_PLUGIN_GET_CLASS (self);
	if (!klass->add_connection) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_NOT_SUPPORTED,
		                     "Plugin does not support adding connections");
		return NULL;
	}

	return klass->add_connection (self, connection, save_to_disk, error);
}

/*****************************************************************************/

void
_nm_settings_plugin_emit_signal_connection_added (NMSettingsPlugin *self,
                                                  NMSettingsConnection *sett_conn)
{
	nm_assert (NM_IS_SETTINGS_PLUGIN (self));
	nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn));

	g_signal_emit (self, signals[CONNECTION_ADDED], 0, sett_conn);
}

void
_nm_settings_plugin_emit_signal_unmanaged_specs_changed (NMSettingsPlugin *self)
{
	nm_assert (NM_IS_SETTINGS_PLUGIN (self));

	g_signal_emit (self, signals[UNMANAGED_SPECS_CHANGED], 0);
}

void
_nm_settings_plugin_emit_signal_unrecognized_specs_changed (NMSettingsPlugin *self)
{
	nm_assert (NM_IS_SETTINGS_PLUGIN (self));

	g_signal_emit (self, signals[UNRECOGNIZED_SPECS_CHANGED], 0);
}

/*****************************************************************************/

static void
nm_settings_plugin_init (NMSettingsPlugin *self)
{
}

static void
nm_settings_plugin_class_init (NMSettingsPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	signals[CONNECTION_ADDED] =
	    g_signal_new (NM_SETTINGS_PLUGIN_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_SETTINGS_CONNECTION);

	signals[UNMANAGED_SPECS_CHANGED] =
	    g_signal_new (NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals[UNRECOGNIZED_SPECS_CHANGED] =
	    g_signal_new (NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
}
