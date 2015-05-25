/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2008 Novell, Inc.
 * Copyright 2008 - 2010 Red Hat, Inc.
 * Copyright 2015 Red Hat, Inc.
 */

#include "config.h"

#include "nm-vpn-editor-plugin.h"

static void nm_vpn_editor_plugin_default_init (NMVpnEditorPluginInterface *iface);

G_DEFINE_INTERFACE (NMVpnEditorPlugin, nm_vpn_editor_plugin, G_TYPE_OBJECT)

static void
nm_vpn_editor_plugin_default_init (NMVpnEditorPluginInterface *iface)
{
	/* Properties */

	/**
	 * NMVpnEditorPlugin:name:
	 *
	 * Short display name of the VPN plugin.
	 */
	g_object_interface_install_property (iface,
		 g_param_spec_string (NM_VPN_EDITOR_PLUGIN_NAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMVpnEditorPlugin:description:
	 *
	 * Longer description of the VPN plugin.
	 */
	g_object_interface_install_property (iface,
		 g_param_spec_string (NM_VPN_EDITOR_PLUGIN_DESCRIPTION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMVpnEditorPlugin:service:
	 *
	 * D-Bus service name of the plugin's VPN service.
	 */
	g_object_interface_install_property (iface,
		 g_param_spec_string (NM_VPN_EDITOR_PLUGIN_SERVICE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}

/**
 * nm_vpn_editor_plugin_get_editor:
 *
 * Returns: (transfer full):
 */
NMVpnEditor *
nm_vpn_editor_plugin_get_editor (NMVpnEditorPlugin *plugin,
                                 NMConnection *connection,
                                 GError **error)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), NULL);

	return NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->get_editor (plugin, connection, error);
}

NMVpnEditorPluginCapability
nm_vpn_editor_plugin_get_capabilities (NMVpnEditorPlugin *plugin)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), 0);

	return NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->get_capabilities (plugin);
}

/**
 * nm_vpn_editor_plugin_import:
 *
 * Returns: (transfer full):
 */
NMConnection *
nm_vpn_editor_plugin_import (NMVpnEditorPlugin *plugin,
                             const char *path,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), NULL);

	if (nm_vpn_editor_plugin_get_capabilities (plugin) & NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT) {
		g_return_val_if_fail (NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->import_from_file != NULL, NULL);
		return NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->import_from_file (plugin, path, error);
	}
	return NULL;
}

gboolean
nm_vpn_editor_plugin_export (NMVpnEditorPlugin *plugin,
                             const char *path,
                             NMConnection *connection,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), FALSE);

	if (nm_vpn_editor_plugin_get_capabilities (plugin) & NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT) {
		g_return_val_if_fail (NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->export_to_file != NULL, FALSE);
		return NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->export_to_file (plugin, path, connection, error);
	}
	return FALSE;
}

char *
nm_vpn_editor_plugin_get_suggested_filename (NMVpnEditorPlugin *plugin,
                                             NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), NULL);

	if (NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->get_suggested_filename)
		return NM_VPN_EDITOR_PLUGIN_GET_INTERFACE (plugin)->get_suggested_filename (plugin, connection);
	return NULL;
}

