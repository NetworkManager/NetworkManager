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
 * Copyright 2008 - 2015 Red Hat, Inc.
 */

#ifndef __NM_VPN_EDITOR_PLUGIN_H__
#define __NM_VPN_EDITOR_PLUGIN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <glib.h>
#include <glib-object.h>

#include "nm-connection.h"
#include "nm-utils.h"

G_BEGIN_DECLS

typedef struct _NMVpnPluginInfo NMVpnPluginInfo;

typedef struct _NMVpnEditorPlugin NMVpnEditorPlugin;
typedef struct _NMVpnEditor NMVpnEditor;

/* Plugin's factory function that returns a GObject that implements
 * NMVpnEditorPlugin.
 */
#ifndef __GI_SCANNER__
typedef NMVpnEditorPlugin * (*NMVpnEditorPluginFactory) (GError **error);
NMVpnEditorPlugin *nm_vpn_editor_plugin_factory (GError **error);
#endif

/*****************************************************************************/
/* Editor plugin interface                        */
/*****************************************************************************/

#define NM_TYPE_VPN_EDITOR_PLUGIN               (nm_vpn_editor_plugin_get_type ())
#define NM_VPN_EDITOR_PLUGIN(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_EDITOR_PLUGIN, NMVpnEditorPlugin))
#define NM_IS_VPN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_EDITOR_PLUGIN))
#define NM_VPN_EDITOR_PLUGIN_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_VPN_EDITOR_PLUGIN, NMVpnEditorPluginInterface))

/**
 * NMVpnEditorPluginCapability:
 * @NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE: unknown or no capability
 * @NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT: the plugin can import new connections
 * @NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT: the plugin can export connections
 * @NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6: the plugin supports IPv6 addressing
 *
 * Flags that indicate certain capabilities of the plugin to editor programs.
 **/
typedef enum /*< flags >*/ {
	NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE   = 0x00,
	NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT = 0x01,
	NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT = 0x02,
	NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6   = 0x04
} NMVpnEditorPluginCapability;

/* Short display name of the VPN plugin */
#define NM_VPN_EDITOR_PLUGIN_NAME "name"

/* Longer description of the VPN plugin */
#define NM_VPN_EDITOR_PLUGIN_DESCRIPTION "description"

/* D-Bus service name of the plugin's VPN service */
#define NM_VPN_EDITOR_PLUGIN_SERVICE "service"

typedef struct _NMVpnEditorPluginVT NMVpnEditorPluginVT;

/**
 * NMVpnEditorPluginInterface:
 * @g_iface: the parent interface
 * @get_editor: returns an #NMVpnEditor, pre-filled with values from @connection
 *   if non-%NULL.
 * @get_capabilities: returns a bitmask of capabilities.
 * @import_from_file: Try to import a connection from the specified path.  On
 *   success, return a partial #NMConnection object.  On error, return %NULL and
 *   set @error with additional information.  Note that @error can be %NULL, in
 *   which case no additional error information should be provided.
 * @export_to_file: Export the given connection to the specified path.  Return
 *   %TRUE on success.  On error, return %FALSE and set @error with additional
 *   error information.  Note that @error can be %NULL, in which case no
 *   additional error information should be provided.
 * @get_suggested_filename: For a given connection, return a suggested file
 *   name.  Returned value will be %NULL or a suggested file name to be freed by
 *   the caller.
 * @notify_plugin_info_set: A callback to be called when the plugin info is set.
 * @get_vt: return a virtual function table to implement further functions in
 *   the plugin, without requiring to update libnm. Used by nm_vpn_editor_plugin_get_vt().
 *
 * Interface for VPN editor plugins.
 */
typedef struct {
	GTypeInterface g_iface;

	NMVpnEditor * (*get_editor) (NMVpnEditorPlugin *plugin,
	                             NMConnection *connection,
	                             GError **error);

	NMVpnEditorPluginCapability (*get_capabilities) (NMVpnEditorPlugin *plugin);

	NMConnection * (*import_from_file) (NMVpnEditorPlugin *plugin,
	                                    const char *path,
	                                    GError **error);

	gboolean (*export_to_file) (NMVpnEditorPlugin *plugin,
	                            const char *path,
	                            NMConnection *connection,
	                            GError **error);

	char * (*get_suggested_filename) (NMVpnEditorPlugin *plugin, NMConnection *connection);

	void (*notify_plugin_info_set) (NMVpnEditorPlugin *plugin,
	                                NMVpnPluginInfo *plugin_info);

	const NMVpnEditorPluginVT *(*get_vt) (NMVpnEditorPlugin *plugin,
	                                      gsize *out_vt_size);
} NMVpnEditorPluginInterface;

GType nm_vpn_editor_plugin_get_type (void);

NMVpnEditor *nm_vpn_editor_plugin_get_editor (NMVpnEditorPlugin *plugin,
                                              NMConnection *connection,
                                              GError **error);

NMVpnEditorPluginCapability nm_vpn_editor_plugin_get_capabilities (NMVpnEditorPlugin *plugin);

NM_AVAILABLE_IN_1_4
gsize nm_vpn_editor_plugin_get_vt (NMVpnEditorPlugin *plugin,
                                   NMVpnEditorPluginVT *vt,
                                   gsize vt_size);

NMConnection *nm_vpn_editor_plugin_import                 (NMVpnEditorPlugin *plugin,
                                                           const char *path,
                                                           GError **error);
gboolean      nm_vpn_editor_plugin_export                 (NMVpnEditorPlugin *plugin,
                                                           const char *path,
                                                           NMConnection *connection,
                                                           GError **error);
char         *nm_vpn_editor_plugin_get_suggested_filename (NMVpnEditorPlugin *plugin,
                                                           NMConnection *connection);

NM_AVAILABLE_IN_1_2
NMVpnEditorPlugin *nm_vpn_editor_plugin_load_from_file  (const char *plugin_name,
                                                         const char *check_service,
                                                         int check_owner,
                                                         NMUtilsCheckFilePredicate check_file,
                                                         gpointer user_data,
                                                         GError **error);

NM_AVAILABLE_IN_1_4
NMVpnEditorPlugin *nm_vpn_editor_plugin_load (const char *plugin_name,
                                              const char *check_service,
                                              GError **error);

NM_AVAILABLE_IN_1_4
NMVpnPluginInfo *nm_vpn_editor_plugin_get_plugin_info (NMVpnEditorPlugin *plugin);
NM_AVAILABLE_IN_1_4
void             nm_vpn_editor_plugin_set_plugin_info (NMVpnEditorPlugin *plugin, NMVpnPluginInfo *plugin_info);

#include "nm-vpn-plugin-info.h"

G_END_DECLS

#endif /* __NM_VPN_EDITOR_PLUGIN_H__ */
