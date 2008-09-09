/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include "nm-vpn-plugin-ui-interface.h"

static void
interface_init (gpointer g_iface)
{
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Properties */
	g_object_interface_install_property (g_iface,
		 g_param_spec_string (NM_VPN_PLUGIN_UI_INTERFACE_NAME,
							  "Name",
							  "VPN Plugin name",
							  NULL,
							  G_PARAM_READABLE));

	g_object_interface_install_property (g_iface,
		 g_param_spec_string (NM_VPN_PLUGIN_UI_INTERFACE_DESC,
							  "Desc",
							  "VPN Plugin description",
							  NULL,
							  G_PARAM_READABLE));

	g_object_interface_install_property (g_iface,
		 g_param_spec_string (NM_VPN_PLUGIN_UI_INTERFACE_SERVICE,
							  "Service",
							  "VPN Plugin D-Bus service name",
							  NULL,
							  G_PARAM_READABLE));

	initialized = TRUE;
}


GType
nm_vpn_plugin_ui_interface_get_type (void)
{
	static GType vpn_plugin_ui_interface_type = 0;

	if (!vpn_plugin_ui_interface_type) {
		const GTypeInfo vpn_plugin_ui_interface_info = {
			sizeof (NMVpnPluginUiInterface), /* class_size */
			interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		vpn_plugin_ui_interface_type = g_type_register_static (G_TYPE_INTERFACE,
														       "NMVpnPluginUiInterface",
														       &vpn_plugin_ui_interface_info,
														       0);

		g_type_interface_add_prerequisite (vpn_plugin_ui_interface_type, G_TYPE_OBJECT);
	}

	return vpn_plugin_ui_interface_type;
}


NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_interface_ui_factory (NMVpnPluginUiInterface *iface,
                                       NMConnection *connection,
                                       GError **error)
{
	return NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->ui_factory (iface, connection, error);
}

guint32
nm_vpn_plugin_ui_interface_get_capabilities (NMVpnPluginUiInterface *iface)
{
	return NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->get_capabilities (iface);
}

NMConnection *
nm_vpn_plugin_ui_interface_import (NMVpnPluginUiInterface *iface,
                                   const char *path,
                                   GError **error)
{
	if (nm_vpn_plugin_ui_interface_get_capabilities (iface) & NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT) {
		g_return_val_if_fail (NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->import != NULL, NULL);
		return NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->import (iface, path, error);
	}
	return NULL;
}

gboolean
nm_vpn_plugin_ui_interface_export (NMVpnPluginUiInterface *iface,
                                   const char *path,
                                   NMConnection *connection,
                                   GError **error)
{
	if (nm_vpn_plugin_ui_interface_get_capabilities (iface) & NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT) {
		g_return_val_if_fail (NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->export != NULL, FALSE);
		return NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->export (iface, path, connection, error);
	}
	return FALSE;
}

char *
nm_vpn_plugin_ui_interface_get_suggested_name (NMVpnPluginUiInterface *iface,
                                               NMConnection *connection)
{
	if (NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->get_suggested_name)
		return NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->get_suggested_name (iface, connection);
	return NULL;
}

gboolean
nm_vpn_plugin_ui_interface_delete_connection (NMVpnPluginUiInterface *iface,
                                              NMConnection *connection,
                                              GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	return NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE (iface)->delete_connection (iface, connection, error);
}


static void
widget_interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Signals */
	g_signal_new ("changed",
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMVpnPluginUiWidgetInterface, changed),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__VOID,
				  G_TYPE_NONE, 0);

	initialized = TRUE;
}

GType
nm_vpn_plugin_ui_widget_interface_get_type (void)
{
	static GType vpn_plugin_ui_widget_interface_type = 0;

	if (!vpn_plugin_ui_widget_interface_type) {
		const GTypeInfo vpn_plugin_ui_widget_interface_info = {
			sizeof (NMVpnPluginUiWidgetInterface), /* class_size */
			widget_interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		vpn_plugin_ui_widget_interface_type = g_type_register_static (G_TYPE_INTERFACE,
		                                                              "NMVpnPluginUiWidgetInterface",
		                                                              &vpn_plugin_ui_widget_interface_info,
		                                                              0);

		g_type_interface_add_prerequisite (vpn_plugin_ui_widget_interface_type, G_TYPE_OBJECT);
	}

	return vpn_plugin_ui_widget_interface_type;
}

GObject *
nm_vpn_plugin_ui_widget_interface_get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	return NM_VPN_PLUGIN_UI_WIDGET_INTERFACE_GET_INTERFACE (iface)->get_widget (iface);
}

gboolean
nm_vpn_plugin_ui_widget_interface_update_connection (NMVpnPluginUiWidgetInterface *iface,
                                                     NMConnection *connection,
                                                     GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	return NM_VPN_PLUGIN_UI_WIDGET_INTERFACE_GET_INTERFACE (iface)->update_connection (iface, connection, error);
}

gboolean
nm_vpn_plugin_ui_widget_interface_save_secrets (NMVpnPluginUiWidgetInterface *iface,
                                                NMConnection *connection,
                                                GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	return NM_VPN_PLUGIN_UI_WIDGET_INTERFACE_GET_INTERFACE (iface)->save_secrets (iface, connection, error);
}

