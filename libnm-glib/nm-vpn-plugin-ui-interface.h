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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_VPN_PLUGIN_UI_INTERFACE_H
#define NM_VPN_PLUGIN_UI_INTERFACE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-connection.h>

G_BEGIN_DECLS

typedef struct _NMVpnPluginUiInterface NMVpnPluginUiInterface;
typedef struct _NMVpnPluginUiWidgetInterface NMVpnPluginUiWidgetInterface;

/* Plugin's factory function that returns a GObject that implements
 * NMVpnPluginUiInterface.
 */
typedef NMVpnPluginUiInterface * (*NMVpnPluginUiFactory) (GError **error);
NMVpnPluginUiInterface *nm_vpn_plugin_ui_factory (GError **error);


/**************************************************/
/* Plugin interface                               */
/**************************************************/

#define NM_TYPE_VPN_PLUGIN_UI_INTERFACE      (nm_vpn_plugin_ui_interface_get_type ())
#define NM_VPN_PLUGIN_UI_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_PLUGIN_UI_INTERFACE, NMVpnPluginUiInterface))
#define NM_IS_VPN_PLUGIN_UI_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_PLUGIN_UI_INTERFACE))
#define NM_VPN_PLUGIN_UI_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_VPN_PLUGIN_UI_INTERFACE, NMVpnPluginUiInterface))

#define NM_VPN_PLUGIN_UI_CAPABILITY_NONE     0x00
#define NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT   0x01
#define NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT   0x02

/* Short display name of the VPN plugin */
#define NM_VPN_PLUGIN_UI_INTERFACE_NAME "name"

/* Longer description of the the VPN plugin */
#define NM_VPN_PLUGIN_UI_INTERFACE_DESC "desc"

/* D-Bus service name of the plugin's VPN service */
#define NM_VPN_PLUGIN_UI_INTERFACE_SERVICE "service"

typedef enum {
	NM_VPN_PLUGIN_UI_INTERFACE_PROP_FIRST = 0x1000,

	NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME = NM_VPN_PLUGIN_UI_INTERFACE_PROP_FIRST,
	NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
	NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE
} NMVpnPluginUiInterfaceProp;

struct _NMVpnPluginUiInterface {
	GTypeInterface g_iface;

	/* Plugin's factory function that returns a GObject that implements
	 * NMVpnPluginUiWidgetInterface, pre-filled with values from 'connection'
	 * if non-NULL.
	 */
	NMVpnPluginUiWidgetInterface * (*ui_factory) (NMVpnPluginUiInterface *iface,
	                                              NMConnection *connection,
	                                              GError **error);

	/* Plugin's capabiltity function that returns a bitmask of capabilities
	 * described by NM_VPN_PLUGIN_UI_CAPABILITY_* defines.
	 */
	guint32 (*get_capabilities) (NMVpnPluginUiInterface *iface);

	/* Try to import a connection from the specified path.  On success, return a
	 * partial NMConnection object.  On error, return NULL and set 'error' with
	 * additional information.  Note that 'error' can be NULL, in which case no
	 * additional error information should be provided.
	 */
	NMConnection * (*import) (NMVpnPluginUiInterface *iface, const char *path, GError **error);

	/* Export the given connection to the specified path.  Return TRUE on success.
	 * On error, return FALSE and set 'error' with additional error information.
	 * Note that 'error' can be NULL, in which case no additional error information
	 * should be provided.
	 */
	gboolean (*export) (NMVpnPluginUiInterface *iface, const char *path, NMConnection *connection, GError **error);

	/* For a given connection, return a suggested file name.  Returned value should
	 * be NULL or a suggested file name allocated via g_malloc/g_new/etc to be freed
	 * by the caller.
	 */
	char * (*get_suggested_name) (NMVpnPluginUiInterface *iface, NMConnection *connection);
};

GType nm_vpn_plugin_ui_interface_get_type (void);

NMVpnPluginUiWidgetInterface *nm_vpn_plugin_ui_interface_ui_factory (NMVpnPluginUiInterface *iface,
                                                                     NMConnection *connection,
                                                                     GError **error);

guint32 nm_vpn_plugin_ui_interface_get_capabilities (NMVpnPluginUiInterface *iface);

NMConnection *nm_vpn_plugin_ui_interface_import (NMVpnPluginUiInterface *iface,
                                                 const char *path,
                                                 GError **error);

gboolean nm_vpn_plugin_ui_interface_export (NMVpnPluginUiInterface *iface,
                                            const char *path,
                                            NMConnection *connection,
                                            GError **error);

char *nm_vpn_plugin_ui_interface_get_suggested_name (NMVpnPluginUiInterface *iface,
                                                     NMConnection *connection);


/**************************************************/
/* UI widget interface                            */
/**************************************************/

#define NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE      (nm_vpn_plugin_ui_widget_interface_get_type ())
#define NM_VPN_PLUGIN_UI_WIDGET_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE, NMVpnPluginUiWidgetInterface))
#define NM_IS_VPN_PLUGIN_UI_WIDGET_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE))
#define NM_VPN_PLUGIN_UI_WIDGET_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE, NMVpnPluginUiWidgetInterface))

struct _NMVpnPluginUiWidgetInterface {
	GTypeInterface g_iface;

	/* Return the GtkWidget for the VPN's UI */
	GObject * (*get_widget) (NMVpnPluginUiWidgetInterface *iface);

	/* Called to save the user-entered options to the connection object */
	void (*update_connection) (NMVpnPluginUiWidgetInterface *iface,
	                           NMConnection *connection);

	/* Emitted when the validity of the user-entered options changes */
	void (*validity_changed) (NMVpnPluginUiWidgetInterface *iface, gboolean valid);
};

GType nm_vpn_plugin_ui_widget_interface_get_type (void);

GObject * nm_vpn_plugin_ui_widget_interface_get_widget (NMVpnPluginUiWidgetInterface *iface);

void nm_vpn_plugin_ui_widget_interface_update_connection (NMVpnPluginUiWidgetInterface *iface,
                                                          NMConnection *connection);

G_END_DECLS

#endif	/* NM_VPN_PLUGIN_UI_INTERFACE_H */
