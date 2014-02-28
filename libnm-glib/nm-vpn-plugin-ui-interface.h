/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
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

/**
 * NMVpnPluginUiCapability:
 * @NM_VPN_PLUGIN_UI_CAPABILITY_NONE: unknown or no capability
 * @NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT: the plugin can import new connections
 * @NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT: the plugin can export connections
 * @NM_VPN_PLUGIN_UI_CAPABILITY_IPV6: the plugin supports IPv6 addressing
 *
 * Flags that indicate to UI programs certain capabilities of the plugin.
 **/
typedef enum /*< flags >*/ {
	NM_VPN_PLUGIN_UI_CAPABILITY_NONE   = 0x00,
	NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT = 0x01,
	NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT = 0x02,
	NM_VPN_PLUGIN_UI_CAPABILITY_IPV6   = 0x04
} NMVpnPluginUiCapability;

/* Short display name of the VPN plugin */
#define NM_VPN_PLUGIN_UI_INTERFACE_NAME "name"

/* Longer description of the VPN plugin */
#define NM_VPN_PLUGIN_UI_INTERFACE_DESC "desc"

/* D-Bus service name of the plugin's VPN service */
#define NM_VPN_PLUGIN_UI_INTERFACE_SERVICE "service"

/**
 * NMVpnPluginUiInterfaceProp:
 * @NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME: the VPN plugin's name
 * @NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC: description of the VPN plugin and what
 * VPN services it supports
 * @NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE: the D-Bus service name used by the
 * plugin's VPN service daemon
 *
 * #GObject property numbers that plugins should override to provide certain
 * information to UI programs.
 **/
typedef enum {
	/* private */
	NM_VPN_PLUGIN_UI_INTERFACE_PROP_FIRST = 0x1000,

	/* public */
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
	NMConnection * (*import_from_file) (NMVpnPluginUiInterface *iface,
	                                    const char *path,
	                                    GError **error);

	/* Export the given connection to the specified path.  Return TRUE on success.
	 * On error, return FALSE and set 'error' with additional error information.
	 * Note that 'error' can be NULL, in which case no additional error information
	 * should be provided.
	 */
	gboolean (*export_to_file) (NMVpnPluginUiInterface *iface,
	                            const char *path,
	                            NMConnection *connection,
	                            GError **error);

	/* For a given connection, return a suggested file name.  Returned value should
	 * be NULL or a suggested file name allocated via g_malloc/g_new/etc to be freed
	 * by the caller.
	 */
	char * (*get_suggested_name) (NMVpnPluginUiInterface *iface, NMConnection *connection);

	/* Deprecated and no longer used */
	gboolean (*delete_connection) (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
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

/* Deprecated and no longer used */
NM_DEPRECATED_IN_0_9_10
gboolean nm_vpn_plugin_ui_interface_delete_connection (NMVpnPluginUiInterface *iface,
                                                       NMConnection *connection,
                                                       GError **error);


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

	/* Called to save the user-entered options to the connection object.  Should
	 * return FALSE and set 'error' if the current options are invalid.  'error'
	 * should contain enough information for the plugin to determine which UI
	 * widget is invalid at a later point in time.  For example, creating unique
	 * error codes for what error occurred and populating the message field
	 * of 'error' with the name of the invalid property.
	 */
	gboolean (*update_connection) (NMVpnPluginUiWidgetInterface *iface,
	                               NMConnection *connection,
	                               GError **error);

	/* Deprecated and no longer used */
	gboolean (*save_secrets) (NMVpnPluginUiWidgetInterface *iface,
	                          NMConnection *connection,
	                          GError **error);

	/* Emitted when the value of a UI widget changes.  May trigger a validity
	 * check via update_connection() to write values to the connection */
	void (*changed) (NMVpnPluginUiWidgetInterface *iface);
};

GType nm_vpn_plugin_ui_widget_interface_get_type (void);

GObject * nm_vpn_plugin_ui_widget_interface_get_widget (NMVpnPluginUiWidgetInterface *iface);

gboolean nm_vpn_plugin_ui_widget_interface_update_connection (NMVpnPluginUiWidgetInterface *iface,
                                                              NMConnection *connection,
                                                              GError **error);

/* Deprecated and no longer used */
NM_DEPRECATED_IN_0_9_10
gboolean nm_vpn_plugin_ui_widget_interface_save_secrets (NMVpnPluginUiWidgetInterface *iface,
                                                         NMConnection *connection,
                                                         GError **error);

G_END_DECLS

#endif	/* NM_VPN_PLUGIN_UI_INTERFACE_H */
