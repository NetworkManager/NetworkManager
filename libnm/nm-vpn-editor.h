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

#ifndef __NM_VPN_EDITOR_H__
#define __NM_VPN_EDITOR_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <glib.h>
#include <glib-object.h>
#include "nm-types.h"

#include "nm-vpn-editor-plugin.h"

G_BEGIN_DECLS

/*****************************************************************************/
/* Editor interface                               */
/*****************************************************************************/

#define NM_TYPE_VPN_EDITOR               (nm_vpn_editor_get_type ())
#define NM_VPN_EDITOR(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_EDITOR, NMVpnEditor))
#define NM_IS_VPN_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_EDITOR))
#define NM_VPN_EDITOR_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_VPN_EDITOR, NMVpnEditorInterface))

/**
 * NMVpnEditorInterface:
 * @g_iface: the parent interface
 * @get_widget: return the #GtkWidget for the VPN editor's UI
 * @placeholder: not currently used
 * @update_connection: called to save the user-entered options to the connection
 *   object.  Should return %FALSE and set @error if the current options are
 *   invalid.  @error should contain enough information for the plugin to
 *   determine which UI widget is invalid at a later point in time.  For
 *   example, creating unique error codes for what error occurred and populating
 *   the message field of @error with the name of the invalid property.
 * @changed: emitted when the value of a UI widget changes.  May trigger a
 *   validity check via @update_connection to write values to the connection.
 *
 * Interface for editing a specific #NMConnection
 */
typedef struct {
	GTypeInterface g_iface;

	GObject * (*get_widget) (NMVpnEditor *editor);

	void (*placeholder) (void);

	gboolean (*update_connection) (NMVpnEditor *editor,
	                               NMConnection *connection,
	                               GError **error);

	void (*changed) (NMVpnEditor *editor);
} NMVpnEditorInterface;

GType nm_vpn_editor_get_type (void);

GObject * nm_vpn_editor_get_widget (NMVpnEditor *editor);

gboolean nm_vpn_editor_update_connection (NMVpnEditor *editor,
                                          NMConnection *connection,
                                          GError **error);

G_END_DECLS

#endif /* __NM_VPN_EDITOR_H__ */
