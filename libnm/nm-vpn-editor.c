// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-vpn-editor.h"

static void nm_vpn_editor_default_init (NMVpnEditorInterface *iface);

G_DEFINE_INTERFACE (NMVpnEditor, nm_vpn_editor, G_TYPE_OBJECT)

static void
nm_vpn_editor_default_init (NMVpnEditorInterface *iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (iface);

	/* Signals */
	g_signal_new ("changed",
	              iface_type,
	              G_SIGNAL_RUN_FIRST,
	              G_STRUCT_OFFSET (NMVpnEditorInterface, changed),
	              NULL, NULL,
	              g_cclosure_marshal_VOID__VOID,
	              G_TYPE_NONE, 0);
}

/**
 * nm_vpn_editor_get_widget:
 * @editor: the #NMVpnEditor
 *
 * Returns: (transfer none):
 */
GObject *
nm_vpn_editor_get_widget (NMVpnEditor *editor)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR (editor), NULL);

	return NM_VPN_EDITOR_GET_INTERFACE (editor)->get_widget (editor);
}

gboolean
nm_vpn_editor_update_connection (NMVpnEditor *editor,
                                 NMConnection *connection,
                                 GError **error)
{
	g_return_val_if_fail (NM_IS_VPN_EDITOR (editor), FALSE);

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	return NM_VPN_EDITOR_GET_INTERFACE (editor)->update_connection (editor, connection, error);
}
