/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmtui-connect
 * @short_description: nm-applet-like functionality
 *
 * nmtui-connect implements activating #NMConnections, including
 * presenting a password dialog if necessary.
 *
 * It's supposed to also implement deactivating them, but it doesn't.
 * FIXME.
 */

#include "config.h"

#include <stdlib.h>

#include <glib/gi18n-lib.h>
#include <nm-utils.h>

#include "nmt-newt.h"

#include "nmtui.h"
#include "nmtui-connect.h"
#include "nmt-connect-connection-list.h"
#include "nmt-password-dialog.h"
#include "nmt-secret-agent.h"
#include "nmt-utils.h"

static void
secrets_requested (NmtSecretAgent *agent,
                   const char     *request_id,
                   const char     *title,
                   const char     *msg,
                   GPtrArray      *secrets,
                   gpointer        user_data)
{
	NmtNewtForm *form;

	form = nmt_password_dialog_new (request_id, title, msg, secrets);
	nmt_newt_form_run_sync (form);

	if (nmt_password_dialog_succeeded (NMT_PASSWORD_DIALOG (form)))
		nmt_secret_agent_response (agent, request_id, secrets);
	else
		nmt_secret_agent_response (agent, request_id, NULL);

	g_object_unref (form);
}

static void
connect_cancelled (NmtNewtForm *form,
                   gpointer     user_data)
{
	NmtSyncOp *op = user_data;
	GError *error = NULL;

	error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");
	nmt_sync_op_complete_boolean (op, FALSE, error);
	g_clear_error (&error);
}

static void
activate_ac_state_changed (GObject    *object,
                           GParamSpec *pspec,
                           gpointer    user_data)
{
	NmtSyncOp *op = user_data;
	NMActiveConnectionState state;
	GError *error = NULL;

	state = nm_active_connection_get_state (NM_ACTIVE_CONNECTION (object));
	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
		return;

	if (state != NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		error = g_error_new_literal (NM_CLIENT_ERROR, NM_CLIENT_ERROR_UNKNOWN,
		                             _("Activation failed"));
	}

	nmt_sync_op_complete_boolean (op, error == NULL, error);
	g_clear_error (&error);
}

static void
activate_callback (NMClient           *client,
                   NMActiveConnection *ac,
                   GError             *error,
                   gpointer            user_data)
{
	NmtSyncOp *op = user_data;

	if (error)
		nmt_sync_op_complete_pointer (op, NULL, error);
	else
		nmt_sync_op_complete_pointer (op, g_object_ref (ac), NULL);
}

static void
add_and_activate_callback (NMClient           *client,
                           NMActiveConnection *ac,
                           const char         *new_connection_path,
                           GError             *error,
                           gpointer            user_data)
{
	/* We don't care about @new_connection_path, so... */
	activate_callback (client, ac, error, user_data);
}

static void
activate_connection (NMConnection *connection,
                     NMDevice     *device,
                     NMObject     *specific_object)
{
	NmtNewtForm *form;
	NMSecretAgent *agent;
	NmtNewtWidget *label;
	NmtSyncOp op;
	const char *specific_object_path;
	NMActiveConnection *ac;
	GError *error = NULL;

	form = g_object_new (NMT_TYPE_NEWT_FORM,
	                     "escape-exits", TRUE,
	                     NULL);
	label = nmt_newt_label_new (_("Connecting..."));
	nmt_newt_form_set_content (form, label);

	agent = nmt_secret_agent_new ();
	nm_secret_agent_register (agent);
	g_signal_connect (agent, "request-secrets", G_CALLBACK (secrets_requested), NULL);

	specific_object_path = specific_object ? nm_object_get_path (specific_object) : NULL;

	/* There's no way to cancel an nm_client_activate_connection() /
	 * nm_client_add_and_activate_connection() call, so we always let them
	 * complete, even if the user hits Esc; they shouldn't normally take long
	 * to complete anyway.
	 */

	nmt_sync_op_init (&op);
	if (connection) {
		nm_client_activate_connection (nm_client,
		                               connection, device, specific_object_path,
		                               activate_callback, &op);
	} else {
		nm_client_add_and_activate_connection (nm_client,
		                                       NULL, device, specific_object_path,
		                                       add_and_activate_callback, &op);
	}

	nmt_newt_form_show (form);

	ac = nmt_sync_op_wait_pointer (&op, &error);
	if (!ac) {
		nmt_newt_message_dialog (_("Could not activate connection: %s"), error->message);
		g_clear_error (&error);
		goto done;
	} else if (nm_active_connection_get_state (ac) == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		/* Already active */
		goto done;
	} else if (!nmt_newt_widget_get_realized (NMT_NEWT_WIDGET (form))) {
		/* User already hit Esc */
		goto done;
	}

	/* Now wait for the connection to actually reach the ACTIVATED state,
	 * allowing the user to cancel if it takes too long.
	 */

	nmt_sync_op_init (&op);

	g_signal_connect (form, "quit", G_CALLBACK (connect_cancelled), &op);
	g_signal_connect (ac, "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (activate_ac_state_changed), &op);

	if (!nmt_sync_op_wait_boolean (&op, &error)) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			nmt_newt_message_dialog (_("Could not activate connection: %s"), error->message);
		g_clear_error (&error);
	}

	g_signal_handlers_disconnect_by_func (form, G_CALLBACK (connect_cancelled), &op);
	g_signal_handlers_disconnect_by_func (ac, G_CALLBACK (activate_ac_state_changed), &op);

 done:
	if (nmt_newt_widget_get_realized (NMT_NEWT_WIDGET (form)))
		nmt_newt_form_quit (form);
	g_object_unref (form);

	/* If the activation failed very quickly, then agent won't be registered yet,
	 * and nm_secret_agent_unregister() would complain if we called it...
	 */
	if (nm_secret_agent_get_registered (agent))
		nm_secret_agent_unregister (agent);
	g_object_unref (agent);
}

static void
listbox_activated (NmtNewtListbox *listbox,
                   gpointer        user_data)
{
	NmtConnectConnectionList *list = NMT_CONNECT_CONNECTION_LIST (listbox);
	NMConnection *connection;
	NMDevice *device;
	NMObject *specific_object;
	NMActiveConnection *ac;

	if (!nmt_connect_connection_list_get_selection (list,
	                                                &connection,
	                                                &device,
	                                                &specific_object,
	                                                &ac))
		return;

	if (ac)
		nm_client_deactivate_connection (nm_client, ac);
	else
		activate_connection (connection, device, specific_object);
}

static void
activate_clicked (NmtNewtButton *button,
                  gpointer       listbox)
{
	listbox_activated (listbox, NULL);
}

static void
listbox_active_changed (GObject    *object,
                        GParamSpec *pspec,
                        gpointer    button)
{
	NmtConnectConnectionList *list = NMT_CONNECT_CONNECTION_LIST (object);
	static const char *activate, *deactivate;
	static int deactivate_padding, activate_padding;
	NMActiveConnection *ac;
	gboolean has_selection;

	if (G_UNLIKELY (activate == NULL)) {
		int activate_width, deactivate_width;

		activate = _("Activate");
		activate_width = nmt_newt_text_width (activate);
		deactivate = _("Deactivate");
		deactivate_width = nmt_newt_text_width (deactivate);

		activate_padding = MAX (0, deactivate_width - activate_width);
		deactivate_padding = MAX (0, activate_width - deactivate_width);
	}

	has_selection = nmt_connect_connection_list_get_selection (list, NULL, NULL, NULL, &ac);

	nmt_newt_component_set_sensitive (button, has_selection);
	if (has_selection && ac) {
		nmt_newt_button_set_label (button, deactivate);
		nmt_newt_widget_set_padding (button, 0, 0, deactivate_padding, 0);
	} else {
		nmt_newt_button_set_label (button, activate);
		nmt_newt_widget_set_padding (button, 0, 0, activate_padding, 0);
	}
}

static NmtNewtForm *
nmt_connect_connection_list (void)
{
	int screen_width, screen_height;
	NmtNewtForm *form;
	NmtNewtWidget *list, *activate, *quit, *bbox, *grid;

	newtGetScreenSize (&screen_width, &screen_height);

	form = g_object_new (NMT_TYPE_NEWT_FORM,
	                     "y", 2,
	                     "height", screen_height - 4,
	                     "escape-exits", TRUE,
	                     NULL);

	grid = nmt_newt_grid_new ();

	list = nmt_connect_connection_list_new ();
	nmt_newt_grid_add (NMT_NEWT_GRID (grid), list, 0, 0);
	nmt_newt_grid_set_flags (NMT_NEWT_GRID (grid), list,
	                         NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y |
	                         NMT_NEWT_GRID_EXPAND_X | NMT_NEWT_GRID_EXPAND_Y);
	g_signal_connect (list, "activated", G_CALLBACK (listbox_activated), NULL);

	bbox = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_VERTICAL);
	nmt_newt_grid_add (NMT_NEWT_GRID (grid), bbox, 1, 0);
	nmt_newt_widget_set_padding (bbox, 1, 1, 0, 1);

	activate = nmt_newt_button_box_add_start (NMT_NEWT_BUTTON_BOX (bbox), _("Activate"));
	g_signal_connect (list, "notify::active", G_CALLBACK (listbox_active_changed), activate);
	listbox_active_changed (G_OBJECT (list), NULL, activate);
	g_signal_connect (activate, "clicked", G_CALLBACK (activate_clicked), list);

	quit = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (bbox), _("Quit"));
	nmt_newt_widget_set_exit_on_activate (quit, TRUE);

	nmt_newt_form_set_content (form, grid);
	return form;
}

static NmtNewtForm *
nmt_connect_connection (const char *identifier)
{
	NmtNewtWidget *list;
	NMConnection *connection;
	NMDevice *device;
	NMObject *specific_object;
	NMActiveConnection *ac;

	list = nmt_connect_connection_list_new ();
	if (!nmt_connect_connection_list_get_connection (NMT_CONNECT_CONNECTION_LIST (list),
	                                                 identifier,
	                                                 &connection,
	                                                 &device,
	                                                 &specific_object,
	                                                 &ac))
		nmt_newt_message_dialog (_("No such connection '%s'"), identifier);
	else if (ac)
		nmt_newt_message_dialog (_("Connection is already active"));
	else
		activate_connection (connection, device, specific_object);
	g_object_unref (list);

	return NULL;
}

NmtNewtForm *
nmtui_connect (int argc, char **argv)
{
	if (argc == 2)
		return nmt_connect_connection (argv[1]);
	else
		return nmt_connect_connection_list ();
}
