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
#include "nmt-utils.h"

static void
connect_complete (GObject      *object,
                  GAsyncResult *result,
                  gpointer      user_data)
{
	NmtSyncOp *op = user_data;
	GError *error = NULL;

	if (nmt_connect_connection_list_activate_finish (NMT_CONNECT_CONNECTION_LIST (object),
	                                                 result, &error))
		nmt_sync_op_complete_boolean (op, TRUE, NULL);
	else
		nmt_sync_op_complete_boolean (op, FALSE, error);
	g_clear_error (&error);
}

static void
nmt_connect_connection (const char *identifier)
{
	NmtNewtWidget *list;
	NmtSyncOp op;
	GError *error = NULL;

	nmt_sync_op_init (&op);
	list = nmt_connect_connection_list_new ();
	nmt_connect_connection_list_activate_async (NMT_CONNECT_CONNECTION_LIST (list), identifier,
	                                            connect_complete, &op);
	if (!nmt_sync_op_wait_boolean (&op, &error)) {
		nmt_newt_message_dialog (_("Could not activate connection: %s"), error->message);
		g_error_free (error);
		nmtui_quit ();
	}
	g_object_unref (list);
}

static void
quit_clicked (NmtNewtButton *button,
              gpointer       user_data)
{
	nmtui_quit ();
}

static void
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

	bbox = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_VERTICAL);
	nmt_newt_grid_add (NMT_NEWT_GRID (grid), bbox, 1, 0);
	nmt_newt_widget_set_padding (bbox, 1, 1, 0, 1);

	// FIXME: the activate button doesn't do anything
	activate = nmt_newt_button_box_add_start (NMT_NEWT_BUTTON_BOX (bbox), _("Activate"));
	quit = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (bbox), _("Quit"));
	nmt_newt_widget_set_exit_on_activate (quit, TRUE);
	g_signal_connect (quit, "clicked", G_CALLBACK (quit_clicked), NULL);

	nmt_newt_form_set_content (form, grid);
	nmt_newt_form_show (form);
	g_object_unref (form);
}

void
nmtui_connect (int argc, char **argv)
{
	if (argc == 2)
		nmt_connect_connection (argv[1]);
	else
		nmt_connect_connection_list ();
}
