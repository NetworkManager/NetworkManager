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
 * SECTION:nmtui-hostname
 * @short_description: hostname-setting functionality
 *
 * nmtui-hostname implements the "set hostname" functionality
 */

#include "nm-default.h"

#include "nmt-newt.h"

#include "nmtui.h"
#include "nmtui-hostname.h"
#include "nmt-utils.h"

static char *
nmtui_hostname_run_dialog (void)
{
	NmtNewtForm *form;
	NmtNewtWidget *widget, *ok, *cancel;
	NmtNewtGrid *grid;
	NmtNewtEntry *entry;
	NmtNewtButtonBox *bbox;
	char *hostname, *ret = NULL;

	form = g_object_new (NMT_TYPE_NEWT_FORM,
	                     "title", _("Set Hostname"),
	                     "escape-exits", TRUE,
	                     NULL);

	widget = nmt_newt_grid_new ();
	nmt_newt_form_set_content (form, widget);
	grid = NMT_NEWT_GRID (widget);

	widget = nmt_newt_label_new (_("Hostname"));
	nmt_newt_grid_add (grid, widget, 0, 0);

	widget = nmt_newt_entry_new (40, 0);
	nmt_newt_widget_set_exit_on_activate (widget, TRUE);
	nmt_newt_grid_add (grid, widget, 1, 0);
	nmt_newt_widget_set_padding (widget, 1, 0, 0, 0);
	entry = NMT_NEWT_ENTRY (widget);

	widget = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_HORIZONTAL);
	nmt_newt_grid_add (grid, widget, 1, 1);
	nmt_newt_widget_set_padding (widget, 0, 1, 0, 0);
	bbox = NMT_NEWT_BUTTON_BOX (widget);

	cancel = nmt_newt_button_box_add_end (bbox, _("Cancel"));
	nmt_newt_widget_set_exit_on_activate (cancel, TRUE);
	ok = nmt_newt_button_box_add_end (bbox, _("OK"));
	nmt_newt_widget_set_exit_on_activate (ok, TRUE);

	g_object_get (G_OBJECT (nm_client),
	              NM_CLIENT_HOSTNAME, &hostname,
	              NULL);
	nmt_newt_entry_set_text (entry, hostname);
	g_free (hostname);

	widget = nmt_newt_form_run_sync (form);
	if (widget == (NmtNewtWidget *)entry || widget == ok)
		ret = g_strdup (nmt_newt_entry_get_text (entry));

	g_object_unref (form);
	return ret;
}

static void
hostname_set (GObject      *object,
              GAsyncResult *result,
              gpointer      op)
{
	GError *error = NULL;

	nm_client_save_hostname_finish (NM_CLIENT (object), result, &error);
	nmt_sync_op_complete_boolean (op, error == NULL, error);
	g_clear_error (&error);
}

NmtNewtForm *
nmtui_hostname (int argc, char **argv)
{
	const char *hostname;
	char *tmp = NULL;
	NmtSyncOp op;
	GError *error = NULL;

	if (argc == 2)
		hostname = argv[1];
	else
		hostname = tmp = nmtui_hostname_run_dialog ();

	if (hostname) {
		nmt_sync_op_init (&op);
		nm_client_save_hostname_async (nm_client, hostname, NULL, hostname_set, &op);
		if (nmt_sync_op_wait_boolean (&op, &error)) {
			/* Translators: this indicates the result. ie, "I have set the hostname to ..." */
			nmt_newt_message_dialog (_("Set hostname to '%s'"), hostname);
		} else {
			nmt_newt_message_dialog (_("Unable to set hostname: %s"), error->message);
			g_error_free (error);
		}

		g_free (tmp);
	}

	return NULL;
}
