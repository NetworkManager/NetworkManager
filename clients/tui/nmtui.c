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
 * SECTION:nmtui
 * @short_description: nmtui toplevel
 *
 * The top level of nmtui. Exists mostly just to call nmtui_connect(),
 * nmtui_edit(), and nmtui_hostname().
 */

#include "nm-default.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>

#include "NetworkManager.h"

#include "nmt-newt.h"
#include "nm-editor-bindings.h"

#include "nmtui.h"
#include "nmtui-edit.h"
#include "nmtui-connect.h"
#include "nmtui-hostname.h"

NMClient *nm_client;
static GMainLoop *loop;

typedef NmtNewtForm * (*NmtuiSubprogram) (int argc, char **argv);

static const struct {
	const char *name, *shortcut, *arg;
	const char *display_name;
	NmtuiSubprogram func;
} subprograms[] = {
	{ "edit",     "nmtui-edit",     N_("connection"),
	  N_("Edit a connection"),
	  nmtui_edit },
	{ "connect",  "nmtui-connect",  N_("connection"),
	  N_("Activate a connection"),
	  nmtui_connect },
	{ "hostname", "nmtui-hostname", N_("new hostname"),
	  N_("Set system hostname"),
	  nmtui_hostname }
};
static const int num_subprograms = G_N_ELEMENTS (subprograms);

static void
quit_func (int argc, char **argv)
{
	nmtui_quit ();
}

static NmtNewtForm *
nmtui_main (int argc, char **argv)
{
	NmtNewtForm *form;
	NmtNewtWidget *widget, *ok;
	NmtNewtGrid *grid;
	NmtNewtListbox *listbox;
	NmtNewtButtonBox *bbox;
	NmtuiSubprogram subprogram = NULL;
	int i;

	form = g_object_new (NMT_TYPE_NEWT_FORM,
	                     "title", _("NetworkManager TUI"),
	                     "escape-exits", TRUE,
	                     NULL);

	widget = nmt_newt_grid_new ();
	nmt_newt_form_set_content (form, widget);
	grid = NMT_NEWT_GRID (widget);

	widget = nmt_newt_label_new (_("Please select an option"));
	nmt_newt_grid_add (grid, widget, 0, 0);

	widget = g_object_new (NMT_TYPE_NEWT_LISTBOX,
	                       "height", num_subprograms + 2,
	                       "skip-null-keys", TRUE,
	                       NULL);
	nmt_newt_grid_add (grid, widget, 0, 1);
	nmt_newt_widget_set_padding (widget, 0, 1, 0, 1);
	nmt_newt_widget_set_exit_on_activate (widget, TRUE);
	listbox = NMT_NEWT_LISTBOX (widget);

	for (i = 0; i < num_subprograms; i++) {
		nmt_newt_listbox_append (listbox, _(subprograms[i].display_name),
		                         subprograms[i].func);
	}
	nmt_newt_listbox_append (listbox, "", NULL);
	nmt_newt_listbox_append (listbox, _("Quit"), quit_func);

	widget = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_HORIZONTAL);
	nmt_newt_grid_add (grid, widget, 0, 2);
	bbox = NMT_NEWT_BUTTON_BOX (widget);

	ok = nmt_newt_button_box_add_end (bbox, _("OK"));
	nmt_newt_widget_set_exit_on_activate (ok, TRUE);

	widget = nmt_newt_form_run_sync (form);
	if (widget)
		subprogram = nmt_newt_listbox_get_active_key (listbox);
	g_object_unref (form);

	if (subprogram)
		return subprogram (argc, argv);
	else
		return NULL;
}

/**
 * nmtui_quit:
 *
 * Causes nmtui to exit.
 */
void
nmtui_quit (void)
{
	g_main_loop_quit (loop);
}

static void
usage (void)
{
	const char *argv0 = g_get_prgname ();
	const char *usage_str = _("Usage");
	int i;

	for (i = 0; i < num_subprograms; i++) {
		if (!strcmp (argv0, subprograms[i].shortcut)) {
			g_printerr ("%s: %s [%s]\n", usage_str, argv0, _(subprograms[i].arg));
			exit (1);
		}
	}

	g_printerr ("%s: nmtui\n", usage_str);
	for (i = 0; i < num_subprograms; i++) {
		g_printerr ("%*s  nmtui %s [%s]\n",
		            nmt_newt_text_width (usage_str), " ",
		            subprograms[i].name,
		            _(subprograms[i].arg));
	}
	exit (1);
}

typedef struct {
	NmtuiSubprogram subprogram;
	int argc;
	char **argv;
} NmtuiStartupData;

static void
toplevel_form_quit (NmtNewtForm *form,
                    gpointer     user_data)
{
       nmtui_quit ();
}

static gboolean
idle_run_subprogram (gpointer user_data)
{
	NmtuiStartupData *data = user_data;
	NmtNewtForm *form;

	form = data->subprogram (data->argc, data->argv);
	if (form) {
		g_signal_connect (form, "quit", G_CALLBACK (toplevel_form_quit), NULL);
		nmt_newt_form_show (form);
		g_object_unref (form);
	} else
		nmtui_quit ();

	return FALSE;
}

gboolean sleep_on_startup = FALSE;
gboolean noinit = FALSE;

GOptionEntry entries[] = {
	{ "sleep", 's', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &sleep_on_startup,
	  "Sleep on startup", NULL },
	{ "noinit", 'n', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &noinit,
	  "Don't initialize newt", NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	GOptionContext *opts;
	GError *error = NULL;
	NmtuiStartupData startup_data;
	const char *prgname;
	int i;

	setlocale (LC_ALL, "");
	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, entries, NULL);

	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("%s: %s: %s\n",
		            argv[0],
		            _("Could not parse arguments"),
		            error->message);
		exit (1);
	}
	g_option_context_free (opts);

	nm_editor_bindings_init ();

	nm_client = nm_client_new (NULL, &error);
	if (!nm_client) {
		g_printerr (_("Could not contact NetworkManager: %s.\n"), error->message);
		g_error_free (error);
		exit (1);
	}
	if (!nm_client_get_nm_running (nm_client)) {
		g_printerr ("%s\n", _("NetworkManager is not running."));
		exit (1);
	}

	if (sleep_on_startup)
		sleep (5);

	startup_data.subprogram = NULL;
	prgname = g_get_prgname ();
	if (g_str_has_prefix (prgname, "lt-"))
		prgname += 3;
	if (!strcmp (prgname, "nmtui")) {
		if (argc > 1) {
			for (i = 0; i < num_subprograms; i++) {
				if (!strcmp (argv[1], subprograms[i].name)) {
					argc--;
					argv[0] = (char *) subprograms[i].shortcut;
					memmove (&argv[1], &argv[2], argc * sizeof (char *));
					startup_data.subprogram = subprograms[i].func;
					break;
				}
			}
		} else
			startup_data.subprogram = nmtui_main;
	} else {
		for (i = 0; i < num_subprograms; i++) {
			if (!strcmp (prgname, subprograms[i].shortcut)) {
				startup_data.subprogram = subprograms[i].func;
				break;
			}
		}
	}
	if (!startup_data.subprogram)
		usage ();

	if (!noinit)
		nmt_newt_init ();

	startup_data.argc = argc;
	startup_data.argv = argv;
	g_idle_add (idle_run_subprogram, &startup_data);
	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	if (!noinit)
		nmt_newt_finished ();

	g_object_unref (nm_client);

	return 0;
}
