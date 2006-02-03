/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * This applet used the GNOME Wireless Applet as a skeleton to build from.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gtk/gtk.h>
#include <libgnomeui/libgnomeui.h>
#include <glib/gi18n-lib.h>

#include "applet.h"

static void session_die (GnomeClient *client, gpointer client_data)
{
        gtk_main_quit ();
}

static gboolean session_save (GnomeClient *client, gpointer client_data)
{
        return TRUE;
}

int main (int argc, char *argv[])
{
	NMWirelessApplet *	nmwa;
	GnomeClient *		client = NULL;

	gnome_program_init ("nm-applet", VERSION, LIBGNOMEUI_MODULE,
			    argc, argv, 
			    GNOME_PARAM_NONE, GNOME_PARAM_NONE);

    	client = gnome_master_client ();
    	gnome_client_set_restart_style (client, GNOME_RESTART_NEVER);

    	g_signal_connect (client, "save_yourself", G_CALLBACK (session_save), NULL);
    	g_signal_connect (client, "die", G_CALLBACK (session_die), NULL);

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	if ((nmwa = nmwa_new ()))
	{
		gtk_widget_show_all (GTK_WIDGET (nmwa));
		gtk_main ();
	}

	return 0;
}
