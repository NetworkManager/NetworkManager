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
 * GNOME Wireless Applet Authors:
 *		Eskil Heyn Olsen <eskil@eskil.dk>
 *		Bastien Nocera <hadess@hadess.net> (Gnome2 port)
 *
 * (C) Copyright 2004 Red Hat, Inc.
 * (C) Copyright 2001, 2002 Free Software Foundation
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <dirent.h>

#include <gnome.h>
#include <panel-applet.h>
#include <panel-applet-gconf.h>
#include <glade/glade.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "NMWirelessApplet.h"
#include "NMWirelessAppletDbus.h"

#define CFG_UPDATE_INTERVAL 2

static char * pixmap_names[] =
{
	"broken-0.png",
	"no-link-0.png",
	"signal-1-40.png",
	"signal-41-60.png",
	"signal-61-80.png",
	"signal-81-100.png",
	"connect-0.png",
	"connect-1.png",
	"connect-2.png",
	"connect-3.png",
};


/* Represents an access point */
typedef struct
{
	char *	essid;
	gboolean	encrypted;
} AccessPoint;

static GladeXML	*xml = NULL;
static gchar		*glade_file = NULL;

static int		nmwa_timeout_handler	(NMWirelessApplet *applet);
static void		nmwa_about_cb			(BonoboUIComponent *uic, NMWirelessApplet *applet);
static GtkWidget *	nmwa_populate_menu		(NMWirelessApplet *applet);

static const BonoboUIVerb nmwa_context_menu_verbs [] =
{
	BONOBO_UI_UNSAFE_VERB ("NMWirelessAbout", nmwa_about_cb),
	BONOBO_UI_VERB_END
};


static GType nmwa_get_type (void)
{
	static GType type = 0;

	if (!type)
	{
		static const GTypeInfo info =
		{
			sizeof (PanelAppletClass),
			NULL, NULL, NULL, NULL, NULL,
			sizeof (NMWirelessApplet),
			0, NULL, NULL
		};

		type = g_type_register_static (PANEL_TYPE_APPLET, "NMWirelessApplet", &info, 0);
	}

	return (type);
}

static void nmwa_draw (NMWirelessApplet *applet)
{
	const char *label_text;
	char *tmp;

	if (applet->pixmaps[applet->pix_state] != applet->current_pixbuf)
	{
		applet->current_pixbuf = (GdkPixbuf *)applet->pixmaps[applet->pix_state];
		gtk_image_set_from_pixbuf (GTK_IMAGE (applet->pixmap), applet->current_pixbuf);
	}
}

static void nmwa_update_state (NMWirelessApplet *applet)
{
	if (applet->nm_active)
	{
		char *status = nmwa_dbus_get_nm_status (applet->connection);
		char *active_device = nmwa_dbus_get_active_device (applet->connection);

		if (active_device && status)
		{
			int	type = nmwa_dbus_get_device_type (applet->connection, active_device);

			switch (type)
			{
				case (DEVICE_TYPE_WIRELESS_ETHERNET):
					applet->have_active_device = TRUE;
					if (strcmp (status, "connected") == 0)
						applet->pix_state = PIX_SIGNAL_4;
					else if (strcmp (status, "connecting") == 0)
					{
						if (    (applet->pix_state < PIX_CONNECT_0)
							|| (applet->pix_state > PIX_CONNECT_2))
							applet->pix_state = PIX_CONNECT_0;
						else
							applet->pix_state++;
					}
					break;

				case (DEVICE_TYPE_WIRED_ETHERNET):
				default:
					applet->have_active_device = FALSE;
					applet->pix_state = PIX_BROKEN;
					break;
			}
		}
		else
		{
			applet->have_active_device = FALSE;
			applet->pix_state = PIX_BROKEN;
		}

		if (active_device)	dbus_free (active_device);
		if (status)		dbus_free (status);
	}
	else
	{
		applet->have_active_device = FALSE;
		applet->pix_state = PIX_BROKEN;
	}

	nmwa_draw (applet);
}

static void nmwa_start_timeout (NMWirelessApplet *applet)
{
	applet->timeout_handler_id = g_timeout_add (CFG_UPDATE_INTERVAL * 1000,
										(GtkFunction)nmwa_timeout_handler, applet);
}

static void nmwa_cancel_timeout (NMWirelessApplet *applet)
{
	g_source_remove (applet->timeout_handler_id);
	applet->timeout_handler_id = -1;
	nmwa_update_state (applet);
}


static void nmwa_load_theme (NMWirelessApplet *applet)
{
	char *pixmapdir;
	char *pixmapname;
	int i;

	pixmapdir = gnome_program_locate_file (NULL, GNOME_FILE_DOMAIN_PIXMAP,
			"NMWirelessApplet/", FALSE, NULL);

	for (i = 0; i < PIX_NUMBER; i++)
	{
		pixmapname = g_build_filename (G_DIR_SEPARATOR_S,
				pixmapdir, pixmap_names[i], NULL);
		applet->pixmaps[i] = gdk_pixbuf_new_from_file (pixmapname, NULL);
		g_free (pixmapname);
	}

	g_free (pixmapdir);
}

  
static int nmwa_timeout_handler (NMWirelessApplet *applet)
{
	/* Try to get a connection to dbus if we don't already have one */
	if (!applet->connection)
		applet->connection = nmwa_dbus_init (applet);

	nmwa_update_state (applet);

  	return (TRUE);
}

void show_error_dialog (gchar *mesg, ...) 
{
	GtkWidget	*dialog;
	char		*tmp;
	va_list	 ap;

	va_start (ap,mesg);
	tmp = g_strdup_vprintf (mesg,ap);
	dialog = gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, mesg, NULL);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_free (tmp);
	va_end (ap);
}

void show_warning_dialog (gchar *mesg, ...) 
{
	GtkWidget	*dialog;
	char		*tmp;
	va_list	 ap;

	va_start (ap,mesg);
	tmp = g_strdup_vprintf (mesg,ap);
	dialog = gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, mesg, NULL);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_free (tmp);
	va_end (ap);
}


static void nmwa_about_cb (BonoboUIComponent *uic, NMWirelessApplet *applet)
{
	GdkPixbuf	*pixbuf;
	char		*file;

	const gchar *authors[] =
	{
		"Dan Williams <dcbw@redhat.com>",
		"Eskil Heyn Olsen <eskil@eskil.org> (GNOME Wireless Applet)",
		"Bastien Nocera <hadess@hadess.net> (GNOME Wireless Applet)",
		NULL
	};

	if (applet->about_dialog != NULL)
	{
		gtk_window_set_screen (GTK_WINDOW (applet->about_dialog), gtk_widget_get_screen (GTK_WIDGET (&applet->base)));
		gtk_window_present (GTK_WINDOW (applet->about_dialog));
		return;
	}

	file = gnome_program_locate_file (NULL, GNOME_FILE_DOMAIN_PIXMAP, "NMWirelessApplet/wireless-applet.png", FALSE, NULL);
	pixbuf = gdk_pixbuf_new_from_file (file, NULL);
	g_free (file);

	applet->about_dialog = gnome_about_new (
			"Wireless Network Applet",
			VERSION,
			"(C) 2004 Red Hat, Inc.\n(C) Copyright 2001, 2002 Free Software Foundation",
			"This utility shows the status of a wireless networking link.",
			authors,
			NULL,
			NULL,
			pixbuf);

	g_object_unref (pixbuf);

	gtk_window_set_screen (GTK_WINDOW (applet->about_dialog), gtk_widget_get_screen (GTK_WIDGET (applet)));
	g_signal_connect (applet->about_dialog, "destroy", G_CALLBACK (gtk_widget_destroyed), &applet->about_dialog);
	gtk_widget_show (applet->about_dialog);

	return;
}


static void nmwa_destroy (NMWirelessApplet *applet, gpointer user_data)
{
	int i;
	
	if (applet->menu)
		gtk_widget_destroy (applet->menu);

	if (applet->timeout_handler_id > 0)
	{
		gtk_timeout_remove (applet->timeout_handler_id);
		applet->timeout_handler_id = 0;
	}

	for (i = 0; i < PIX_NUMBER; i++)
		g_object_unref (applet->pixmaps[i]);

	if (applet->about_dialog)
	{
		gtk_widget_destroy (applet->about_dialog);
		applet->about_dialog = NULL;
	}
}


static void nmwa_get_menu_pos (GtkMenu *menu, gint *x, gint *y, gboolean *push_in, gpointer data)
{
	NMWirelessApplet	*applet = data;
	GtkRequisition		 reqmenu, reqapplet;
	gint				 tempx, tempy, width, height;
	gint				 screen_width, screen_height;
	
	gtk_widget_size_request (GTK_WIDGET (menu), &reqmenu);
	gdk_window_get_origin (GTK_WIDGET (applet)->window, &tempx, &tempy);
	gdk_window_get_geometry (GTK_WIDGET (applet)->window, NULL, NULL, &width, &height, NULL);

	switch (panel_applet_get_orient (PANEL_APPLET (applet)))
	{
		case PANEL_APPLET_ORIENT_DOWN:
			tempy += height;
			break;
		case PANEL_APPLET_ORIENT_UP:
			tempy -= reqmenu.height;
			break;
		case PANEL_APPLET_ORIENT_LEFT:
			tempx -= reqmenu.width;
			break;
		case PANEL_APPLET_ORIENT_RIGHT:
			tempx += width;
			break;
	}
	screen_width = gdk_screen_width ();
	screen_height = gdk_screen_height ();
	*x = CLAMP (tempx, 0, MAX (0, screen_width - reqmenu.width));
	*y = CLAMP (tempy, 0, MAX (0, screen_height - reqmenu.height));
}


static void nmwa_button_clicked (GtkWidget *button, NMWirelessApplet *applet)
{
	if (applet->menu != NULL) 
	{
	  gtk_menu_popdown (GTK_MENU (applet->menu));
	  g_object_unref(G_OBJECT(applet->menu));
	  applet->menu = NULL;
	}
	else
	{
		applet->menu = nmwa_populate_menu (applet);
		gtk_menu_popup (GTK_MENU (applet->menu), NULL, NULL, nmwa_get_menu_pos, applet, 0, gtk_get_current_event_time());
	}
}


/*
 * nmwa_add_menu_item
 *
 * Callback from nmwa_dbus_add_networks_to_menu() during network enumeration.
 * Given a network, add it to our networks menu.
 *
 */
void nmwa_add_menu_item (char *network, gboolean current, gpointer user_data)
{
	GtkWidget		*menu = (GtkWidget *)user_data;
	GtkWidget		*menu_item;

	g_return_if_fail (network != NULL);
	g_return_if_fail (menu != NULL);

	menu_item = gtk_check_menu_item_new_with_label (network);
	gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (menu_item), current);
	gtk_widget_show (menu_item);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
}


/*
 * nmwa_populate_menu
 *
 * Set up our networks menu from scratch
 *
 */
static GtkWidget * nmwa_populate_menu (NMWirelessApplet *applet)
{
	GtkWidget		 *menu;
	GtkWidget		 *menu_item;
	int		 	  num_networks;
	char			**networks;

	g_assert(applet->nm_active);
	g_return_if_fail (applet != NULL);

	menu = gtk_menu_new ();

	nmwa_dbus_add_networks_to_menu (applet->connection, menu);

	return (menu);
}


static void nmwa_setup_widgets (NMWirelessApplet *applet)
{
	GtkRequisition	 req;
	gint			 total_size = 0;
	gboolean		 horizontal = FALSE;
	gint			 panel_size;
	GtkWidget		*menu_item;
	
	panel_size = panel_applet_get_size (PANEL_APPLET (applet));
	switch (panel_applet_get_orient(PANEL_APPLET (applet)))
	{
		case PANEL_APPLET_ORIENT_LEFT:
		case PANEL_APPLET_ORIENT_RIGHT:
			horizontal = FALSE;
			break;
		case PANEL_APPLET_ORIENT_UP:
		case PANEL_APPLET_ORIENT_DOWN:
			horizontal = TRUE;
			break;
	}

	/* construct pixmap widget */
	applet->pixmap = gtk_image_new ();
	gtk_image_set_from_pixbuf (GTK_IMAGE (applet->pixmap), applet->pixmaps[PIX_BROKEN]);
	gtk_widget_size_request (applet->pixmap, &req);
	gtk_widget_show (applet->pixmap);

	if (horizontal)
		total_size += req.height;
	else
		total_size += req.width;
	
	/* pack */
	if (applet->button)
		gtk_widget_destroy (applet->button);

	if (horizontal && (total_size <= panel_size))
		applet->box = gtk_vbox_new (FALSE, 0);
	else if (horizontal && (total_size > panel_size))
		applet->box = gtk_hbox_new (FALSE, 0);
	else if (!horizontal && (total_size <= panel_size))
		applet->box = gtk_hbox_new (FALSE, 0);
	else 
		applet->box = gtk_vbox_new (FALSE, 0);

	applet->button = gtk_button_new ();
	g_signal_connect(applet->button, "clicked", G_CALLBACK(nmwa_button_clicked), applet);
	gtk_button_set_relief (GTK_BUTTON (applet->button), GTK_RELIEF_NONE);
	gtk_container_add (GTK_CONTAINER(applet->button), applet->box);

	gtk_box_pack_start (GTK_BOX (applet->box), applet->pixmap, TRUE, TRUE, 0);
	gtk_widget_show (applet->button);
	gtk_widget_show (applet->box);
	gtk_container_add (GTK_CONTAINER (applet), applet->button);

	applet->current_pixbuf = NULL;
	applet->about_dialog = NULL;

	applet->menu = NULL;
}

static void change_size_cb(PanelApplet *pa, gint s, NMWirelessApplet *applet)
{
	nmwa_setup_widgets (applet);
	nmwa_timeout_handler (applet);
}

static void change_orient_cb(PanelApplet *pa, gint s, NMWirelessApplet *applet)
{
	nmwa_setup_widgets (applet);
	nmwa_timeout_handler (applet);
}

static gboolean do_not_eat_button_press (GtkWidget *widget, GdkEventButton *event)
{
	if (event->button != 1)
		g_signal_stop_emission_by_name (widget, "button_press_event");

	return (FALSE);
}

static void change_background_cb(PanelApplet *a, PanelAppletBackgroundType type,
				GdkColor *color, GdkPixmap *pixmap, NMWirelessApplet *applet)
{
	GtkRcStyle *rc_style = gtk_rc_style_new ();

	switch (type)
	{
		case PANEL_PIXMAP_BACKGROUND:
			gtk_widget_modify_style (GTK_WIDGET (applet), rc_style);
			break;

		case PANEL_COLOR_BACKGROUND:
			gtk_widget_modify_bg (GTK_WIDGET (applet), GTK_STATE_NORMAL, color);
			break;

		case PANEL_NO_BACKGROUND:
			gtk_widget_modify_style (GTK_WIDGET (applet), rc_style);
			break;

		default:
			gtk_widget_modify_style (GTK_WIDGET (applet), rc_style);
			break;
	}

	gtk_rc_style_unref (rc_style);
}

static GtkWidget * nmwa_new (NMWirelessApplet *applet)
{
	panel_applet_set_flags (PANEL_APPLET (applet), PANEL_APPLET_EXPAND_MINOR);

	gtk_widget_hide(GTK_WIDGET(applet));

	applet->pix_state = PIX_BROKEN;
	applet->connection = nmwa_dbus_init(applet);
	applet->have_active_device = FALSE;
	applet->nm_active = nmwa_dbus_nm_is_running(applet->connection);
	
	nmwa_load_theme (applet);
	nmwa_setup_widgets (applet);

	g_signal_connect (applet,"destroy", G_CALLBACK (nmwa_destroy),NULL);
	g_signal_connect (applet->button, "button_press_event", G_CALLBACK (do_not_eat_button_press), NULL);

	nmwa_timeout_handler (applet);
	nmwa_start_timeout (applet);

	panel_applet_setup_menu_from_file (PANEL_APPLET (applet), NULL, "NMWirelessApplet.xml", NULL,
						nmwa_context_menu_verbs, applet);

	if (panel_applet_get_locked_down (PANEL_APPLET (applet)))
	{
		BonoboUIComponent *popup_component;

		popup_component = panel_applet_get_popup_component (PANEL_APPLET (applet));
		bonobo_ui_component_set_prop (popup_component, "/commands/NMWirelessApplet", "hidden", "1", NULL);
	}

	g_signal_connect (G_OBJECT (applet), "change_size", G_CALLBACK (change_size_cb), applet);
	g_signal_connect (G_OBJECT (applet), "change_orient", G_CALLBACK (change_orient_cb), applet);
 	g_signal_connect (G_OBJECT (applet), "change_background", G_CALLBACK (change_background_cb), applet);

	return (GTK_WIDGET (applet));
}

static gboolean nmwa_fill (NMWirelessApplet *applet)
{
	gnome_window_icon_set_default_from_file (ICONDIR"/NMWirelessApplet/wireless-applet.png");

	glade_gnome_init ();
	glade_file = gnome_program_locate_file (NULL, GNOME_FILE_DOMAIN_DATADIR,
		 "NMWirelessApplet/wireless-applet.glade", FALSE, NULL);

	gtk_widget_show (nmwa_new (applet));
	return (TRUE);
}

static gboolean nmwa_factory (NMWirelessApplet *applet, const gchar *iid, gpointer data)
{
	gboolean retval = FALSE;

	if (!strcmp (iid, "OAFIID:NMWirelessApplet"))
		retval = nmwa_fill (applet);

	return (retval);
}

PANEL_APPLET_BONOBO_FACTORY ("OAFIID:NMWirelessApplet_Factory",
		nmwa_get_type (),
		"wireless",
		"0",
		(PanelAppletFactoryCallback) nmwa_factory,
		NULL)

