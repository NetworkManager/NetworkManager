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
#include <gconf/gconf-client.h>

#include "config.h"
#include "NMWirelessApplet.h"
#include "NMWirelessAppletDbus.h"

#define CFG_UPDATE_INTERVAL 1
#define NM_GCONF_WIRELESS_NETWORKS_PATH		"/system/networking/wireless/networks"

static char * pixmap_names[] =
{
	"no-networkmanager.png",
	"wired.png",
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

static char *glade_file;

static void		nmwa_about_cb		(BonoboUIComponent *uic, NMWirelessApplet *applet);
static GtkWidget *	nmwa_populate_menu	(NMWirelessApplet *applet);
static void		nmwa_dispose_menu_items (NMWirelessApplet *applet);

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


/*
 * nmwa_redraw
 *
 * Actually update the applet's pixmap so that our panel icon reflects
 * the state of the applet
 *
 */
static void nmwa_redraw (NMWirelessApplet *applet)
{
	if (applet->pixmaps[applet->pix_state] != applet->current_pixbuf)
	{
		applet->current_pixbuf = (GdkPixbuf *)applet->pixmaps[applet->pix_state];
		gtk_image_set_from_pixbuf (GTK_IMAGE (applet->pixmap), applet->current_pixbuf);
	}
}


/*
 * nmwa_update_state
 *
 * Figure out what the currently active device is from NetworkManager, its type,
 * and what our icon on the panel should look like for each type.
 *
 */
static void nmwa_update_state (NMWirelessApplet *applet)
{
	switch (applet->applet_state)
	{
		case (APPLET_STATE_NO_NM):
			applet->pix_state = PIX_NO_NETWORKMANAGER;
			break;

		case (APPLET_STATE_NO_CONNECTION):
			applet->pix_state = PIX_WIRED;	/* FIXME: get a "no connection" picture */
			break;

		case (APPLET_STATE_WIRED):
		case (APPLET_STATE_WIRED_CONNECTING):
			applet->pix_state = PIX_WIRED;
			break;

		case (APPLET_STATE_WIRELESS):
			applet->pix_state = PIX_WIRELESS_SIGNAL_4;
			break;

		case (APPLET_STATE_WIRELESS_CONNECTING):
			if (applet->pix_state < PIX_WIRELESS_CONNECT_0)
				applet->pix_state = PIX_WIRELESS_CONNECT_0;
			else if (applet->pix_state >= PIX_WIRELESS_CONNECT_3)
				applet->pix_state = PIX_WIRELESS_CONNECT_0;
			else
				applet->pix_state++;
			break;

		default:
			break;
	}
}


/*
 * nmwa_redraw_timeout
 *
 * Called regularly to update the applet's state and icon in the panel
 *
 */  
static int nmwa_redraw_timeout (NMWirelessApplet *applet)
{
	nmwa_update_state (applet);
	nmwa_redraw (applet);

  	return (TRUE);
}

static void nmwa_start_redraw_timeout (NMWirelessApplet *applet)
{
	applet->redraw_timeout_id = g_timeout_add (CFG_UPDATE_INTERVAL * 1000,
										(GtkFunction)nmwa_redraw_timeout, applet);
}

static void nmwa_cancel_timeout (NMWirelessApplet *applet)
{
	g_source_remove (applet->redraw_timeout_id);
	applet->redraw_timeout_id = -1;
	nmwa_update_state (applet);
	nmwa_redraw (applet);
}


static void nmwa_load_theme (NMWirelessApplet *applet)
{
	char		*pixmapdir;
	char		*pixmapname;
	int		 i;
	GError	*error = NULL;

	pixmapdir = gnome_program_locate_file (NULL, GNOME_FILE_DOMAIN_PIXMAP,
			"NMWirelessApplet/", FALSE, NULL);

	for (i = 0; i < PIX_NUMBER; i++)
	{
		pixmapname = g_build_filename (G_DIR_SEPARATOR_S,
				pixmapdir, pixmap_names[i], NULL);
		applet->pixmaps[i] = gdk_pixbuf_new_from_file_at_size (pixmapname, 32, 16, NULL);
		g_free (pixmapname);
	}

	pixmapname = g_build_filename (G_DIR_SEPARATOR_S, pixmapdir, "keyring.png", NULL);
	applet->key_pixbuf = gdk_pixbuf_new_from_file_at_size (pixmapname, 16, 16, &error);
	g_free (pixmapname);
	pixmapname = g_build_filename (G_DIR_SEPARATOR_S, pixmapdir, "wired.png", NULL);
	applet->wired_icon = gdk_pixbuf_new_from_file_at_size (pixmapname, 16, 16, &error);
	g_free (pixmapname);
	pixmapname = g_build_filename (G_DIR_SEPARATOR_S, pixmapdir, "wireless.png", NULL);
	applet->wireless_icon = gdk_pixbuf_new_from_file_at_size (pixmapname, 16, 16, &error);
	g_free (pixmapname);

	g_free (pixmapdir);
}


/*
 * show_warning_dialog
 *
 * pop up a warning or error dialog with certain text
 *
 */
static void show_warning_dialog (gboolean error, gchar *mesg, ...) 
{
	GtkWidget	*dialog;
	char		*tmp;
	va_list	 ap;

	va_start (ap,mesg);
	tmp = g_strdup_vprintf (mesg,ap);
	dialog = gtk_message_dialog_new (NULL, 0, error ? GTK_MESSAGE_ERROR : GTK_MESSAGE_WARNING,
								GTK_BUTTONS_OK, mesg, NULL);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_free (tmp);
	va_end (ap);
}


/*
 * nmwa_about_cb
 *
 * Display our about dialog
 *
 */
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


/*
 * nmwa_destroy
 *
 * Destroy the applet and clean up its data
 *
 */
static void nmwa_destroy (NMWirelessApplet *applet, gpointer user_data)
{
	int i;
	
	if (applet->menu)
		nmwa_dispose_menu_items (applet);

	if (applet->redraw_timeout_id > 0)
	{
		gtk_timeout_remove (applet->redraw_timeout_id);
		applet->redraw_timeout_id = 0;
	}

	for (i = 0; i < PIX_NUMBER; i++)
		g_object_unref (applet->pixmaps[i]);

	if (applet->about_dialog)
	{
		gtk_widget_destroy (applet->about_dialog);
		applet->about_dialog = NULL;
	}

	if (applet->gconf_client)
		g_object_unref (G_OBJECT (applet->gconf_client));
}


/*
 * nmwa_get_menu_pos
 *
 * When displaying the popup menu, figure out exactly where to put it on the screen
 *
 */
static void nmwa_get_menu_pos (GtkMenu *menu, gint *x, gint *y, gboolean *push_in, gpointer data)
{
	NMWirelessApplet	*applet = data;
	GtkRequisition		 reqmenu;
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


/*
 * nmwa_handle_network_choice
 *
 * Ask the user whether to add the network they have chosen to the trusted
 * networks list, and then stuff the network into gconf in either the trusted
 * or preferred networks list depending on their choice.  This notifies
 * NetworkInfoManager that the networks list has changed, and it notifies
 * NetworkManager about those changes, triggering an AP switch.
 */
void nmwa_handle_network_choice (NMWirelessApplet *applet, char *network)
{
	GConfEntry	*gconf_entry;
	char			*key;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (network != NULL);

	/* Update GConf to set timestamp for this network, or add it if
	 * it doesn't already exist.
	 */

	/* Update timestamp on network */
	key = g_strdup_printf ("%s/%s/timestamp", NM_GCONF_WIRELESS_NETWORKS_PATH, network);
	gconf_client_set_int (applet->gconf_client, key, time (NULL), NULL);
	g_free (key);

	/* Force-set the essid too so that we have a semi-complete network entry */
	key = g_strdup_printf ("%s/%s/essid", NM_GCONF_WIRELESS_NETWORKS_PATH, network);
	gconf_client_set_string (applet->gconf_client, key, network, NULL);
	g_free (key);

	fprintf (stderr, "Forcing network '%s'\n", network);
	nmwa_dbus_set_network (applet->connection, network);
}


/*
 * nmwa_menu_item_activate
 *
 * Signal function called when user clicks on a menu item
 *
 */
void nmwa_menu_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	char				*tag;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	if ((tag = g_object_get_data (G_OBJECT (item), "network")))
		nmwa_handle_network_choice (applet, tag);
	else if ((tag = g_object_get_data (G_OBJECT (item), "device")))
		nmwa_dbus_set_device (applet->connection, tag);
}


/*
 * nmwa_toplevel_menu_activate
 *
 * Pop up the wireless networks menu in response to a click on the applet
 *
 */
static void nmwa_toplevel_menu_activate (GtkWidget *menu, NMWirelessApplet *applet)
{
	nmwa_dispose_menu_items (applet);
	nmwa_populate_menu (applet);
	gtk_widget_show (applet->menu);
}


/*
 * nmwa_menu_add_separator_item
 *
 */
void nmwa_menu_add_separator_item (GtkWidget *menu)
{
	GtkWidget	*menu_item;

	menu_item = gtk_separator_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nmwa_menu_add_text_item
 *
 * Add a non-clickable text item to a menu
 *
 */
void nmwa_menu_add_text_item (GtkWidget *menu, char *text)
{
	GtkWidget		*menu_item;

	g_return_if_fail (text != NULL);
	g_return_if_fail (menu != NULL);

	menu_item = gtk_menu_item_new_with_label (text);
	gtk_widget_set_sensitive (menu_item, FALSE);

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nmwa_menu_add_device_item
 *
 * Add a network device to the menu
 *
 */
void nmwa_menu_add_device_item (GtkWidget *menu, GdkPixbuf *icon, char *name, char *nm_device, gboolean current, gpointer user_data)
{
	GtkWidget		*menu_item;
	GtkWidget		*label;
	GtkWidget		*hbox;
	GtkWidget		*image;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (icon != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (nm_device != NULL);

	menu_item = gtk_menu_item_new ();
	hbox = gtk_hbox_new (FALSE, 5);
	gtk_container_add (GTK_CONTAINER (menu_item), hbox);
	gtk_widget_show (hbox);

	if ((image = gtk_image_new_from_pixbuf (icon)))
	{
		gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 2);
		gtk_widget_show (image);
	}

	label = gtk_label_new (name);
	if (current)
	{
		char *markup = g_strdup_printf ("<span weight=\"bold\">%s</span>", name);
		gtk_label_set_markup (GTK_LABEL (label), markup);
		g_free (markup);
	}
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_box_pack_start (GTK_BOX (hbox), label, TRUE, TRUE, 2);
	gtk_widget_show (label);

	g_object_set_data (G_OBJECT (menu_item), "device", g_strdup (nm_device));
	g_signal_connect(G_OBJECT (menu_item), "activate", G_CALLBACK(nmwa_menu_item_activate), user_data);

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nmwa_menu_add_devices
 *
 */
void nmwa_menu_add_devices (GtkWidget *menu, NMWirelessApplet *applet)
{
	GSList	*element;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	g_mutex_lock (applet->data_mutex);
	element = applet->devices;
	if (!element)
		nmwa_menu_add_text_item (menu, _("There are no network devices..."));
	else
	{
		/* Add all devices in our device list to the menu */
		while (element)
		{
			NetworkDevice *dev = (NetworkDevice *)(element->data);

			if (dev && ((dev->type == DEVICE_TYPE_WIRED_ETHERNET) || (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET)))
			{
				GdkPixbuf	*icon = (dev->type == DEVICE_TYPE_WIRED_ETHERNET) ? applet->wired_icon : applet->wireless_icon;
				char		*name_string;
				gboolean	 current = applet->active_device ? (strcmp (applet->active_device, dev->nm_device) == 0) : FALSE;

				name_string = g_strdup_printf ("%s (%s)", (dev->hal_name ? dev->hal_name : dev->nm_name),
						(dev->type == DEVICE_TYPE_WIRED_ETHERNET) ? "wired" : "wireless");
				nmwa_menu_add_device_item (menu, icon, name_string, dev->nm_device, current, applet);
			}

			element = g_slist_next (element);
		}
	}
	g_mutex_unlock (applet->data_mutex);
}


/*
 * nmwa_menu_add_network
 *
 * Add a wireless network menu item
 *
 */
void nmwa_menu_add_network (GtkWidget *menu, GdkPixbuf *key, char *text, char *network, gboolean current,
						gboolean encrypted, guint8 quality, gpointer user_data)
{
	GtkWidget		*menu_item;
	GtkWidget		*label;
	GtkWidget		*hbox;
	GtkWidget		*progress;
	float		 percent;

	g_return_if_fail (text != NULL);
	g_return_if_fail (menu != NULL);

	menu_item = gtk_menu_item_new ();
	hbox = gtk_hbox_new (FALSE, 5);
	gtk_container_add (GTK_CONTAINER (menu_item), hbox);
	gtk_widget_show (hbox);

	label = gtk_label_new (text);
	if (current)
	{
		char *markup = g_strdup_printf ("<span weight=\"bold\">%s</span>", text);
		gtk_label_set_markup (GTK_LABEL (label), markup);
		g_free (markup);
	}
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_box_pack_start (GTK_BOX (hbox), label, TRUE, TRUE, 2);
	gtk_widget_show (label);

	progress = gtk_progress_bar_new ();
	percent = ((float)quality / (float)0x100);
	percent = (percent < 0 ? 0 : (percent > 1.0 ? 1.0 : percent));
	gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progress), percent);
	gtk_box_pack_start (GTK_BOX (hbox), progress, TRUE, TRUE, 0);
	gtk_widget_show (progress);

	if (encrypted)
	{
		GtkWidget		*image;

		if ((image = gtk_image_new_from_pixbuf (key)))
		{
			gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 2);
			gtk_widget_show (image);
		}
	}

	g_object_set_data (G_OBJECT (menu_item), "network", g_strdup (network));
	g_signal_connect(G_OBJECT (menu_item), "activate", G_CALLBACK(nmwa_menu_item_activate), user_data);

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nmwa_menu_add_networks
 *
 */
void nmwa_menu_add_networks (GtkWidget *menu, NMWirelessApplet *applet)
{
	GSList	*element;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	g_mutex_lock (applet->data_mutex);
	element = applet->networks;
	if (!element)
		nmwa_menu_add_text_item (menu, _("There are no wireless networks..."));
	else
	{
		nmwa_menu_add_text_item (menu, _("Wireless Networks"));

		/* Add all networks in our network list to the menu */
		while (element)
		{
			WirelessNetwork *net = (WirelessNetwork *)(element->data);

			if (net)
				nmwa_menu_add_network (menu, applet->key_pixbuf, net->essid,
						net->essid, net->active, net->encrypted, net->quality, applet);

			element = g_slist_next (element);
		}
	}
	g_mutex_unlock (applet->data_mutex);
}

/*
 * nmwa_menu_item_data_free
 *
 * Frees the "network" data tag on a menu item we've created
 *
 */
static void nmwa_menu_item_data_free (GtkWidget *menu_item, gpointer data)
{
	char	*tag;
	GtkWidget *menu;

	g_return_if_fail (menu_item != NULL);

	menu = GTK_WIDGET(data);

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "network")))
	{
		g_object_set_data (G_OBJECT (menu_item), "network", NULL);
		g_free (tag);
	}

	gtk_container_remove(GTK_CONTAINER(menu), menu_item);
}


/*
 * nmwa_dispose_menu_items
 *
 * Destroy the menu and each of its items data tags
 *
 */
void nmwa_dispose_menu_items (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	/* Free the "network" data on each menu item */
	gtk_container_foreach (GTK_CONTAINER (applet->menu), nmwa_menu_item_data_free, applet->menu);
}


/*
 * nmwa_populate_menu
 *
 * Set up our networks menu from scratch
 *
 */
GtkWidget * nmwa_populate_menu (NMWirelessApplet *applet)
{
	GtkWidget		 *menu = applet->menu;

	g_return_val_if_fail (applet != NULL, NULL);

	if (applet->applet_state == APPLET_STATE_NO_NM)
	{
		nmwa_menu_add_text_item (menu, _("NetworkManager is not running..."));
		return NULL;
	}

	nmwa_menu_add_text_item (menu, _("Network Connections"));
	nmwa_menu_add_devices (menu, applet);
	nmwa_menu_add_separator_item (menu);	

	switch (applet->applet_state)
	{
		case (APPLET_STATE_NO_CONNECTION):
			nmwa_menu_add_text_item (menu, _("No network connection is currently active..."));
			break;

		case (APPLET_STATE_WIRED):
		case (APPLET_STATE_WIRED_CONNECTING):
			nmwa_menu_add_text_item (menu, _("A wired network connection is currently active..."));
			break;

		case (APPLET_STATE_WIRELESS):
		case (APPLET_STATE_WIRELESS_CONNECTING):
			nmwa_menu_add_networks (menu, applet);
			break;

		default:
			break;
	}

	return (menu);
}


/*
 * mnwa_setup_widgets
 *
 * Intialize the applet's widgets and packing, create the initial
 * menu of networks.
 *
 */
static void nmwa_setup_widgets (NMWirelessApplet *applet)
{
	gboolean		 horizontal = FALSE;
	gint			 panel_size;
	GtkWidget      *menu_bar;

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
	gtk_image_set_from_pixbuf (GTK_IMAGE (applet->pixmap), applet->pixmaps[PIX_WIRED]);
	//gtk_widget_size_request (applet->pixmap, &req);
	gtk_widget_show (applet->pixmap);

	/*
	if (horizontal)
		total_size += req.height;
	else
		total_size += req.width;
	*/

	menu_bar = gtk_menu_bar_new ();
	applet->toplevel_menu = gtk_menu_item_new();
	gtk_container_add (GTK_CONTAINER(applet->toplevel_menu), applet->pixmap);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), applet->toplevel_menu);
	g_signal_connect(applet->toplevel_menu, "activate", G_CALLBACK(nmwa_toplevel_menu_activate), applet);

	applet->menu = gtk_menu_new();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM(applet->toplevel_menu), applet->menu);

	gtk_widget_show (menu_bar);
	gtk_widget_show (applet->toplevel_menu);
	gtk_widget_show (applet->menu);

	gtk_container_add (GTK_CONTAINER (applet), menu_bar);

	applet->current_pixbuf = NULL;
	applet->about_dialog = NULL;
}

static void change_size_cb(PanelApplet *pa, gint s, NMWirelessApplet *applet)
{
	nmwa_setup_widgets (applet);
	nmwa_redraw_timeout (applet);
}

static void change_orient_cb(PanelApplet *pa, gint s, NMWirelessApplet *applet)
{
	nmwa_setup_widgets (applet);
	nmwa_redraw_timeout (applet);
}

static gboolean do_not_eat_button_press (GtkWidget *widget, GdkEventButton *event)
{
     printf ("Getting button press\n");
	/*if (event->button != 1)
		g_signal_stop_emission_by_name (widget, "button_press_event");
	*/
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


/*
 * nmwa_new
 *
 * Create the initial instance of our wireless applet
 *
 */
static GtkWidget * nmwa_new (NMWirelessApplet *applet)
{
	GError	*error = NULL;

	panel_applet_set_flags (PANEL_APPLET (applet), PANEL_APPLET_EXPAND_MINOR);
	gtk_widget_hide(GTK_WIDGET(applet));

	applet->gconf_client = gconf_client_get_default ();
	if (!applet->gconf_client)
		return (NULL);

	applet->ui_resources = glade_xml_new(glade_file, NULL, NULL);
	if (!applet->ui_resources)
	{
		show_warning_dialog (TRUE, _("The NetworkManager Applet could not find some required resources (the glade file was not found).")); 
		g_object_unref (G_OBJECT (applet->gconf_client));
		return (NULL);
	}

	applet->applet_state = APPLET_STATE_NO_NM;
	applet->networks = NULL;
	applet->devices = NULL;
	applet->active_device = NULL;

	/* Start our dbus thread */
	if (!(applet->data_mutex = g_mutex_new ()))
	{
		g_object_unref (G_OBJECT (applet->gconf_client));
		/* FIXME: free glade file */
		return (NULL);
	}
	if (!(applet->dbus_thread = g_thread_create (nmwa_dbus_worker, applet, FALSE, &error)))
	{
		g_mutex_free (applet->data_mutex);
		g_object_unref (G_OBJECT (applet->gconf_client));
		/* FIXME: free glade file */
		return (NULL);
	}

	/* Load pixmaps and create applet widgets */
	nmwa_load_theme (applet);
	nmwa_setup_widgets (applet);

	g_signal_connect (applet,"destroy", G_CALLBACK (nmwa_destroy),NULL);
	//g_signal_connect (applet->toplevel_menu, "button_press_event", G_CALLBACK (do_not_eat_button_press), NULL);

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

	/* Start redraw timeout */
	nmwa_start_redraw_timeout (applet);

	return (GTK_WIDGET (applet));
}

static gboolean nmwa_fill (NMWirelessApplet *applet)
{
	gnome_window_icon_set_default_from_file (ICONDIR"/NMWirelessApplet/wireless-applet.png");

	glade_gnome_init ();
	glade_file = gnome_program_locate_file (NULL, GNOME_FILE_DOMAIN_DATADIR,
		 "NMWirelessApplet/wireless-applet.glade", FALSE, NULL);
	if (!glade_file)
	{
		show_warning_dialog (TRUE, _("The NetworkManager Applet could not find some required resources (the glade file was not found).")); 
		return (FALSE);
	}

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

