/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * (C) Copyright 2004-2005 Red Hat, Inc.
 * (C) Copyright 2001, 2002 Free Software Foundation
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <libgnomeui/libgnomeui.h>

#if !GTK_CHECK_VERSION(2,6,0)
#include <gnome.h>
#endif

#include <glade/glade.h>
#include <gconf/gconf-client.h>

#ifdef ENABLE_NOTIFY
#include <libnotify/notify.h>
#endif

#include "applet.h"
#include "applet-compat.h"
#include "applet-dbus.h"
#include "applet-dbus-devices.h"
#include "applet-dbus-vpn.h"
#include "applet-dbus-info.h"
#include "applet-notifications.h"
#include "other-network-dialog.h"
#include "passphrase-dialog.h"
#include "menu-items.h"
#include "vpn-password-dialog.h"
#include "vpn-connection.h"
#include "nm-utils.h"
#include "dbus-method-dispatcher.h"

/* Compat for GTK 2.4 and lower... */
#if (GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 6)
	#define GTK_STOCK_MEDIA_PAUSE		GTK_STOCK_STOP
	#define GTK_STOCK_MEDIA_PLAY		GTK_STOCK_REFRESH
	#define GTK_STOCK_ABOUT			GTK_STOCK_DIALOG_INFO
	#define GTK_STOCK_INFO			GTK_STOCK_DIALOG_INFO
#endif

/* Compat for GTK 2.6 */
#if (GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION == 6)
	#define GTK_STOCK_INFO			GTK_STOCK_DIALOG_INFO
#endif

static GObject *				nma_constructor (GType type, guint n_props, GObjectConstructParam *construct_props);
static gboolean				nma_icons_init (NMApplet *applet);
static void					nma_icons_free (NMApplet *applet);
static void					nma_context_menu_update (NMApplet *applet);
static GtkWidget *				nma_get_instance (NMApplet *applet);
static void					nma_dropdown_menu_deactivate_cb (GtkWidget *menu, NMApplet *applet);
static G_GNUC_NORETURN void		nma_destroy (NMApplet *applet);
static GType					nma_get_type (void);	/* for G_DEFINE_TYPE */

G_DEFINE_TYPE(NMApplet, nma, EGG_TYPE_TRAY_ICON)

/*
 * nm_null_safe_strcmp
 *
 * Doesn't freaking segfault if s1/s2 are NULL
 *
 */
int nm_null_safe_strcmp (const char *s1, const char *s2)
{
	if (!s1 && !s2)
		return 0;
	if (!s1 && s2)
		return -1;
	if (s1 && !s2)
		return 1;
		
	return (strcmp (s1, s2));
}


/*
 * nma_get_first_active_device
 *
 * Return the first device marked as "active".
 *
 */
NetworkDevice * nma_get_first_active_device (GSList *dev_list)
{
	GSList *	elt;

	for (elt = dev_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice *dev = (NetworkDevice *)(elt->data);
		if (network_device_get_active (dev))
			return dev;
	}

	return NULL;
}


static void nma_init (NMApplet *applet)
{
	applet->animation_id = 0;
	applet->animation_step = 0;
	glade_gnome_init ();

	if (!nma_icons_init (applet))
		return;

/*	gtk_window_set_default_icon_from_file (ICONDIR"/NMApplet/wireless-applet.png", NULL); */
	gtk_widget_show (nma_get_instance (applet));
}

static void nma_class_init (NMAppletClass *klass)
{
	GObjectClass *gobject_class;

	gtk_icon_theme_append_search_path (gtk_icon_theme_get_default (),
								ICONDIR);

	gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->constructor = nma_constructor;
}

static GObject *nma_constructor (GType type, guint n_props, GObjectConstructParam *construct_props)
{
	GObject *obj;
	NMApplet *applet;
	NMAppletClass *klass;

	klass = NM_APPLET_CLASS (g_type_class_peek (type));
	obj = G_OBJECT_CLASS (nma_parent_class)->constructor (type, n_props, construct_props);
	applet =  NM_APPLET (obj);

	return obj;
}

static GtkWidget * get_label (GtkWidget *info_dialog, GladeXML *xml, const char *name)
{
	GtkWidget *label;

	if (xml != NULL)
	{
		label = glade_xml_get_widget (xml, name);
		g_object_set_data (G_OBJECT (info_dialog), name, label);
	}
	else
		label = g_object_get_data (G_OBJECT (info_dialog), name);

	return label;
}

static void nma_show_socket_err (GtkWidget *info_dialog, const char *err)
{
	GtkWidget *error_dialog;

	error_dialog = gtk_message_dialog_new_with_markup (GTK_WINDOW (info_dialog), 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
			"<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s", _("Error displaying connection information:"), err);
	gtk_window_present (GTK_WINDOW (error_dialog));
	g_signal_connect_swapped (error_dialog, "response", G_CALLBACK (gtk_widget_destroy), error_dialog);
}

static gboolean nma_update_info (NMApplet *applet)
{
	GtkWidget *info_dialog;
	char *addr = NULL, *broadcast = NULL, *primary_dns = NULL, *secondary_dns = NULL;
	char *mac = NULL, *iface_and_type = NULL, *route = NULL, *mask = NULL, *speed = NULL;
	GtkWidget *label;
	int mbs;
	const char *iface = NULL, *driver = NULL;
	NetworkDevice *dev;

	info_dialog = glade_xml_get_widget (applet->info_dialog_xml, "info_dialog");
	if (!info_dialog)
	{
		char *err = g_strdup (_("Could not find some required resources (the glade file)!"));
		nma_show_socket_err (info_dialog, err);
		g_free (err);
		return FALSE;
	}
	
	if ((dev = nma_get_first_active_device (applet->device_list)))
		iface = network_device_get_iface (dev);

	if (!dev || !iface)
	{
		char *err = g_strdup (_("No active connections!"));
		nma_show_socket_err (info_dialog, err);
		g_free (err);
		return FALSE;
	}

	if (!(driver = network_device_get_driver (dev)))
		driver = "(unknown)";
	mac = (char*) network_device_get_address (dev);
	broadcast = (char*) network_device_get_broadcast (dev);
	addr = (char*) network_device_get_ip4_address (dev);
	mask = (char*) network_device_get_netmask (dev);
	route = (char*) network_device_get_route (dev);
	primary_dns = (char*) network_device_get_primary_dns (dev);
	secondary_dns = (char*) network_device_get_secondary_dns (dev);

	mbs = network_device_get_speed (dev);
	if (mbs)
		speed = g_strdup_printf ("%d Mb/s", mbs);

	if (network_device_is_wired (dev))
		iface_and_type = g_strdup_printf (_("Wired Ethernet (%s)"), iface);
	else
		iface_and_type = g_strdup_printf (_("Wireless Ethernet (%s)"), iface);	

	label = get_label (info_dialog, applet->info_dialog_xml, "label-interface");
	gtk_label_set_text (GTK_LABEL (label), iface_and_type);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-speed");
	gtk_label_set_text (GTK_LABEL (label), mbs ? speed : "Unknown");

	label = get_label (info_dialog, applet->info_dialog_xml, "label-driver");
	gtk_label_set_text (GTK_LABEL (label), driver);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-ip-address");
	gtk_label_set_text (GTK_LABEL (label), addr);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-broadcast-address");
	gtk_label_set_text (GTK_LABEL (label), broadcast);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-subnet-mask");
	gtk_label_set_text (GTK_LABEL (label), mask);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-default-route");
	gtk_label_set_text (GTK_LABEL (label), route);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-primary-dns");
	gtk_label_set_text (GTK_LABEL (label), primary_dns);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-secondary-dns");
	gtk_label_set_text (GTK_LABEL (label), secondary_dns);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-hardware-address");
	gtk_label_set_text (GTK_LABEL (label), mac);

	g_free (iface_and_type);
	g_free (speed);

	return TRUE;
}

static void nma_show_info_cb (GtkMenuItem *mi, NMApplet *applet)
{
	GtkWidget *info_dialog;

	info_dialog = glade_xml_get_widget (applet->info_dialog_xml, "info_dialog");

	if (nma_update_info (applet))
	{
		gtk_window_present (GTK_WINDOW (info_dialog));
		g_signal_connect_swapped (info_dialog, "response", G_CALLBACK (gtk_widget_hide), info_dialog);
	}
}

static void about_dialog_activate_link_cb (GtkAboutDialog *about,
                                           const gchar *url,
                                           gpointer data)
{
	gnome_url_show (url, NULL);
}

static void nma_about_cb (GtkMenuItem *mi, NMApplet *applet)
{
	static const gchar *authors[] =
	{
		"The Red Hat Desktop Team, including:\n",
		"Christopher Aillon <caillon@redhat.com>",
		"Jonathan Blandford <jrb@redhat.com>",
		"John Palmieri <johnp@redhat.com>",
		"Ray Strode <rstrode@redhat.com>",
		"Colin Walters <walters@redhat.com>",
		"Dan Williams <dcbw@redhat.com>",
		"David Zeuthen <davidz@redhat.com>",
		"\nAnd others, including:\n",
		"Bill Moss <bmoss@clemson.edu>",
		"Tom Parker",
		"j@bootlab.org",
		"Peter Jones <pjones@redhat.com>",
		"Robert Love <rml@novell.com>",
		"Tim Niemueller <tim@niemueller.de>",
		NULL
	};

	static const gchar *artists[] =
	{
		"Diana Fong <dfong@redhat.com>",
		NULL
	};

#if !GTK_CHECK_VERSION(2,6,0)
	GdkPixbuf	*pixbuf;
	char		*file;
	GtkWidget	*about_dialog;

	/* GTK 2.4 and earlier, have to use libgnome for about dialog */
	file = gnome_program_locate_file (NULL, GNOME_FILE_DOMAIN_PIXMAP, "gnome-networktool.png", FALSE, NULL);
	pixbuf = gdk_pixbuf_new_from_file (file, NULL);
	g_free (file);

	about_dialog = gnome_about_new (_("NetworkManager Applet"),
	                                VERSION,
	                                _("Copyright \xc2\xa9 2004-2006 Red Hat, Inc.\n"
							    "Copyright \xc2\xa9 2005-2006 Novell, Inc."),
	                                _("Notification area applet for managing your network devices and connections."),
	                                authors,
	                                NULL,
	                                _("translator-credits"),
	                                pixbuf);
	g_object_unref (pixbuf);

	gtk_window_set_screen (GTK_WINDOW (about_dialog), gtk_widget_get_screen (GTK_WIDGET (applet)));
	g_signal_connect (about_dialog, "destroy", G_CALLBACK (gtk_widget_destroyed), &about_dialog);
	gtk_widget_show (about_dialog);

#else

	static gboolean been_here = FALSE;
	if (!been_here)
	{
		been_here = TRUE;
		gtk_about_dialog_set_url_hook (about_dialog_activate_link_cb, NULL, NULL);
	}

	/* GTK 2.6 and later code */
	gtk_show_about_dialog (NULL,
	                       "name", _("NetworkManager Applet"),
	                       "version", VERSION,
	                       "copyright", _("Copyright \xc2\xa9 2004-2005 Red Hat, Inc.\n"
					                  "Copyright \xc2\xa9 2005-2006 Novell, Inc."),
	                       "comments", _("Notification area applet for managing your network devices and connections."),
	                       "website", "http://www.gnome.org/projects/NetworkManager/",
	                       "authors", authors,
	                       "artists", artists,
	                       "translator-credits", _("translator-credits"),
	                       "logo-icon-name", GTK_STOCK_NETWORK,
	                       NULL);
#endif
}


#ifndef ENABLE_NOTIFY
/*
 * nma_show_vpn_failure_dialog
 *
 * Present the VPN failure dialog.
 *
 */
static void
nma_show_vpn_failure_dialog (const char *title,
                              const char *msg)
{
	GtkWidget	*dialog;

	g_return_if_fail (title != NULL);
	g_return_if_fail (msg != NULL);

	dialog = gtk_message_dialog_new_with_markup (NULL, 0, GTK_MESSAGE_ERROR,
				GTK_BUTTONS_OK, msg, NULL);
	gtk_window_set_title (GTK_WINDOW (dialog), title);
	g_signal_connect (dialog, "response", G_CALLBACK (gtk_widget_destroy), NULL);
	g_signal_connect (dialog, "close", G_CALLBACK (gtk_widget_destroy), NULL);

	/* Bash focus-stealing prevention in the face */
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_widget_show_all (dialog);
}
#endif


/*
 * nma_schedule_vpn_failure_alert
 *
 * Schedule display of a VPN failure message.
 *
 */
void nma_show_vpn_failure_alert (NMApplet *applet, const char *member, const char *vpn_name, const char *error_msg)
{
	char *title = NULL;
	char *desc = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (member != NULL);
	g_return_if_fail (vpn_name != NULL);
	g_return_if_fail (error_msg != NULL);

	if (!strcmp (member, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED))
	{
		title = g_strdup (_("VPN Login Failure"));
		desc = g_strdup_printf (_("Could not start the VPN connection '%s' due to a login failure."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED))
	{
		title = g_strdup (_("VPN Start Failure"));
		desc = g_strdup_printf (_("Could not start the VPN connection '%s' due to a failure launching the VPN program."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED))
	{
		title = g_strdup (_("VPN Connect Failure"));
		desc = g_strdup_printf (_("Could not start the VPN connection '%s' due to a connection error."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD))
	{
		title = g_strdup (_("VPN Configuration Error"));
		desc = g_strdup_printf (_("The VPN connection '%s' was not correctly configured."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD))
	{
		title = g_strdup (_("VPN Connect Failure"));
		desc = g_strdup_printf (_("Could not start the VPN connection '%s' because the VPN server did not return an adequate network configuration."), vpn_name);
	}

	if (title && desc)
	{
		char * msg;

#ifdef ENABLE_NOTIFY
		msg = g_strdup_printf ("\n%s\n%s", desc, error_msg);
		nma_send_event_notification (applet, NOTIFY_URGENCY_CRITICAL,
			title, msg, "gnome-lockscreen");
#else
		msg = g_strdup_printf ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n"
			"%s\n\n%s", title, desc, error_msg);
		nma_show_vpn_failure_dialog (title, msg);
#endif
		g_free (msg);
	}

	g_free (title);
	g_free (desc);
}


#ifndef ENABLE_NOTIFY
/*
 * nma_show_vpn_login_banner_dialog
 *
 * Present the VPN login banner dialog.
 *
 */
static void
nma_show_vpn_login_banner_dialog (const char *title,
                                   const char *msg)
{
	GtkWidget	*dialog;

	g_return_if_fail (title != NULL);
	g_return_if_fail (msg != NULL);

	dialog = gtk_message_dialog_new_with_markup (NULL, 0, GTK_MESSAGE_INFO,
					GTK_BUTTONS_OK, msg, NULL);
	gtk_window_set_title (GTK_WINDOW (dialog), title);
	g_signal_connect (dialog, "response", G_CALLBACK (gtk_widget_destroy), NULL);
	g_signal_connect (dialog, "close", G_CALLBACK (gtk_widget_destroy), NULL);

	/* Bash focus-stealing prevention in the face */
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_widget_show_all (dialog);
}
#endif


/*
 * nma_schedule_vpn_login_banner
 *
 * Schedule a display of the VPN banner
 *
 */
void nma_show_vpn_login_banner (NMApplet *applet, const char *vpn_name, const char *banner)
{
	const char *	title;
	char *		msg;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (vpn_name != NULL);
	g_return_if_fail (banner != NULL);

	title = _("VPN Login Message");
#ifdef ENABLE_NOTIFY
	msg = g_strdup_printf ("\n%s", banner);
	nma_send_event_notification (applet, NOTIFY_URGENCY_LOW,
		title, msg, "gnome-lockscreen");
#else
	msg = g_strdup_printf ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
	                       title, banner);
	nma_show_vpn_login_banner_dialog (title, msg);
#endif
	g_free (msg);
}


/*
 * nma_driver_notify_get_ignored_list
 *
 * Return list of devices for which we are supposed to ignore driver
 * notifications for from GConf.
 *
 */
static GSList *nma_driver_notify_get_ignored_list (NMApplet *applet)
{
	char			*key;
	GConfValue	*value;
	GSList		*mac_list = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (applet->gconf_client != NULL, NULL);

	/* Get current list of access point MAC addresses for this AP from GConf */
	key = g_strdup_printf ("%s/non_notify_cards", GCONF_PATH_PREFS);
	value = gconf_client_get (applet->gconf_client, key, NULL);

	if (value && (value->type == GCONF_VALUE_LIST) && (gconf_value_get_list_type (value) == GCONF_VALUE_STRING))
		mac_list = gconf_client_get_list (applet->gconf_client, key, GCONF_VALUE_STRING, NULL);

	if (value)
		gconf_value_free (value);
	g_free (key);

	return (mac_list);
}


/*
 * nma_driver_notify_is_device_ignored
 *
 * Look in GConf and determine whether or not we are supposed to
 * ignore driver notifications for a particular device.
 *
 */
static gboolean nma_driver_notify_is_device_ignored (NMApplet *applet, NetworkDevice *dev)
{
	gboolean		found = FALSE;
	GSList *		mac_list = NULL;
	GSList *		elt;
	const char *	dev_addr;

	g_return_val_if_fail (applet != NULL, TRUE);
	g_return_val_if_fail (applet->gconf_client != NULL, TRUE);
	g_return_val_if_fail (dev != NULL, TRUE);

	dev_addr = network_device_get_address (dev);
	g_return_val_if_fail (dev_addr != NULL, TRUE);
	g_return_val_if_fail (strlen (dev_addr) > 0, TRUE);

	mac_list = nma_driver_notify_get_ignored_list (applet);

	/* Ensure that the MAC isn't already in the list */
	for (elt = mac_list; elt; elt = g_slist_next (elt))
	{
		if (elt->data && !strcmp (dev_addr, elt->data))
		{
			found = TRUE;
			break;
		}
	}

	/* Free the list, since gconf_client_set_list deep-copies it */
	g_slist_foreach (mac_list, (GFunc)g_free, NULL);
	g_slist_free (mac_list);

	return found;
}


/*
 * nma_driver_notify_ignore_device
 *
 * Add a device's MAC address to the list of ones that we ignore
 * in GConf.  Stores user's pref for "Don't remind me".
 *
 */
static void nma_driver_notify_ignore_device (NMApplet *applet, NetworkDevice *dev)
{
	gboolean		found = FALSE;
	GSList *		new_mac_list = NULL;
	GSList *		elt;
	const char *	dev_addr;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->gconf_client != NULL);
	g_return_if_fail (dev != NULL);

	dev_addr = network_device_get_address (dev);
	g_return_if_fail (dev_addr != NULL);
	g_return_if_fail (strlen (dev_addr) > 0);

	new_mac_list = nma_driver_notify_get_ignored_list (applet);

	/* Ensure that the MAC isn't already in the list */
	for (elt = new_mac_list; elt; elt = g_slist_next (elt))
	{
		if (elt->data && !strcmp (dev_addr, elt->data))
		{
			found = TRUE;
			break;
		}
	}

	/* Add the new MAC address to the end of the list */
	if (!found)
	{
		char *key = g_strdup_printf ("%s/non_notify_cards", GCONF_PATH_PREFS);

		new_mac_list = g_slist_append (new_mac_list, g_strdup (dev_addr));
		gconf_client_set_list (applet->gconf_client, key, GCONF_VALUE_STRING, new_mac_list, NULL);
		g_free (key);
	}

	/* Free the list, since gconf_client_set_list deep-copies it */
	g_slist_foreach (new_mac_list, (GFunc)g_free, NULL);
	g_slist_free (new_mac_list);
}

static gboolean nma_driver_notify_dialog_delete_cb (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy (widget);
	return FALSE;
}

static gboolean nma_driver_notify_dialog_destroy_cb (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	DriverNotifyCBData	*cb_data = (DriverNotifyCBData *)(user_data);
	NetworkDevice		*dev;

	g_return_val_if_fail (cb_data != NULL, FALSE);
	g_return_val_if_fail (cb_data->xml != NULL, FALSE);

	dev = cb_data->dev;
	g_return_val_if_fail (dev != NULL, FALSE);

	network_device_unref (dev);

	g_object_unref (cb_data->xml);
	g_free (cb_data);

	return FALSE;
}


static gboolean nma_driver_notify_ok_cb (GtkButton *button, gpointer user_data)
{
	DriverNotifyCBData	*cb_data = (DriverNotifyCBData *)(user_data);
	NetworkDevice		*dev;
	NMApplet	*applet;
	GtkWidget			*dialog;
	GtkWidget			*checkbox;

	g_return_val_if_fail (cb_data != NULL, FALSE);
	g_return_val_if_fail (cb_data->xml != NULL, FALSE);

	dev = cb_data->dev;
	g_return_val_if_fail (dev != NULL, FALSE);

	applet = cb_data->applet;
	g_return_val_if_fail (applet != NULL, FALSE);

	checkbox = glade_xml_get_widget (cb_data->xml, "dont_remind_checkbox");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (checkbox)))
		nma_driver_notify_ignore_device (applet, dev);

	dialog = glade_xml_get_widget (cb_data->xml, "driver_sucks_dialog");
	gtk_widget_destroy (dialog);

	return FALSE;
}


/*
 * nma_driver_notify
 *
 * Notify the user if there's some problem with the driver
 * of a specific network device.
 *
 */
gboolean nma_driver_notify (gpointer user_data)
{
	DriverNotifyCBData *	cb_data = (DriverNotifyCBData *)(user_data);
	NetworkDevice *		dev;
	NMApplet *		applet;
	GtkWidget *			dialog;
	GtkLabel *			label;
	char *				label_text = NULL;
	char *				temp = NULL;
	GtkButton *			button;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	dev = cb_data->dev;
	g_return_val_if_fail (dev != NULL, FALSE);

	if (!(applet = cb_data->applet) || !applet->glade_file)
		goto out;

	/* If the user has already requested that we ignore notifications for
	 * this device, don't do anything.
	 */
	if (nma_driver_notify_is_device_ignored (applet, dev))
		goto out;

	if (!(cb_data->xml = glade_xml_new (applet->glade_file, "driver_sucks_dialog", NULL)))
	{
		nma_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		goto out;
	}

	dialog = glade_xml_get_widget (cb_data->xml, "driver_sucks_dialog");
	g_signal_connect (G_OBJECT (dialog), "destroy-event", GTK_SIGNAL_FUNC (nma_driver_notify_dialog_destroy_cb), cb_data);
	g_signal_connect (G_OBJECT (dialog), "delete-event", GTK_SIGNAL_FUNC (nma_driver_notify_dialog_delete_cb), cb_data);

	label = GTK_LABEL (glade_xml_get_widget (cb_data->xml, "driver_sucks_label"));

	if (network_device_is_wireless (dev) && !(network_device_get_capabilities (dev) & NM_DEVICE_CAP_WIRELESS_SCAN))
	{
		temp = g_strdup_printf (_("The network device \"%s (%s)\" does not support wireless scanning."),
		                        network_device_get_desc (dev), network_device_get_iface (dev));
		label_text = g_strdup_printf (gtk_label_get_label (label), temp);
		g_free (temp);
	}

	if (network_device_is_wired (dev) && !(network_device_get_capabilities (dev) & NM_DEVICE_CAP_CARRIER_DETECT))
	{
		temp = g_strdup_printf (_("The network device \"%s (%s)\" does not support link detection."),
		                        network_device_get_desc (dev), network_device_get_iface (dev));
		label_text = g_strdup_printf (gtk_label_get_label (label), temp);
		g_free (temp);
	}

	if (label_text)
		gtk_label_set_markup (label, label_text);

	button = GTK_BUTTON (glade_xml_get_widget (cb_data->xml, "ok_button"));
	g_signal_connect (G_OBJECT (button), "clicked", GTK_SIGNAL_FUNC (nma_driver_notify_ok_cb), cb_data);

	/* Bash focus-stealing prevention in the face */
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_widget_show_all (dialog);

out:
	network_device_unref (cb_data->dev);
	return (FALSE);
}


/*
 * nma_get_first_active_vpn_connection
 *
 * Return the first active VPN connection, if any.
 *
 */
VPNConnection *nma_get_first_active_vpn_connection (NMApplet *applet)
{
	VPNConnection *	vpn;
	NMVPNActStage		vpn_state;
	GSList *			elt;

	for (elt = applet->vpn_connections; elt; elt = g_slist_next (elt))
	{
		vpn = (VPNConnection*) elt->data;
		vpn_state = nma_vpn_connection_get_stage (vpn);
		if (vpn_state == NM_VPN_ACT_STAGE_ACTIVATED)
			return vpn;
	}

	return NULL;
}

static VPNConnection *nma_get_first_activating_vpn_connection (NMApplet *applet)
{
	VPNConnection *	vpn;
	GSList *			elt;

	for (elt = applet->vpn_connections; elt; elt = g_slist_next (elt))
	{
		vpn = (VPNConnection*) elt->data;
		if (nma_vpn_connection_is_activating (vpn))
			return vpn;
	}

	return NULL;
}


static void nma_set_icon (NMApplet *applet, GdkPixbuf *link_icon, GdkPixbuf *vpn_icon)
{
	GtkRequisition requisition;
	GdkPixbuf	*composite;
	VPNConnection	*vpn;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (link_icon != NULL);

	composite = gdk_pixbuf_copy (link_icon);

	vpn = nma_get_first_active_vpn_connection (applet);
	if (!vpn)
		vpn = nma_get_first_activating_vpn_connection (applet);

	if (vpn && vpn_icon)
		gdk_pixbuf_composite (vpn_icon, composite, 0, 0, gdk_pixbuf_get_width (vpn_icon),
							gdk_pixbuf_get_height (vpn_icon), 0, 0, 1.0, 1.0, GDK_INTERP_NEAREST, 255);

	gtk_image_set_from_pixbuf (GTK_IMAGE (applet->pixmap), composite);

	/* Add some padding to the applet to ensure the
	 * highlight has some space.
	 */
	gtk_widget_set_size_request (GTK_WIDGET (applet), -1, -1);
	gtk_widget_size_request (GTK_WIDGET (applet), &requisition);
	gtk_widget_set_size_request (GTK_WIDGET (applet), requisition.width + 6, requisition.height + 2);

	g_object_unref (composite);
}


static GdkPixbuf *nma_get_connected_icon (NMApplet *applet, NetworkDevice *dev)
{
	int strength = 0;
	GdkPixbuf *pixbuf = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	if (network_device_is_wireless (dev))
	{
		if (applet->is_adhoc)
			pixbuf = applet->adhoc_icon;
		else
		{
			strength = CLAMP ((int)network_device_get_strength (dev), 0, 100);
			if (strength > 80)
				pixbuf = applet->wireless_100_icon;
			else if (strength > 55)
				pixbuf = applet->wireless_75_icon;
			else if (strength > 30)
				pixbuf = applet->wireless_50_icon;
			else if (strength > 5)
				pixbuf = applet->wireless_25_icon;
			else
				pixbuf = applet->wireless_00_icon;
		}
	}
	else
		pixbuf = applet->wired_icon;

	return pixbuf;
}


static GdkPixbuf * nma_act_stage_to_pixbuf (NMApplet *applet, NetworkDevice *dev, WirelessNetwork *net, char **tip)
{
	const char *essid;
	const char *iface;
	gint connecting_stage = -1;
	GdkPixbuf *pixbuf = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (tip != NULL, NULL);

	iface = network_device_get_iface (dev);
	essid = net ? wireless_network_get_essid (net) : NULL;
	switch (network_device_get_act_stage (dev))
	{
		case NM_ACT_STAGE_DEVICE_PREPARE:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Preparing device %s for the wired network..."), iface);
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Preparing device %s for the wireless network '%s'..."), iface, essid);
			connecting_stage = 0;
			break;
		}

		case NM_ACT_STAGE_DEVICE_CONFIG:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Configuring device %s for the wired network..."), iface);
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Attempting to join the wireless network '%s'..."), essid);
			connecting_stage = 0;
			break;
		}

		case NM_ACT_STAGE_NEED_USER_KEY:
		{
			if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Waiting for Network Key for the wireless network '%s'..."), essid);
			connecting_stage = 0;
			break;
		}

		case NM_ACT_STAGE_IP_CONFIG_START:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wired network..."));
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wireless network '%s'..."), essid);
			connecting_stage = 1;
			break;
		}

		case NM_ACT_STAGE_IP_CONFIG_GET:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wired network..."));
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wireless network '%s'..."), essid);
			connecting_stage = 2;
			break;
		}

		case NM_ACT_STAGE_IP_CONFIG_COMMIT:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Finishing connection to the wired network..."));
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Finishing connection to the wireless network '%s'..."), essid);
			connecting_stage = 2;
			break;
		}

		default:
		case NM_ACT_STAGE_ACTIVATED:
		case NM_ACT_STAGE_FAILED:
		case NM_ACT_STAGE_CANCELLED:
		case NM_ACT_STAGE_UNKNOWN:
			break;
	}

	if (connecting_stage >= 0 && connecting_stage < NUM_CONNECTING_STAGES)
	{
		if (applet->animation_step >= NUM_CONNECTING_FRAMES)
			applet->animation_step = 0;

		pixbuf = applet->network_connecting_icons[connecting_stage][applet->animation_step];
	}

	return pixbuf;
}


/*
 * animation_timeout
 *
 * Jump to the next frame of the applets icon if the icon
 * is supposed to be animated.
 *
 */
static gboolean animation_timeout (NMApplet *applet)
{
	NetworkDevice *act_dev;
	GdkPixbuf *pixbuf;

	g_return_val_if_fail (applet != NULL, FALSE);

	if (!applet->nm_running)
	{
		applet->animation_step = 0;
		applet->animation_id = 0;
		return FALSE;
	}

	act_dev = nma_get_first_active_device (applet->device_list);
	if (!act_dev)
	{
		applet->animation_step = 0;
		applet->animation_id = 0;
		return FALSE;
	}

	if (applet->nm_state == NM_STATE_CONNECTING)
	{
		if (act_dev)
		{
			char *tip = NULL;
			pixbuf = nma_act_stage_to_pixbuf (applet, act_dev, NULL, &tip);
			g_free (tip);

			if (pixbuf)
				nma_set_icon (applet, pixbuf, NULL);
		}
		applet->animation_step ++;
	}
	else if (nma_get_first_activating_vpn_connection (applet) != NULL)
	{
		pixbuf = nma_get_connected_icon (applet, act_dev);

		if (applet->animation_step >= NUM_VPN_CONNECTING_FRAMES)
			applet->animation_step = 0;

		nma_set_icon (applet, pixbuf, applet->vpn_connecting_icons[applet->animation_step]);
		applet->animation_step ++;
	}
	else
	{
		applet->animation_step = 0;
		nma_update_state (applet);
		return FALSE;
	}

	return TRUE;
}


/*
 * nma_update_state
 *
 * Figure out what the currently active device is from NetworkManager, its type,
 * and what our icon on the panel should look like for each type.
 *
 */
void nma_update_state (NMApplet *applet)
{
	gboolean			show_applet = TRUE;
	gboolean			need_animation = FALSE;
	GdkPixbuf *		pixbuf = NULL;
	gint				strength = -1;
	char *			tip = NULL;
	char *			vpntip = NULL;
	WirelessNetwork *	active_network = NULL;
	NetworkDevice *	act_dev = NULL;
	VPNConnection		*vpn;

	act_dev = nma_get_first_active_device (applet->device_list);
	if (act_dev && network_device_is_wireless (act_dev))
	{
		active_network = network_device_get_active_wireless_network (act_dev);
		strength = CLAMP ((int)network_device_get_strength (act_dev), 0, 100);
	}

	if (!applet->nm_running)
	{
		show_applet = FALSE;
		tip = g_strdup (_("NetworkManager is not running"));
		goto done;
	}

	switch (applet->nm_state)
	{
		case NM_STATE_ASLEEP:
			pixbuf = applet->no_connection_icon;
			tip = g_strdup (_("Networking disabled"));
			break;

		case NM_STATE_DISCONNECTED:
			pixbuf = applet->no_connection_icon;
			tip = g_strdup (_("No network connection"));
			break;

		case NM_STATE_CONNECTED:
			if (network_device_is_wired (act_dev))
				tip = g_strdup (_("Wired network connection"));
			else if (network_device_is_wireless (act_dev))
			{
				if (applet->is_adhoc)
					tip = g_strdup (_("Connected to an Ad-Hoc wireless network"));
				else
					tip = g_strdup_printf (_("Wireless network connection to '%s' (%d%%)"),
					                       active_network ? wireless_network_get_essid (active_network) : "(unknown)", strength);
			}
			pixbuf = nma_get_connected_icon (applet, act_dev);
			break;

		case NM_STATE_CONNECTING:
			if (act_dev)
			{
				pixbuf = nma_act_stage_to_pixbuf (applet, act_dev, active_network, &tip);
				need_animation = TRUE;
			}
			break;

		default:
			break;
	}

	vpn = nma_get_first_active_vpn_connection (applet);
	if (vpn != NULL)
	{
		vpntip = g_strdup_printf (_("VPN connection to '%s'"), nma_vpn_connection_get_name (vpn));
	}
	else
	{
		vpn = nma_get_first_activating_vpn_connection (applet);
		if (vpn != NULL)
		{
			need_animation = TRUE;
			vpntip = g_strdup_printf (_("VPN connecting to '%s'"), nma_vpn_connection_get_name (vpn));
		}
	}

	if (vpntip)
	{
		char *newtip;
		newtip = g_strconcat (tip, "\n", vpntip, NULL);
		g_free (vpntip);
		g_free (tip);
		tip = newtip;
	}

done:
	if (!applet->tooltips)
		applet->tooltips = gtk_tooltips_new ();

	gtk_tooltips_set_tip (applet->tooltips, applet->event_box, tip, NULL);
	g_free (tip);

	applet->animation_step = 0;
	if (need_animation && applet->animation_id == 0)
		applet->animation_id = g_timeout_add (100, (GSourceFunc) animation_timeout, applet);
	else if (!need_animation)
	{
		if (applet->animation_id)
		{
			g_source_remove (applet->animation_id);
			applet->animation_id = 0;
		}

		if (pixbuf)
			nma_set_icon (applet, pixbuf, applet->vpn_lock_icon);
		else
			show_applet = FALSE;
	}

	/* determine if we should hide the notification icon */
	if (show_applet)
		gtk_widget_show (GTK_WIDGET (applet));
	else
		gtk_widget_hide (GTK_WIDGET (applet));
}


/*
 * nma_redraw_timeout
 *
 * Called regularly to update the applet's state and icon in the panel
 *
 */
static int nma_redraw_timeout (NMApplet *applet)
{
	if (!applet->animation_id)
		nma_update_state (applet);

  	return TRUE;
}


/*
 * show_warning_dialog
 *
 * pop up a warning or error dialog with certain text
 *
 */
static gboolean show_warning_dialog (char *mesg)
{
	GtkWidget	*	dialog;

	dialog = gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, mesg, NULL);

	/* Bash focus-stealing prevention in the face */
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_window_present (GTK_WINDOW (dialog));

	g_signal_connect_swapped (dialog, "response", G_CALLBACK (gtk_widget_destroy), dialog);
	g_free (mesg);

	return FALSE;
}


/*
 * nma_schedule_warning_dialog
 *
 * Run a warning dialog in the main event loop.
 *
 */
void nma_schedule_warning_dialog (NMApplet *applet, const char *msg)
{
	char *lcl_msg;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (msg != NULL);

	lcl_msg = g_strdup (msg);
	g_idle_add ((GSourceFunc) show_warning_dialog, lcl_msg);
}


/*
 * nma_get_device_for_nm_device
 *
 * Searches the device list for a device that matches the
 * NetworkManager ID given.
 *
 */
NetworkDevice *nma_get_device_for_nm_path (GSList *dev_list, const char *nm_path)
{
	NetworkDevice	*found_dev = NULL;
	GSList		*elt;

	g_return_val_if_fail (nm_path != NULL, NULL);
	g_return_val_if_fail (strlen (nm_path), NULL);

	for (elt = dev_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice	*dev = (NetworkDevice *)(elt->data);
		if (dev && (strcmp (network_device_get_nm_path (dev), nm_path) == 0))
		{
			found_dev = dev;
			break;
		}
	}

	return (found_dev);
}


/*
 * nma_menu_item_activate
 *
 * Signal function called when user clicks on a menu item
 *
 */
static void nma_menu_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;
	NetworkDevice		*dev = NULL;
	WirelessNetwork	*net = NULL;
	char				*tag;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	if (!(tag = g_object_get_data (G_OBJECT (item), "device")))
		return;

	if ((dev = nma_get_device_for_nm_path (applet->device_list, tag)))
		network_device_ref (dev);

	if (!dev)
		return;

	if ((tag = g_object_get_data (G_OBJECT (item), "network")))
		net = network_device_get_wireless_network_by_essid (dev, tag);

	nma_dbus_set_device (applet->connection, dev, net ? wireless_network_get_essid (net) : NULL, NULL);
	network_device_unref (dev);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_vpn_item_activate
 *
 * Signal function called when user clicks on a VPN menu item
 *
 */
static void nma_menu_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;
	char				*tag;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	if ((tag = g_object_get_data (G_OBJECT (item), "vpn")))
	{
		VPNConnection	*vpn = (VPNConnection *)tag;
		const char	*name = nma_vpn_connection_get_name (vpn);
		GSList         *passwords;
		VPNConnection	*active_vpn = nma_get_first_active_vpn_connection (applet);

		if (vpn != active_vpn)
		{
			char *gconf_key;
			char *escaped_name;
			gboolean last_attempt_success;
			gboolean reprompt;

			escaped_name = gconf_escape_key (name, strlen (name));
			gconf_key = g_strdup_printf ("%s/%s/last_attempt_success", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
			last_attempt_success = gconf_client_get_bool (applet->gconf_client, gconf_key, NULL);
			g_free (gconf_key);
			g_free (escaped_name);

			reprompt = ! last_attempt_success; /* it's obvious, but.. */

			if ((passwords = nma_vpn_request_password (applet, 
											    name, 
											    nma_vpn_connection_get_service (vpn), 
											    reprompt)) != NULL)
			{
				nma_dbus_vpn_activate_connection (applet->connection, name, passwords);

				g_slist_foreach (passwords, (GFunc)g_free, NULL);
				g_slist_free (passwords);
			}
		}
	}

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_connect_item_activate
 *
 * Signal function called when user clicks on a dialup menu item
 *
 */
static void nma_menu_dialup_connect_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet *applet = (NMApplet *) user_data;
	const char *dialup;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	dialup = g_object_get_data (G_OBJECT (item), "dialup");
	if (!dialup)
		return;

	nma_dbus_dialup_activate_connection (applet, dialup);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_dialup_hangup_activate
 *
 * Signal function called when user clicks on a dialup menu item
 *
 */
static void nma_menu_dialup_disconnect_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet *applet = (NMApplet *) user_data;
	const char *dialup;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	dialup = g_object_get_data (G_OBJECT (item), "dialup");
	if (!dialup)
		return;

	nma_dbus_dialup_deactivate_connection (applet, dialup);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_configure_vpn_item_activate
 *
 * Signal function called when user clicks "Configure VPN..."
 *
 */
static void nma_menu_configure_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;
	const char *argv[] = { BINDIR "/nm-vpn-properties", NULL};

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	g_spawn_async (NULL, (gchar **) argv, NULL, 0, NULL, NULL, NULL, NULL);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}

/*
 * nma_menu_disconnect_vpn_item_activate
 *
 * Signal function called when user clicks "Disconnect VPN..."
 *
 */
static void nma_menu_disconnect_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	nma_dbus_vpn_deactivate_connection (applet->connection);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_add_separator_item
 *
 */
static void nma_menu_add_separator_item (GtkWidget *menu)
{
	GtkWidget	*menu_item;
	menu_item = gtk_separator_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nma_menu_add_text_item
 *
 * Add a non-clickable text item to a menu
 *
 */
static void nma_menu_add_text_item (GtkWidget *menu, char *text)
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
 * nma_menu_add_device_item
 *
 * Add a network device to the menu
 *
 */
static void nma_menu_add_device_item (GtkWidget *menu, NetworkDevice *device, gint n_devices, NMApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (applet != NULL);

	switch (network_device_get_type (device))
	{
		case DEVICE_TYPE_802_3_ETHERNET:
		{
			NMWiredMenuItem *item = wired_menu_item_new ();
			GtkCheckMenuItem *gtk_item = wired_menu_item_get_check_item (item);

			wired_menu_item_update (item, device, n_devices);
			if (network_device_get_active (device))
				gtk_check_menu_item_set_active (gtk_item, TRUE);
			gtk_check_menu_item_set_draw_as_radio (gtk_item, TRUE);

			g_object_set_data (G_OBJECT (gtk_item), "device", g_strdup (network_device_get_nm_path (device)));
			g_object_set_data (G_OBJECT (gtk_item), "nm-item-data", item);
			g_signal_connect(G_OBJECT (gtk_item), "activate", G_CALLBACK (nma_menu_item_activate), applet);

			gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (gtk_item));
			gtk_widget_show (GTK_WIDGET (gtk_item));
			break;
		}

		case DEVICE_TYPE_802_11_WIRELESS:
		{
			NMWirelessMenuItem *item;
			GtkMenuItem *gtk_item;

			if (!applet->wireless_enabled)
				break;

			item = wireless_menu_item_new ();
			gtk_item = wireless_menu_item_get_item (item);

			wireless_menu_item_update (item, device, n_devices);

			g_object_set_data (G_OBJECT (gtk_item), "device", g_strdup (network_device_get_nm_path (device)));
			g_object_set_data (G_OBJECT (gtk_item), "nm-item-data", item);
			g_signal_connect(G_OBJECT (gtk_item), "activate", G_CALLBACK (nma_menu_item_activate), applet);

			gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (gtk_item));
			gtk_widget_show (GTK_WIDGET (gtk_item));
			break;
		}

		default:
			break;
	}
}


static void custom_essid_item_selected (GtkWidget *menu_item, NMApplet *applet)
{
	nma_other_network_dialog_run (applet, FALSE);
}


static void nma_menu_add_custom_essid_item (GtkWidget *menu, NMApplet *applet)
{
	GtkWidget *menu_item;
	GtkWidget *label;

	menu_item = gtk_menu_item_new ();
	label = gtk_label_new_with_mnemonic (_("_Connect to Other Wireless Network..."));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_container_add (GTK_CONTAINER (menu_item), label);
	gtk_widget_show_all (menu_item);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	g_signal_connect (menu_item, "activate", G_CALLBACK (custom_essid_item_selected), applet);
}


static void new_network_item_selected (GtkWidget *menu_item, NMApplet *applet)
{
	nma_other_network_dialog_run (applet, TRUE);
}


static void nma_menu_add_create_network_item (GtkWidget *menu, NMApplet *applet)
{
	GtkWidget *menu_item;
	GtkWidget *label;

	menu_item = gtk_menu_item_new ();
	label = gtk_label_new_with_mnemonic (_("Create _New Wireless Network..."));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_container_add (GTK_CONTAINER (menu_item), label);
	gtk_widget_show_all (menu_item);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	g_signal_connect (menu_item, "activate", G_CALLBACK (new_network_item_selected), applet);
}


typedef struct AddNetworksCB
{
	NMApplet *	applet;
	gboolean			has_encrypted;
	GtkWidget *		menu;
} AddNetworksCB;


/*
 * nma_add_networks_helper
 *
 */
static void nma_add_networks_helper (NetworkDevice *dev, WirelessNetwork *net, gpointer user_data)
{
	AddNetworksCB *	cb_data = (AddNetworksCB *)user_data;
	NMNetworkMenuItem *	item;
	GtkCheckMenuItem *	gtk_item;
	NMApplet *		applet;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (net != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->menu != NULL);
	g_return_if_fail (cb_data->applet != NULL);

	applet = cb_data->applet;
	item = network_menu_item_new (applet->encryption_size_group);
	gtk_item = network_menu_item_get_check_item (item);

	gtk_menu_shell_append (GTK_MENU_SHELL (cb_data->menu), GTK_WIDGET (gtk_item));
	if (   (applet->nm_state == NM_STATE_CONNECTED)
	    || (applet->nm_state == NM_STATE_CONNECTING))
	{
		if (network_device_get_active (dev) && wireless_network_get_active (net))
			gtk_check_menu_item_set_active (gtk_item, TRUE);
	}
	network_menu_item_update (applet, item, net, cb_data->has_encrypted);

	g_object_set_data (G_OBJECT (gtk_item), "network", g_strdup (wireless_network_get_essid (net)));
	g_object_set_data (G_OBJECT (gtk_item), "device", g_strdup (network_device_get_nm_path (dev)));
	g_object_set_data (G_OBJECT (gtk_item), "nm-item-data", item);
	g_signal_connect (G_OBJECT (gtk_item), "activate", G_CALLBACK (nma_menu_item_activate), applet);

	gtk_widget_show (GTK_WIDGET (gtk_item));
}


/*
 * nma_has_encrypted_networks_helper
 *
 */
static void nma_has_encrypted_networks_helper (NetworkDevice *dev, WirelessNetwork *net, gpointer user_data)
{
	gboolean *has_encrypted = user_data;
	int		capabilities;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (net != NULL);
	g_return_if_fail (has_encrypted != NULL);

	capabilities = wireless_network_get_capabilities (net);
	if (    (capabilities & NM_802_11_CAP_PROTO_WEP)
		|| (capabilities & NM_802_11_CAP_PROTO_WPA)
		|| (capabilities & NM_802_11_CAP_PROTO_WPA2))
		*has_encrypted = TRUE;
}


/*
 * nma_menu_device_add_networks
 *
 */
static void nma_menu_device_add_networks (GtkWidget *menu, NetworkDevice *dev, NMApplet *applet)
{
	gboolean			has_encrypted = FALSE;
	AddNetworksCB *	add_networks_cb = NULL;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev != NULL);

	if (!network_device_is_wireless (dev) || !applet->wireless_enabled)
		return;

	/* Check for any security */
	network_device_foreach_wireless_network (dev, nma_has_encrypted_networks_helper, &has_encrypted);

	add_networks_cb = g_malloc0 (sizeof (AddNetworksCB));
	add_networks_cb->applet = applet;
	add_networks_cb->has_encrypted = has_encrypted;
	add_networks_cb->menu = menu;

	/* Add all networks in our network list to the menu */
	network_device_foreach_wireless_network (dev, nma_add_networks_helper, add_networks_cb);

	g_free (add_networks_cb);
}


/*
 * nma_menu_add_devices
 *
 */
static void nma_menu_add_vpn_menu (GtkWidget *menu, NMApplet *applet)
{
	GtkMenuItem	*item;
	GtkMenu		*vpn_menu;
	GtkMenuItem	*other_item;
	GSList		*elt;
	VPNConnection	*active_vpn;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_VPN Connections")));

	vpn_menu = GTK_MENU (gtk_menu_new ());
	active_vpn = nma_get_first_active_vpn_connection (applet);

	for (elt = applet->vpn_connections; elt; elt = g_slist_next (elt))
	{
		GtkCheckMenuItem	*vpn_item;
		VPNConnection		*vpn = elt->data;
		const char		*vpn_name = nma_vpn_connection_get_name (vpn);

		vpn_item = GTK_CHECK_MENU_ITEM (gtk_check_menu_item_new_with_label (vpn_name));
		/* temporarily do this until we support multiple VPN connections */
		gtk_check_menu_item_set_draw_as_radio (vpn_item, TRUE);

		nma_vpn_connection_ref (vpn);
		g_object_set_data (G_OBJECT (vpn_item), "vpn", vpn);

		/* FIXME: all VPN items except the active one are disabled,
		 * due to a bug in the VPN handling code in NM.  See commit to
		 * src/vpn-manager/nm-vpn-service.c on 2006-02-28 by dcbw for
		 * more details.
		 */
		if (active_vpn)
		{
			if (active_vpn == vpn)
				gtk_check_menu_item_set_active (vpn_item, TRUE);
			else
				gtk_widget_set_sensitive (GTK_WIDGET (vpn_item), FALSE);
		}

		if (applet->nm_state != NM_STATE_CONNECTED)
			gtk_widget_set_sensitive (GTK_WIDGET (vpn_item), FALSE);

		g_signal_connect (G_OBJECT (vpn_item), "activate", G_CALLBACK (nma_menu_vpn_item_activate), applet);
		gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (vpn_item));
	}

	/* Draw a seperator, but only if we have VPN connections above it */
	if (applet->vpn_connections)
	{
		other_item = GTK_MENU_ITEM (gtk_separator_menu_item_new ());
		gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (other_item));
	}

	other_item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_Configure VPN...")));
	g_signal_connect (G_OBJECT (other_item), "activate", G_CALLBACK (nma_menu_configure_vpn_item_activate), applet);
	gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (other_item));

	other_item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_Disconnect VPN...")));
	g_signal_connect (G_OBJECT (other_item), "activate", G_CALLBACK (nma_menu_disconnect_vpn_item_activate), applet);
	if (!active_vpn)
		gtk_widget_set_sensitive (GTK_WIDGET (other_item), FALSE);
	gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (other_item));

	gtk_menu_item_set_submenu (item, GTK_WIDGET (vpn_menu));

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));
	gtk_widget_show_all (GTK_WIDGET (item));
}


static void nma_menu_add_dialup_menu (GtkWidget *menu, NMApplet *applet)
{
	GtkMenuItem *item;
	GtkMenu *dialup_menu;
	GSList *elt;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_Dial Up Connections")));

	dialup_menu = GTK_MENU (gtk_menu_new ());
	for (elt = applet->dialup_list; elt; elt = g_slist_next (elt))
	{
		GtkMenuItem *connect_item, *disconnect_item;
		char *name = elt->data;
		char *label;

		/* FIXME: We should save and then check the state of the devices and show Connect _or_ Disconnect for each item */

		label = g_strdup_printf (_("Connect to %s..."), name);
		connect_item = GTK_MENU_ITEM (gtk_menu_item_new_with_label (label));
		g_free (label);
		g_object_set_data (G_OBJECT (connect_item), "dialup", name);
		g_signal_connect (G_OBJECT (connect_item), "activate", G_CALLBACK (nma_menu_dialup_connect_item_activate), applet);
		gtk_menu_shell_append (GTK_MENU_SHELL (dialup_menu), GTK_WIDGET (connect_item));

		label = g_strdup_printf (_("Disconnect from %s..."), name);
		disconnect_item = GTK_MENU_ITEM (gtk_menu_item_new_with_label (label));
		g_free (label);
		g_object_set_data (G_OBJECT (disconnect_item), "dialup", name);
		g_signal_connect (G_OBJECT (disconnect_item), "activate", G_CALLBACK (nma_menu_dialup_disconnect_item_activate), applet);
		gtk_menu_shell_append (GTK_MENU_SHELL (dialup_menu), GTK_WIDGET (disconnect_item));
	}

	gtk_menu_item_set_submenu (item, GTK_WIDGET (dialup_menu));
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));
	gtk_widget_show_all (GTK_WIDGET (item));
}


/** Returns TRUE if, and only if, we have VPN support installed
 *
 *  Algorithm: just check whether any files exist in the directory
 *  /etc/NetworkManager/VPN
 */
static gboolean is_vpn_available (void)
{
	GDir *dir;
	gboolean result;

	result = FALSE;
	if ((dir = g_dir_open (VPN_NAME_FILES_DIR, 0, NULL)) != NULL) {
		if (g_dir_read_name (dir) != NULL)
			result = TRUE;
		g_dir_close (dir);
	}

	return result;
}

/*
 * nma_menu_add_devices
 *
 */
static void nma_menu_add_devices (GtkWidget *menu, NMApplet *applet)
{
	GSList	*element;
	gint n_wireless_interfaces = 0;
	gint n_wired_interfaces = 0;
	gboolean vpn_available, dialup_available;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	if (!applet->device_list)
	{
		nma_menu_add_text_item (menu, _("No network devices have been found"));
		return;
	}

	if (applet->nm_state == NM_STATE_ASLEEP)
	{
		nma_menu_add_text_item (menu, _("Networking disabled"));
		return;
	}

	for (element = applet->device_list; element; element = element->next)
	{
		NetworkDevice *dev = (NetworkDevice *)(element->data);

		g_assert (dev);

		/* Ignore unsupported devices */
		if (!(network_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED))
			continue;

		switch (network_device_get_type (dev))
		{
			case DEVICE_TYPE_802_11_WIRELESS:
				n_wireless_interfaces++;
				break;
			case DEVICE_TYPE_802_3_ETHERNET:
				n_wired_interfaces++;
				break;
			default:
				break;
		}
	}

	/* Add all devices in our device list to the menu */
	for (element = applet->device_list; element; element = element->next)
	{
		NetworkDevice *dev = (NetworkDevice *)(element->data);

		if (dev)
		{
			gint n_devices = 0;

			/* Ignore unsupported devices */
			if (!(network_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED))
				continue;

			switch (network_device_get_type (dev))
			{
				case DEVICE_TYPE_802_3_ETHERNET:
					n_devices = n_wired_interfaces;
					break;

				case DEVICE_TYPE_802_11_WIRELESS:
					n_devices = n_wireless_interfaces;
					break;

				default:
					break;
			}

			if (n_devices >= 0)
			{
				nma_menu_add_device_item (menu, dev, n_devices, applet);
				nma_menu_device_add_networks (menu, dev, applet);
			}
		}
	}

	/* Add the VPN and Dial Up menus and their associated seperator */
	vpn_available = is_vpn_available ();
	dialup_available = !! applet->dialup_list;
	if (vpn_available || dialup_available)
	{
		nma_menu_add_separator_item (menu);
		if (vpn_available)
			nma_menu_add_vpn_menu (menu, applet);
		if (dialup_available)
			nma_menu_add_dialup_menu (menu, applet);
	}

	if (n_wireless_interfaces > 0 && applet->wireless_enabled)
	{
		/* Add the "Other wireless network..." entry */
		nma_menu_add_separator_item (menu);
		nma_menu_add_custom_essid_item (menu, applet);
		nma_menu_add_create_network_item (menu, applet);
	}
}


static void nma_set_wireless_enabled_cb (GtkWidget *widget, NMApplet *applet)
{
	gboolean state;

	g_return_if_fail (applet != NULL);

	state = gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM (widget));
	if (applet->wireless_enabled != state)
		nma_dbus_enable_wireless (applet, state);
}


static void nma_set_networking_enabled_cb (GtkWidget *widget, NMApplet *applet)
{
	gboolean state;

	g_return_if_fail (applet != NULL);

	state = gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM (widget));
	if ((applet->nm_state == NM_STATE_ASLEEP && state) || (applet->nm_state != NM_STATE_ASLEEP && !state))
		nma_dbus_enable_networking (applet, state);
}


/*
 * nma_menu_item_data_free
 *
 * Frees the "network" data tag on a menu item we've created
 *
 */
static void nma_menu_item_data_free (GtkWidget *menu_item, gpointer data)
{
	char	*tag;
	GtkMenu	*menu;

	g_return_if_fail (menu_item != NULL);
	g_return_if_fail (data != NULL);

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "network")))
	{
		g_object_set_data (G_OBJECT (menu_item), "network", NULL);
		g_free (tag);
	}

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "nm-item-data")))
	{
		g_object_set_data (G_OBJECT (menu_item), "nm-item-data", NULL);
		g_free (tag);
	}

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "device")))
	{
		g_object_set_data (G_OBJECT (menu_item), "device", NULL);
		g_free (tag);
	}

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "vpn")))
	{
		g_object_set_data (G_OBJECT (menu_item), "vpn", NULL);
		nma_vpn_connection_unref ((VPNConnection *)tag);
	}

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "disconnect")))
	{
		g_object_set_data (G_OBJECT (menu_item), "disconnect", NULL);
		g_free (tag);
	}

	if ((menu = GTK_MENU (gtk_menu_item_get_submenu (GTK_MENU_ITEM (menu_item)))))
		gtk_container_foreach (GTK_CONTAINER (menu), nma_menu_item_data_free, menu);

	gtk_widget_destroy (menu_item);
}


/*
 * nma_dispose_menu_items
 *
 * Destroy the menu and each of its items data tags
 *
 */
static void nma_dropdown_menu_clear (GtkWidget *menu)
{
	g_return_if_fail (menu != NULL);

	/* Free the "network" data on each menu item, and destroy the item */
	gtk_container_foreach (GTK_CONTAINER (menu), nma_menu_item_data_free, menu);
}


/*
 * nma_dropdown_menu_populate
 *
 * Set up our networks menu from scratch
 *
 */
static void nma_dropdown_menu_populate (GtkWidget *menu, NMApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	if (!applet->nm_running)
		nma_menu_add_text_item (menu, _("NetworkManager is not running..."));
	else
		nma_menu_add_devices (menu, applet);
}


/*
 * nma_dropdown_menu_show_cb
 *
 * Pop up the wireless networks menu
 *
 */
static void nma_dropdown_menu_show_cb (GtkWidget *menu, NMApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	if (!applet->tooltips)
		applet->tooltips = gtk_tooltips_new ();
	gtk_tooltips_set_tip (applet->tooltips, applet->event_box, NULL, NULL);

	if (applet->dropdown_menu && (menu == applet->dropdown_menu))
	{
		nma_dropdown_menu_clear (applet->dropdown_menu);
		nma_dropdown_menu_populate (applet->dropdown_menu, applet);
		gtk_widget_show_all (applet->dropdown_menu);
	}

	nmi_dbus_signal_user_interface_activated (applet->connection);
}

/*
 * nma_dropdown_menu_create
 *
 * Create the applet's dropdown menu
 *
 */
static GtkWidget *nma_dropdown_menu_create (GtkMenuItem *parent, NMApplet *applet)
{
	GtkWidget	*menu;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (applet != NULL, NULL);

	menu = gtk_menu_new ();
	gtk_container_set_border_width (GTK_CONTAINER (menu), 0);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (parent), menu);
	g_signal_connect (menu, "show", G_CALLBACK (nma_dropdown_menu_show_cb), applet);

	return menu;
}


/*
 * nma_context_menu_update
 *
 */
static void nma_context_menu_update (NMApplet *applet)
{
	GSList *element;
	gboolean have_wireless = FALSE;
	NetworkDevice *dev;
	const char *iface = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->stop_wireless_item != NULL);
	g_return_if_fail (applet->info_menu_item != NULL);

	if ((dev = nma_get_first_active_device (applet->device_list)))
		iface = network_device_get_iface (dev);

	if (!dev || !iface)
		gtk_widget_set_sensitive (applet->info_menu_item, FALSE);
	else
		gtk_widget_set_sensitive (applet->info_menu_item, TRUE);

	for (element = applet->device_list; element; element = element->next)
	{
		dev = (NetworkDevice *)(element->data);

		g_assert (dev);

		if (network_device_get_type (dev) == DEVICE_TYPE_802_11_WIRELESS)
		{
			have_wireless = TRUE;
			break;
		}
	}

	if (have_wireless && applet->nm_state != NM_STATE_ASLEEP)
		gtk_widget_show_all (applet->stop_wireless_item);
	else
		gtk_widget_hide (applet->stop_wireless_item);
}


/*
 * nma_enable_wireless_set_active
 *
 * Set the 'Enable Wireless' menu item state to match the daemon's last DBUS
 * message.  We cannot just do this at menu creation time because the DBUS
 * message might not have been sent yet or in case the daemon state changes
 * out from under us.
 */
void nma_enable_wireless_set_active (NMApplet *applet)
{
	   gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (applet->stop_wireless_item), applet->wireless_enabled);
}


/*
 * nma_enable_networking_set_active
 *
 * Set the 'Enable Networking' menu item state to match the daemon's last DBUS
 * message.  We cannot just do this at menu creation time because the DBUS
 * message might not have been sent yet or in case the daemon state changes
 * out from under us.
 */
static inline void nma_enable_networking_set_active (NMApplet *applet)
{
	   gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (applet->enable_networking_item), applet->nm_state != NM_STATE_ASLEEP);
}


/*
 * nma_set_running
 *
 * Set whether NM is running to TRUE or FALSE.
 *
 */
void nma_set_running (NMApplet *applet, gboolean running)
{
	if (running == applet->nm_running)
		return;

	applet->nm_running = running;

	/* if NM became active, start drawing our icon, else stop drawing it */
	if (applet->nm_running && !applet->redraw_timeout_id)
		applet->redraw_timeout_id = g_timeout_add (1000, (GSourceFunc) nma_redraw_timeout, applet);
	else if (!applet->nm_running && applet->redraw_timeout_id)
	{
		g_source_remove (applet->redraw_timeout_id);
		applet->redraw_timeout_id = 0;
	}
}

/*
 * nma_set_state
 *
 * Set the applet's state to one of the NMState enumerations.
 *
 */
void nma_set_state (NMApplet *applet, enum NMState state)
{
	g_return_if_fail (applet != NULL);
	g_return_if_fail (state <= NM_STATE_DISCONNECTED);
	applet->nm_state = state;
	nma_enable_networking_set_active (applet);
}


/*
 * nma_context_menu_create
 *
 * Generate the contextual popup menu.
 *
 */
static GtkWidget *nma_context_menu_create (NMApplet *applet)
{
	GtkWidget	*menu;
	GtkWidget	*menu_item;
	GtkWidget *image;

	g_return_val_if_fail (applet != NULL, NULL);

	menu = gtk_menu_new ();

	/* 'Enable Networking' item */
	applet->enable_networking_item = gtk_check_menu_item_new_with_mnemonic (_("Enable _Networking"));
	nma_enable_networking_set_active (applet);
	g_signal_connect (G_OBJECT (applet->enable_networking_item), "toggled", G_CALLBACK (nma_set_networking_enabled_cb), applet);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), applet->enable_networking_item);

	/* 'Enable Wireless' item */
	applet->stop_wireless_item = gtk_check_menu_item_new_with_mnemonic (_("Enable _Wireless"));
	nma_enable_wireless_set_active (applet);
	g_signal_connect (G_OBJECT (applet->stop_wireless_item), "toggled", G_CALLBACK (nma_set_wireless_enabled_cb), applet);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), applet->stop_wireless_item);

	/* 'Connection Information' item */
	applet->info_menu_item = gtk_image_menu_item_new_with_mnemonic (_("Connection _Information"));
	g_signal_connect (G_OBJECT (applet->info_menu_item), "activate", G_CALLBACK (nma_show_info_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_INFO, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (applet->info_menu_item), image);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), applet->info_menu_item);

	/* Separator */
	nma_menu_add_separator_item (menu);

#if 0	/* FIXME: Implement the help callback, nma_help_cb()! */
	/* Help item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("_Help"));
	g_signal_connect (G_OBJECT (menu_item), "activate", G_CALLBACK (nma_help_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_HELP, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_set_sensitive (GTK_WIDGET (menu_item), FALSE);
#endif

	/* About item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("_About"));
	g_signal_connect (G_OBJECT (menu_item), "activate", G_CALLBACK (nma_about_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);

	gtk_widget_show_all (menu);

	return menu;
}


/*
 * nma_theme_change_cb
 *
 * Destroy the popdown menu when the theme changes
 *
 */
static void nma_theme_change_cb (NMApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->dropdown_menu)
		nma_dropdown_menu_clear (applet->dropdown_menu);

	if (applet->top_menu_item)
	{
		gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));
		applet->dropdown_menu = nma_dropdown_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);
		g_signal_connect (applet->dropdown_menu, "deactivate", G_CALLBACK (nma_dropdown_menu_deactivate_cb), applet);
	}
}

/*
 * nma_menu_position_func
 *
 * Position main dropdown menu, adapted from netapplet
 *
 */
static void nma_menu_position_func (GtkMenu *menu G_GNUC_UNUSED, int *x, int *y, gboolean *push_in, gpointer user_data)
{
	int screen_w, screen_h, button_x, button_y, panel_w, panel_h;
	GtkRequisition requisition;
	GdkScreen *screen;
	NMApplet *applet = (NMApplet *)user_data;

	screen = gtk_widget_get_screen (applet->event_box);
	screen_w = gdk_screen_get_width (screen);
	screen_h = gdk_screen_get_height (screen);

	gdk_window_get_origin (applet->event_box->window, &button_x, &button_y);
	gtk_window_get_size (GTK_WINDOW (gtk_widget_get_toplevel (applet->event_box)), &panel_w, &panel_h);

	*x = button_x;

	/* Check to see if we would be placing the menu off of the end of the screen. */
	gtk_widget_size_request (GTK_WIDGET (menu), &requisition);
	if (button_y + panel_h + requisition.height >= screen_h)
		*y = button_y - requisition.height;
	else
		*y = button_y + panel_h;

	*push_in = TRUE;
}

/*
 * nma_toplevel_menu_button_press_cb
 *
 * Handle left/right-clicks for the dropdown and context popup menus
 *
 */
static gboolean nma_toplevel_menu_button_press_cb (GtkWidget *widget, GdkEventButton *event, NMApplet *applet)
{
	g_return_val_if_fail (applet != NULL, FALSE);

	switch (event->button)
	{
		case 1:
			gtk_widget_set_state (applet->event_box, GTK_STATE_SELECTED);
			gtk_menu_popup (GTK_MENU (applet->dropdown_menu), NULL, NULL, nma_menu_position_func, applet, event->button, event->time);
			return TRUE;
		case 3:
			nma_context_menu_update (applet);
			gtk_menu_popup (GTK_MENU (applet->context_menu), NULL, NULL, nma_menu_position_func, applet, event->button, event->time);
			return TRUE;
		default:
			g_signal_stop_emission_by_name (widget, "button_press_event");
			return FALSE;
	}

	return FALSE;
}


/*
 * nma_toplevel_menu_button_press_cb
 *
 * Handle left-unclick on the dropdown menu.
 *
 */
static void nma_dropdown_menu_deactivate_cb (GtkWidget *menu, NMApplet *applet)
{

	g_return_if_fail (applet != NULL);

	gtk_widget_set_state (applet->event_box, GTK_STATE_NORMAL);
}


/*
 * nma_setup_widgets
 *
 * Intialize the applet's widgets and packing, create the initial
 * menu of networks.
 *
 */
static void nma_setup_widgets (NMApplet *applet)
{
	/* Event box is the main applet widget */
	applet->event_box = gtk_event_box_new ();
	gtk_container_set_border_width (GTK_CONTAINER (applet->event_box), 0);

	applet->top_menu_item = gtk_menu_item_new();
	gtk_widget_set_name (applet->top_menu_item, "ToplevelMenu");
	gtk_container_set_border_width (GTK_CONTAINER (applet->top_menu_item), 0);

	applet->pixmap = gtk_image_new ();
	gtk_container_add (GTK_CONTAINER (applet->event_box), applet->pixmap);
	gtk_container_add (GTK_CONTAINER (applet), applet->event_box);
 	gtk_widget_show_all (GTK_WIDGET (applet));
 
	applet->dropdown_menu = nma_dropdown_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);
	g_signal_connect (applet->event_box, "button_press_event", G_CALLBACK (nma_toplevel_menu_button_press_cb), applet);
	g_signal_connect (applet->dropdown_menu, "deactivate", G_CALLBACK (nma_dropdown_menu_deactivate_cb), applet);

	applet->context_menu = nma_context_menu_create (applet);
	applet->encryption_size_group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
}


/*
 * nma_gconf_info_notify_callback
 *
 * Callback from gconf when wireless key/values have changed.
 *
 */
static void nma_gconf_info_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMApplet *	applet = (NMApplet *)user_data;
	const char *		key = NULL;

	g_return_if_fail (client != NULL);
	g_return_if_fail (entry != NULL);
	g_return_if_fail (applet != NULL);

	if ((key = gconf_entry_get_key (entry)))
	{
		int	net_path_len = strlen (GCONF_PATH_WIRELESS_NETWORKS) + 1;

		if (strncmp (GCONF_PATH_WIRELESS_NETWORKS"/", key, net_path_len) == 0)
		{
			char 	*network = g_strdup ((key + net_path_len));
			char		*slash_pos;
			char		*unescaped_network;

			/* If its a key under the network name, zero out the slash so we
			 * are left with only the network name.
			 */
			unescaped_network = gconf_unescape_key (network, strlen (network));
			if ((slash_pos = strchr (unescaped_network, '/')))
				*slash_pos = '\0';

			nmi_dbus_signal_update_network (applet->connection, unescaped_network, NETWORK_TYPE_ALLOWED);
			g_free (unescaped_network);
			g_free (network);
		}
	}
}


/*
 * nma_gconf_vpn_connections_notify_callback
 *
 * Callback from gconf when VPN connection values have changed.
 *
 */
static void nma_gconf_vpn_connections_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMApplet *	applet = (NMApplet *)user_data;
	const char *		key = NULL;

	/*g_debug ("Entering nma_gconf_vpn_connections_notify_callback, key='%s'", gconf_entry_get_key (entry));*/

	g_return_if_fail (client != NULL);
	g_return_if_fail (entry != NULL);
	g_return_if_fail (applet != NULL);

	if ((key = gconf_entry_get_key (entry)))
	{
		int	path_len = strlen (GCONF_PATH_VPN_CONNECTIONS) + 1;

		if (strncmp (GCONF_PATH_VPN_CONNECTIONS"/", key, path_len) == 0)
		{
			char 	 *name = g_strdup ((key + path_len));
			char		 *slash_pos;
			char	 	 *unescaped_name;
			char       *name_path;
			GConfValue *value;

			/* If its a key under the the VPN name, zero out the slash so we
			 * are left with only the VPN name.
			 */
			if ((slash_pos = strchr (name, '/')))
				*slash_pos = '\0';
			unescaped_name = gconf_unescape_key (name, strlen (name));

			/* Check here if the name entry is gone so we can remove the conn from the UI */
			name_path = g_strdup_printf ("%s/%s/name", GCONF_PATH_VPN_CONNECTIONS, name);
			gconf_client_clear_cache (client);
			value = gconf_client_get (client, name_path, NULL);
			if (value == NULL) {
				/*g_debug ("removing '%s' from UI", name_path);*/
				nma_dbus_vpn_remove_one_vpn_connection (applet, unescaped_name);
			} else {
				gconf_value_free (value);
			}
			g_free (name_path);

			nmi_dbus_signal_update_vpn_connection (applet->connection, unescaped_name);

			g_free (unescaped_name);
			g_free (name);
		}

	}
}


/*
 * nma_destroy
 *
 * Destroy the applet and clean up its data
 *
 */
static void G_GNUC_NORETURN nma_destroy (NMApplet *applet)
{
	if (applet->dropdown_menu)
		nma_dropdown_menu_clear (applet->dropdown_menu);
	if (applet->top_menu_item)
		gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));

	nma_icons_free (applet);

	nmi_passphrase_dialog_destroy (applet);
#ifdef ENABLE_NOTIFY
	if (applet->notification)
	{
		notify_notification_close (applet->notification, NULL);
		g_object_unref (applet->notification);
	}
#endif

	nma_set_running (applet, FALSE);
	if (applet->connection_timeout_id) {
		g_source_remove (applet->connection_timeout_id);
		applet->connection_timeout_id = 0;
	}

	if (applet->gconf_client)
		g_object_unref (G_OBJECT (applet->gconf_client));

	nma_free_data_model (applet);

	g_free (applet->glade_file);

	gconf_client_notify_remove (applet->gconf_client, applet->gconf_prefs_notify_id);
	gconf_client_notify_remove (applet->gconf_client, applet->gconf_vpn_notify_id);
	g_object_unref (G_OBJECT (applet->gconf_client));

	dbus_method_dispatcher_unref (applet->nmi_methods);

	exit (EXIT_SUCCESS);
}


/*
 * nma_get_instance
 *
 * Create the initial instance of our wireless applet
 *
 */
static GtkWidget * nma_get_instance (NMApplet *applet)
{
	gtk_widget_hide (GTK_WIDGET (applet));

	applet->nm_running = FALSE;
	applet->device_list = NULL;
	applet->vpn_connections = NULL;
	applet->dialup_list = NULL;
	applet->nm_state = NM_STATE_DISCONNECTED;
	applet->tooltips = NULL;
	applet->passphrase_dialog = NULL;
	applet->connection_timeout_id = 0;
	applet->redraw_timeout_id = 0;
#ifdef ENABLE_NOTIFY
	applet->notification = NULL;
#endif

	applet->glade_file = g_build_filename (GLADEDIR, "applet.glade", NULL);
	if (!applet->glade_file || !g_file_test (applet->glade_file, G_FILE_TEST_IS_REGULAR))
	{
		nma_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		g_free (applet->glade_file);
		applet->glade_file = NULL;
		return NULL;
	}

	applet->info_dialog_xml = glade_xml_new (applet->glade_file, "info_dialog", NULL);

	applet->gconf_client = gconf_client_get_default ();
	if (!applet->gconf_client)
		return NULL;

	gconf_client_add_dir (applet->gconf_client, GCONF_PATH_WIRELESS, GCONF_CLIENT_PRELOAD_NONE, NULL);
	applet->gconf_prefs_notify_id = gconf_client_notify_add (applet->gconf_client, GCONF_PATH_WIRELESS,
						nma_gconf_info_notify_callback, applet, NULL, NULL);

	gconf_client_add_dir (applet->gconf_client, GCONF_PATH_VPN_CONNECTIONS, GCONF_CLIENT_PRELOAD_NONE, NULL);
	applet->gconf_vpn_notify_id = gconf_client_notify_add (applet->gconf_client, GCONF_PATH_VPN_CONNECTIONS,
						nma_gconf_vpn_connections_notify_callback, applet, NULL, NULL);

	/* Convert old-format stored network entries to the new format.
	 * Must be RUN BEFORE DBUS INITIALIZATION since we have to do
	 * synchronous calls against gnome-keyring.
	 */
	nma_compat_convert_oldformat_entries (applet->gconf_client);

	/* D-Bus init stuff */
	dbus_g_thread_init ();
	applet->nmi_methods = nmi_dbus_nmi_methods_setup ();
	nma_dbus_init_helper (applet);
	if (!applet->connection)
		nma_start_dbus_connection_watch (applet);

	/* Load pixmaps and create applet widgets */
	nma_setup_widgets (applet);

	g_signal_connect (applet, "destroy", G_CALLBACK (nma_destroy), NULL);
	g_signal_connect (applet, "style-set", G_CALLBACK (nma_theme_change_cb), NULL);

	return GTK_WIDGET (applet);
}


static void nma_icons_free (NMApplet *applet)
{
	int i;

	g_object_unref (applet->no_connection_icon);
	g_object_unref (applet->wired_icon);
	g_object_unref (applet->adhoc_icon);
	g_object_unref (applet->vpn_lock_icon);

	g_object_unref (applet->wireless_00_icon);
	g_object_unref (applet->wireless_25_icon);
	g_object_unref (applet->wireless_50_icon);
	g_object_unref (applet->wireless_75_icon);
	g_object_unref (applet->wireless_100_icon);

	for (i = 0; i < NUM_CONNECTING_STAGES; i++)
	{
		int j;

		for (j = 0; j < NUM_CONNECTING_FRAMES; j++)
			g_object_unref (applet->network_connecting_icons[i][j]);
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
		g_object_unref (applet->vpn_connecting_icons[i]);
}

static void nma_icons_zero (NMApplet *applet)
{
	int i;

	applet->no_connection_icon = NULL;
	applet->wired_icon = NULL;
	applet->adhoc_icon = NULL;
	applet->vpn_lock_icon = NULL;

	applet->wireless_00_icon = NULL;
	applet->wireless_25_icon = NULL;
	applet->wireless_50_icon = NULL;
	applet->wireless_75_icon = NULL;
	applet->wireless_100_icon = NULL;

	for (i = 0; i < NUM_CONNECTING_STAGES; i++)
	{
		int j;

		for (j = 0; j < NUM_CONNECTING_FRAMES; j++)
			applet->network_connecting_icons[i][j] = NULL;
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
		applet->vpn_connecting_icons[i] = NULL;

}

#define ICON_LOAD(x, y)	\
	{		\
		GError *err = NULL; \
		x = gtk_icon_theme_load_icon (icon_theme, y, 22, 0, &err); \
		if (x == NULL) { \
			success = FALSE; \
			g_warning ("Icon %s missing: %s", y, err->message); \
			g_error_free (err); \
			goto out; \
		} \
	}

static gboolean
nma_icons_load_from_disk (NMApplet *applet, GtkIconTheme *icon_theme)
{
	int		i;
	gboolean	success;

	/*
	 * NULL out the icons, so if we error and call nma_icons_free(), we don't hit stale
	 * data on the not-yet-reached icons.  This can happen off nma_icon_theme_changed().
	 */
	nma_icons_zero (applet);

	ICON_LOAD(applet->no_connection_icon, "nm-no-connection");
	ICON_LOAD(applet->wired_icon, "nm-device-wired");
	ICON_LOAD(applet->adhoc_icon, "nm-adhoc");
	ICON_LOAD(applet->vpn_lock_icon, "nm-vpn-lock");

	ICON_LOAD(applet->wireless_00_icon, "nm-signal-00");
	ICON_LOAD(applet->wireless_25_icon, "nm-signal-25");
	ICON_LOAD(applet->wireless_50_icon, "nm-signal-50");
	ICON_LOAD(applet->wireless_75_icon, "nm-signal-75");
	ICON_LOAD(applet->wireless_100_icon, "nm-signal-100");

	for (i = 0; i < NUM_CONNECTING_STAGES; i++)
	{
		int j;

		for (j = 0; j < NUM_CONNECTING_FRAMES; j++)
		{
			char *name;

			name = g_strdup_printf ("nm-stage%02d-connecting%02d", i+1, j+1);
			ICON_LOAD(applet->network_connecting_icons[i][j], name);
			g_free (name);
		}
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
	{
		char *name;

		name = g_strdup_printf ("nm-vpn-connecting%02d", i+1);
		ICON_LOAD(applet->vpn_connecting_icons[i], name);
		g_free (name);
	}

	success = TRUE;

out:
	if (!success)
	{
		char *msg = g_strdup(_("The NetworkManager applet could not find some required resources.  It cannot continue.\n"));
		show_warning_dialog (msg);
		nma_icons_free (applet);
	}

	return success;
}

static void nma_icon_theme_changed (GtkIconTheme *icon_theme, NMApplet *applet)
{
	nma_icons_free (applet);
	nma_icons_load_from_disk (applet, icon_theme);
	/* FIXME: force redraw */
}

static gboolean nma_icons_init (NMApplet *applet)
{
	GtkIconTheme *icon_theme;
	const gchar *style = " \
		style \"MenuBar\" \
		{ \
			GtkMenuBar::shadow_type = GTK_SHADOW_NONE \
			GtkMenuBar::internal-padding = 0 \
		} \
		style \"MenuItem\" \
		{ \
			xthickness=0 \
			ythickness=0 \
		} \
		class \"GtkMenuBar\" style \"MenuBar\"\
		widget \"*ToplevelMenu*\" style \"MenuItem\"\
		";	

	/* FIXME: Do we need to worry about other screens? */
	gtk_rc_parse_string (style);

	icon_theme = gtk_icon_theme_get_default ();
	if (!nma_icons_load_from_disk (applet, icon_theme))
		return FALSE;
	g_signal_connect (icon_theme, "changed", G_CALLBACK (nma_icon_theme_changed), applet);
	return TRUE;
}


NMApplet *nma_new ()
{
	return g_object_new (NM_TYPE_APPLET, "title", "NetworkManager", NULL);
}

