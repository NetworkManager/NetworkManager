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

#include "applet.h"
#include "applet-dbus.h"
#include "applet-dbus-devices.h"
#include "applet-dbus-vpn.h"
#include "applet-dbus-info.h"
#include "other-network-dialog.h"
#include "passphrase-dialog.h"
#include "menu-items.h"
#include "vpn-password-dialog.h"
#include "vpn-connection.h"
#include "nm-utils.h"

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

static GObject *	nmwa_constructor (GType type, guint n_props, GObjectConstructParam *construct_props);
static void		setup_stock (void);
static gboolean	nmwa_icons_init (NMWirelessApplet *applet);
static void		nmwa_icons_free (NMWirelessApplet *applet);
static void		nmwa_about_cb (NMWirelessApplet *applet);
static void		nmwa_context_menu_update (NMWirelessApplet *applet);
static GtkWidget *	nmwa_get_instance (NMWirelessApplet *applet);

G_DEFINE_TYPE(NMWirelessApplet, nmwa, EGG_TYPE_TRAY_ICON)

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
 * nmwa_get_first_active_device
 *
 * Return the first device marked as "active".
 *
 */
NetworkDevice * nmwa_get_first_active_device (GSList *dev_list)
{
	GSList *	elt;

	if (!dev_list)
		return NULL;

	for (elt = dev_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice *dev = (NetworkDevice *)(elt->data);

		if (network_device_get_active (dev))
			return dev;
	}

	return NULL;
}


static void nmwa_init (NMWirelessApplet *applet)
{
	applet->animation_id = 0;
	applet->animation_step = 0;
	glade_gnome_init ();

	setup_stock ();
	if (!nmwa_icons_init (applet))
		return;

/*	gtk_window_set_default_icon_from_file (ICONDIR"/NMWirelessApplet/wireless-applet.png", NULL); */
	gtk_widget_show (nmwa_get_instance (applet));
}

static void nmwa_class_init (NMWirelessAppletClass *klass)
{
	GObjectClass *gobject_class;

	gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->constructor = nmwa_constructor;
}

static GObject *nmwa_constructor (GType type, guint n_props, GObjectConstructParam *construct_props)
{
	GObject *obj;
	NMWirelessApplet *applet;
	NMWirelessAppletClass *klass;

	klass = NM_WIRELESS_APPLET_CLASS (g_type_class_peek (type));
	obj = G_OBJECT_CLASS (nmwa_parent_class)->constructor (type, n_props, construct_props);
	applet =  NM_WIRELESS_APPLET (obj);

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

static void nmwa_show_socket_err (GtkWidget *info_dialog, const char *err)
{
	GtkWidget *error_dialog;
	char *msg;
	
	msg = g_strdup_printf ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
	                       _("Error displaying connection information: "), err);
	error_dialog = gtk_message_dialog_new_with_markup (GTK_WINDOW (info_dialog), 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
	g_free (msg);
	gtk_window_present (GTK_WINDOW (error_dialog));
	g_signal_connect_swapped (error_dialog, "response", G_CALLBACK (gtk_widget_destroy), error_dialog);
}

static gboolean nmwa_update_info (NMWirelessApplet *applet)
{
	GtkWidget *info_dialog;
	char *addr = NULL, *mask = NULL, *broadcast = NULL;
	char *mac = NULL, *iface_and_type = NULL, *route = NULL;
	GtkWidget *label;
	const char *iface = NULL;
	NetworkDevice *dev;

	info_dialog = glade_xml_get_widget (applet->info_dialog_xml, "info_dialog");
	if (!info_dialog)
	{
		char *err = g_strdup (_("Could not find some required resources (the glade file)!"));
		nmwa_show_socket_err (info_dialog, err);
		g_free (err);
		return FALSE;
	}
	
	if ((dev = nmwa_get_first_active_device (applet->device_list)))
		iface = network_device_get_iface (dev);

	if (!dev || !iface)
	{
		char *err = g_strdup (_("No active connections!"));
		nmwa_show_socket_err (info_dialog, err);
		g_free (err);
		return FALSE;
	}

	mac = (char*) network_device_get_address (dev);
	broadcast = (char*) network_device_get_broadcast (dev);
	addr = (char*) network_device_get_ip4_address (dev);
	mask = (char*) network_device_get_netmask (dev);
	route = (char*) network_device_get_route (dev);

	if (network_device_is_wired (dev))
		iface_and_type = g_strdup_printf (_("Wired Ethernet (%s)"), iface);
	else
		iface_and_type = g_strdup_printf (_("Wireless Ethernet (%s)"), iface);	

	label = get_label (info_dialog, applet->info_dialog_xml, "label-interface");
	gtk_label_set_text (GTK_LABEL (label), iface_and_type);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-ip-address");
	gtk_label_set_text (GTK_LABEL (label), addr);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-broadcast-address");
	gtk_label_set_text (GTK_LABEL (label), broadcast);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-subnet-mask");
	gtk_label_set_text (GTK_LABEL (label), mask);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-hardware-address");
	gtk_label_set_text (GTK_LABEL (label), mac);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-default-route");
	gtk_label_set_text (GTK_LABEL (label), route);

	g_free (iface_and_type);

	return TRUE;
}

static void nmwa_show_info_cb (GtkMenuItem *mi, NMWirelessApplet *applet)
{
	GtkWidget *info_dialog;

	info_dialog = glade_xml_get_widget (applet->info_dialog_xml, "info_dialog");

	if (nmwa_update_info (applet))
	{
		gtk_window_present (GTK_WINDOW (info_dialog));
		g_signal_connect_swapped (info_dialog, "response", G_CALLBACK (gtk_widget_hide), info_dialog);
	}
}

static void nmwa_about_cb (NMWirelessApplet *applet)
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
		NULL
	};

	static const gchar *artists[] =
	{
		"Diana Fong <dfong@redhat.com>",
		NULL
	};

	static const gchar *documenters[] =
	{
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
	                                _("Copyright (C) 2004-2005 Red Hat, Inc."),
	                                _("Notification area applet for managing your network devices and connections."),
	                                authors,
	                                documenters,
	                                NULL,
	                                pixbuf);
	g_object_unref (pixbuf);

	gtk_window_set_screen (GTK_WINDOW (about_dialog), gtk_widget_get_screen (GTK_WIDGET (applet)));
	g_signal_connect (about_dialog, "destroy", G_CALLBACK (gtk_widget_destroyed), &about_dialog);
	gtk_widget_show (about_dialog);

#else

	/* GTK 2.6 and later code */
	gtk_show_about_dialog (NULL,
	                       "name", _("NetworkManager Applet"),
	                       "version", VERSION,
	                       "copyright", _("Copyright (C) 2004-2005 Red Hat, Inc."),
	                       "comments", _("Notification area applet for managing your network devices and connections."),
	                       "authors", authors,
	                       "artists", artists,
	                       "documenters", documenters,
	                       "translator-credits", _("translator-credits"),
	                       "logo-icon-name", GTK_STOCK_NETWORK,
	                       NULL);
#endif
}

typedef struct DialogCBData
{
	char *msg;
	char *title;
} DialogCBData;

static void free_dialog_cb_data (DialogCBData *data)
{
	g_return_if_fail (data != NULL);

	g_free (data->msg);
	g_free (data->title);
	memset (data, 0, sizeof (DialogCBData));
	g_free (data);
}

static void vpn_failure_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	DialogCBData *data;

	if ((data = g_object_get_data (G_OBJECT (dialog), "data")))
	{
		g_object_set_data (G_OBJECT (dialog), "data", NULL);
		free_dialog_cb_data (data);
	}

	gtk_widget_destroy (dialog);
}


/*
 * nmwa_show_vpn_failure_dialog
 *
 * Present the VPN failure dialog.
 *
 */
static gboolean nmwa_show_vpn_failure_dialog (DialogCBData *cb_data)
{
	GtkWidget	*dialog;
	guint32	 timestamp;

	g_return_val_if_fail (cb_data != NULL, FALSE);
	g_return_val_if_fail (cb_data->msg != NULL, FALSE);
	g_return_val_if_fail (cb_data->title != NULL, FALSE);

	dialog = gtk_message_dialog_new_with_markup (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, cb_data->msg, NULL);
	gtk_window_set_title (GTK_WINDOW (dialog), cb_data->title);
	g_signal_connect (dialog, "response", G_CALLBACK (vpn_failure_dialog_close_cb), NULL);
	g_signal_connect (dialog, "close", G_CALLBACK (vpn_failure_dialog_close_cb), NULL);
	g_object_set_data (G_OBJECT (dialog), "data", cb_data);
	gtk_widget_show_all (dialog);

	/* Bash focus-stealing prevention in the face */
	timestamp = gdk_x11_get_server_time (dialog->window);
	gdk_x11_window_set_user_time (dialog->window, timestamp);

	return FALSE;
}


/*
 * nmwa_schedule_vpn_failure_dialog
 *
 * Schedule display of the VPN Failure dialog.
 *
 */
void nmwa_schedule_vpn_failure_dialog (NMWirelessApplet *applet, const char *member, const char *vpn_name, const char *error_msg)
{
	DialogCBData *cb_data = NULL;
	gchar *error_head = NULL;
	gchar *error_desc = NULL;
	gchar *error_data = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (member != NULL);
	g_return_if_fail (vpn_name != NULL);
	g_return_if_fail (error_msg != NULL);

	cb_data = g_malloc0 (sizeof (DialogCBData));
	cb_data->title = g_strdup (_("VPN Error"));

	if (!strcmp (member, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED))
	{
		error_head = g_strdup (_("VPN Login Failure"));
		error_desc = g_strdup_printf (_("Could not start the VPN connection '%s' due to a login failure."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED))
	{
		error_head = g_strdup (_("VPN Start Failure"));
		error_desc = g_strdup_printf (_("Could not start the VPN connection '%s' due to a failure launching the VPN program."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED))
	{
		error_head = g_strdup (_("VPN Connect Failure"));
		error_desc = g_strdup_printf (_("Could not start the VPN connection '%s' due to a connection error."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD))
	{
		error_head = g_strdup (_("VPN Configuration Error"));
		error_desc = g_strdup_printf (_("The VPN connection '%s' was not correctly configured."), vpn_name);
	}
	else if (!strcmp (member, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD))
	{
		error_head = g_strdup (_("VPN Connect Failure"));
		error_desc = g_strdup_printf (_("Could not start the VPN connection '%s' because the VPN server did not return an adequate network configuration."), vpn_name);
	}
	else
	{
		free_dialog_cb_data (cb_data);
		return;
	}

	error_data = g_strdup_printf (_("The VPN service said: \"%s\""), error_msg);

	cb_data->msg = g_strdup_printf ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n"
	                                "%s\n\n%s", error_head, error_desc, error_data);

	g_free (error_head);
	g_free (error_desc);
	g_free (error_data);

	g_idle_add ((GSourceFunc) nmwa_show_vpn_failure_dialog, cb_data);
}


static void vpn_login_banner_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	char *message;

	if ((message = g_object_get_data (G_OBJECT (dialog), "message")))
	{
		g_object_set_data (G_OBJECT (dialog), "message", NULL);
		g_free (message);
	}

	gtk_widget_destroy (dialog);
}


/*
 * nmwa_show_vpn_login_banner_dialog
 *
 * Present the VPN login banner dialog.
 *
 */
static gboolean nmwa_show_vpn_login_banner_dialog (char *message)
{
	GtkWidget	*dialog;
	guint32	 timestamp;

	g_return_val_if_fail (message != NULL, FALSE);

	dialog = gtk_message_dialog_new_with_markup (NULL, 0, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, message, NULL);
	g_signal_connect (dialog, "response", G_CALLBACK (vpn_login_banner_dialog_close_cb), NULL);
	g_signal_connect (dialog, "close", G_CALLBACK (vpn_login_banner_dialog_close_cb), NULL);
	g_object_set_data (G_OBJECT (dialog), "message", message);
	gtk_widget_show_all (dialog);

	/* Bash focus-stealing prevention in the face */
	timestamp = gdk_x11_get_server_time (dialog->window);
	gdk_x11_window_set_user_time (dialog->window, timestamp);

	return FALSE;
}


/*
 * nmwa_schedule_vpn_login_banner_dialog
 *
 * Schedule display of the VPN Login Banner dialog.
 *
 */
void nmwa_schedule_vpn_login_banner_dialog (NMWirelessApplet *applet, const char *vpn_name, const char *banner)
{
	char *msg;
	char *msg2;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (vpn_name != NULL);
	g_return_if_fail (banner != NULL);

	msg2 = g_strdup_printf (_("VPN connection '%s' said:"), vpn_name);
	msg = g_strdup_printf ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s\n\n\"%s\"",
	                       _("VPN Login Message"), msg2, banner);
	g_free (msg2);

	g_idle_add ((GSourceFunc) nmwa_show_vpn_login_banner_dialog, msg);
}


/*
 * nmwa_driver_notify_get_ignored_list
 *
 * Return list of devices for which we are supposed to ignore driver
 * notifications for from GConf.
 *
 */
static GSList *nmwa_driver_notify_get_ignored_list (NMWirelessApplet *applet)
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
 * nmwa_driver_notify_is_device_ignored
 *
 * Look in GConf and determine whether or not we are supposed to
 * ignore driver notifications for a particular device.
 *
 */
static gboolean nmwa_driver_notify_is_device_ignored (NMWirelessApplet *applet, NetworkDevice *dev)
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

	mac_list = nmwa_driver_notify_get_ignored_list (applet);

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
 * nmwa_driver_notify_ignore_device
 *
 * Add a device's MAC address to the list of ones that we ignore
 * in GConf.  Stores user's pref for "Don't remind me".
 *
 */
static void nmwa_driver_notify_ignore_device (NMWirelessApplet *applet, NetworkDevice *dev)
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

	new_mac_list = nmwa_driver_notify_get_ignored_list (applet);

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

static gboolean nmwa_driver_notify_dialog_delete_cb (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy (widget);
	return FALSE;
}

static gboolean nmwa_driver_notify_dialog_destroy_cb (GtkWidget *widget, GdkEvent *event, gpointer user_data)
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


static gboolean nmwa_driver_notify_ok_cb (GtkButton *button, gpointer user_data)
{
	DriverNotifyCBData	*cb_data = (DriverNotifyCBData *)(user_data);
	NetworkDevice		*dev;
	NMWirelessApplet	*applet;
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
		nmwa_driver_notify_ignore_device (applet, dev);

	dialog = glade_xml_get_widget (cb_data->xml, "driver_sucks_dialog");
	gtk_widget_destroy (dialog);

	return FALSE;
}


/*
 * nmwa_driver_notify
 *
 * Notify the user if there's some problem with the driver
 * of a specific network device.
 *
 */
gboolean nmwa_driver_notify (gpointer user_data)
{
	DriverNotifyCBData *	cb_data = (DriverNotifyCBData *)(user_data);
	NetworkDevice *		dev;
	NMWirelessApplet *		applet;
	GtkWidget *			dialog;
	GtkLabel *			label;
	char *				label_text = NULL;
	char *				temp = NULL;
	GtkButton *			button;
	guint32				timestamp;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	dev = cb_data->dev;
	g_return_val_if_fail (dev != NULL, FALSE);

	if (!(applet = cb_data->applet) || !applet->glade_file)
		goto out;

	/* If the user has already requested that we ignore notifications for
	 * this device, don't do anything.
	 */
	if (nmwa_driver_notify_is_device_ignored (applet, dev))
		goto out;

	if (!(cb_data->xml = glade_xml_new (applet->glade_file, "driver_sucks_dialog", NULL)))
	{
		nmwa_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		goto out;
	}

	dialog = glade_xml_get_widget (cb_data->xml, "driver_sucks_dialog");
	g_signal_connect (G_OBJECT (dialog), "destroy-event", GTK_SIGNAL_FUNC (nmwa_driver_notify_dialog_destroy_cb), cb_data);
	g_signal_connect (G_OBJECT (dialog), "delete-event", GTK_SIGNAL_FUNC (nmwa_driver_notify_dialog_delete_cb), cb_data);

	label = GTK_LABEL (glade_xml_get_widget (cb_data->xml, "driver_sucks_label"));

	switch (network_device_get_driver_support_level (dev))
	{
		case NM_DRIVER_NO_WIRELESS_SCAN:
			temp = g_strdup_printf (_("The network device \"%s (%s)\" does not support wireless scanning."),
			                        network_device_get_desc (dev), network_device_get_iface (dev));
			label_text = g_strdup_printf (gtk_label_get_label (label), temp);
			g_free (temp);
		break;

		case NM_DRIVER_NO_CARRIER_DETECT:
			temp = g_strdup_printf (_("The network device \"%s (%s)\" does not support link detection."),
			                        network_device_get_desc (dev), network_device_get_iface (dev));
			label_text = g_strdup_printf (gtk_label_get_label (label), temp);
			g_free (temp);
			break;

		default:
			break;
	}

	if (label_text)
		gtk_label_set_markup (label, label_text);

	button = GTK_BUTTON (glade_xml_get_widget (cb_data->xml, "ok_button"));
	g_signal_connect (G_OBJECT (button), "clicked", GTK_SIGNAL_FUNC (nmwa_driver_notify_ok_cb), cb_data);

	gtk_widget_show_all (GTK_WIDGET (dialog));

	/* Bash focus-stealing prevention in the face */
	timestamp = gdk_x11_get_server_time (dialog->window);
	gdk_x11_window_set_user_time (dialog->window, timestamp);

out:
	network_device_unref (cb_data->dev);
	return (FALSE);
}


/*
 * nmwa_get_first_active_vpn_connection
 *
 * Return the first active VPN connection, if any.
 *
 */
VPNConnection *nmwa_get_first_active_vpn_connection (NMWirelessApplet *applet)
{
	VPNConnection *	vpn;
	NMVPNActStage		vpn_state;
	GSList *			elt;

	for (elt = applet->vpn_connections; elt; elt = g_slist_next (elt))
	{
		vpn = (VPNConnection*) elt->data;
		vpn_state = nmwa_vpn_connection_get_state (vpn);
		if (vpn_state == NM_VPN_ACT_STAGE_ACTIVATED)
			return vpn;
	}

	return NULL;
}

VPNConnection *nmwa_get_first_activating_vpn_connection (NMWirelessApplet *applet)
{
	VPNConnection *	vpn;
	GSList *			elt;

	for (elt = applet->vpn_connections; elt; elt = g_slist_next (elt))
	{
		vpn = (VPNConnection*) elt->data;
		if (nmwa_vpn_connection_is_activating (vpn))
			return vpn;
	}

	return NULL;
}

static void nmwa_set_icon (NMWirelessApplet *applet, GdkPixbuf *link_icon, GdkPixbuf *vpn_icon)
{
	GdkPixbuf	*composite;
	VPNConnection	*vpn;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (link_icon != NULL);

	composite = gdk_pixbuf_copy (link_icon);

	vpn = nmwa_get_first_active_vpn_connection (applet);
	if (!vpn)
		vpn = nmwa_get_first_activating_vpn_connection (applet);

	if (vpn)
	{
		if (!vpn_icon)
			goto out;

		gdk_pixbuf_composite (vpn_icon, composite, 0, 0, gdk_pixbuf_get_width (vpn_icon),
							gdk_pixbuf_get_height (vpn_icon), 0, 0, 1.0, 1.0, GDK_INTERP_NEAREST, 255);
	}

out:
	gtk_image_set_from_pixbuf (GTK_IMAGE (applet->pixmap), composite);

	g_object_unref (composite);
}


static void nmwa_set_progress (NMWirelessApplet *applet, GdkPixbuf *progress_icon)
{
	g_return_if_fail (applet != NULL);

	gtk_image_set_from_pixbuf (GTK_IMAGE (applet->progress_bar), progress_icon);
	if (!progress_icon)
		gtk_widget_hide (applet->progress_bar);
	else
		gtk_widget_show (applet->progress_bar);
}

static GdkPixbuf *nmwa_get_connected_icon (NMWirelessApplet *applet, NetworkDevice *dev)
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


/*
 * animation_timeout
 *
 * Jump to the next frame of the applets icon if the icon
 * is supposed to be animated.
 *
 */
static gboolean animation_timeout (NMWirelessApplet *applet)
{
	NetworkDevice *act_dev;

	g_return_val_if_fail (applet != NULL, FALSE);

	if (!applet->nm_running)
	{
		applet->animation_step = 0;
		return TRUE;
	}

	act_dev = nmwa_get_first_active_device (applet->device_list);

	if (applet->nm_state == NM_STATE_CONNECTING)
	{
		if (act_dev && network_device_is_wireless (act_dev))
		{
			if (applet->animation_step >= NUM_WIRELESS_CONNECTING_FRAMES)
				applet->animation_step = 0;
			nmwa_set_icon (applet, applet->wireless_connecting_icons[applet->animation_step], NULL);
		}
		else if (act_dev)
		{
			if (applet->animation_step >= NUM_WIRED_CONNECTING_FRAMES)
				applet->animation_step = 0;
			nmwa_set_icon (applet, applet->wired_connecting_icons[applet->animation_step], NULL);
		}
		applet->animation_step ++;
	}
	else if (nmwa_get_first_activating_vpn_connection (applet) != NULL)
	{
		GdkPixbuf *connected_icon;
		connected_icon = nmwa_get_connected_icon (applet, act_dev);

		if (applet->animation_step >= NUM_VPN_CONNECTING_FRAMES)
			applet->animation_step = 0;
		nmwa_set_icon (applet, connected_icon, applet->vpn_connecting_icons[applet->animation_step]);
		applet->animation_step ++;
	}

	return TRUE;
}


static GdkPixbuf * nmwa_act_stage_to_pixbuf (NMWirelessApplet *applet, NetworkDevice *dev, WirelessNetwork *net, char **tip)
{
	const char *essid;
	const char *iface;

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
			return applet->progress_icons[1];
		}

		case NM_ACT_STAGE_DEVICE_CONFIG:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Configuring device %s for the wired network..."), iface);
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Attempting to join the wireless network '%s'..."), essid);
			return applet->progress_icons[3];
		}

		case NM_ACT_STAGE_NEED_USER_KEY:
		{
			if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Waiting for Network Key for the wireless network '%s'..."), essid);
			return applet->progress_icons[4];
		}

		case NM_ACT_STAGE_IP_CONFIG_START:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wired network..."));
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wireless network '%s'..."), essid);
			return applet->progress_icons[5];
		}

		case NM_ACT_STAGE_IP_CONFIG_GET:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wired network..."));
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Requesting a network address from the wireless network '%s'..."), essid);
			return applet->progress_icons[8];
		}

		case NM_ACT_STAGE_IP_CONFIG_COMMIT:
		{
			if (network_device_is_wired (dev))
				*tip = g_strdup_printf (_("Finishing connection to the wired network..."));
			else if (network_device_is_wireless (dev))
				*tip = g_strdup_printf (_("Finishing connection to the wireless network '%s'..."), essid);
			return applet->progress_icons[10];
		}

		default:
		case NM_ACT_STAGE_ACTIVATED:
		case NM_ACT_STAGE_FAILED:
		case NM_ACT_STAGE_CANCELLED:
		case NM_ACT_STAGE_UNKNOWN:
			break;
	}
	return NULL;
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
	gboolean			show_applet = TRUE;
	gboolean			need_animation = FALSE;
	GdkPixbuf *		pixbuf = NULL;
	GdkPixbuf *		progress = NULL;
	gint				strength = -1;
	char *			tip = NULL;
	char *			vpntip = NULL;
	WirelessNetwork *	active_network = NULL;
	NetworkDevice *	act_dev = NULL;
	VPNConnection		*vpn;

	act_dev = nmwa_get_first_active_device (applet->device_list);
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

	if (!act_dev)
		applet->nm_state = NM_STATE_DISCONNECTED;

	switch (applet->nm_state)
	{
		case NM_STATE_ASLEEP:
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

			pixbuf = nmwa_get_connected_icon (applet, act_dev);

			break;

		case NM_STATE_CONNECTING:
			progress = nmwa_act_stage_to_pixbuf (applet, act_dev, active_network, &tip);
			need_animation = TRUE;
			break;

		default:
			break;
	}

	vpn = nmwa_get_first_active_vpn_connection (applet);
	if (vpn != NULL)
	{
		vpntip = g_strdup_printf (_("VPN connection to '%s'"), nmwa_vpn_connection_get_name (vpn));
	}
	else
	{
		vpn = nmwa_get_first_activating_vpn_connection (applet);
		if (vpn != NULL)
		{
			need_animation = TRUE;
			vpntip = g_strdup_printf (_("VPN connecting to '%s'"), nmwa_vpn_connection_get_name (vpn));
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

	nmwa_set_progress (applet, progress);

	applet->animation_step = 0;
	if (applet->animation_id)
		g_source_remove (applet->animation_id);
	if (need_animation)
		applet->animation_id = g_timeout_add (100, (GSourceFunc) animation_timeout, applet);
	else
	{
		if (pixbuf)
			nmwa_set_icon (applet, pixbuf, applet->vpn_lock_icon);
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
 * nmwa_redraw_timeout
 *
 * Called regularly to update the applet's state and icon in the panel
 *
 */
static int nmwa_redraw_timeout (NMWirelessApplet *applet)
{
	nmwa_update_state (applet);

  	return (TRUE);
}

static void nmwa_start_redraw_timeout (NMWirelessApplet *applet)
{
	applet->redraw_timeout_id = g_timeout_add (1000, (GtkFunction) nmwa_redraw_timeout, applet);
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
	guint32		timestamp;

	dialog = gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, mesg, NULL);
	gtk_widget_realize (dialog);

	/* Bash focus-stealing prevention in the face */
	timestamp = gdk_x11_get_server_time (dialog->window);
	gdk_x11_window_set_user_time (dialog->window, timestamp);

	gtk_window_present (GTK_WINDOW (dialog));
	g_signal_connect_swapped (dialog, "response", G_CALLBACK (gtk_widget_destroy), dialog);
	g_free (mesg);

	return FALSE;
}


/*
 * nmwa_schedule_warning_dialog
 *
 * Run a warning dialog in the main event loop.
 *
 */
void nmwa_schedule_warning_dialog (NMWirelessApplet *applet, const char *msg)
{
	char *lcl_msg;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (msg != NULL);

	lcl_msg = g_strdup (msg);
	g_idle_add ((GSourceFunc) show_warning_dialog, lcl_msg);
}


/*
 * nmwa_get_device_for_nm_device
 *
 * Searches the device list for a device that matches the
 * NetworkManager ID given.
 *
 */
NetworkDevice *nmwa_get_device_for_nm_path (GSList *dev_list, const char *nm_path)
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
 * nmwa_menu_item_activate
 *
 * Signal function called when user clicks on a menu item
 *
 */
static void nmwa_menu_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	NetworkDevice		*dev = NULL;
	WirelessNetwork	*net = NULL;
	char				*tag;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	if (!(tag = g_object_get_data (G_OBJECT (item), "device")))
		return;

	if ((dev = nmwa_get_device_for_nm_path (applet->device_list, tag)))
		network_device_ref (dev);

	if (!dev)
		return;

	if ((tag = g_object_get_data (G_OBJECT (item), "network")))
		net = network_device_get_wireless_network_by_essid (dev, tag);

	nmwa_dbus_set_device (applet->connection, dev, net ? wireless_network_get_essid (net) : NULL, -1, NULL);
	network_device_unref (dev);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nmwa_menu_vpn_item_activate
 *
 * Signal function called when user clicks on a VPN menu item
 *
 */
static void nmwa_menu_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	char				*tag;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	if ((tag = g_object_get_data (G_OBJECT (item), "vpn")))
	{
		VPNConnection	*vpn = (VPNConnection *)tag;
		const char	*name = nmwa_vpn_connection_get_name (vpn);
		GSList         *passwords;
		VPNConnection	*active_vpn = nmwa_get_first_active_vpn_connection (applet);

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

			if ((passwords = nmwa_vpn_request_password (applet, 
											    name, 
											    nmwa_vpn_connection_get_service (vpn), 
											    reprompt)) != NULL)
			{
				nmwa_dbus_vpn_activate_connection (applet->connection, name, passwords);

				g_slist_foreach (passwords, (GFunc)g_free, NULL);
				g_slist_free (passwords);
			}
		}
	}

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nmwa_menu_dialup_item_activate
 *
 * Signal function called when user clicks on a dialup menu item
 *
 */
static void nmwa_menu_dialup_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMWirelessApplet *applet = (NMWirelessApplet *) user_data;
	const char *dialup;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	dialup = g_object_get_data (G_OBJECT (item), "dialup");
	if (!dialup)
		return;

	nmwa_dbus_dialup_activate_connection (applet, dialup);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nmwa_menu_configure_vpn_item_activate
 *
 * Signal function called when user clicks "Configure VPN..."
 *
 */
static void nmwa_menu_configure_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	const char *argv[] = { BINDIR "/nm-vpn-properties", NULL};

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	g_spawn_async (NULL, (gchar **) argv, NULL, 0, NULL, NULL, NULL, NULL);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}

/*
 * nmwa_menu_disconnect_vpn_item_activate
 *
 * Signal function called when user clicks "Disconnect VPN..."
 *
 */
static void nmwa_menu_disconnect_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;

	g_return_if_fail (item != NULL);
	g_return_if_fail (applet != NULL);

	nmwa_dbus_vpn_deactivate_connection (applet->connection);

	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nmwa_menu_add_separator_item
 *
 */
static void nmwa_menu_add_separator_item (GtkWidget *menu)
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
static void nmwa_menu_add_text_item (GtkWidget *menu, char *text)
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
static void nmwa_menu_add_device_item (GtkWidget *menu, NetworkDevice *device, gint n_devices, NMWirelessApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (applet != NULL);

	switch (network_device_get_type (device))
	{
		case DEVICE_TYPE_WIRED_ETHERNET:
		{
			NMWiredMenuItem *item = wired_menu_item_new ();
			GtkCheckMenuItem *gtk_item = wired_menu_item_get_check_item (item);

			wired_menu_item_update (item, device, n_devices);
			if (network_device_get_active (device))
				gtk_check_menu_item_set_active (gtk_item, TRUE);
			gtk_check_menu_item_set_draw_as_radio (gtk_item, TRUE);

			g_object_set_data (G_OBJECT (gtk_item), "device", g_strdup (network_device_get_nm_path (device)));
			g_object_set_data (G_OBJECT (gtk_item), "nm-item-data", item);
			g_signal_connect(G_OBJECT (gtk_item), "activate", G_CALLBACK (nmwa_menu_item_activate), applet);

			gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (gtk_item));
			gtk_widget_show (GTK_WIDGET (gtk_item));
			break;
		}

		case DEVICE_TYPE_WIRELESS_ETHERNET:
		{
			NMWirelessMenuItem *item = wireless_menu_item_new ();
			GtkMenuItem *gtk_item = wireless_menu_item_get_item (item);

			wireless_menu_item_update (item, device, n_devices);

			g_object_set_data (G_OBJECT (gtk_item), "device", g_strdup (network_device_get_nm_path (device)));
			g_object_set_data (G_OBJECT (gtk_item), "nm-item-data", item);
			g_signal_connect(G_OBJECT (gtk_item), "activate", G_CALLBACK (nmwa_menu_item_activate), applet);

			gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (gtk_item));
			gtk_widget_show (GTK_WIDGET (gtk_item));
			break;
		}

		default:
			break;
	}
}


static void custom_essid_item_selected (GtkWidget *menu_item, NMWirelessApplet *applet)
{
	nmwa_other_network_dialog_run (applet, FALSE);
}


static void nmwa_menu_add_custom_essid_item (GtkWidget *menu, NMWirelessApplet *applet)
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


static void new_network_item_selected (GtkWidget *menu_item, NMWirelessApplet *applet)
{
	nmwa_other_network_dialog_run (applet, TRUE);
}


static void nmwa_menu_add_create_network_item (GtkWidget *menu, NMWirelessApplet *applet)
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
	NMWirelessApplet *	applet;
	gboolean			has_encrypted;
	GtkWidget *		menu;
} AddNetworksCB;


/*
 * nmwa_add_networks_helper
 *
 */
static void nmwa_add_networks_helper (NetworkDevice *dev, WirelessNetwork *net, gpointer user_data)
{
	AddNetworksCB *	cb_data = (AddNetworksCB *)user_data;
	NMNetworkMenuItem *	item;
	GtkCheckMenuItem *	gtk_item;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (net != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->menu != NULL);
	g_return_if_fail (cb_data->applet != NULL);

	item = network_menu_item_new (cb_data->applet->encryption_size_group);
	gtk_item = network_menu_item_get_check_item (item);

	gtk_menu_shell_append (GTK_MENU_SHELL (cb_data->menu), GTK_WIDGET (gtk_item));
	if (network_device_get_active (dev) && wireless_network_get_active (net))
		gtk_check_menu_item_set_active (gtk_item, TRUE);
	network_menu_item_update (item, net, cb_data->has_encrypted);

	g_object_set_data (G_OBJECT (gtk_item), "network", g_strdup (wireless_network_get_essid (net)));
	g_object_set_data (G_OBJECT (gtk_item), "device", g_strdup (network_device_get_nm_path (dev)));
	g_object_set_data (G_OBJECT (gtk_item), "nm-item-data", item);
	g_signal_connect (G_OBJECT (gtk_item), "activate", G_CALLBACK (nmwa_menu_item_activate), cb_data->applet);

	gtk_widget_show (GTK_WIDGET (gtk_item));
}


/*
 * nmwa_has_encrypted_networks_helper
 *
 */
static void nmwa_has_encrypted_networks_helper (NetworkDevice *dev, WirelessNetwork *net, gpointer user_data)
{
	gboolean * has_encrypted = user_data;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (net != NULL);
	g_return_if_fail (has_encrypted != NULL);

	if (wireless_network_get_encrypted (net))
		*has_encrypted = TRUE;
}


/*
 * nmwa_menu_device_add_networks
 *
 */
static void nmwa_menu_device_add_networks (GtkWidget *menu, NetworkDevice *dev, NMWirelessApplet *applet)
{
	gboolean			has_encrypted = FALSE;
	AddNetworksCB *	add_networks_cb = NULL;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev != NULL);

	if (!network_device_is_wireless (dev))
		return;

	/* Check for any security */
	network_device_foreach_wireless_network (dev, nmwa_has_encrypted_networks_helper, &has_encrypted);

	add_networks_cb = g_malloc0 (sizeof (AddNetworksCB));
	add_networks_cb->applet = applet;
	add_networks_cb->has_encrypted = has_encrypted;
	add_networks_cb->menu = menu;

	/* Add all networks in our network list to the menu */
	network_device_foreach_wireless_network (dev, nmwa_add_networks_helper, add_networks_cb);

	g_free (add_networks_cb);
}


/*
 * nmwa_menu_add_devices
 *
 */
static void nmwa_menu_add_vpn_menu (GtkWidget *menu, NMWirelessApplet *applet)
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
	active_vpn = nmwa_get_first_active_vpn_connection (applet);

	for (elt = applet->vpn_connections; elt; elt = g_slist_next (elt))
	{
		GtkCheckMenuItem	*vpn_item;
		VPNConnection		*vpn = elt->data;
		const char		*vpn_name = nmwa_vpn_connection_get_name (vpn);

		vpn_item = GTK_CHECK_MENU_ITEM (gtk_check_menu_item_new_with_label (vpn_name));
		/* temporarily do this until we support multiple VPN connections */
		gtk_check_menu_item_set_draw_as_radio (vpn_item, TRUE);

		nmwa_vpn_connection_ref (vpn);
		g_object_set_data (G_OBJECT (vpn_item), "vpn", vpn);

		if (active_vpn && active_vpn == vpn)
			gtk_check_menu_item_set_active (vpn_item, TRUE);

		g_signal_connect (G_OBJECT (vpn_item), "activate", G_CALLBACK (nmwa_menu_vpn_item_activate), applet);
		gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (vpn_item));
	}

	/* Draw a seperator, but only if we have VPN connections above it */
	if (applet->vpn_connections)
	{
		other_item = GTK_MENU_ITEM (gtk_separator_menu_item_new ());
		gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (other_item));
	}

	other_item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_Configure VPN...")));
	g_signal_connect (G_OBJECT (other_item), "activate", G_CALLBACK (nmwa_menu_configure_vpn_item_activate), applet);
	gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (other_item));

	other_item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_Disconnect VPN...")));
	g_signal_connect (G_OBJECT (other_item), "activate", G_CALLBACK (nmwa_menu_disconnect_vpn_item_activate), applet);
	if (!active_vpn)
		gtk_widget_set_sensitive (GTK_WIDGET (other_item), FALSE);
	gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (other_item));

	gtk_menu_item_set_submenu (item, GTK_WIDGET (vpn_menu));

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));
	gtk_widget_show_all (GTK_WIDGET (item));
}


static void nmwa_menu_add_dialup_menu (GtkWidget *menu, NMWirelessApplet *applet)
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
		GtkMenuItem *dialup_item;
		char *name = elt->data;
		const char *label;

		label = g_strdup_printf (_("Connect to %s..."), name);
		dialup_item = GTK_MENU_ITEM (gtk_menu_item_new_with_label (label));
		g_object_set_data (G_OBJECT (dialup_item), "dialup", name);

		g_signal_connect (G_OBJECT (dialup_item), "activate", G_CALLBACK (nmwa_menu_dialup_item_activate), applet);
		gtk_menu_shell_append (GTK_MENU_SHELL (dialup_menu), GTK_WIDGET (dialup_item));
	}

	gtk_menu_item_set_submenu (item, GTK_WIDGET (dialup_menu));
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));
	gtk_widget_show_all (GTK_WIDGET (item));
}


/** Returns TRUE if, and only if, we have VPN support installed
 *
 *  Algorithm: just check whether any .name files exist in
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
 * nmwa_menu_add_devices
 *
 */
static void nmwa_menu_add_devices (GtkWidget *menu, NMWirelessApplet *applet)
{
	GSList	*element;
	gint n_wireless_interfaces = 0;
	gint n_wired_interfaces = 0;
	gboolean vpn_available, dialup_available;

	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	if (! applet->device_list)
	{
		nmwa_menu_add_text_item (menu, _("No network devices have been found"));
		return;
	}

	for (element = applet->device_list; element; element = element->next)
	{
		NetworkDevice *dev = (NetworkDevice *)(element->data);

		g_assert (dev);

		switch (network_device_get_type (dev))
		{
			case DEVICE_TYPE_WIRELESS_ETHERNET:
				n_wireless_interfaces++;
				break;
			case DEVICE_TYPE_WIRED_ETHERNET:
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

			switch (network_device_get_type (dev))
			{
				case DEVICE_TYPE_WIRED_ETHERNET:
					n_devices = n_wired_interfaces;
					break;

				case DEVICE_TYPE_WIRELESS_ETHERNET:
					n_devices = n_wireless_interfaces;
					break;

				default:
					break;
			}

			if (n_devices >= 0)
			{
				nmwa_menu_add_device_item (menu, dev, n_devices, applet);
				nmwa_menu_device_add_networks (menu, dev, applet);
			}
		}
	}

	/* Add the VPN and Dial Up menus and their associated seperator */
	vpn_available = is_vpn_available ();
	dialup_available = !! applet->dialup_list;
	if (vpn_available || dialup_available)
	{
		nmwa_menu_add_separator_item (menu);
		if (vpn_available)
			nmwa_menu_add_vpn_menu (menu, applet);
		if (dialup_available)
			nmwa_menu_add_dialup_menu (menu, applet);
	}

	if (n_wireless_interfaces > 0)
	{
		/* Add the "Other wireless network..." entry */
		nmwa_menu_add_separator_item (menu);
		nmwa_menu_add_custom_essid_item (menu, applet);
		nmwa_menu_add_create_network_item (menu, applet);
	}
}


static void nmwa_set_wireless_enabled_cb (GtkWidget *widget, NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	nmwa_dbus_enable_wireless (applet, !applet->wireless_enabled);
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
		nmwa_vpn_connection_unref ((VPNConnection *)tag);
	}

	if ((tag = g_object_get_data (G_OBJECT (menu_item), "disconnect")))
	{
		g_object_set_data (G_OBJECT (menu_item), "disconnect", NULL);
		g_free (tag);
	}

	if ((menu = GTK_MENU (gtk_menu_item_get_submenu (GTK_MENU_ITEM (menu_item)))))
		gtk_container_foreach (GTK_CONTAINER (menu), nmwa_menu_item_data_free, menu);

	gtk_widget_destroy (menu_item);
}


/*
 * nmwa_dispose_menu_items
 *
 * Destroy the menu and each of its items data tags
 *
 */
static void nmwa_dropdown_menu_clear (GtkWidget *menu)
{
	g_return_if_fail (menu != NULL);

	/* Free the "network" data on each menu item, and destroy the item */
	gtk_container_foreach (GTK_CONTAINER (menu), nmwa_menu_item_data_free, menu);
}


/*
 * nmwa_dropdown_menu_populate
 *
 * Set up our networks menu from scratch
 *
 */
static void nmwa_dropdown_menu_populate (GtkWidget *menu, NMWirelessApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	if (!applet->nm_running)
		nmwa_menu_add_text_item (menu, _("NetworkManager is not running..."));
	else
		nmwa_menu_add_devices (menu, applet);
}


/*
 * nmwa_dropdown_menu_show_cb
 *
 * Pop up the wireless networks menu
 *
 */
static void nmwa_dropdown_menu_show_cb (GtkWidget *menu, NMWirelessApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);

	if (!applet->tooltips)
		applet->tooltips = gtk_tooltips_new ();
	gtk_tooltips_set_tip (applet->tooltips, applet->event_box, NULL, NULL);

	if (applet->dropdown_menu && (menu == applet->dropdown_menu))
	{
		nmwa_dropdown_menu_clear (applet->dropdown_menu);
		nmwa_dropdown_menu_populate (applet->dropdown_menu, applet);
		gtk_widget_show_all (applet->dropdown_menu);
	}

	nmi_dbus_signal_user_interface_activated (applet->connection);
}

/*
 * nmwa_dropdown_menu_create
 *
 * Create the applet's dropdown menu
 *
 */
static GtkWidget *nmwa_dropdown_menu_create (GtkMenuItem *parent, NMWirelessApplet *applet)
{
	GtkWidget	*menu;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (applet != NULL, NULL);

	menu = gtk_menu_new ();
	gtk_container_set_border_width (GTK_CONTAINER (menu), 0);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (parent), menu);
	g_signal_connect (menu, "show", G_CALLBACK (nmwa_dropdown_menu_show_cb), applet);

	return menu;
}


/*
 * nmwa_context_menu_update
 *
 */
static void nmwa_context_menu_update (NMWirelessApplet *applet)
{
	GSList *element;
	gboolean have_wireless = FALSE;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->stop_wireless_item != NULL);

	for (element = applet->device_list; element; element = element->next)
	{
		NetworkDevice *dev = (NetworkDevice *)(element->data);

		g_assert (dev);

		if (network_device_get_type (dev) == DEVICE_TYPE_WIRELESS_ETHERNET)
		{
			have_wireless = TRUE;
			break;
		}
	}

	if (have_wireless)
		gtk_widget_show_all (applet->stop_wireless_item);
	else
		gtk_widget_hide (applet->stop_wireless_item);
}


/*
 * nmwa_context_menu_create
 *
 * Generate the contextual popup menu.
 *
 */
static GtkWidget *nmwa_context_menu_create (NMWirelessApplet *applet)
{
	GtkWidget	*menu;
	GtkWidget	*menu_item;
	GtkWidget *image;

	g_return_val_if_fail (applet != NULL, NULL);

	menu = gtk_menu_new ();

	/* Wireless Enabled item */
	applet->stop_wireless_item = gtk_check_menu_item_new_with_mnemonic (_("_Wireless Enabled"));
	gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (applet->stop_wireless_item), TRUE);
	g_signal_connect (G_OBJECT (applet->stop_wireless_item), "activate", G_CALLBACK (nmwa_set_wireless_enabled_cb), applet);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), applet->stop_wireless_item);

	/* Connection Information item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("Connection _Information"));
	g_signal_connect (G_OBJECT (menu_item), "activate", G_CALLBACK (nmwa_show_info_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_INFO, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);

	/* Separator */
	nmwa_menu_add_separator_item (menu);

	/* Help item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("_Help"));
/*	g_signal_connect (G_OBJECT (menu_item), "activate", G_CALLBACK (nmwa_help_cb), applet); */
	image = gtk_image_new_from_stock (GTK_STOCK_HELP, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_set_sensitive (GTK_WIDGET (menu_item), FALSE);

	/* About item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("_About"));
	g_signal_connect (G_OBJECT (menu_item), "activate", G_CALLBACK (nmwa_about_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);

	gtk_widget_show_all (menu);

	return menu;
}


/*
 * nmwa_theme_change_cb
 *
 * Destroy the popdown menu when the theme changes
 *
 */
static void nmwa_theme_change_cb (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->dropdown_menu)
		nmwa_dropdown_menu_clear (applet->dropdown_menu);

	if (applet->top_menu_item)
	{
		gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));
		applet->dropdown_menu = nmwa_dropdown_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);
	}
}

/*
 * nmwa_toplevel_menu_button_press_cb
 *
 * Handle right-clicks for the context popup menu
 *
 */
static gboolean nmwa_toplevel_menu_button_press_cb (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;

	g_return_val_if_fail (applet != NULL, FALSE);

	if (event->button != 1)
		g_signal_stop_emission_by_name (widget, "button_press_event");

	if (event->button == 3)
	{
		nmwa_context_menu_update (applet);
		gtk_menu_popup (GTK_MENU (applet->context_menu), NULL, NULL, NULL, applet, event->button, event->time);
		return (TRUE);
	}

	return (FALSE);
}


/*
 * nmwa_setup_widgets
 *
 * Intialize the applet's widgets and packing, create the initial
 * menu of networks.
 *
 */
static void nmwa_setup_widgets (NMWirelessApplet *applet)
{
	GtkWidget      *menu_bar;

	/* Event box for tooltips */
	applet->event_box = gtk_event_box_new ();
	gtk_container_set_border_width (GTK_CONTAINER (applet->event_box), 0);

	menu_bar = gtk_menu_bar_new ();

	applet->top_menu_item = gtk_menu_item_new();
	gtk_widget_set_name (applet->top_menu_item, "ToplevelMenu");
	gtk_container_set_border_width (GTK_CONTAINER (applet->top_menu_item), 0);
	g_signal_connect (applet->top_menu_item, "button_press_event", G_CALLBACK (nmwa_toplevel_menu_button_press_cb), applet);

	applet->dropdown_menu = nmwa_dropdown_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);

	applet->pixmap = gtk_image_new ();
	applet->progress_bar = gtk_image_new ();

	applet->icon_box = gtk_hbox_new (FALSE, 3);
	gtk_container_set_border_width (GTK_CONTAINER (applet->icon_box), 0);

	/* Set up the widget structure and show the applet */
	gtk_container_add (GTK_CONTAINER (applet->icon_box), applet->progress_bar);
	gtk_container_add (GTK_CONTAINER (applet->icon_box), applet->pixmap);
	gtk_container_add (GTK_CONTAINER (applet->top_menu_item), applet->icon_box);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu_bar), applet->top_menu_item);
	gtk_container_add (GTK_CONTAINER (applet->event_box), menu_bar);
	gtk_container_add (GTK_CONTAINER (applet), applet->event_box);
	gtk_widget_show_all (GTK_WIDGET (applet));

	applet->context_menu = nmwa_context_menu_create (applet);
	applet->encryption_size_group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
}


/*
 * nmwa_gconf_info_notify_callback
 *
 * Callback from gconf when wireless key/values have changed.
 *
 */
static void nmwa_gconf_info_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMWirelessApplet *	applet = (NMWirelessApplet *)user_data;
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
 * nmwa_gconf_vpn_connections_notify_callback
 *
 * Callback from gconf when VPN connection values have changed.
 *
 */
static void nmwa_gconf_vpn_connections_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMWirelessApplet *	applet = (NMWirelessApplet *)user_data;
	const char *		key = NULL;

	/*g_debug ("Entering nmwa_gconf_vpn_connections_notify_callback, key='%s'", gconf_entry_get_key (entry));*/

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
				nmwa_dbus_vpn_remove_one_vpn_connection (applet, unescaped_name);
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
 * nmwa_destroy
 *
 * Destroy the applet and clean up its data
 *
 */
static void nmwa_destroy (NMWirelessApplet *applet, gpointer user_data)
{
	if (applet->dropdown_menu)
		nmwa_dropdown_menu_clear (applet->dropdown_menu);
	if (applet->top_menu_item)
		gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));

	nmwa_icons_free (applet);

	nmi_passphrase_dialog_destroy (applet->passphrase_dialog);

	if (applet->redraw_timeout_id > 0)
	{
		gtk_timeout_remove (applet->redraw_timeout_id);
		applet->redraw_timeout_id = 0;
	}

	if (applet->gconf_client)
		g_object_unref (G_OBJECT (applet->gconf_client));

	nmwa_free_data_model (applet);

	g_free (applet->glade_file);

	gconf_client_notify_remove (applet->gconf_client, applet->gconf_prefs_notify_id);
	gconf_client_notify_remove (applet->gconf_client, applet->gconf_vpn_notify_id);
	g_object_unref (G_OBJECT (applet->gconf_client));

	exit (EXIT_SUCCESS);
}


/*
 * nmwa_get_instance
 *
 * Create the initial instance of our wireless applet
 *
 */
static GtkWidget * nmwa_get_instance (NMWirelessApplet *applet)
{
	gtk_widget_hide (GTK_WIDGET (applet));

	applet->nm_running = FALSE;
	applet->device_list = NULL;
	applet->vpn_connections = NULL;
	applet->dialup_list = NULL;
	applet->nm_state = NM_STATE_DISCONNECTED;
	applet->tooltips = NULL;

	applet->glade_file = g_build_filename (GLADEDIR, "wireless-applet.glade", NULL);
	if (!applet->glade_file || !g_file_test (applet->glade_file, G_FILE_TEST_IS_REGULAR))
	{
		nmwa_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		g_free (applet->glade_file);
		applet->glade_file = NULL;
		return NULL;
	}

	applet->info_dialog_xml = glade_xml_new (applet->glade_file, "info_dialog", NULL);
	applet->passphrase_dialog = nmi_passphrase_dialog_init (applet);

	applet->gconf_client = gconf_client_get_default ();
	if (!applet->gconf_client)
		return NULL;

	gconf_client_add_dir (applet->gconf_client, GCONF_PATH_WIRELESS, GCONF_CLIENT_PRELOAD_NONE, NULL);
	applet->gconf_prefs_notify_id = gconf_client_notify_add (applet->gconf_client, GCONF_PATH_WIRELESS,
						nmwa_gconf_info_notify_callback, applet, NULL, NULL);

	gconf_client_add_dir (applet->gconf_client, GCONF_PATH_VPN_CONNECTIONS, GCONF_CLIENT_PRELOAD_NONE, NULL);
	applet->gconf_vpn_notify_id = gconf_client_notify_add (applet->gconf_client, GCONF_PATH_VPN_CONNECTIONS,
						nmwa_gconf_vpn_connections_notify_callback, applet, NULL, NULL);

	nmwa_dbus_init_helper (applet);

	/* Load pixmaps and create applet widgets */
	nmwa_setup_widgets (applet);

	g_signal_connect (applet, "destroy", G_CALLBACK (nmwa_destroy), NULL);
	g_signal_connect (applet, "style-set", G_CALLBACK (nmwa_theme_change_cb), NULL);

	/* Start redraw timeout */
	nmwa_start_redraw_timeout (applet);

	return GTK_WIDGET (applet);
}

static void setup_stock (void)
{
	GtkIconFactory *ifactory;
	GtkIconSet *iset;
	GtkIconSource *isource;
	static gboolean initted = FALSE;

	if (initted)
		return;

	ifactory = gtk_icon_factory_new ();
	iset = gtk_icon_set_new ();
	isource = gtk_icon_source_new ();

	/* we use the lockscreen icon to get a key */
	gtk_icon_source_set_icon_name (isource, "gnome-lockscreen");
	gtk_icon_set_add_source (iset, isource);
	gtk_icon_factory_add (ifactory, "gnome-lockscreen", iset);
	gtk_icon_factory_add_default (ifactory);

	initted = TRUE;
}

static void nmwa_icons_free (NMWirelessApplet *applet)
{
	gint i;

	g_object_unref (applet->no_connection_icon);
	g_object_unref (applet->wired_icon);
	g_object_unref (applet->adhoc_icon);
	g_object_unref (applet->vpn_lock_icon);

	g_object_unref (applet->wireless_00_icon);
	g_object_unref (applet->wireless_25_icon);
	g_object_unref (applet->wireless_50_icon);
	g_object_unref (applet->wireless_75_icon);
	g_object_unref (applet->wireless_100_icon);

	for (i = 0; i < NUM_WIRED_CONNECTING_FRAMES; i++)
		g_object_unref (applet->wired_connecting_icons[i]);

	for (i = 0; i < NUM_WIRELESS_CONNECTING_FRAMES; i++)
		g_object_unref (applet->wireless_connecting_icons[i]);

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
		g_object_unref (applet->vpn_connecting_icons[i]);
}

#define ICON_LOAD(x, y)	\
	{		\
		GError *err = NULL; \
		x = gtk_icon_theme_load_icon (icon_theme, y, icon_size, 0, &err); \
		if (x == NULL) { \
			success = FALSE; \
			g_warning ("Icon %s missing: %s", y, err->message); \
			g_error_free (err); \
			goto out; \
		} \
	}

static gboolean
nmwa_icons_load_from_disk (NMWirelessApplet *applet, GtkIconTheme *icon_theme)
{
	char *	name;
	int		i;
	gboolean	success = FALSE;

	/* Assume icons are square */
	gint icon_size = 22;

	ICON_LOAD(applet->no_connection_icon, "nm-no-connection");
	ICON_LOAD(applet->wired_icon, "nm-device-wired");
	ICON_LOAD(applet->adhoc_icon, "nm-adhoc");
	ICON_LOAD(applet->vpn_lock_icon, "nm-vpn-lock");

	ICON_LOAD(applet->wireless_00_icon, "nm-signal-00");
	ICON_LOAD(applet->wireless_25_icon, "nm-signal-25");
	ICON_LOAD(applet->wireless_50_icon, "nm-signal-50");
	ICON_LOAD(applet->wireless_75_icon, "nm-signal-75");
	ICON_LOAD(applet->wireless_100_icon, "nm-signal-100");

	for (i = 0; i < NUM_PROGRESS_FRAMES; i++)
	{
		name = g_strdup_printf ("nm-progress%02d", i+1);
		ICON_LOAD(applet->progress_icons[i], name);
		g_free (name);
	}

	for (i = 0; i < NUM_WIRED_CONNECTING_FRAMES; i++)
	{
		name = g_strdup_printf ("nm-connecting%02d", i+1);
		ICON_LOAD(applet->wired_connecting_icons[i], name);
		g_free (name);
	}

	for (i = 0; i < NUM_WIRELESS_CONNECTING_FRAMES; i++)
	{
		name = g_strdup_printf ("nm-connecting%02d", i+1);
		ICON_LOAD(applet->wireless_connecting_icons[i], name);
		g_free (name);
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
	{
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
		nmwa_icons_free (applet);
	}

	return success;
}

static void nmwa_icon_theme_changed (GtkIconTheme *icon_theme, NMWirelessApplet *applet)
{
	nmwa_icons_free (applet);
	nmwa_icons_load_from_disk (applet, icon_theme);
	/* FIXME: force redraw */
}

static gboolean nmwa_icons_init (NMWirelessApplet *applet)
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
	if (!nmwa_icons_load_from_disk (applet, icon_theme))
		return FALSE;
	g_signal_connect (icon_theme, "changed", G_CALLBACK (nmwa_icon_theme_changed), applet);
	return TRUE;
}


NMWirelessApplet *nmwa_new ()
{
	return g_object_new (NM_TYPE_WIRELESS_APPLET, "title", "NetworkManager", NULL);
}

