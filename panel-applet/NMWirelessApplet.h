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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NM_WIRELESS_APPLET_H
#define NM_WIRELESS_APPLET_H

#include <gnome.h>
#include <panel-applet.h>
#include <panel-applet-gconf.h>
#include <gconf/gconf-client.h>
#include <glade/glade.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

typedef enum
{
	PIX_NO_NETWORKMANAGER,
	PIX_WIRED,
	PIX_WIRELESS_NO_LINK,
	PIX_WIRELESS_SIGNAL_1,
	PIX_WIRELESS_SIGNAL_2,
	PIX_WIRELESS_SIGNAL_3,
	PIX_WIRELESS_SIGNAL_4,
	PIX_WIRELESS_CONNECT_0,
	PIX_WIRELESS_CONNECT_1,
	PIX_WIRELESS_CONNECT_2,
	PIX_WIRELESS_CONNECT_3,
	PIX_NUMBER
} PixmapState;


typedef enum
{
	APPLET_STATE_NO_NM,
	APPLET_STATE_NO_CONNECTION,
	APPLET_STATE_WIRED,
	APPLET_STATE_WIRED_CONNECTING,
	APPLET_STATE_WIRELESS,
	APPLET_STATE_WIRELESS_CONNECTING,
	APPLET_STATE_IGNORE
} AppletState;


/*
 * Applet instance data
 *
 */
typedef struct
{
	PanelApplet		 base;

	DBusConnection		*connection;
	GConfClient		*gconf_client;
	GladeXML			*ui_resources;
	guint			 redraw_timeout_id;
	GThread			*dbus_thread;
	GMainContext		*thread_context;

	PixmapState		 pix_state;	// Index into pixmaps array
	GdkPixbuf			*pixmaps[PIX_NUMBER];
	GdkPixbuf			*current_pixbuf;
	GdkPixbuf			*key_pixbuf;
	GdkPixbuf			*wired_icon;
	GdkPixbuf			*wireless_icon;

	/* Data model elements */
	GMutex			*data_mutex;
	GSList			*devices;
	char				*active_device;
	AppletState		 applet_state;

	/* Direct UI elements */
	GtkWidget			*pixmap;
	GtkWidget			*box;
	GtkWidget			*about_dialog;
	GtkWidget			*menu;
	GtkWidget			*toplevel_menu;
} NMWirelessApplet;


/*
 * Representation of a wireless network
 *
 */
typedef struct
{
	char		*nm_name;
	char		*essid;
	gboolean	 encrypted;
	gboolean	 active;
	guint8	 quality;
} WirelessNetwork;

/*
 * Representation of network device
 *
 */
typedef struct
{
	char		*nm_device;
	int		 type;
	char		*nm_name;
	char		*hal_name;
	char		*udi;
	GSList	*networks;
} NetworkDevice;

#endif
