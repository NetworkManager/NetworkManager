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
#include <gconf/gconf-client.h>
#include <glade/glade.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#ifndef BUILD_NOTIFICATION_ICON
#include <panel-applet.h>
#include <panel-applet-gconf.h>
#else
#include "eggtrayicon.h"
#endif

typedef enum
{
	APPLET_STATE_NO_NM,
	APPLET_STATE_NO_CONNECTION,
	APPLET_STATE_WIRED,
	APPLET_STATE_WIRED_CONNECTING,
	APPLET_STATE_WIRELESS,
	APPLET_STATE_WIRELESS_CONNECTING,
	APPLET_STATE_WIRELESS_SCANNING,
	APPLET_STATE_IGNORE
} AppletState;


/*
 * Representation of a wireless network
 *
 */
typedef struct
{
	int		 refcount;
	char		*nm_name;
	char		*essid;
	gboolean	 encrypted;
	gboolean	 active;
	gint8	 strength;
} WirelessNetwork;

/*
 * Representation of network device
 *
 */
typedef struct
{
	int		 refcount;
	char		*nm_device;
	int		 type;
	gboolean	 link;
	char		*nm_name;
	char		*hal_name;
	char		*udi;
	gint		 strength;
	GSList	*networks;
} NetworkDevice;



#ifdef BUILD_NOTIFICATION_ICON

#define NM_TYPE_WIRELESS_APPLET (nmwa_get_type())
#define NM_WIRELESS_APPLET(object) (G_TYPE_CHECK_INSTANCE_CAST((object), NM_TYPE_WIRELESS_APPLET, NMWirelessApplet))
#define NM_WIRELESS_APPLET_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_WIRELESS_APPLET, NMWirelessAppletClass))
#define NM_IS_WIRELESS_APPLET(object) (G_TYPE_CHECK_INSTANCE_TYPE((object), NM_TYPE_WIRELESS_APPLET))
#define NM_IS_WIRELESS_APPLET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_WIRELESS_APPLET))
#define NM_WIRELESS_APPLET_GET_CLASS(object) (G_TYPE_INSTANCE_GET_CLASS((object), NM_TYPE_WIRELESS_APPLET, NMWirelessAppletClass))

typedef struct
{
	EggTrayIconClass	parent_class;
} NMWirelessAppletClass; 
#endif

/*
 * Applet instance data
 *
 */
typedef struct
{
	EggTrayIcon		 parent;

	DBusConnection		*connection;
	GConfClient		*gconf_client;
	GladeXML			*ui_resources;
	guint			 redraw_timeout_id;
	GThread			*dbus_thread;
	GMainContext		*thread_context;

        /* Data model elements */
	GMutex			*data_mutex;
	AppletState		 applet_state;
	gboolean			 is_adhoc;
	GSList			*device_list;
	NetworkDevice		*active_device;
	char				*nm_status;
	NetworkDevice		*dbus_active_device;

	GdkPixbuf *no_nm_icon;
	GdkPixbuf *wired_icon;
	GdkPixbuf *adhoc_icon;
#define NUM_WIRED_CONNECTING_FRAMES 11
	GdkPixbuf *wired_connecting_icons[NUM_WIRED_CONNECTING_FRAMES];
	GdkPixbuf *wireless_00_icon;
	GdkPixbuf *wireless_25_icon;
	GdkPixbuf *wireless_50_icon;
	GdkPixbuf *wireless_75_icon;
	GdkPixbuf *wireless_100_icon;
#define NUM_WIRELESS_CONNECTING_FRAMES 11
	GdkPixbuf *wireless_connecting_icons[NUM_WIRELESS_CONNECTING_FRAMES];
#define NUM_WIRELESS_SCANNING_FRAMES 16
	GdkPixbuf *wireless_scanning_icons[NUM_WIRELESS_SCANNING_FRAMES];

	/* Animation stuff */
	int animation_step;
	guint animation_id;

	/* Direct UI elements */
	GtkWidget			*pixmap;
	GtkWidget			*menu;
	GtkWidget			*toplevel_menu;
	GtkWidget			*event_box;
	GtkSizeGroup        *encryption_size_group;
	GtkTooltips		*tooltips;
} NMWirelessApplet;


NetworkDevice		*nmwa_get_device_for_nm_device (NMWirelessApplet *applet, const char *nm_dev);
NMWirelessApplet	*nmwa_new (void);
void				 show_warning_dialog (gboolean error, gchar *mesg, ...);

#endif
