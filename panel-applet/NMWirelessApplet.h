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
#include <gtk/gtk.h>
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
#include <net/ethernet.h>

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
	guint32	 driver_support_level;
	char		*addr;
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
#ifdef BUILD_NOTIFICATION_ICON
	EggTrayIcon		 parent;
#endif

	DBusConnection		*connection;
	GConfClient		*gconf_client;
	char				*glade_file;
	guint			 redraw_timeout_id;

	/* dbus thread stuff */
	GThread			*dbus_thread;
	GMainContext		*thread_context;
	GMainLoop			*thread_loop;
	gboolean			 thread_done;

        /* Data model elements */
	GMutex			*data_mutex;
	AppletState		 applet_state;
	gboolean			 is_adhoc;
	gboolean			 scanning_enabled;
	gboolean			 wireless_enabled;

	GSList			*gui_device_list;
	NetworkDevice		*gui_active_device;
	char				*gui_nm_status;

	GSList			*dbus_device_list;
	NetworkDevice		*dbus_active_device;
	char				*dbus_nm_status;

	GdkPixbuf			*no_nm_icon;
	GdkPixbuf			*no_connection_icon;
	GdkPixbuf			*wired_icon;
	GdkPixbuf			*adhoc_icon;
#define NUM_WIRED_CONNECTING_FRAMES 11
	GdkPixbuf			*wired_connecting_icons[NUM_WIRED_CONNECTING_FRAMES];
	GdkPixbuf			*wireless_00_icon;
	GdkPixbuf			*wireless_25_icon;
	GdkPixbuf			*wireless_50_icon;
	GdkPixbuf			*wireless_75_icon;
	GdkPixbuf			*wireless_100_icon;
#define NUM_WIRELESS_CONNECTING_FRAMES 11
	GdkPixbuf			*wireless_connecting_icons[NUM_WIRELESS_CONNECTING_FRAMES];
#define NUM_WIRELESS_SCANNING_FRAMES 16
	GdkPixbuf			*wireless_scanning_icons[NUM_WIRELESS_SCANNING_FRAMES];

	/* Animation stuff */
	int				 animation_step;
	guint			 animation_id;

	/* Direct UI elements */
	GtkWidget			*pixmap;
	GtkWidget			*top_menu_item;
	GtkWidget			*dropdown_menu;
	GtkWidget			*event_box;
	GtkSizeGroup        *encryption_size_group;
	GtkTooltips		*tooltips;

	GtkWidget			*context_menu;
	GtkWidget			*pause_scanning_item;
	GtkWidget			*stop_wireless_item;

} NMWirelessApplet;

typedef struct
{
	NMWirelessApplet	*applet;
	NetworkDevice		*dev;
	GladeXML			*xml;
} DriverNotifyCBData;

NetworkDevice		*nmwa_get_device_for_nm_device (GSList *dev_list, const char *nm_dev);
WirelessNetwork	*nmwa_get_net_for_nm_net (NetworkDevice *dev, const char *net_path);
WirelessNetwork	*nmwa_get_net_by_essid (NetworkDevice *dev, const char *essid);
NMWirelessApplet	*nmwa_new (void);
void				 show_warning_dialog (gboolean error, gchar *mesg, ...);
gboolean			 nmwa_driver_notify (gpointer user_data);

#endif
