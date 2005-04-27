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

#ifndef APPLET_H
#define APPLET_H
#include <gtk/gtk.h>
#include <gconf/gconf-client.h>
#include <glade/glade.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include "eggtrayicon.h"
#include <net/ethernet.h>

#include "nm-device.h"
#include "wireless-network.h"


/*
 * Preference locations
 */
#define GCONF_PATH_WIRELESS_NETWORKS	"/system/networking/wireless/networks"
#define GCONF_PATH_VPN_CONNECTIONS		"/system/networking/vpn_connections"
#define GCONF_PATH_PREFS				"/apps/NetworkManagerApplet"


typedef struct VPNConnection VPNConnection;


#define NM_TYPE_WIRELESS_APPLET			(nmwa_get_type())
#define NM_WIRELESS_APPLET(object)			(G_TYPE_CHECK_INSTANCE_CAST((object), NM_TYPE_WIRELESS_APPLET, NMWirelessApplet))
#define NM_WIRELESS_APPLET_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_WIRELESS_APPLET, NMWirelessAppletClass))
#define NM_IS_WIRELESS_APPLET(object)		(G_TYPE_CHECK_INSTANCE_TYPE((object), NM_TYPE_WIRELESS_APPLET))
#define NM_IS_WIRELESS_APPLET_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_WIRELESS_APPLET))
#define NM_WIRELESS_APPLET_GET_CLASS(object)	(G_TYPE_INSTANCE_GET_CLASS((object), NM_TYPE_WIRELESS_APPLET, NMWirelessAppletClass))

typedef struct
{
	EggTrayIconClass	parent_class;
} NMWirelessAppletClass; 

/*
 * Applet instance data
 *
 */
typedef struct
{
	EggTrayIcon		parent;

	DBusConnection *	connection;
	GConfClient *		gconf_client;
	guint		 	gconf_net_notify_id;
	guint		 	gconf_vpn_notify_id;
	char	*			glade_file;
	guint			redraw_timeout_id;

	/* dbus thread stuff */
	GThread *			dbus_thread;
	GMainContext *		thread_context;
	GMainLoop *		thread_loop;
	gboolean			thread_done;

        /* Data model elements */
	GMutex *			data_mutex;
	gboolean			is_adhoc;
	gboolean			scanning_enabled;
	gboolean			wireless_enabled;
	gboolean			nm_running;

	GSList *			gui_device_list;
	NetworkDevice *	gui_active_device;
	NMState			gui_nm_state;

	GSList *			dev_pending_call_list;
	GSList *			dbus_device_list;
	NetworkDevice *	dbus_active_device;
	char *			dbus_active_device_path;
	NMState			dbus_nm_state;

	GSList *			gui_vpn_connections;
	VPNConnection *	gui_active_vpn;

	GSList *			vpn_pending_call_list;
	char *			dbus_active_vpn_name;
	GSList *			dbus_vpn_connections;
	VPNConnection *	dbus_active_vpn;

	GdkPixbuf *		no_nm_icon;
	GdkPixbuf *		no_connection_icon;
	GdkPixbuf *		wired_icon;
	GdkPixbuf *		adhoc_icon;
#define NUM_WIRED_CONNECTING_FRAMES 11
	GdkPixbuf *		wired_connecting_icons[NUM_WIRED_CONNECTING_FRAMES];
	GdkPixbuf *		wireless_00_icon;
	GdkPixbuf *		wireless_25_icon;
	GdkPixbuf *		wireless_50_icon;
	GdkPixbuf *		wireless_75_icon;
	GdkPixbuf *		wireless_100_icon;
#define NUM_WIRELESS_CONNECTING_FRAMES 11
	GdkPixbuf *		wireless_connecting_icons[NUM_WIRELESS_CONNECTING_FRAMES];
#define NUM_WIRELESS_SCANNING_FRAMES 16
	GdkPixbuf *		wireless_scanning_icons[NUM_WIRELESS_SCANNING_FRAMES];
	GdkPixbuf *		vpn_lock_icon;

	/* Animation stuff */
	int				animation_step;
	guint			animation_id;

	/* Direct UI elements */
	GtkWidget *		pixmap;
	GtkWidget *		top_menu_item;
	GtkWidget *		dropdown_menu;
	GtkWidget *		vpn_menu;
	GtkWidget *		event_box;
	GtkSizeGroup *		encryption_size_group;
	GtkTooltips *		tooltips;

	GtkWidget *		context_menu;
	GtkWidget *		pause_scanning_item;
	GtkWidget *		stop_wireless_item;

	GtkWidget *		passphrase_dialog;
} NMWirelessApplet;

typedef struct
{
	NMWirelessApplet *	applet;
	NetworkDevice *	dev;
	GladeXML *		xml;
} DriverNotifyCBData;

NetworkDevice *	nmwa_get_device_for_nm_device			(GSList *dev_list, const char *nm_dev);
NMWirelessApplet *	nmwa_new							(void);
void				nmwa_schedule_warning_dialog			(NMWirelessApplet *applet, const char *msg);
gboolean			nmwa_driver_notify					(gpointer user_data);
void				nmwa_schedule_vpn_login_failure_dialog	(NMWirelessApplet *applet, const char *vpn_name, const char *error_msg);
void				nmwa_schedule_vpn_login_banner_dialog	(NMWirelessApplet *applet, const char *vpn_name, const char *banner);

int				nm_null_safe_strcmp					(const char *s1, const char *s2);

#endif
