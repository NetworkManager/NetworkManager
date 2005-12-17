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
#include "dbus-method-dispatcher.h"


/*
 * Preference locations
 */
#define GCONF_PATH_WIRELESS_NETWORKS	"/system/networking/wireless/networks"
#define GCONF_PATH_WIRELESS			"/system/networking/wireless"
#define GCONF_PATH_VPN_CONNECTIONS		"/system/networking/vpn_connections"
#define GCONF_PATH_PREFS				"/apps/NetworkManagerApplet"


typedef struct VPNConnection VPNConnection;


enum NMWAEncryptionKeyTypes
{
	KEY_TYPE_128_BIT_PASSPHRASE = 0,
	KEY_TYPE_ASCII_KEY = 1,
	KEY_TYPE_HEX_KEY = 2
};

static GType nmwa_get_type (void); /* prototype for G_DEFINE_TYPE */

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
	DBusMethodDispatcher *	nmi_methods;
	GConfClient *		gconf_client;
	guint		 	gconf_prefs_notify_id;
	guint		 	gconf_vpn_notify_id;
	char	*			glade_file;
	guint			redraw_timeout_id;

	/* Data model elements */
	gboolean			is_adhoc;
	gboolean			wireless_enabled;
	gboolean			nm_running;

	NMState			nm_state;
	GSList *			device_list;
	GSList *			dialup_list;
	GSList *			vpn_connections;

	GdkPixbuf *		no_connection_icon;
	GdkPixbuf *		wired_icon;
	GdkPixbuf *		adhoc_icon;
	GdkPixbuf *		wireless_00_icon;
	GdkPixbuf *		wireless_25_icon;
	GdkPixbuf *		wireless_50_icon;
	GdkPixbuf *		wireless_75_icon;
	GdkPixbuf *		wireless_100_icon;
#define NUM_CONNECTING_STAGES 3
#define NUM_CONNECTING_FRAMES 11
	GdkPixbuf *		network_connecting_icons[NUM_CONNECTING_STAGES][NUM_CONNECTING_FRAMES];
#define NUM_VPN_CONNECTING_FRAMES 14
	GdkPixbuf *		vpn_connecting_icons[NUM_VPN_CONNECTING_FRAMES];
	GdkPixbuf *		vpn_lock_icon;

	/* Animation stuff */
	int				animation_step;
	guint			animation_id;

	/* Direct UI elements */
	GtkWidget *		icon_box;
	GtkWidget *		pixmap;
	GtkWidget *		top_menu_item;
	GtkWidget *		dropdown_menu;
	GtkWidget *		vpn_menu;
	GtkWidget *		event_box;
	GtkSizeGroup *		encryption_size_group;
	GtkTooltips *		tooltips;

	GtkWidget *		context_menu;
	GtkWidget *		stop_wireless_item;
	GtkWidget *		info_menu_item;

	GtkWidget *		passphrase_dialog;
	GladeXML *		info_dialog_xml;
} NMWirelessApplet;

typedef struct
{
	NMWirelessApplet *	applet;
	NetworkDevice *	dev;
	GladeXML *		xml;
} DriverNotifyCBData;

NetworkDevice *	nmwa_get_device_for_nm_path			(GSList *dev_list, const char *nm_dev);
NMWirelessApplet *	nmwa_new							(void);
void				nmwa_schedule_warning_dialog			(NMWirelessApplet *applet, const char *msg);
gboolean			nmwa_driver_notify					(gpointer user_data);
void				nmwa_schedule_vpn_failure_dialog		(NMWirelessApplet *applet, const char *member, const char *vpn_name, const char *error_msg);
void				nmwa_schedule_vpn_login_banner_dialog	(NMWirelessApplet *applet, const char *vpn_name, const char *banner);

NetworkDevice *	nmwa_get_first_active_device			(GSList *dev_list);
VPNConnection *	nmwa_get_first_active_vpn_connection	(NMWirelessApplet *applet);

void				nmwa_enable_wireless_set_active		(NMWirelessApplet *applet);

int				nm_null_safe_strcmp					(const char *s1, const char *s2);

#endif
