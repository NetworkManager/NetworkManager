/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
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

#ifndef NETWORK_MANAGER_INFO_H
#define NETWORK_MANAGER_INFO_H

#include <syslog.h>
#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <glade/glade.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <gconf/gconf-client.h>
#include "NetworkManager.h"

struct NMIAppInfo
{
	GladeXML		*passphrase_dialog;
	GtkWidget		*vpn_password_dialog;
	DBusMessage		*vpn_password_message;
	char			*orig_label_text;
	DBusConnection	*connection;
	GConfClient	*gconf_client;

	GladeXML		*networks_dialog;
	GtkListStore	*networks_list_store;

	GdkPixbuf		*padlock_pixbuf;

	/*
	GtkWidget	*notification_icon;
	*/
	GPid			notification_icon_pid;
	guint		notification_icon_watch;
	guint		notification_icon_respawn_counter;
	GTimer		*notification_icon_respawn_timer;

	GSource		*shutdown_timeout;
};
typedef struct NMIAppInfo NMIAppInfo;

NMWirelessScanMethod nmi_gconf_get_wireless_scan_method (NMIAppInfo *info);

#endif
