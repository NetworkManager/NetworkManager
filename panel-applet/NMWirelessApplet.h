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

typedef enum
{
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
	PIX_NUMBER,
} PixmapState;


typedef struct
{
	PanelApplet		 base;

	DBusConnection		*connection;
	gboolean			 nm_active;
	GConfClient		*gconf_client;
	GladeXML			*net_dialog;

	PixmapState		 pix_state;
	/* contains pointers into the images GList.
	 * 0-100 are for link */
	GdkPixbuf			*pixmaps[PIX_NUMBER];
	/* pointer to the current used file name */
	GdkPixbuf			*current_pixbuf;
	GdkPixbuf			*key_pixbuf;

	GtkWidget			*pixmap;
	GtkWidget			*button;
	GtkWidget			*box;
	GtkWidget			*about_dialog;
	GtkWidget			*menu;

	guint			 timeout_handler_id;
} NMWirelessApplet;


void			nmwa_add_menu_item	(NMWirelessApplet *applet, GtkWidget *menu, char *text, char *tag,
								gboolean current, gboolean encrypted);

GtkWidget *	nmwa_populate_menu	(NMWirelessApplet *applet);

void			nmwa_dispose_menu	(NMWirelessApplet *applet);

#endif
