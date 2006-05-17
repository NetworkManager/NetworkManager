/* menu-info.h: Simple menu items for the Applet to use
 *
 * Jonathan Blandford <jrb@redhat.com>
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

#ifndef MENU_ITEMS_H
#define MENU_ITEMS_H

#include <gtk/gtk.h>
#include "applet.h"


typedef struct NMWiredMenuItem NMWiredMenuItem;
typedef struct NMWirelessMenuItem NMWirelessMenuItem;
typedef struct NMNetworkMenuItem NMNetworkMenuItem;


NMWiredMenuItem	*wired_menu_item_new (void);
GtkCheckMenuItem	*wired_menu_item_get_check_item (NMWiredMenuItem *item);
void				 wired_menu_item_update (NMWiredMenuItem *item, NetworkDevice *dev, const gint n_devices);

NMWirelessMenuItem	*wireless_menu_item_new (void);
GtkMenuItem		*wireless_menu_item_get_item (NMWirelessMenuItem *item);
void				 wireless_menu_item_update (NMWirelessMenuItem *item, NetworkDevice *dev, const gint n_devices);

NMNetworkMenuItem	*network_menu_item_new (GtkSizeGroup *encryption_size_group);
GtkCheckMenuItem	*network_menu_item_get_check_item (NMNetworkMenuItem *item);
void				 network_menu_item_update (NMApplet *applet, NMNetworkMenuItem *item, WirelessNetwork *network, const gboolean is_encrypted);

/* Helper function; escapes an essid for human readable display. */
char      		*nm_menu_network_escape_essid_for_display (const char *essid);


#endif /* MENU_INFO_H */
